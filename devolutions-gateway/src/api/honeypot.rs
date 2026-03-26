use std::convert::Infallible;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::response::sse::{Event, KeepAlive, Sse};
use futures::StreamExt as _;
use serde::Deserialize;
use tokio_stream::wrappers::BroadcastStream;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::{HoneypotStreamReadScope, HoneypotWatchScope};
use crate::honeypot::{HoneypotCursorError, HoneypotMode, HoneypotStreamError};
use crate::http::HttpError;

pub fn make_router<S>(state: DgwState) -> axum::Router<S> {
    let Some(runtime) = state.honeypot.runtime() else {
        return axum::Router::new().with_state(state);
    };

    let bootstrap_path = runtime.bootstrap_path().to_owned();
    let events_path = runtime.events_path().to_owned();

    axum::Router::new()
        .route(bootstrap_path.as_str(), axum::routing::get(get_bootstrap))
        .route(events_path.as_str(), axum::routing::get(get_events))
        .route(
            "/jet/honeypot/session/{id}/stream-token",
            axum::routing::post(post_stream_token),
        )
        .with_state(state)
}

pub(crate) async fn get_bootstrap(
    State(state): State<DgwState>,
    _scope: HoneypotWatchScope,
) -> Result<Json<honeypot_contracts::frontend::BootstrapResponse>, HttpError> {
    let HoneypotMode::Enabled(runtime) = &state.honeypot else {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    };

    let sessions = state
        .sessions
        .get_running_sessions()
        .await
        .map_err(HttpError::internal().err())?;

    Ok(Json(runtime.bootstrap_response(sessions)))
}

#[derive(Deserialize)]
pub(crate) struct HoneypotEventsQuery {
    cursor: Option<String>,
}

pub(crate) async fn get_events(
    State(state): State<DgwState>,
    Query(query): Query<HoneypotEventsQuery>,
    _scope: HoneypotWatchScope,
) -> Result<Sse<impl futures::Stream<Item = Result<Event, Infallible>>>, HttpError> {
    let HoneypotMode::Enabled(runtime) = &state.honeypot else {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    };

    let cursor = query
        .cursor
        .ok_or_else(|| HttpError::conflict().msg("cursor expired"))?;
    let (replay, receiver) = runtime.stream_from_cursor(&cursor).map_err(map_cursor_error)?;

    let replay_stream = futures::stream::iter(replay.into_iter().map(|event| Ok(to_sse_event(event))));
    let live_stream = BroadcastStream::new(receiver).filter_map(|result| async move {
        match result {
            Ok(event) => Some(Ok(to_sse_event(event))),
            Err(_) => None,
        }
    });

    Ok(Sse::new(replay_stream.chain(live_stream)).keep_alive(KeepAlive::default()))
}

pub(crate) async fn post_stream_token(
    State(state): State<DgwState>,
    Path(session_id): Path<Uuid>,
    _watch_scope: HoneypotWatchScope,
    _stream_scope: HoneypotStreamReadScope,
    Json(request): Json<honeypot_contracts::stream::StreamTokenRequest>,
) -> Result<Json<honeypot_contracts::stream::StreamTokenResponse>, HttpError> {
    use honeypot_contracts::Versioned as _;

    let HoneypotMode::Enabled(runtime) = &state.honeypot else {
        return Err(HttpError::not_found().msg("honeypot mode is disabled"));
    };

    request
        .ensure_supported_schema()
        .map_err(|_| HttpError::bad_request().msg("unsupported stream token schema version"))?;

    if request.session_id != session_id.to_string() {
        return Err(HttpError::bad_request().msg("session id does not match request path"));
    }

    let session = state
        .sessions
        .get_session_info(session_id)
        .await
        .map_err(HttpError::internal().err())?
        .ok_or_else(|| HttpError::not_found().msg("session not found"))?;

    match runtime.issue_stream_token(&session).await {
        Ok(response) => {
            let _ = state.sessions.sync_honeypot_metadata(session_id).await;
            Ok(Json(response))
        }
        Err(error) => {
            let _ = state.sessions.sync_honeypot_metadata(session_id).await;
            Err(map_stream_error(error))
        }
    }
}

fn map_cursor_error(_: HoneypotCursorError) -> HttpError {
    HttpError::conflict().msg("cursor expired")
}

fn map_stream_error(error: HoneypotStreamError) -> HttpError {
    match error {
        HoneypotStreamError::NoActiveLease => HttpError::conflict().msg("no active honeypot lease"),
        HoneypotStreamError::ControlPlaneUnavailable => {
            HttpError::bad_gateway().msg("honeypot control plane is unavailable")
        }
        HoneypotStreamError::ControlPlane(error) => HttpError::bad_gateway()
            .with_msg("honeypot control plane request failed")
            .build(error),
        HoneypotStreamError::StreamUnavailable => HttpError::bad_gateway().msg("honeypot stream is unavailable"),
    }
}

fn to_sse_event(event: honeypot_contracts::events::EventEnvelope) -> Event {
    let event_kind = event_kind_name(&event.payload);
    let data = serde_json::to_string(&event).unwrap_or_else(|_| "{}".to_owned());

    Event::default().id(event.global_cursor).event(event_kind).data(data)
}

fn event_kind_name(payload: &honeypot_contracts::events::EventPayload) -> &'static str {
    use honeypot_contracts::events::EventPayload;

    match payload {
        EventPayload::SessionStarted { .. } => "session.started",
        EventPayload::SessionAssigned { .. } => "session.assigned",
        EventPayload::SessionStreamReady { .. } => "session.stream.ready",
        EventPayload::SessionEnded { .. } => "session.ended",
        EventPayload::SessionKilled { .. } => "session.killed",
        EventPayload::SessionRecycleRequested { .. } => "session.recycle.requested",
        EventPayload::HostRecycled { .. } => "host.recycled",
        EventPayload::SessionStreamFailed { .. } => "session.stream.failed",
        EventPayload::ProxyStatusDegraded { .. } => "proxy.status.degraded",
    }
}
