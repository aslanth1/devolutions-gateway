use axum::Router;
use axum::extract::State;
use axum::routing::post;
use uuid::Uuid;

use crate::DgwState;
use crate::extract::ScopeToken;
use crate::http::HttpError;
use crate::session::{KillResult, SessionKillMetadata};
use crate::token::AccessScope;

pub fn make_router<S>(state: DgwState) -> Router<S> {
    Router::new()
        .route("/{id}/terminate", post(terminate_session))
        .with_state(state)
}

/// Terminate forcefully a running session
#[cfg_attr(feature = "openapi", utoipa::path(
    post,
    operation_id = "TerminateSession",
    tag = "Sessions",
    path = "/jet/session/{id}/terminate",
    params(
        ("id" = Uuid, Path, description = "Session / association ID of the session to terminate")
    ),
    responses(
        (status = 200, description = "Session terminated successfully"),
        (status = 400, description = "Bad request"),
        (status = 401, description = "Invalid or missing authorization token"),
        (status = 403, description = "Insufficient permissions"),
        (status = 404, description = "No running session found with provided ID"),
        (status = 500, description = "Unexpected server error"),
    ),
    security(("scope_token" = ["gateway.session.terminate"])),
))]
pub(crate) async fn terminate_session(
    State(state): State<DgwState>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    scope_token: ScopeToken,
) -> Result<(), HttpError> {
    let kill_metadata = authorize_terminate_scope(&state, &scope_token)?;

    let kill_result = match kill_metadata {
        Some(kill_metadata) => {
            state
                .sessions
                .kill_session_with_metadata(session_id, kill_metadata)
                .await
        }
        None => state.sessions.kill_session(session_id).await,
    }
    .map_err(HttpError::internal().err())?;

    match kill_result {
        KillResult::Success => Ok(()),
        KillResult::NotFound => Err(HttpError::not_found().msg("session not found")),
    }
}

fn authorize_terminate_scope(
    state: &DgwState,
    scope_token: &ScopeToken,
) -> Result<Option<SessionKillMetadata>, HttpError> {
    let conf = state.conf_handle.get_conf();
    let scope = &scope_token.0.scope;

    if matches!(scope, AccessScope::Wildcard | AccessScope::SessionTerminate) {
        return if state.honeypot.is_enabled() {
            ensure_honeypot_session_kill_enabled(&conf)?;
            Ok(Some(SessionKillMetadata::operator(scope_token.0.token_id())))
        } else {
            Ok(None)
        };
    }

    if !state.honeypot.is_enabled() {
        return Err(HttpError::forbidden().msg("invalid scope for route"));
    }

    ensure_honeypot_session_kill_enabled(&conf)?;

    match scope {
        AccessScope::HoneypotSessionKill | AccessScope::HoneypotSystemKill => {
            Ok(Some(SessionKillMetadata::operator(scope_token.0.token_id())))
        }
        _ => Err(HttpError::forbidden().msg("invalid scope for route")),
    }
}

fn ensure_honeypot_session_kill_enabled(conf: &crate::config::Conf) -> Result<(), HttpError> {
    if conf.honeypot.kill_switch.enable_session_kill {
        Ok(())
    } else {
        Err(HttpError::conflict().msg("honeypot session kill is disabled"))
    }
}
