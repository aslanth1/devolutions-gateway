mod auth;
pub mod config;

use std::sync::Arc;

use anyhow::Context as _;
use askama::Template;
use axum::body::Body;
use axum::extract::{Form, Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt as _;
use honeypot_contracts::events::{SessionState, StreamState};
use honeypot_contracts::frontend::{
    BootstrapResponse, BootstrapSession, ClipboardCaptureRequest, ClipboardCaptureResponse, ClipboardCaptureState,
    CommandProposalRequest, CommandProposalResponse, CommandProposalState, CommandVoteChoice, CommandVoteRequest,
    CommandVoteResponse, CommandVoteState, KeyboardCaptureRequest, KeyboardCaptureResponse, KeyboardCaptureState,
};
use honeypot_contracts::stream::{StreamPreview, StreamTokenRequest, StreamTokenResponse, StreamTransport};
use tokio::net::TcpListener;

use self::auth::{AuthError, FrontendAuth, OperatorAccess, RequiredScope};
use self::config::FrontendConfig;

#[derive(Clone)]
pub struct FrontendRuntime {
    config: FrontendConfig,
    auth: FrontendAuth,
    client: reqwest::Client,
}

impl FrontendRuntime {
    pub fn new(config: FrontendConfig) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(config.proxy.connect_timeout_secs))
            .timeout(std::time::Duration::from_secs(config.proxy.request_timeout_secs))
            .build()
            .context("build frontend proxy client")?;
        let auth = FrontendAuth::from_config(&config.auth).context("build frontend auth gate")?;

        Ok(Self { config, auth, client })
    }

    pub fn bind_addr(&self) -> std::net::SocketAddr {
        self.config.http.bind_addr
    }

    async fn fetch_bootstrap(&self) -> anyhow::Result<BootstrapResponse> {
        let response = self
            .authorized(self.client.get(self.config.proxy.bootstrap_url()?))
            .send()
            .await
            .context("request bootstrap from proxy")?
            .error_for_status()
            .context("proxy bootstrap request failed")?;

        response
            .json::<BootstrapResponse>()
            .await
            .context("decode proxy bootstrap response")
    }

    async fn fetch_session(&self, session_id: &str) -> anyhow::Result<Option<BootstrapSession>> {
        let bootstrap = self.fetch_bootstrap().await?;

        Ok(bootstrap
            .sessions
            .into_iter()
            .find(|session| session.session_id == session_id))
    }

    async fn fetch_stream_token(&self, session_id: &str) -> anyhow::Result<StreamTokenResponse> {
        let request = StreamTokenRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("frontend-stream-token-{session_id}"),
            session_id: session_id.to_owned(),
        };

        let response = self
            .authorized(self.client.post(self.config.proxy.stream_token_url(session_id)?))
            .json(&request)
            .send()
            .await
            .with_context(|| format!("request stream token for session {session_id}"))?
            .error_for_status()
            .with_context(|| format!("proxy stream-token request failed for session {session_id}"))?;

        response
            .json::<StreamTokenResponse>()
            .await
            .with_context(|| format!("decode proxy stream-token response for session {session_id}"))
    }

    fn stream_player_url(&self, preview: &StreamPreview, operator_token: &str) -> anyhow::Result<String> {
        let mut url = self.config.proxy.resolve_stream_url(&preview.stream_endpoint)?;
        url.query_pairs_mut().append_pair("token", operator_token);

        Ok(url.to_string())
    }

    async fn open_events(&self, cursor: &str) -> anyhow::Result<reqwest::Response> {
        self.authorized(self.client.get(self.config.proxy.events_url(cursor)?))
            .send()
            .await
            .with_context(|| format!("open proxy event stream from cursor {cursor}"))?
            .error_for_status()
            .context("proxy events request failed")
    }

    async fn kill_session(&self, session_id: &str) -> Result<(), FrontendKillError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let terminate_url = self
            .config
            .proxy
            .terminate_url(session_id)
            .map_err(FrontendKillError::Proxy)?;
        let response = self
            .authorized(self.client.post(terminate_url))
            .send()
            .await
            .with_context(|| format!("request proxy session terminate for {session_id}"))
            .map_err(FrontendKillError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::NO_CONTENT => Ok(()),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendKillError::NotFound),
            ReqwestStatusCode::CONFLICT => Err(FrontendKillError::Conflict),
            status => Err(FrontendKillError::Proxy(anyhow::anyhow!(
                "proxy session terminate failed with {status}"
            ))),
        }
    }

    async fn quarantine_session(&self, session_id: &str) -> Result<(), FrontendKillError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let quarantine_url = self
            .config
            .proxy
            .quarantine_url(session_id)
            .map_err(FrontendKillError::Proxy)?;
        let response = self
            .authorized(self.client.post(quarantine_url))
            .send()
            .await
            .with_context(|| format!("request proxy session quarantine for {session_id}"))
            .map_err(FrontendKillError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::NO_CONTENT => Ok(()),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendKillError::NotFound),
            ReqwestStatusCode::CONFLICT => Err(FrontendKillError::Conflict),
            status => Err(FrontendKillError::Proxy(anyhow::anyhow!(
                "proxy session quarantine failed with {status}"
            ))),
        }
    }

    async fn kill_all_sessions(&self) -> Result<(), FrontendKillError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let terminate_url = self
            .config
            .proxy
            .system_terminate_url()
            .map_err(FrontendKillError::Proxy)?;
        let response = self
            .authorized(self.client.post(terminate_url))
            .send()
            .await
            .context("request proxy system terminate")
            .map_err(FrontendKillError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::NO_CONTENT => Ok(()),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendKillError::NotFound),
            ReqwestStatusCode::CONFLICT => Err(FrontendKillError::Conflict),
            status => Err(FrontendKillError::Proxy(anyhow::anyhow!(
                "proxy system terminate failed with {status}"
            ))),
        }
    }

    async fn propose_command(
        &self,
        session_id: &str,
        request: &CommandProposalRequest,
    ) -> Result<CommandProposalResponse, FrontendProposalError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let propose_url = self
            .config
            .proxy
            .propose_url(session_id)
            .map_err(FrontendProposalError::Proxy)?;
        let response = self
            .authorized(self.client.post(propose_url))
            .json(request)
            .send()
            .await
            .with_context(|| format!("request proxy command proposal placeholder for {session_id}"))
            .map_err(FrontendProposalError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::ACCEPTED => response
                .json::<CommandProposalResponse>()
                .await
                .with_context(|| format!("decode proxy command proposal placeholder for {session_id}"))
                .map_err(FrontendProposalError::Proxy),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendProposalError::NotFound),
            status => Err(FrontendProposalError::Proxy(anyhow::anyhow!(
                "proxy command proposal placeholder failed with {status}"
            ))),
        }
    }

    async fn vote_on_command(
        &self,
        session_id: &str,
        request: &CommandVoteRequest,
    ) -> Result<CommandVoteResponse, FrontendVoteError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let vote_url = self
            .config
            .proxy
            .vote_url(session_id)
            .map_err(FrontendVoteError::Proxy)?;
        let response = self
            .authorized(self.client.post(vote_url))
            .json(request)
            .send()
            .await
            .with_context(|| format!("request proxy command vote placeholder for {session_id}"))
            .map_err(FrontendVoteError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::ACCEPTED => response
                .json::<CommandVoteResponse>()
                .await
                .with_context(|| format!("decode proxy command vote placeholder for {session_id}"))
                .map_err(FrontendVoteError::Proxy),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendVoteError::NotFound),
            status => Err(FrontendVoteError::Proxy(anyhow::anyhow!(
                "proxy command vote placeholder failed with {status}"
            ))),
        }
    }

    async fn capture_keyboard(
        &self,
        session_id: &str,
        request: &KeyboardCaptureRequest,
    ) -> Result<KeyboardCaptureResponse, FrontendKeyboardError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let keyboard_url = self
            .config
            .proxy
            .keyboard_url(session_id)
            .map_err(FrontendKeyboardError::Proxy)?;
        let response = self
            .authorized(self.client.post(keyboard_url))
            .json(request)
            .send()
            .await
            .with_context(|| format!("request proxy keyboard placeholder for {session_id}"))
            .map_err(FrontendKeyboardError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::ACCEPTED => response
                .json::<KeyboardCaptureResponse>()
                .await
                .with_context(|| format!("decode proxy keyboard placeholder for {session_id}"))
                .map_err(FrontendKeyboardError::Proxy),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendKeyboardError::NotFound),
            status => Err(FrontendKeyboardError::Proxy(anyhow::anyhow!(
                "proxy keyboard placeholder failed with {status}"
            ))),
        }
    }

    async fn capture_clipboard(
        &self,
        session_id: &str,
        request: &ClipboardCaptureRequest,
    ) -> Result<ClipboardCaptureResponse, FrontendClipboardError> {
        use reqwest::StatusCode as ReqwestStatusCode;

        let clipboard_url = self
            .config
            .proxy
            .clipboard_url(session_id)
            .map_err(FrontendClipboardError::Proxy)?;
        let response = self
            .authorized(self.client.post(clipboard_url))
            .json(request)
            .send()
            .await
            .with_context(|| format!("request proxy clipboard placeholder for {session_id}"))
            .map_err(FrontendClipboardError::Proxy)?;

        match response.status() {
            ReqwestStatusCode::OK | ReqwestStatusCode::ACCEPTED => response
                .json::<ClipboardCaptureResponse>()
                .await
                .with_context(|| format!("decode proxy clipboard placeholder for {session_id}"))
                .map_err(FrontendClipboardError::Proxy),
            ReqwestStatusCode::NOT_FOUND => Err(FrontendClipboardError::NotFound),
            status => Err(FrontendClipboardError::Proxy(anyhow::anyhow!(
                "proxy clipboard placeholder failed with {status}"
            ))),
        }
    }

    fn authorized(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.config.auth.proxy_bearer_token {
            request.bearer_auth(token)
        } else {
            request
        }
    }

    fn authorize_operator(
        &self,
        headers: &HeaderMap,
        query_token: Option<&str>,
        required_scope: RequiredScope,
    ) -> Result<OperatorAccess, AuthError> {
        self.auth.authorize(headers, query_token, required_scope)
    }

    async fn health_snapshot(&self) -> (StatusCode, FrontendHealthResponse) {
        match self.fetch_bootstrap().await {
            Ok(bootstrap) => {
                let live_session_count = bootstrap
                    .sessions
                    .iter()
                    .filter(|session| session_is_live_for_dashboard(session.state))
                    .count();
                let ready_tile_count = bootstrap
                    .sessions
                    .iter()
                    .filter(|session| {
                        session_is_live_for_dashboard(session.state)
                            && session.stream_state == StreamState::Ready
                            && session.stream_preview.is_some()
                    })
                    .count();

                (
                    StatusCode::OK,
                    FrontendHealthResponse {
                        service_state: FrontendServiceState::Ready,
                        proxy_bootstrap_reachable: true,
                        live_session_count,
                        ready_tile_count,
                        degraded_reasons: Vec::new(),
                    },
                )
            }
            Err(error) => (
                StatusCode::SERVICE_UNAVAILABLE,
                FrontendHealthResponse {
                    service_state: FrontendServiceState::Degraded,
                    proxy_bootstrap_reachable: false,
                    live_session_count: 0,
                    ready_tile_count: 0,
                    degraded_reasons: vec![format!("bootstrap unavailable: {error:#}")],
                },
            ),
        }
    }
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<FrontendRuntime>,
}

#[derive(Debug, Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum FrontendServiceState {
    Ready,
    Degraded,
}

#[derive(Debug, serde::Serialize)]
struct FrontendHealthResponse {
    service_state: FrontendServiceState,
    proxy_bootstrap_reachable: bool,
    live_session_count: usize,
    ready_tile_count: usize,
    degraded_reasons: Vec<String>,
}

#[derive(Debug)]
enum FrontendKillError {
    NotFound,
    Conflict,
    Proxy(anyhow::Error),
}

#[derive(Debug)]
enum FrontendProposalError {
    NotFound,
    Proxy(anyhow::Error),
}

#[derive(Debug)]
enum FrontendVoteError {
    NotFound,
    Proxy(anyhow::Error),
}

#[derive(Debug)]
enum FrontendKeyboardError {
    NotFound,
    Proxy(anyhow::Error),
}

#[derive(Debug)]
enum FrontendClipboardError {
    NotFound,
    Proxy(anyhow::Error),
}

pub async fn run_frontend(config: FrontendConfig) -> anyhow::Result<()> {
    let runtime = Arc::new(FrontendRuntime::new(config)?);
    let bind_addr = runtime.bind_addr();
    let state = AppState {
        runtime: Arc::clone(&runtime),
    };

    let router = Router::new()
        .route("/", get(index_handler))
        .route("/health", get(health_handler))
        .route("/events", get(events_handler))
        .route("/tile/{id}", get(tile_handler))
        .route("/session/{id}", get(session_handler))
        .route("/session/{id}/clipboard", post(clipboard_handler))
        .route("/session/{id}/keyboard", post(keyboard_handler))
        .route("/session/{id}/propose", post(propose_handler))
        .route("/session/{id}/vote", post(vote_handler))
        .route("/session/{id}/kill", post(kill_handler))
        .route("/session/{id}/quarantine", post(quarantine_handler))
        .route("/system/kill", post(system_kill_handler))
        .with_state(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind honeypot frontend listener at {bind_addr}"))?;

    tracing::info!(%bind_addr, "honeypot frontend listening");

    axum::serve(listener, router).await.context("serve honeypot frontend")
}

async fn health_handler(State(state): State<AppState>) -> Response {
    let (status, response) = state.runtime.health_snapshot().await;
    (status, Json(response)).into_response()
}

#[derive(serde::Deserialize, Default)]
struct OperatorTokenQuery {
    token: Option<String>,
}

async fn index_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::Watch)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    match state.runtime.fetch_bootstrap().await {
        Ok(bootstrap) => Html(render_dashboard_page(&state.runtime.config, &bootstrap, &access)).into_response(),
        Err(error) => frontend_error(StatusCode::BAD_GATEWAY, &format!("bootstrap unavailable: {error:#}")),
    }
}

#[derive(serde::Deserialize)]
struct EventsQuery {
    cursor: String,
    token: Option<String>,
}

async fn events_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<EventsQuery>,
) -> Response {
    if let Err(error) = state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::Watch)
    {
        return auth_error(error);
    }

    match state.runtime.open_events(&query.cursor).await {
        Ok(response) => {
            let stream = response
                .bytes_stream()
                .map(|chunk| chunk.map_err(std::io::Error::other));

            let mut headers = HeaderMap::new();
            headers.insert(CONTENT_TYPE, HeaderValue::from_static("text/event-stream"));
            headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-cache"));

            (headers, Body::from_stream(stream)).into_response()
        }
        Err(error) => frontend_error(StatusCode::BAD_GATEWAY, &format!("event stream unavailable: {error:#}")),
    }
}

async fn tile_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::Watch)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    match state.runtime.fetch_session(&session_id).await {
        Ok(Some(session)) if session_is_live_for_dashboard(session.state) => {
            Html(render_session_tile(&session, &access)).into_response()
        }
        Ok(Some(_)) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Ok(None) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(error) => frontend_error(StatusCode::BAD_GATEWAY, &format!("session lookup failed: {error:#}")),
    }
}

async fn session_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let is_fragment_request = headers.get("X-Requested-With").and_then(|value| value.to_str().ok())
        == Some("honeypot-frontend")
        || headers.get("HX-Request").and_then(|value| value.to_str().ok()) == Some("true");
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::StreamRead)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let session = match state.runtime.fetch_session(&session_id).await {
        Ok(Some(session)) if session_is_live_for_dashboard(session.state) => session,
        Ok(Some(_)) => return frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Ok(None) => return frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(error) => {
            return frontend_error(StatusCode::BAD_GATEWAY, &format!("session lookup failed: {error:#}"));
        }
    };

    let stream_preview = if matches!(session.state, SessionState::Assigned | SessionState::Ready)
        || session.stream_state == StreamState::Ready
        || session.stream_preview.is_some()
    {
        match state.runtime.fetch_stream_token(&session.session_id).await {
            Ok(response) => Some(StreamPreview {
                stream_id: response.stream_id,
                transport: response.transport,
                stream_endpoint: response.stream_endpoint,
                token_expires_at: response.expires_at,
            }),
            Err(error) => {
                tracing::warn!(session_id = %session.session_id, error = %error, "stream token request failed");
                session.stream_preview.clone()
            }
        }
    } else {
        None
    };
    let player_url =
        stream_preview.as_ref().and_then(|preview| {
            state.runtime.stream_player_url(preview, access.raw_token()).map_or_else(
            |error| {
                tracing::warn!(session_id = %session.session_id, error = %error, "stream player url build failed");
                None
            },
            Some,
        )
        });

    Html(render_focus_panel(
        &session,
        stream_preview.as_ref(),
        player_url.as_deref(),
        &access,
        !is_fragment_request && player_url.is_none(),
    ))
    .into_response()
}

async fn kill_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::SessionKill)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    match state.runtime.kill_session(&session_id).await {
        Ok(()) => Html(render_kill_notice(&session_id, access.raw_token())).into_response(),
        Err(FrontendKillError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendKillError::Conflict) => frontend_error(
            StatusCode::CONFLICT,
            "session kill is unavailable for this honeypot session",
        ),
        Err(FrontendKillError::Proxy(error)) => {
            frontend_error(StatusCode::BAD_GATEWAY, &format!("kill request failed: {error:#}"))
        }
    }
}

#[derive(serde::Deserialize)]
struct ClipboardCaptureForm {
    clipboard_text: String,
}

#[derive(serde::Deserialize)]
struct KeyboardCaptureForm {
    key_sequence: String,
}

#[derive(serde::Deserialize)]
struct CommandProposalForm {
    command_text: String,
}

#[derive(serde::Deserialize)]
struct CommandVoteForm {
    proposal_id: String,
    vote: CommandVoteChoice,
}

async fn keyboard_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
    Form(form): Form<KeyboardCaptureForm>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::CommandApprove)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let request = KeyboardCaptureRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("frontend-keyboard-capture-{session_id}-{}", proposal_nonce()),
        key_sequence: form.key_sequence,
    };

    match state.runtime.capture_keyboard(&session_id, &request).await {
        Ok(response) => Html(render_keyboard_capture_notice(&response, access.raw_token())).into_response(),
        Err(FrontendKeyboardError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendKeyboardError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("keyboard placeholder failed: {error:#}"),
        ),
    }
}

async fn clipboard_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
    Form(form): Form<ClipboardCaptureForm>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::CommandApprove)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let request = ClipboardCaptureRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("frontend-clipboard-capture-{session_id}-{}", proposal_nonce()),
        clipboard_text: form.clipboard_text,
    };

    match state.runtime.capture_clipboard(&session_id, &request).await {
        Ok(response) => Html(render_clipboard_capture_notice(&response, access.raw_token())).into_response(),
        Err(FrontendClipboardError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendClipboardError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("clipboard placeholder failed: {error:#}"),
        ),
    }
}

async fn propose_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
    Form(form): Form<CommandProposalForm>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::CommandPropose)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let request = CommandProposalRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("frontend-command-proposal-{session_id}-{}", proposal_nonce()),
        command_text: form.command_text,
    };

    match state.runtime.propose_command(&session_id, &request).await {
        Ok(response) => Html(render_command_proposal_notice(
            &response,
            access.raw_token(),
            access.can_approve_commands(),
        ))
        .into_response(),
        Err(FrontendProposalError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendProposalError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("command proposal placeholder failed: {error:#}"),
        ),
    }
}

async fn vote_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
    Form(form): Form<CommandVoteForm>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::CommandApprove)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let request = CommandVoteRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("frontend-command-vote-{session_id}-{}", proposal_nonce()),
        proposal_id: form.proposal_id,
        vote: form.vote,
    };

    match state.runtime.vote_on_command(&session_id, &request).await {
        Ok(response) => Html(render_command_vote_notice(&response, access.raw_token())).into_response(),
        Err(FrontendVoteError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendVoteError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("command vote placeholder failed: {error:#}"),
        ),
    }
}

async fn quarantine_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(session_id): Path<String>,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::SessionKill)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    match state.runtime.quarantine_session(&session_id).await {
        Ok(()) => Html(render_quarantine_notice(&session_id, access.raw_token())).into_response(),
        Err(FrontendKillError::NotFound) => frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(FrontendKillError::Conflict) => frontend_error(
            StatusCode::CONFLICT,
            "session quarantine is unavailable for this honeypot session",
        ),
        Err(FrontendKillError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("quarantine request failed: {error:#}"),
        ),
    }
}

async fn system_kill_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<OperatorTokenQuery>,
) -> Response {
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::SystemKill)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    match state.runtime.kill_all_sessions().await {
        Ok(()) => Html(render_system_kill_notice(access.raw_token())).into_response(),
        Err(FrontendKillError::Conflict) => frontend_error(StatusCode::CONFLICT, "honeypot system kill is disabled"),
        Err(FrontendKillError::NotFound) => {
            frontend_error(StatusCode::NOT_FOUND, "honeypot system kill route is unavailable")
        }
        Err(FrontendKillError::Proxy(error)) => frontend_error(
            StatusCode::BAD_GATEWAY,
            &format!("system kill request failed: {error:#}"),
        ),
    }
}

fn frontend_error(status: StatusCode, message: &str) -> Response {
    (status, Html(render_error_fragment(message))).into_response()
}

fn auth_error(error: AuthError) -> Response {
    match error {
        AuthError::MissingToken => frontend_error(StatusCode::UNAUTHORIZED, "operator token is missing"),
        AuthError::InvalidToken(error) => frontend_error(
            StatusCode::UNAUTHORIZED,
            &format!("operator token is invalid: {error:#}"),
        ),
        AuthError::Forbidden { required, actual } => frontend_error(
            StatusCode::FORBIDDEN,
            &format!(
                "operator token scope {actual:?} does not satisfy required scope {}",
                required.label()
            ),
        ),
    }
}

#[derive(Template)]
#[template(path = "dashboard.html")]
struct DashboardPageTemplate<'a> {
    title: &'a str,
    session_count: usize,
    replay_cursor: &'a str,
    replay_cursor_json: &'a str,
    operator_token_json: &'a str,
    has_live_sessions: bool,
    system_kill_button_html: &'a str,
    tiles_html: &'a str,
}

#[derive(Template)]
#[template(path = "session_tile.html")]
struct SessionTileTemplate<'a> {
    session_id: &'a str,
    state_class: &'a str,
    state_label: &'a str,
    stream_label: &'a str,
    vm_lease_id: &'a str,
    last_event_id: &'a str,
    auth_query: &'a str,
    has_preview: bool,
    preview_stream_id: &'a str,
    preview_transport_label: &'a str,
    preview_message: &'a str,
    action_buttons_html: &'a str,
}

#[derive(Template)]
#[template(path = "focus_panel.html")]
struct FocusPanelTemplate<'a> {
    session_id: &'a str,
    state_label: &'a str,
    stream_label: &'a str,
    focus_actions_html: &'a str,
    has_stream_preview: bool,
    has_player_url: bool,
    player_url: &'a str,
    player_url_missing_note: &'a str,
    transport_label: &'a str,
    stream_id: &'a str,
    token_expires_at: &'a str,
    focus_note: &'a str,
    standalone_retry: bool,
}

fn render_dashboard_page(config: &FrontendConfig, bootstrap: &BootstrapResponse, access: &OperatorAccess) -> String {
    let operator_token = access.raw_token();
    let system_kill_button = render_system_kill_button(access);
    let live_sessions = bootstrap
        .sessions
        .iter()
        .filter(|session| session_is_live_for_dashboard(session.state))
        .collect::<Vec<_>>();
    let tiles = if live_sessions.is_empty() {
        "<div class=\"empty-state\">No live sessions are visible yet.</div>".to_owned()
    } else {
        live_sessions
            .iter()
            .map(|session| render_session_tile(session, access))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let session_count = bootstrap
        .sessions
        .iter()
        .filter(|session| session_is_live_for_dashboard(session.state))
        .count();
    let operator_token_json = serde_json::to_string(operator_token).unwrap_or_else(|_| "\"invalid-token\"".to_owned());
    let replay_cursor_json = serde_json::to_string(&bootstrap.replay_cursor).unwrap_or_else(|_| "\"0\"".to_owned());

    DashboardPageTemplate {
        title: &config.ui.title,
        session_count,
        replay_cursor: &bootstrap.replay_cursor,
        replay_cursor_json: &replay_cursor_json,
        operator_token_json: &operator_token_json,
        has_live_sessions: !live_sessions.is_empty(),
        system_kill_button_html: &system_kill_button,
        tiles_html: &tiles,
    }
    .render()
    .unwrap_or_else(|error| format!("dashboard template render failed: {error}"))
}

fn render_session_tile(session: &BootstrapSession, access: &OperatorAccess) -> String {
    let operator_token = access.raw_token();
    let vm_lease_id = session.vm_lease_id.as_deref().unwrap_or("pending-lease");
    let state_label = session_state_label(session.state);
    let stream_label = stream_state_label(session.stream_state);
    let state_class = state_label.replace(' ', "-").to_ascii_lowercase();
    let auth_query = operator_token_query(operator_token);
    let action_buttons = render_session_action_buttons(session, operator_token, access.can_kill_sessions());
    let (has_preview, preview_stream_id, preview_transport_label, preview_message) =
        session.stream_preview.as_ref().map_or_else(
            || {
                let message = if session.stream_state == StreamState::Failed {
                    "No live source is available."
                } else {
                    "Awaiting preview."
                };
                (false, "", "", message)
            },
            |preview| {
                (
                    true,
                    preview.stream_id.as_str(),
                    stream_transport_label(preview.transport),
                    "",
                )
            },
        );

    SessionTileTemplate {
        session_id: &session.session_id,
        state_class: &state_class,
        state_label,
        stream_label,
        vm_lease_id,
        last_event_id: &session.last_event_id,
        auth_query: &auth_query,
        has_preview,
        preview_stream_id,
        preview_transport_label,
        preview_message,
        action_buttons_html: &action_buttons,
    }
    .render()
    .unwrap_or_else(|error| format!("session tile template render failed: {error}"))
}

fn render_focus_panel(
    session: &BootstrapSession,
    stream_preview: Option<&StreamPreview>,
    player_url: Option<&str>,
    access: &OperatorAccess,
    standalone_retry: bool,
) -> String {
    let session_id = session.session_id.as_str();
    let state_label = session_state_label(session.state);
    let stream_label = stream_state_label(session.stream_state);
    let focus_actions = render_focus_action_buttons(session, access);
    let (
        has_stream_preview,
        has_player_url,
        player_url,
        player_url_missing_note,
        transport_label,
        stream_id,
        token_expires_at,
        focus_note,
    ) = stream_preview.map_or_else(
        || {
            let focus_note = if session.stream_state == StreamState::Failed {
                "The proxy has not observed an active recording producer for this session."
            } else {
                "The frontend could not resolve a stream preview for this session yet."
            };
            (false, false, "", "", "", "", "", focus_note)
        },
        |preview| {
            let missing_note = "The frontend could not resolve a live player URL for this session yet.";
            (
                true,
                player_url.is_some(),
                player_url.unwrap_or(""),
                missing_note,
                stream_transport_label(preview.transport),
                preview.stream_id.as_str(),
                preview.token_expires_at.as_str(),
                "Refresh reconnects near the live tail while the attacker session is still active.",
            )
        },
    );

    FocusPanelTemplate {
        session_id: &session_id,
        state_label: &state_label,
        stream_label: &stream_label,
        focus_actions_html: &focus_actions,
        has_stream_preview,
        has_player_url,
        player_url,
        player_url_missing_note,
        transport_label,
        stream_id,
        token_expires_at,
        focus_note,
        standalone_retry,
    }
    .render()
    .unwrap_or_else(|error| format!("focus panel template render failed: {error}"))
}

fn render_kill_notice(session_id: &str, operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);
    let session_id = escape_html(session_id);

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>Kill requested</strong>
      <p>Session <code>{session_id}</code> is waiting for the proxy to emit <code>session.killed</code>.</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#
    )
}

fn render_quarantine_notice(session_id: &str, operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);
    let session_id = escape_html(session_id);

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>Quarantine requested</strong>
      <p>Session <code>{session_id}</code> is waiting for the proxy to emit <code>session.killed</code> and then request a quarantined recycle.</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#
    )
}

fn render_command_proposal_notice(
    response: &CommandProposalResponse,
    operator_token: &str,
    can_approve_commands: bool,
) -> String {
    let auth_query = operator_token_query(operator_token);
    let state_label = match response.proposal_state {
        CommandProposalState::Deferred => "Proposal deferred",
        CommandProposalState::Rejected => "Proposal rejected",
    };
    let guidance = match response.proposal_state {
        CommandProposalState::Deferred => {
            "The placeholder recorded the request and deferred it without executing anything."
        }
        CommandProposalState::Rejected => {
            "The placeholder recorded the request and rejected it without executing anything."
        }
    };
    let vote_controls =
        render_command_vote_controls(response, operator_token, can_approve_commands && !response.executed);

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>{state_label}</strong>
      <p>Session <code>{session_id}</code> recorded command proposal <code>{proposal_id}</code> at <code>{recorded_at}</code>.</p>
      <p><strong>Command</strong><br><code>{command_text}</code></p>
      <p><strong>Reason</strong><br><code>{decision_reason}</code></p>
      <p>{guidance}</p>
      {vote_controls}
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#,
        state_label = escape_html(state_label),
        session_id = escape_html(&response.session_id),
        proposal_id = escape_html(&response.proposal_id),
        recorded_at = escape_html(&response.recorded_at),
        command_text = escape_html(&response.command_text),
        decision_reason = escape_html(&response.decision_reason),
        guidance = escape_html(guidance),
        vote_controls = vote_controls,
        auth_query = auth_query,
    )
}

fn render_command_vote_controls(
    response: &CommandProposalResponse,
    operator_token: &str,
    can_approve_commands: bool,
) -> String {
    if response.proposal_state != CommandProposalState::Deferred {
        return String::new();
    }

    if !can_approve_commands {
        return "<p><strong>Voting</strong><br><span>Approve scope is required to record the placeholder vote.</span></p>"
            .to_owned();
    }

    let auth_query = operator_token_query(operator_token);
    let session_id = escape_html(&response.session_id);
    let proposal_id = escape_html(&response.proposal_id);

    format!(
        r##"<form class="focus-actions" hx-post="/session/{session_id}/vote?{auth_query}" hx-target="#focus-panel" hx-swap="innerHTML">
  <input type="hidden" name="proposal_id" value="{proposal_id}">
  <button class="quarantine-button" type="submit" name="vote" value="approve">Record approval placeholder</button>
  <button class="kill-button" type="submit" name="vote" value="reject">Record rejection placeholder</button>
</form>"##
    )
}

fn render_command_vote_notice(response: &CommandVoteResponse, operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);
    let state_label = match response.vote_state {
        CommandVoteState::Deferred => "Vote deferred",
        CommandVoteState::Rejected => "Vote rejected",
    };
    let vote_label = match response.vote {
        CommandVoteChoice::Approve => "approve",
        CommandVoteChoice::Reject => "reject",
    };
    let guidance = match response.vote_state {
        CommandVoteState::Deferred => "The placeholder recorded the vote and kept execution disabled.",
        CommandVoteState::Rejected => "The placeholder recorded the rejection and kept execution disabled.",
    };

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>{state_label}</strong>
      <p>Session <code>{session_id}</code> recorded vote <code>{vote_id}</code> for proposal <code>{proposal_id}</code> at <code>{recorded_at}</code>.</p>
      <p><strong>Vote</strong><br><code>{vote_label}</code></p>
      <p><strong>Reason</strong><br><code>{decision_reason}</code></p>
      <p>{guidance}</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#,
        state_label = escape_html(state_label),
        session_id = escape_html(&response.session_id),
        vote_id = escape_html(&response.vote_id),
        proposal_id = escape_html(&response.proposal_id),
        recorded_at = escape_html(&response.recorded_at),
        vote_label = escape_html(vote_label),
        decision_reason = escape_html(&response.decision_reason),
        guidance = escape_html(guidance),
        auth_query = auth_query,
    )
}

fn render_keyboard_capture_notice(response: &KeyboardCaptureResponse, operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);
    let state_label = match response.capture_state {
        KeyboardCaptureState::DisabledByPolicy => "Keyboard capture disabled",
    };
    let guidance = match response.capture_state {
        KeyboardCaptureState::DisabledByPolicy => {
            "The placeholder recorded only request metadata and kept keyboard injection disabled."
        }
    };

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>{state_label}</strong>
      <p>Session <code>{session_id}</code> recorded keyboard placeholder <code>{capture_id}</code> at <code>{recorded_at}</code>.</p>
      <p><strong>Requested key count</strong><br><code>{requested_key_count}</code></p>
      <p><strong>Reason</strong><br><code>{decision_reason}</code></p>
      <p>{guidance}</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#,
        state_label = escape_html(state_label),
        session_id = escape_html(&response.session_id),
        capture_id = escape_html(&response.capture_id),
        recorded_at = escape_html(&response.recorded_at),
        requested_key_count = response.requested_key_count,
        decision_reason = escape_html(&response.decision_reason),
        guidance = escape_html(guidance),
        auth_query = auth_query,
    )
}

fn render_clipboard_capture_notice(response: &ClipboardCaptureResponse, operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);
    let state_label = match response.capture_state {
        ClipboardCaptureState::DisabledByPolicy => "Clipboard capture disabled",
    };
    let guidance = match response.capture_state {
        ClipboardCaptureState::DisabledByPolicy => {
            "The placeholder recorded only request metadata and kept clipboard injection disabled."
        }
    };

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>{state_label}</strong>
      <p>Session <code>{session_id}</code> recorded clipboard placeholder <code>{capture_id}</code> at <code>{recorded_at}</code>.</p>
      <p><strong>Requested byte count</strong><br><code>{requested_byte_count}</code></p>
      <p><strong>Reason</strong><br><code>{decision_reason}</code></p>
      <p>{guidance}</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#,
        state_label = escape_html(state_label),
        session_id = escape_html(&response.session_id),
        capture_id = escape_html(&response.capture_id),
        recorded_at = escape_html(&response.recorded_at),
        requested_byte_count = response.requested_byte_count,
        decision_reason = escape_html(&response.decision_reason),
        guidance = escape_html(guidance),
        auth_query = auth_query,
    )
}

fn render_system_kill_notice(operator_token: &str) -> String {
    let auth_query = operator_token_query(operator_token);

    format!(
        r#"<div class="focus-shell">
  <div class="focus-empty">
    <div>
      <strong>Global kill requested</strong>
      <p>The proxy is terminating all active honeypot sessions and waiting to emit <code>session.killed</code> for each one.</p>
      <p>New honeypot intake will stay halted when the proxy kill-switch policy requires it.</p>
      <p><a class="badge" href="/?{auth_query}">Return to dashboard</a></p>
    </div>
  </div>
</div>"#
    )
}

fn proposal_nonce() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn render_session_action_buttons(session: &BootstrapSession, operator_token: &str, can_kill_sessions: bool) -> String {
    if !can_kill_sessions || !session_can_be_killed(session.state) {
        return String::new();
    }

    let session_id = escape_html(&session.session_id);
    let auth_query = operator_token_query(operator_token);

    format!(
        r##"<div class="tile-actions">
  <button
    class="quarantine-button"
    type="button"
    hx-post="/session/{session_id}/quarantine?{auth_query}"
    hx-target="#focus-panel"
    hx-swap="innerHTML"
    hx-confirm="Quarantine guest for session {session_id}?">
    Quarantine guest
  </button>
  <button
    class="kill-button"
    type="button"
    hx-post="/session/{session_id}/kill?{auth_query}"
    hx-target="#focus-panel"
    hx-swap="innerHTML"
    hx-confirm="Kill session {session_id}?">
    Kill session
  </button>
</div>"##
    )
}

fn render_system_kill_button(access: &OperatorAccess) -> String {
    if !access.can_trigger_system_kill() {
        return String::new();
    }

    let auth_query = operator_token_query(access.raw_token());

    format!(
        r##"<button
  class="kill-button"
  type="button"
  hx-post="/system/kill?{auth_query}"
  hx-target="#focus-panel"
  hx-swap="innerHTML"
  hx-confirm="Kill all active honeypot sessions?">
  Global kill
</button>"##
    )
}

fn render_focus_action_buttons(session: &BootstrapSession, access: &OperatorAccess) -> String {
    if !access.can_kill_sessions() || !session_can_be_killed(session.state) {
        return String::new();
    }

    let session_id = escape_html(&session.session_id);
    let auth_query = operator_token_query(access.raw_token());

    format!(
        r##"<div class="focus-actions">
  <button
    class="quarantine-button"
    type="button"
    hx-post="/session/{session_id}/quarantine?{auth_query}"
    hx-target="#focus-panel"
    hx-swap="innerHTML"
    hx-confirm="Quarantine guest for session {session_id}?">
    Quarantine guest
  </button>
  <button
    class="kill-button"
    type="button"
    hx-post="/session/{session_id}/kill?{auth_query}"
    hx-target="#focus-panel"
    hx-swap="innerHTML"
    hx-confirm="Kill session {session_id}?">
    Kill session
  </button>
</div>"##
    )
}

fn session_can_be_killed(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Connected | SessionState::Assigned | SessionState::Ready
    )
}

fn session_is_live_for_dashboard(state: SessionState) -> bool {
    matches!(
        state,
        SessionState::Connected | SessionState::Assigned | SessionState::Ready
    )
}

fn render_error_fragment(message: &str) -> String {
    format!(
        r#"<div class="focus-empty">
  <div>
    <strong>Frontend request failed</strong>
    <p>{}</p>
  </div>
</div>"#,
        escape_html(message)
    )
}

fn session_state_label(state: SessionState) -> &'static str {
    match state {
        SessionState::Connected => "connected",
        SessionState::Assigned => "assigned",
        SessionState::Ready => "ready",
        SessionState::Disconnected => "disconnected",
        SessionState::Killed => "killed",
        SessionState::RecycleRequested => "recycle requested",
        SessionState::Recycled => "recycled",
    }
}

fn stream_state_label(state: StreamState) -> &'static str {
    match state {
        StreamState::Pending => "pending",
        StreamState::Ready => "ready",
        StreamState::Failed => "failed",
    }
}

fn stream_transport_label(transport: StreamTransport) -> &'static str {
    match transport {
        StreamTransport::Sse => "sse",
        StreamTransport::Websocket => "websocket",
    }
}

fn escape_html(input: &str) -> String {
    input
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn operator_token_query(operator_token: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("token", operator_token);
    query.finish()
}

#[cfg(test)]
mod tests {
    use devolutions_gateway::token::AccessScope;
    use honeypot_contracts::frontend::BootstrapSession;

    use super::*;

    fn test_access(raw_token: &str, scope: AccessScope) -> OperatorAccess {
        OperatorAccess::test_only(raw_token, scope)
    }

    #[test]
    fn tile_render_escapes_untrusted_fields() {
        let session = BootstrapSession {
            session_id: "<session>".to_owned(),
            vm_lease_id: Some("lease&1".to_owned()),
            state: SessionState::Assigned,
            last_event_id: "\"event\"".to_owned(),
            last_session_seq: 1,
            stream_state: StreamState::Pending,
            stream_preview: None,
        };

        let html = render_session_tile(&session, &test_access("operator-token", AccessScope::Wildcard));

        assert!(html.contains("&lt;session&gt;"));
        assert!(html.contains("lease&amp;1"));
        assert!(html.contains("&quot;event&quot;"));
        assert!(html.contains("token=operator-token"));
        assert!(html.contains("Kill session"));
    }

    #[test]
    fn focus_panel_renders_stream_preview_metadata() {
        let session = BootstrapSession {
            session_id: "session-1".to_owned(),
            vm_lease_id: Some("lease-1".to_owned()),
            state: SessionState::Ready,
            last_event_id: "event-1".to_owned(),
            last_session_seq: 2,
            stream_state: StreamState::Ready,
            stream_preview: None,
        };
        let preview = StreamPreview {
            stream_id: "stream-1".to_owned(),
            transport: StreamTransport::Websocket,
            stream_endpoint: "/jet/honeypot/session/session-1/stream?stream_id=stream-1".to_owned(),
            token_expires_at: "2026-03-26T12:00:00Z".to_owned(),
        };

        let html = render_focus_panel(
            &session,
            Some(&preview),
            Some("http://127.0.0.1:7171/jet/honeypot/session/session-1/stream?stream_id=stream-1&token=operator-token"),
            &test_access("operator-token", AccessScope::Wildcard),
            false,
        );

        assert!(html.contains("stream-1"));
        assert!(html.contains("iframe"));
        assert!(html.contains("stream_id=stream-1&amp;token=operator-token"));
        assert!(html.contains("Refresh reconnects near the live tail"));
        assert!(html.contains("Kill session"));
    }

    #[test]
    fn focus_panel_renders_standalone_retry_when_player_url_is_missing() {
        let session = BootstrapSession {
            session_id: "session-1".to_owned(),
            vm_lease_id: Some("lease-1".to_owned()),
            state: SessionState::Assigned,
            last_event_id: "event-1".to_owned(),
            last_session_seq: 2,
            stream_state: StreamState::Pending,
            stream_preview: None,
        };

        let html = render_focus_panel(
            &session,
            None,
            None,
            &test_access("operator-token", AccessScope::Wildcard),
            true,
        );

        assert!(html.contains("window.location.replace(window.location.href)"));
        assert!(html.contains("Stream unavailable"));
    }
}
