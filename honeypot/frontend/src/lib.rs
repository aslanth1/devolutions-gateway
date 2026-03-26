mod auth;
pub mod config;

use std::sync::Arc;

use anyhow::Context as _;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, CONTENT_TYPE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures::StreamExt as _;
use honeypot_contracts::events::{SessionState, StreamState};
use honeypot_contracts::frontend::{BootstrapResponse, BootstrapSession};
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
}

#[derive(Clone)]
struct AppState {
    runtime: Arc<FrontendRuntime>,
}

#[derive(Debug)]
enum FrontendKillError {
    NotFound,
    Conflict,
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
        .route("/session/{id}/kill", post(kill_handler))
        .route("/system/kill", post(system_kill_handler))
        .with_state(state);

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind honeypot frontend listener at {bind_addr}"))?;

    tracing::info!(%bind_addr, "honeypot frontend listening");

    axum::serve(listener, router).await.context("serve honeypot frontend")
}

async fn health_handler() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "status": "ok" }))
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
        Ok(Some(session)) => Html(render_session_tile(&session, &access)).into_response(),
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
    let access = match state
        .runtime
        .authorize_operator(&headers, query.token.as_deref(), RequiredScope::StreamRead)
    {
        Ok(access) => access,
        Err(error) => return auth_error(error),
    };

    let session = match state.runtime.fetch_session(&session_id).await {
        Ok(Some(session)) => session,
        Ok(None) => return frontend_error(StatusCode::NOT_FOUND, "session not found"),
        Err(error) => {
            return frontend_error(StatusCode::BAD_GATEWAY, &format!("session lookup failed: {error:#}"));
        }
    };

    let stream_preview = if let Some(preview) = &session.stream_preview {
        Some(preview.clone())
    } else {
        match state.runtime.fetch_stream_token(&session.session_id).await {
            Ok(response) => Some(StreamPreview {
                stream_id: response.stream_id,
                transport: response.transport,
                stream_endpoint: response.stream_endpoint,
                token_expires_at: response.expires_at,
            }),
            Err(error) => {
                tracing::warn!(session_id = %session.session_id, error = %error, "stream token request failed");
                None
            }
        }
    };

    Html(render_focus_panel(&session, stream_preview.as_ref(), &access)).into_response()
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

fn render_dashboard_page(config: &FrontendConfig, bootstrap: &BootstrapResponse, access: &OperatorAccess) -> String {
    let operator_token = access.raw_token();
    let system_kill_button = render_system_kill_button(access);
    let tiles = if bootstrap.sessions.is_empty() {
        "<div class=\"empty-state\">No live sessions are visible yet.</div>".to_owned()
    } else {
        bootstrap
            .sessions
            .iter()
            .map(|session| render_session_tile(session, access))
            .collect::<Vec<_>>()
            .join("\n")
    };

    let title = escape_html(&config.ui.title);
    let replay_cursor = escape_html(&bootstrap.replay_cursor);
    let session_count = bootstrap.sessions.len();
    let operator_token_json = serde_json::to_string(operator_token).unwrap_or_else(|_| "\"invalid-token\"".to_owned());

    format!(
        r#"<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <script src="https://unpkg.com/htmx.org@2.0.4"></script>
  <style>
    :root {{
      --paper: #f5ecd9;
      --ink: #1f1b16;
      --accent: #c54d20;
      --accent-2: #0d6a73;
      --shadow: rgba(31, 27, 22, 0.14);
      --panel: rgba(255, 251, 243, 0.88);
      --ended: #8c8578;
      --warning: #aa2d18;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      font-family: "Space Grotesk", "Avenir Next", "Segoe UI", sans-serif;
      color: var(--ink);
      background:
        radial-gradient(circle at top left, rgba(197, 77, 32, 0.24), transparent 32rem),
        radial-gradient(circle at top right, rgba(13, 106, 115, 0.18), transparent 28rem),
        linear-gradient(180deg, #fffaf0 0%, var(--paper) 100%);
    }}
    .shell {{
      max-width: 1400px;
      margin: 0 auto;
      padding: 2rem;
    }}
    .masthead {{
      display: flex;
      gap: 1rem;
      align-items: end;
      justify-content: space-between;
      margin-bottom: 1.5rem;
    }}
    .kicker {{
      margin: 0;
      font-size: 0.8rem;
      letter-spacing: 0.18em;
      text-transform: uppercase;
      color: var(--accent-2);
    }}
    h1 {{
      margin: 0.25rem 0 0;
      font-size: clamp(2rem, 4vw, 3.3rem);
      line-height: 0.95;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }}
    .status-bar {{
      display: grid;
      gap: 0.75rem;
      padding: 1rem 1.2rem;
      border-radius: 1.2rem;
      background: var(--panel);
      box-shadow: 0 1.4rem 3rem var(--shadow);
      min-width: 16rem;
    }}
    .status-metric {{
      font-size: 0.9rem;
      color: rgba(31, 27, 22, 0.72);
    }}
    .layout {{
      display: grid;
      grid-template-columns: minmax(0, 1.7fr) minmax(22rem, 0.9fr);
      gap: 1.25rem;
    }}
    .tile-grid, .focus-panel {{
      padding: 1rem;
      border-radius: 1.5rem;
      background: var(--panel);
      box-shadow: 0 1.4rem 3rem var(--shadow);
    }}
    .tile-grid {{
      display: grid;
      gap: 0.9rem;
      align-content: start;
      min-height: 22rem;
    }}
    .session-tile {{
      display: grid;
      gap: 0.7rem;
      padding: 1rem;
      border: 1px solid rgba(31, 27, 22, 0.08);
      border-radius: 1.2rem;
      background: rgba(255, 255, 255, 0.72);
      transition: transform 140ms ease, box-shadow 140ms ease;
    }}
    .session-tile:hover {{
      transform: translateY(-2px);
      box-shadow: 0 1rem 2rem rgba(31, 27, 22, 0.1);
    }}
    .session-tile.state-ended, .session-tile.state-killed {{
      opacity: 0.64;
      border-color: rgba(140, 133, 120, 0.4);
    }}
    .tile-hit {{
      color: inherit;
      text-decoration: none;
      display: grid;
      gap: 0.7rem;
    }}
    .tile-head {{
      display: flex;
      justify-content: space-between;
      gap: 1rem;
      align-items: start;
    }}
    .badge {{
      display: inline-flex;
      align-items: center;
      gap: 0.35rem;
      padding: 0.25rem 0.55rem;
      border-radius: 999px;
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      background: rgba(197, 77, 32, 0.12);
      color: var(--accent);
    }}
    .tile-meta {{
      display: grid;
      gap: 0.2rem;
      font-size: 0.92rem;
      color: rgba(31, 27, 22, 0.74);
    }}
    .tile-actions, .focus-actions {{
      display: flex;
      justify-content: end;
      gap: 0.75rem;
    }}
    .kill-button {{
      border: 0;
      border-radius: 999px;
      padding: 0.6rem 0.9rem;
      font: inherit;
      font-size: 0.9rem;
      letter-spacing: 0.03em;
      background: linear-gradient(135deg, #9f2f13, #c54d20);
      color: #fff7f2;
      cursor: pointer;
      box-shadow: 0 0.7rem 1.4rem rgba(159, 47, 19, 0.18);
    }}
    .kill-button:hover {{
      filter: brightness(1.05);
    }}
    .focus-panel {{
      min-height: 22rem;
    }}
    .focus-empty, .empty-state {{
      display: grid;
      place-items: center;
      min-height: 100%;
      color: rgba(31, 27, 22, 0.58);
      text-align: center;
      padding: 2rem;
      border: 1px dashed rgba(31, 27, 22, 0.14);
      border-radius: 1rem;
    }}
    .focus-shell {{
      display: grid;
      gap: 1rem;
    }}
    .stream-stage {{
      min-height: 18rem;
      display: grid;
      place-items: center;
      border-radius: 1rem;
      background: linear-gradient(135deg, rgba(13, 106, 115, 0.12), rgba(197, 77, 32, 0.14));
      border: 1px solid rgba(13, 106, 115, 0.2);
      text-align: center;
      padding: 1.5rem;
    }}
    .focus-note {{
      margin: 0;
      color: rgba(31, 27, 22, 0.68);
    }}
    code {{
      font-family: "IBM Plex Mono", "Cascadia Code", monospace;
      font-size: 0.88rem;
      overflow-wrap: anywhere;
    }}
    @media (max-width: 900px) {{
      .shell {{ padding: 1rem; }}
      .layout {{ grid-template-columns: 1fr; }}
      .masthead {{ align-items: start; flex-direction: column; }}
      .status-bar {{ min-width: 0; width: 100%; }}
    }}
  </style>
</head>
<body>
  <div class="shell">
    <header class="masthead">
      <div>
        <p class="kicker">Watch and kill operator surface</p>
        <h1>{title}</h1>
      </div>
      <section class="status-bar">
        <div class="status-metric">Live sessions: <strong>{session_count}</strong></div>
        <div class="status-metric">Replay cursor: <code id="cursor-value">{replay_cursor}</code></div>
        {system_kill_button}
      </section>
    </header>
    <main class="layout">
      <section id="tile-grid" class="tile-grid">
        {tiles}
      </section>
      <aside id="focus-panel" class="focus-panel">
        <div class="focus-empty">Choose a live tile to inspect stream metadata and session state.</div>
      </aside>
    </main>
  </div>
  <script>
    (() => {{
      let replayCursor = {replay_cursor_json};
      const operatorToken = {operator_token_json};
      let reconnectTimer = null;
      const cursorNode = document.getElementById("cursor-value");
      const tileGrid = document.getElementById("tile-grid");
      const focusPanel = document.getElementById("focus-panel");

      function authedPath(path) {{
        const url = new URL(path, window.location.origin);
        url.searchParams.set("token", operatorToken);
        return `${{url.pathname}}${{url.search}}`;
      }}

      async function fetchHtml(path) {{
        const response = await fetch(authedPath(path), {{ headers: {{ "X-Requested-With": "honeypot-frontend" }} }});
        if (response.status === 404) {{
          return null;
        }}
        if (!response.ok) {{
          throw new Error(`request failed for ${{path}} with ${{response.status}}`);
        }}
        return response.text();
      }}

      async function upsertTile(sessionId) {{
        const html = await fetchHtml(`/tile/${{encodeURIComponent(sessionId)}}`);
        const existing = document.getElementById(`session-tile-${{sessionId}}`);
        if (html === null) {{
          existing?.remove();
          return;
        }}

        const wrapper = document.createElement("div");
        wrapper.innerHTML = html.trim();
        const incoming = wrapper.firstElementChild;
        if (!incoming) {{
          return;
        }}

        if (existing) {{
          existing.replaceWith(incoming);
        }} else {{
          tileGrid.prepend(incoming);
        }}
      }}

      function dropTile(sessionId, message) {{
        document.getElementById(`session-tile-${{sessionId}}`)?.remove();
        const focused = focusPanel.querySelector("[data-focused-session-id]");
        if (focused && focused.getAttribute("data-focused-session-id") === sessionId) {{
          focusPanel.innerHTML = `<div class="focus-empty">${{message}}</div>`;
        }}
      }}

      function scheduleReconnect() {{
        if (reconnectTimer !== null) {{
          return;
        }}
        reconnectTimer = window.setTimeout(() => {{
          reconnectTimer = null;
          connectEvents();
        }}, 1500);
      }}

      function connectEvents() {{
        const source = new EventSource(authedPath(`/events?cursor=${{encodeURIComponent(replayCursor)}}`));

        source.onmessage = async (event) => {{
          let payload = null;
          try {{
            payload = JSON.parse(event.data);
          }} catch (_error) {{
            return;
          }}

          replayCursor = payload.global_cursor || event.lastEventId || replayCursor;
          cursorNode.textContent = replayCursor;

          const sessionId = payload.session_id;
          if (!sessionId) {{
            return;
          }}

          switch (payload.event_kind) {{
            case "session.ended":
              dropTile(sessionId, "This session has ended.");
              break;
            case "session.killed":
              dropTile(sessionId, "This session was killed.");
              break;
            default:
              try {{
                await upsertTile(sessionId);
              }} catch (_error) {{
                source.close();
                scheduleReconnect();
              }}
              break;
          }}
        }};

        source.onerror = () => {{
          source.close();
          scheduleReconnect();
        }};
      }}

      connectEvents();
    }})();
  </script>
</body>
</html>"#,
        replay_cursor_json = serde_json::to_string(&bootstrap.replay_cursor).unwrap_or_else(|_| "\"0\"".to_owned()),
        operator_token_json = operator_token_json,
        system_kill_button = system_kill_button,
    )
}

fn render_session_tile(session: &BootstrapSession, access: &OperatorAccess) -> String {
    let operator_token = access.raw_token();
    let session_id = escape_html(&session.session_id);
    let vm_lease_id = session.vm_lease_id.as_deref().unwrap_or("pending-lease");
    let last_event_id = escape_html(&session.last_event_id);
    let state_label = session_state_label(session.state);
    let stream_label = stream_state_label(session.stream_state);
    let auth_query = operator_token_query(operator_token);
    let kill_button = render_kill_button(session, operator_token, access.can_kill_sessions());
    let preview_label = session
        .stream_preview
        .as_ref()
        .map(|preview| {
            format!(
                "<div class=\"tile-meta\"><strong>Stream</strong><code>{}</code><span>{}</span></div>",
                escape_html(&preview.stream_id),
                escape_html(&preview.stream_endpoint)
            )
        })
        .unwrap_or_else(|| {
            "<div class=\"tile-meta\"><strong>Stream</strong><span>Awaiting preview.</span></div>".to_owned()
        });

    format!(
        r##"<article class="session-tile state-{state_class}" id="session-tile-{session_id}">
  <a class="tile-hit" href="/session/{session_id}?{auth_query}" hx-get="/session/{session_id}?{auth_query}" hx-target="#focus-panel" hx-swap="innerHTML">
    <div class="tile-head">
      <div>
        <div class="badge">{state_label}</div>
      </div>
      <div class="tile-meta"><strong>Stream</strong><span>{stream_label}</span></div>
    </div>
    <div class="tile-meta"><strong>Session</strong><code>{session_id}</code></div>
    <div class="tile-meta"><strong>Lease</strong><code>{vm_lease_id}</code></div>
    <div class="tile-meta"><strong>Last event</strong><code>{last_event_id}</code></div>
    {preview_label}
  </a>
  {kill_button}
</article>"##,
        state_class = state_label.replace(' ', "-").to_ascii_lowercase(),
        state_label = escape_html(state_label),
        stream_label = escape_html(stream_label),
        vm_lease_id = escape_html(vm_lease_id),
        preview_label = preview_label,
        auth_query = auth_query,
        kill_button = kill_button,
    )
}

fn render_focus_panel(
    session: &BootstrapSession,
    stream_preview: Option<&StreamPreview>,
    access: &OperatorAccess,
) -> String {
    let session_id = escape_html(&session.session_id);
    let state_label = escape_html(session_state_label(session.state));
    let stream_label = escape_html(stream_state_label(session.stream_state));
    let focus_actions = render_focus_kill_button(session, access);
    let body = if let Some(preview) = stream_preview {
        format!(
            r#"<div class="stream-stage">
  <div>
    <div class="badge">{transport}</div>
    <h2>Session {session_id}</h2>
    <p class="focus-note">Player shell only for now. The stream transport endpoint is ready for later Milestone 4 integration.</p>
    <p><strong>Stream ID</strong><br><code>{stream_id}</code></p>
    <p><strong>Endpoint</strong><br><code>{stream_endpoint}</code></p>
    <p><strong>Token expires</strong><br><code>{token_expires_at}</code></p>
  </div>
</div>"#,
            transport = escape_html(stream_transport_label(preview.transport)),
            stream_id = escape_html(&preview.stream_id),
            stream_endpoint = escape_html(&preview.stream_endpoint),
            token_expires_at = escape_html(&preview.token_expires_at),
        )
    } else {
        r#"<div class="stream-stage">
  <div>
    <h2>Stream unavailable</h2>
    <p class="focus-note">The frontend could not resolve a stream preview for this session yet.</p>
  </div>
</div>"#
            .to_owned()
    };

    format!(
        r#"<div class="focus-shell" data-focused-session-id="{session_id}">
  <div class="tile-meta"><strong>Session</strong><code>{session_id}</code></div>
  <div class="tile-meta"><strong>State</strong><span>{state_label}</span></div>
  <div class="tile-meta"><strong>Stream state</strong><span>{stream_label}</span></div>
  {focus_actions}
  {body}
</div>"#
    )
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

fn render_kill_button(session: &BootstrapSession, operator_token: &str, can_kill_sessions: bool) -> String {
    if !can_kill_sessions || !session_can_be_killed(session.state) {
        return String::new();
    }

    let session_id = escape_html(&session.session_id);
    let auth_query = operator_token_query(operator_token);

    format!(
        r##"<div class="tile-actions">
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

fn render_focus_kill_button(session: &BootstrapSession, access: &OperatorAccess) -> String {
    if !access.can_kill_sessions() || !session_can_be_killed(session.state) {
        return String::new();
    }

    let session_id = escape_html(&session.session_id);
    let auth_query = operator_token_query(access.raw_token());

    format!(
        r##"<div class="focus-actions">
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
        SessionState::WaitingForLease | SessionState::Assigned | SessionState::StreamReady
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
        SessionState::WaitingForLease => "waiting for lease",
        SessionState::Assigned => "assigned",
        SessionState::StreamReady => "stream ready",
        SessionState::Ended => "ended",
        SessionState::Killed => "killed",
        SessionState::RecycleRequested => "recycle requested",
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
            state: SessionState::StreamReady,
            last_event_id: "event-1".to_owned(),
            last_session_seq: 2,
            stream_state: StreamState::Ready,
            stream_preview: None,
        };
        let preview = StreamPreview {
            stream_id: "stream-1".to_owned(),
            transport: StreamTransport::Sse,
            stream_endpoint: "https://streams.example/session-1".to_owned(),
            token_expires_at: "2026-03-26T12:00:00Z".to_owned(),
        };

        let html = render_focus_panel(
            &session,
            Some(&preview),
            &test_access("operator-token", AccessScope::Wildcard),
        );

        assert!(html.contains("stream-1"));
        assert!(html.contains("https://streams.example/session-1"));
        assert!(html.contains("Player shell only"));
        assert!(html.contains("Kill session"));
    }
}
