use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router, response::Response};
use honeypot_contracts::events::{SessionState, StreamState};
use honeypot_contracts::frontend::{BootstrapResponse, BootstrapSession};
use honeypot_contracts::stream::{StreamPreview, StreamTokenResponse, StreamTransport};
use testsuite::cli::wait_for_tcp_port;
use testsuite::honeypot_frontend::{
    HoneypotFrontendTestConfig, find_unused_port, honeypot_frontend_tokio_cmd, read_http_response,
    write_honeypot_frontend_config,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

const FRONTEND_PROXY_TOKEN: &str = "frontend-proxy-token";
const HONEYPOT_WATCH_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwOTkiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Qud2F0Y2gifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_STREAM_READ_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwOTkiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Quc3RyZWFtLnJlYWQifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";

#[derive(Clone)]
struct MockProxyState {
    bootstrap: BootstrapResponse,
    events_body: String,
    stream_tokens: HashMap<String, StreamTokenResponse>,
    observed_tokens: Arc<Mutex<Vec<String>>>,
}

#[tokio::test]
async fn frontend_dashboard_renders_bootstrap_sessions() {
    let session_id = Uuid::new_v4().to_string();
    let (proxy_addr, proxy_handle, observed_tokens) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "42".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-1".to_owned()),
                state: SessionState::StreamReady,
                last_event_id: "event-1".to_owned(),
                last_session_seq: 2,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: "stream-1".to_owned(),
                    transport: StreamTransport::Sse,
                    stream_endpoint: "https://streams.example/session-1".to_owned(),
                    token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                }),
            }],
        },
        "id: 42\nevent: session.started\ndata: {}\n\n".to_owned(),
        HashMap::new(),
    ))
    .await;

    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://{proxy_addr}/"))
            .proxy_bearer_token(Some(FRONTEND_PROXY_TOKEN.to_owned()))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let (status_line, _headers, body) = read_http_response(port, &authed_path("/", HONEYPOT_WATCH_SCOPE_TOKEN))
        .await
        .expect("read dashboard");
    let body = String::from_utf8(body).expect("decode dashboard html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Observation Deck"));
    assert!(body.contains(session_id.as_str()));
    assert!(body.contains("session-tile-"));
    assert!(body.contains("id=\"cursor-value\">42</code>"));
    assert!(body.contains("hx-get=\"/session/"));
    assert!(body.contains("token="));

    let tokens = observed_tokens.lock().await.clone();
    assert!(
        tokens
            .iter()
            .any(|token| token == &format!("Bearer {FRONTEND_PROXY_TOKEN}"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_events_route_proxies_proxy_sse() {
    let (proxy_addr, proxy_handle, _observed_tokens) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-2".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "0".to_owned(),
            sessions: Vec::new(),
        },
        "id: 7\nevent: session.started\ndata: {\"event_kind\":\"session.started\",\"global_cursor\":\"7\"}\n\n"
            .to_owned(),
        HashMap::new(),
    ))
    .await;

    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://{proxy_addr}/"))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let (status_line, headers, body) =
        read_http_response(port, &authed_path("/events?cursor=0", HONEYPOT_WATCH_SCOPE_TOKEN))
            .await
            .expect("read events response");
    let body = String::from_utf8(body).expect("decode event stream");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(headers.contains("text/event-stream"), "{headers}");
    assert!(body.contains("event: session.started"));
    assert!(body.contains("global_cursor\":\"7\""));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_focus_fragment_uses_stream_token_when_preview_is_missing() {
    let session_id = Uuid::new_v4().to_string();
    let mut stream_tokens = HashMap::new();
    stream_tokens.insert(
        session_id.clone(),
        StreamTokenResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "stream-token-1".to_owned(),
            session_id: session_id.clone(),
            vm_lease_id: "lease-2".to_owned(),
            stream_id: "stream-2".to_owned(),
            stream_endpoint: "https://streams.example/focus".to_owned(),
            transport: StreamTransport::Sse,
            issued_at: "2026-03-26T12:00:00Z".to_owned(),
            expires_at: "2026-03-26T12:05:00Z".to_owned(),
        },
    );

    let (proxy_addr, proxy_handle, _observed_tokens) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-3".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "11".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-2".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-3".to_owned(),
                last_session_seq: 1,
                stream_state: StreamState::Pending,
                stream_preview: None,
            }],
        },
        "id: 11\nevent: session.assigned\ndata: {}\n\n".to_owned(),
        stream_tokens,
    ))
    .await;

    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://{proxy_addr}/"))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let path = authed_path(
        format!("/session/{session_id}").as_str(),
        HONEYPOT_STREAM_READ_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = read_http_response(port, &path).await.expect("read focus fragment");
    let body = String::from_utf8(body).expect("decode focus fragment");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("stream-2"));
    assert!(body.contains("https://streams.example/focus"));
    assert!(body.contains("Player shell only"));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_dashboard_requires_operator_token() {
    let (proxy_addr, proxy_handle, _observed_tokens) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-auth-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "0".to_owned(),
            sessions: Vec::new(),
        },
        String::new(),
        HashMap::new(),
    ))
    .await;

    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://{proxy_addr}/"))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let (status_line, _headers, body) = read_http_response(port, "/").await.expect("read dashboard");
    let body = String::from_utf8(body).expect("decode unauthorized body");

    assert!(status_line.contains("401"), "{status_line}");
    assert!(body.contains("operator token is missing"));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_focus_fragment_requires_stream_read_scope() {
    let session_id = Uuid::new_v4().to_string();
    let (proxy_addr, proxy_handle, _observed_tokens) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-auth-2".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "8".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-auth".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-auth".to_owned(),
                last_session_seq: 1,
                stream_state: StreamState::Pending,
                stream_preview: None,
            }],
        },
        String::new(),
        HashMap::new(),
    ))
    .await;

    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://{proxy_addr}/"))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let path = authed_path(format!("/session/{session_id}").as_str(), HONEYPOT_WATCH_SCOPE_TOKEN);
    let (status_line, _headers, body) = read_http_response(port, &path).await.expect("read focus fragment");
    let body = String::from_utf8(body).expect("decode forbidden body");

    assert!(status_line.contains("403"), "{status_line}");
    assert!(body.contains("gateway.honeypot.stream.read"));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

async fn start_mock_proxy(
    state: MockProxyState,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<Vec<String>>>,
) {
    let observed_tokens = Arc::clone(&state.observed_tokens);
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("bind mock proxy listener");
    let addr = listener.local_addr().expect("read mock proxy address");

    let router = Router::new()
        .route("/jet/honeypot/bootstrap", get(mock_bootstrap))
        .route("/jet/honeypot/events", get(mock_events))
        .route("/jet/honeypot/session/{id}/stream-token", post(mock_stream_token))
        .with_state(state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve mock proxy");
    });

    (addr, handle, observed_tokens)
}

fn mock_state(
    bootstrap: BootstrapResponse,
    events_body: String,
    stream_tokens: HashMap<String, StreamTokenResponse>,
) -> MockProxyState {
    MockProxyState {
        bootstrap,
        events_body,
        stream_tokens,
        observed_tokens: Arc::new(Mutex::new(Vec::new())),
    }
}

fn authed_path(path: &str, token: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}token={token}")
}

async fn mock_bootstrap(State(state): State<MockProxyState>, headers: HeaderMap) -> Json<BootstrapResponse> {
    record_token(&state, &headers).await;
    Json(state.bootstrap)
}

async fn mock_events(State(state): State<MockProxyState>, headers: HeaderMap) -> impl IntoResponse {
    record_token(&state, &headers).await;

    let mut response = Response::new(Body::from(state.events_body));
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/event-stream"),
    );
    response
}

async fn mock_stream_token(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    record_token(&state, &headers).await;

    match state.stream_tokens.get(&session_id) {
        Some(response) => (StatusCode::OK, Json(response.clone())).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn record_token(state: &MockProxyState, headers: &HeaderMap) {
    if let Some(value) = headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()) {
        state.observed_tokens.lock().await.push(value.to_owned());
    }
}
