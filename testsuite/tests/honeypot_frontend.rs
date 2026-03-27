use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::header::AUTHORIZATION;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::prelude::*;
use honeypot_contracts::events::{SessionState, StreamState};
use honeypot_contracts::frontend::{
    BootstrapResponse, BootstrapSession, CommandProposalRequest, CommandProposalResponse, CommandProposalState,
    CommandVoteChoice, CommandVoteRequest, CommandVoteResponse, CommandVoteState, KeyboardCaptureRequest,
    KeyboardCaptureResponse, KeyboardCaptureState,
};
use honeypot_contracts::stream::{StreamPreview, StreamTokenResponse, StreamTransport};
use serde_json::Value;
use testsuite::cli::wait_for_tcp_port;
use testsuite::honeypot_frontend::{
    HoneypotFrontendTestConfig, find_unused_port, honeypot_frontend_tokio_cmd, read_http_response, send_http_request,
    write_honeypot_frontend_config,
};
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use uuid::Uuid;

const FRONTEND_PROXY_TOKEN: &str = "frontend-proxy-token";
const HONEYPOT_WATCH_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwOTkiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Qud2F0Y2gifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_STREAM_READ_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwOTkiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Quc3RyZWFtLnJlYWQifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_COMMAND_PROPOSE_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAxMDEiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3QuY29tbWFuZC5wcm9wb3NlIn0.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_COMMAND_APPROVE_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAxMDMiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3QuY29tbWFuZC5hcHByb3ZlIn0.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";

#[derive(Clone)]
struct MockProxyState {
    bootstrap: Arc<Mutex<BootstrapResponse>>,
    events_body: Arc<Mutex<String>>,
    stream_tokens: Arc<Mutex<HashMap<String, StreamTokenResponse>>>,
    observed_tokens: Arc<Mutex<Vec<String>>>,
    terminated_sessions: Arc<Mutex<Vec<String>>>,
    quarantined_sessions: Arc<Mutex<Vec<String>>>,
    system_terminate_requests: Arc<Mutex<u32>>,
}

#[tokio::test]
async fn frontend_dashboard_renders_bootstrap_sessions() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "42".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-1".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-1".to_owned(),
                last_session_seq: 2,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: "stream-1".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: format!("/jet/honeypot/session/{session_id}/stream?stream_id=stream-1"),
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
async fn frontend_health_reports_ready_when_bootstrap_is_reachable() {
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-health-ready".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "6".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: Uuid::new_v4().to_string(),
                vm_lease_id: Some("lease-health".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-health".to_owned(),
                last_session_seq: 3,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: "stream-health".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: "/jet/honeypot/session/session-health/stream?stream_id=stream-health".to_owned(),
                    token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                }),
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

    let (status_line, _headers, body) = read_http_response(port, "/health").await.expect("read health response");
    let body: Value = serde_json::from_slice(&body).expect("decode health json");

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(body["service_state"], "ready");
    assert_eq!(body["proxy_bootstrap_reachable"], true);
    assert_eq!(body["live_session_count"], 1);
    assert_eq!(body["ready_tile_count"], 1);
    assert_eq!(body["degraded_reasons"], Value::Array(Vec::new()));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_health_reports_degraded_when_bootstrap_is_unreachable() {
    let tempdir = tempfile::tempdir().expect("create frontend tempdir");
    let config_path = tempdir.path().join("frontend.toml");
    let port = find_unused_port();
    let missing_proxy_port = find_unused_port();
    write_honeypot_frontend_config(
        &config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{port}"))
            .proxy_base_url(format!("http://127.0.0.1:{missing_proxy_port}/"))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let (status_line, _headers, body) = read_http_response(port, "/health").await.expect("read health response");
    let body: Value = serde_json::from_slice(&body).expect("decode health json");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(body["service_state"], "degraded");
    assert_eq!(body["proxy_bootstrap_reachable"], false);
    assert_eq!(body["live_session_count"], 0);
    assert_eq!(body["ready_tile_count"], 0);
    assert!(
        body["degraded_reasons"]
            .as_array()
            .expect("degraded reasons array")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("bootstrap unavailable"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
}

#[tokio::test]
async fn frontend_health_recovers_when_proxy_bootstrap_becomes_reachable() {
    let reserved_listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind reserved proxy port");
    let proxy_addr = reserved_listener.local_addr().expect("read reserved proxy address");
    drop(reserved_listener);

    let state = mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-health-recovery".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "8".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: Uuid::new_v4().to_string(),
                vm_lease_id: Some("lease-recovery".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-recovery".to_owned(),
                last_session_seq: 4,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: "stream-recovery".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: "/jet/honeypot/session/session-recovery/stream?stream_id=stream-recovery"
                        .to_owned(),
                    token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                }),
            }],
        },
        String::new(),
        HashMap::new(),
    );

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

    let (status_line, _headers, body) = read_http_response(port, "/health")
        .await
        .expect("read initial health response");
    let body: Value = serde_json::from_slice(&body).expect("decode initial health json");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(body["service_state"], "degraded");
    assert_eq!(body["proxy_bootstrap_reachable"], false);
    assert!(
        body["degraded_reasons"]
            .as_array()
            .expect("degraded reasons array")
            .iter()
            .any(|reason| reason.as_str().unwrap_or_default().contains("bootstrap unavailable"))
    );

    let (
        bound_proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy_on_addr(state, proxy_addr).await;
    assert_eq!(bound_proxy_addr, proxy_addr);

    let mut recovered = None;
    for _ in 0..20 {
        let (status_line, _headers, body) = read_http_response(port, "/health")
            .await
            .expect("read recovered health response");
        let body: Value = serde_json::from_slice(&body).expect("decode recovered health json");

        if status_line.contains("200")
            && body["service_state"] == "ready"
            && body["proxy_bootstrap_reachable"] == true
            && body["live_session_count"] == 1
            && body["ready_tile_count"] == 1
        {
            recovered = Some((status_line, body));
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (status_line, body) =
        recovered.expect("frontend health did not recover after proxy bootstrap became reachable");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(body["service_state"], "ready");
    assert_eq!(body["proxy_bootstrap_reachable"], true);
    assert_eq!(body["live_session_count"], 1);
    assert_eq!(body["ready_tile_count"], 1);
    assert_eq!(body["degraded_reasons"], Value::Array(Vec::new()));

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_events_route_proxies_proxy_sse() {
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
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
async fn frontend_stream_lifecycle_promotes_live_tile_and_removes_it_after_recycle() {
    let session_id = Uuid::new_v4().to_string();
    let stream_id = "stream-lifecycle".to_owned();
    let stream_endpoint = format!("/jet/honeypot/session/{session_id}/stream?stream_id={stream_id}");
    let token_path = authed_path(
        format!("/session/{session_id}").as_str(),
        HONEYPOT_STREAM_READ_SCOPE_TOKEN,
    );

    let mut stream_tokens = HashMap::new();
    stream_tokens.insert(
        session_id.clone(),
        StreamTokenResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "stream-token-lifecycle".to_owned(),
            session_id: session_id.clone(),
            vm_lease_id: "lease-lifecycle".to_owned(),
            stream_id: stream_id.clone(),
            stream_endpoint: stream_endpoint.clone(),
            transport: StreamTransport::Websocket,
            issued_at: "2026-03-26T12:00:00Z".to_owned(),
            expires_at: "2026-03-26T12:05:00Z".to_owned(),
        },
    );

    let state = mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-lifecycle-empty".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "30".to_owned(),
            sessions: Vec::new(),
        },
        "id: 31\nevent: session.stream.ready\ndata: {\"event_kind\":\"session.stream.ready\",\"session_id\":\"pending\",\"global_cursor\":\"31\"}\n\n"
            .to_owned(),
        stream_tokens,
    );
    let lifecycle_state = state.clone();

    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(state).await;

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

    let (status_line, _headers, body) = read_http_response(port, &authed_path("/", HONEYPOT_WATCH_SCOPE_TOKEN))
        .await
        .expect("read initial dashboard");
    let body = String::from_utf8(body).expect("decode initial dashboard");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("No live sessions are visible yet."), "{body}");
    assert!(!body.contains(&session_id), "{body}");

    set_bootstrap(
        &lifecycle_state,
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-lifecycle-live".to_owned(),
            generated_at: "2026-03-26T12:00:30Z".to_owned(),
            replay_cursor: "31".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-lifecycle".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-lifecycle-ready".to_owned(),
                last_session_seq: 3,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: stream_id.clone(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: stream_endpoint.clone(),
                    token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                }),
            }],
        },
    )
    .await;
    set_events_body(
        &lifecycle_state,
        format!(
            "id: 31\nevent: session.stream.ready\ndata: {{\"event_kind\":\"session.stream.ready\",\"session_id\":\"{session_id}\",\"global_cursor\":\"31\"}}\n\n"
        ),
    )
    .await;

    let (status_line, _headers, body) = read_http_response(port, &authed_path("/", HONEYPOT_WATCH_SCOPE_TOKEN))
        .await
        .expect("read live dashboard");
    let body = String::from_utf8(body).expect("decode live dashboard");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains(&session_id), "{body}");
    assert!(body.contains(&stream_id), "{body}");
    assert!(body.contains("session-tile-"), "{body}");

    let (events_status, events_headers, events_body) =
        read_http_response(port, &authed_path("/events?cursor=30", HONEYPOT_WATCH_SCOPE_TOKEN))
            .await
            .expect("read live event stream");
    let events_body = String::from_utf8(events_body).expect("decode live events");

    assert!(events_status.contains("200"), "{events_status}");
    assert!(events_headers.contains("text/event-stream"), "{events_headers}");
    assert!(events_body.contains("event: session.stream.ready"), "{events_body}");
    assert!(events_body.contains(&session_id), "{events_body}");

    let (status_line, _headers, body) = read_http_response(port, &token_path)
        .await
        .expect("read live focus fragment");
    let body = String::from_utf8(body).expect("decode live focus fragment");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("<iframe"), "{body}");
    assert!(body.contains(&stream_endpoint), "{body}");
    assert!(body.contains("Refresh reconnects near the live tail"), "{body}");

    set_bootstrap(
        &lifecycle_state,
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-lifecycle-recycled".to_owned(),
            generated_at: "2026-03-26T12:01:00Z".to_owned(),
            replay_cursor: "32".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-lifecycle".to_owned()),
                state: SessionState::Recycled,
                last_event_id: "event-lifecycle-recycled".to_owned(),
                last_session_seq: 4,
                stream_state: StreamState::Failed,
                stream_preview: None,
            }],
        },
    )
    .await;
    set_events_body(
        &lifecycle_state,
        format!(
            "id: 32\nevent: host.recycled\ndata: {{\"event_kind\":\"host.recycled\",\"session_id\":\"{session_id}\",\"global_cursor\":\"32\"}}\n\n"
        ),
    )
    .await;

    let (events_status, _events_headers, events_body) =
        read_http_response(port, &authed_path("/events?cursor=31", HONEYPOT_WATCH_SCOPE_TOKEN))
            .await
            .expect("read recycle event stream");
    let events_body = String::from_utf8(events_body).expect("decode recycle events");

    assert!(events_status.contains("200"), "{events_status}");
    assert!(events_body.contains("event: host.recycled"), "{events_body}");
    assert!(events_body.contains(&session_id), "{events_body}");

    let (status_line, _headers, body) = read_http_response(port, &authed_path("/", HONEYPOT_WATCH_SCOPE_TOKEN))
        .await
        .expect("read recycled dashboard");
    let body = String::from_utf8(body).expect("decode recycled dashboard");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(!body.contains(&session_id), "{body}");
    assert!(body.contains("No live sessions are visible yet."), "{body}");

    let tile_path = authed_path(format!("/tile/{session_id}").as_str(), HONEYPOT_WATCH_SCOPE_TOKEN);
    let (tile_status, _headers, _body) = read_http_response(port, &tile_path).await.expect("read recycled tile");
    assert!(tile_status.contains("404"), "{tile_status}");

    let (focus_status, _headers, _body) = read_http_response(port, &token_path)
        .await
        .expect("read recycled focus");
    assert!(focus_status.contains("404"), "{focus_status}");

    let observed_tokens = observed_tokens.lock().await.clone();
    assert!(
        observed_tokens
            .iter()
            .any(|entry| entry == &format!("STREAM_TOKEN:{session_id}"))
    );

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
            stream_endpoint: format!("/jet/honeypot/session/{session_id}/stream?stream_id=stream-2"),
            transport: StreamTransport::Websocket,
            issued_at: "2026-03-26T12:00:00Z".to_owned(),
            expires_at: "2026-03-26T12:05:00Z".to_owned(),
        },
    );

    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
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
    assert!(body.contains("stream-2"), "{body}");
    assert!(body.contains("<iframe"), "{body}");
    assert!(body.contains("/jet/honeypot/session/"), "{body}");
    assert!(body.contains("stream_id=stream-2&amp;token="), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("STREAM_TOKEN:{session_id}"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_focus_fragment_renders_bootstrap_preview_and_renews_stream_token() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-preview".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "12".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-preview".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-preview".to_owned(),
                last_session_seq: 2,
                stream_state: StreamState::Ready,
                stream_preview: Some(StreamPreview {
                    stream_id: "stream-preview".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: format!("/jet/honeypot/session/{session_id}/stream?stream_id=stream-preview"),
                    token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                }),
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

    let path = authed_path(
        format!("/session/{session_id}").as_str(),
        HONEYPOT_STREAM_READ_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = read_http_response(port, &path).await.expect("read focus fragment");
    let body = String::from_utf8(body).expect("decode focus fragment");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("stream-preview"), "{body}");
    assert!(body.contains("<iframe"), "{body}");
    assert!(body.contains("stream_id=stream-preview&amp;token="), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("STREAM_TOKEN:{session_id}"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_focus_fragment_uses_only_the_requested_sessions_stream_binding() {
    let session_a = Uuid::new_v4().to_string();
    let session_b = Uuid::new_v4().to_string();
    let mut stream_tokens = HashMap::new();
    stream_tokens.insert(
        session_a.clone(),
        StreamTokenResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "stream-token-session-a".to_owned(),
            session_id: session_a.clone(),
            vm_lease_id: "lease-a".to_owned(),
            stream_id: "stream-a".to_owned(),
            stream_endpoint: format!("/jet/honeypot/session/{session_a}/stream?stream_id=stream-a"),
            transport: StreamTransport::Websocket,
            issued_at: "2026-03-26T12:00:00Z".to_owned(),
            expires_at: "2026-03-26T12:05:00Z".to_owned(),
        },
    );

    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-session-isolation".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "18".to_owned(),
            sessions: vec![
                BootstrapSession {
                    session_id: session_a.clone(),
                    vm_lease_id: Some("lease-a".to_owned()),
                    state: SessionState::Assigned,
                    last_event_id: "event-a".to_owned(),
                    last_session_seq: 1,
                    stream_state: StreamState::Pending,
                    stream_preview: None,
                },
                BootstrapSession {
                    session_id: session_b.clone(),
                    vm_lease_id: Some("lease-b".to_owned()),
                    state: SessionState::Ready,
                    last_event_id: "event-b".to_owned(),
                    last_session_seq: 2,
                    stream_state: StreamState::Ready,
                    stream_preview: Some(StreamPreview {
                        stream_id: "stream-b".to_owned(),
                        transport: StreamTransport::Websocket,
                        stream_endpoint: format!("/jet/honeypot/session/{session_b}/stream?stream_id=stream-b"),
                        token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                    }),
                },
            ],
        },
        String::new(),
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
        format!("/session/{session_a}").as_str(),
        HONEYPOT_STREAM_READ_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = read_http_response(port, &path).await.expect("read focus fragment");
    let body = String::from_utf8(body).expect("decode focus fragment");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("stream-a"), "{body}");
    assert!(
        body.contains(&format!("/jet/honeypot/session/{session_a}/stream")),
        "{body}"
    );
    assert!(!body.contains("stream-b"), "{body}");
    assert!(!body.contains(session_b.as_str()), "{body}");

    let observed_tokens = observed_tokens.lock().await.clone();
    assert!(
        observed_tokens
            .iter()
            .any(|entry| entry == &format!("STREAM_TOKEN:{session_a}"))
    );
    assert!(
        !observed_tokens
            .iter()
            .any(|entry| entry == &format!("STREAM_TOKEN:{session_b}"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_command_proposal_route_records_and_defers_without_execution() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-proposal-deferred".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "19".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-proposal".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-proposal".to_owned(),
                last_session_seq: 2,
                stream_state: StreamState::Ready,
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

    let proposal_path = authed_path(
        format!("/session/{session_id}/propose").as_str(),
        HONEYPOT_COMMAND_PROPOSE_SCOPE_TOKEN,
    );
    let body = b"command_text=cmd.exe%20%2Fc%20whoami";
    let (status_line, _headers, body) = send_http_request(
        port,
        "POST",
        &proposal_path,
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await
    .expect("read proposal placeholder");
    let body = String::from_utf8(body).expect("decode proposal placeholder html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Proposal deferred"), "{body}");
    assert!(body.contains("disabled_by_policy"), "{body}");
    assert!(body.contains("cmd.exe /c whoami"), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("PROPOSE:{session_id}:cmd.exe /c whoami"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_command_proposal_route_records_rejection_for_empty_command() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-proposal-rejected".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "20".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-proposal".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-proposal".to_owned(),
                last_session_seq: 2,
                stream_state: StreamState::Ready,
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

    let proposal_path = authed_path(
        format!("/session/{session_id}/propose").as_str(),
        HONEYPOT_COMMAND_PROPOSE_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = send_http_request(
        port,
        "POST",
        &proposal_path,
        Some("application/x-www-form-urlencoded"),
        b"command_text=%20%20%20",
    )
    .await
    .expect("read proposal placeholder");
    let body = String::from_utf8(body).expect("decode proposal placeholder html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Proposal rejected"), "{body}");
    assert!(body.contains("empty_command"), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("PROPOSE:{session_id}:"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_command_vote_route_records_deferred_approval_without_execution() {
    let session_id = Uuid::new_v4().to_string();
    let proposal_id = "proposal-approve-1";
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-vote-approval".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "21".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-vote".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-vote".to_owned(),
                last_session_seq: 3,
                stream_state: StreamState::Ready,
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

    let vote_path = authed_path(
        format!("/session/{session_id}/vote").as_str(),
        HONEYPOT_COMMAND_APPROVE_SCOPE_TOKEN,
    );
    let body = format!("proposal_id={proposal_id}&vote=approve");
    let (status_line, _headers, body) = send_http_request(
        port,
        "POST",
        &vote_path,
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
    )
    .await
    .expect("read vote placeholder");
    let body = String::from_utf8(body).expect("decode vote placeholder html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Vote deferred"), "{body}");
    assert!(body.contains("disabled_by_policy"), "{body}");
    assert!(body.contains("approve"), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("VOTE:{session_id}:{proposal_id}:approve"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_command_vote_route_records_rejection_without_execution() {
    let session_id = Uuid::new_v4().to_string();
    let proposal_id = "proposal-reject-1";
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-vote-reject".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "22".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-vote".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-vote".to_owned(),
                last_session_seq: 3,
                stream_state: StreamState::Ready,
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

    let vote_path = authed_path(
        format!("/session/{session_id}/vote").as_str(),
        HONEYPOT_COMMAND_APPROVE_SCOPE_TOKEN,
    );
    let body = format!("proposal_id={proposal_id}&vote=reject");
    let (status_line, _headers, body) = send_http_request(
        port,
        "POST",
        &vote_path,
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
    )
    .await
    .expect("read vote placeholder");
    let body = String::from_utf8(body).expect("decode vote placeholder html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Vote rejected"), "{body}");
    assert!(body.contains("rejected_by_operator"), "{body}");
    assert!(body.contains("reject"), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("VOTE:{session_id}:{proposal_id}:reject"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_keyboard_capture_route_returns_disabled_placeholder() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-keyboard".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "23".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-keyboard".to_owned()),
                state: SessionState::Ready,
                last_event_id: "event-keyboard".to_owned(),
                last_session_seq: 3,
                stream_state: StreamState::Ready,
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

    let keyboard_path = authed_path(
        format!("/session/{session_id}/keyboard").as_str(),
        HONEYPOT_COMMAND_APPROVE_SCOPE_TOKEN,
    );
    let body = b"key_sequence=abc123";
    let (status_line, _headers, body) = send_http_request(
        port,
        "POST",
        &keyboard_path,
        Some("application/x-www-form-urlencoded"),
        body,
    )
    .await
    .expect("read keyboard placeholder");
    let body = String::from_utf8(body).expect("decode keyboard placeholder html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Keyboard capture disabled"), "{body}");
    assert!(body.contains("disabled_by_policy"), "{body}");
    assert!(!body.contains("abc123"), "{body}");
    assert!(
        observed_tokens
            .lock()
            .await
            .iter()
            .any(|entry| entry == &format!("KEYBOARD:{session_id}:6"))
    );

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_dashboard_filters_terminal_sessions_from_bootstrap() {
    let live_session_id = Uuid::new_v4().to_string();
    let disconnected_session_id = Uuid::new_v4().to_string();
    let recycled_session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-live-only".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "14".to_owned(),
            sessions: vec![
                BootstrapSession {
                    session_id: live_session_id.clone(),
                    vm_lease_id: Some("lease-live".to_owned()),
                    state: SessionState::Ready,
                    last_event_id: "event-live".to_owned(),
                    last_session_seq: 2,
                    stream_state: StreamState::Ready,
                    stream_preview: Some(StreamPreview {
                        stream_id: "stream-live".to_owned(),
                        transport: StreamTransport::Websocket,
                        stream_endpoint: format!(
                            "/jet/honeypot/session/{live_session_id}/stream?stream_id=stream-live"
                        ),
                        token_expires_at: "2026-03-26T12:05:00Z".to_owned(),
                    }),
                },
                BootstrapSession {
                    session_id: disconnected_session_id.clone(),
                    vm_lease_id: Some("lease-disconnected".to_owned()),
                    state: SessionState::Disconnected,
                    last_event_id: "event-disconnected".to_owned(),
                    last_session_seq: 3,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
                BootstrapSession {
                    session_id: recycled_session_id.clone(),
                    vm_lease_id: Some("lease-recycled".to_owned()),
                    state: SessionState::Recycled,
                    last_event_id: "event-recycled".to_owned(),
                    last_session_seq: 4,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
            ],
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

    let (status_line, _headers, body) = read_http_response(port, &authed_path("/", HONEYPOT_WATCH_SCOPE_TOKEN))
        .await
        .expect("read dashboard");
    let body = String::from_utf8(body).expect("decode dashboard html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains(&live_session_id), "{body}");
    assert!(!body.contains(&disconnected_session_id), "{body}");
    assert!(!body.contains(&recycled_session_id), "{body}");

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_tile_route_rejects_terminal_sessions() {
    let disconnected_session_id = Uuid::new_v4().to_string();
    let recycled_session_id = Uuid::new_v4().to_string();
    let recycle_requested_session_id = Uuid::new_v4().to_string();
    let killed_session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-terminal-tiles".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "15".to_owned(),
            sessions: vec![
                BootstrapSession {
                    session_id: disconnected_session_id.clone(),
                    vm_lease_id: Some("lease-disconnected".to_owned()),
                    state: SessionState::Disconnected,
                    last_event_id: "event-disconnected".to_owned(),
                    last_session_seq: 3,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
                BootstrapSession {
                    session_id: recycled_session_id.clone(),
                    vm_lease_id: Some("lease-recycled".to_owned()),
                    state: SessionState::Recycled,
                    last_event_id: "event-recycled".to_owned(),
                    last_session_seq: 4,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
                BootstrapSession {
                    session_id: recycle_requested_session_id.clone(),
                    vm_lease_id: Some("lease-recycle-requested".to_owned()),
                    state: SessionState::RecycleRequested,
                    last_event_id: "event-recycle-requested".to_owned(),
                    last_session_seq: 5,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
                BootstrapSession {
                    session_id: killed_session_id.clone(),
                    vm_lease_id: Some("lease-killed".to_owned()),
                    state: SessionState::Killed,
                    last_event_id: "event-killed".to_owned(),
                    last_session_seq: 6,
                    stream_state: StreamState::Failed,
                    stream_preview: None,
                },
            ],
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

    for session_id in [
        &disconnected_session_id,
        &recycled_session_id,
        &recycle_requested_session_id,
        &killed_session_id,
    ] {
        let path = authed_path(format!("/tile/{session_id}").as_str(), HONEYPOT_WATCH_SCOPE_TOKEN);
        let (status_line, _headers, _body) = read_http_response(port, &path).await.expect("read tile response");
        assert!(status_line.contains("404"), "{session_id}: {status_line}");
    }

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_dashboard_requires_operator_token() {
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
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
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
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

#[tokio::test]
async fn frontend_dashboard_shows_kill_button_and_forwards_kill_requests() {
    let session_id = Uuid::new_v4().to_string();
    let session_kill_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-kill-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "13".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-kill".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-kill".to_owned(),
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
            .proxy_bearer_token(Some(FRONTEND_PROXY_TOKEN.to_owned()))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let dashboard_path = authed_path("/", &session_kill_token);
    let (status_line, _headers, body) = read_http_response(port, &dashboard_path).await.expect("read dashboard");
    let body = String::from_utf8(body).expect("decode dashboard html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Kill session"));
    assert!(body.contains(&format!("/session/{session_id}/kill?token=")));

    let kill_path = authed_path(format!("/session/{session_id}/kill").as_str(), &session_kill_token);
    let (status_line, _headers, body) = send_http_request(port, "POST", &kill_path, None, &[])
        .await
        .expect("post kill route");
    let body = String::from_utf8(body).expect("decode kill response");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Kill requested"));
    assert_eq!(
        terminated_sessions.lock().await.as_slice(),
        std::slice::from_ref(&session_id)
    );

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
async fn frontend_dashboard_shows_quarantine_button_and_forwards_requests() {
    let session_id = Uuid::new_v4().to_string();
    let session_kill_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-quarantine-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "17".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-quarantine".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-quarantine".to_owned(),
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
            .proxy_bearer_token(Some(FRONTEND_PROXY_TOKEN.to_owned()))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let dashboard_path = authed_path("/", &session_kill_token);
    let (status_line, _headers, body) = read_http_response(port, &dashboard_path).await.expect("read dashboard");
    let body = String::from_utf8(body).expect("decode dashboard html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Quarantine guest"));
    assert!(body.contains(&format!("/session/{session_id}/quarantine?token=")));

    let quarantine_path = authed_path(
        format!("/session/{session_id}/quarantine").as_str(),
        &session_kill_token,
    );
    let (status_line, _headers, body) = send_http_request(port, "POST", &quarantine_path, None, &[])
        .await
        .expect("post quarantine route");
    let body = String::from_utf8(body).expect("decode quarantine response");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Quarantine requested"));
    assert_eq!(
        quarantined_sessions.lock().await.as_slice(),
        std::slice::from_ref(&session_id)
    );

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
async fn frontend_dashboard_shows_system_kill_button_and_forwards_request() {
    let system_kill_token = honeypot_scope_token("gateway.honeypot.system.kill");
    let (
        proxy_addr,
        proxy_handle,
        observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-system-kill-1".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "21".to_owned(),
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
            .proxy_bearer_token(Some(FRONTEND_PROXY_TOKEN.to_owned()))
            .build(),
    )
    .expect("write frontend config");

    let mut child = honeypot_frontend_tokio_cmd();
    child.env("HONEYPOT_FRONTEND_CONFIG_PATH", &config_path);
    let mut child = child.spawn().expect("spawn frontend");

    wait_for_tcp_port(port).await.expect("wait for frontend port");

    let dashboard_path = authed_path("/", &system_kill_token);
    let (status_line, _headers, body) = read_http_response(port, &dashboard_path).await.expect("read dashboard");
    let body = String::from_utf8(body).expect("decode dashboard html");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Global kill"));
    assert!(body.contains("/system/kill?token="));

    let kill_path = authed_path("/system/kill", &system_kill_token);
    let (status_line, _headers, body) = send_http_request(port, "POST", &kill_path, None, &[])
        .await
        .expect("post system kill route");
    let body = String::from_utf8(body).expect("decode system kill response");

    assert!(status_line.contains("200"), "{status_line}");
    assert!(body.contains("Global kill requested"));
    assert_eq!(*system_terminate_requests.lock().await, 1);

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
async fn frontend_quarantine_route_requires_session_kill_scope() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-quarantine-2".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "19".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-quarantine-2".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-quarantine-2".to_owned(),
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

    let quarantine_path = authed_path(
        format!("/session/{session_id}/quarantine").as_str(),
        HONEYPOT_WATCH_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = send_http_request(port, "POST", &quarantine_path, None, &[])
        .await
        .expect("post forbidden quarantine route");
    let body = String::from_utf8(body).expect("decode forbidden quarantine response");

    assert!(status_line.contains("403"), "{status_line}");
    assert!(body.contains("gateway.honeypot.session.kill"));
    assert!(quarantined_sessions.lock().await.is_empty());

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_kill_route_requires_session_kill_scope() {
    let session_id = Uuid::new_v4().to_string();
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        terminated_sessions,
        _quarantined_sessions,
        _system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-kill-2".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "0".to_owned(),
            sessions: vec![BootstrapSession {
                session_id: session_id.clone(),
                vm_lease_id: Some("lease-kill-2".to_owned()),
                state: SessionState::Assigned,
                last_event_id: "event-kill-2".to_owned(),
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

    let kill_path = authed_path(
        format!("/session/{session_id}/kill").as_str(),
        HONEYPOT_WATCH_SCOPE_TOKEN,
    );
    let (status_line, _headers, body) = send_http_request(port, "POST", &kill_path, None, &[])
        .await
        .expect("post forbidden kill route");
    let body = String::from_utf8(body).expect("decode forbidden kill response");

    assert!(status_line.contains("403"), "{status_line}");
    assert!(body.contains("gateway.honeypot.session.kill"));
    assert!(terminated_sessions.lock().await.is_empty());

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

#[tokio::test]
async fn frontend_system_kill_route_requires_system_kill_scope() {
    let session_kill_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let (
        proxy_addr,
        proxy_handle,
        _observed_tokens,
        _terminated_sessions,
        _quarantined_sessions,
        system_terminate_requests,
    ) = start_mock_proxy(mock_state(
        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "bootstrap-system-kill-2".to_owned(),
            generated_at: "2026-03-26T12:00:00Z".to_owned(),
            replay_cursor: "22".to_owned(),
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

    let kill_path = authed_path("/system/kill", &session_kill_token);
    let (status_line, _headers, body) = send_http_request(port, "POST", &kill_path, None, &[])
        .await
        .expect("post forbidden system kill route");
    let body = String::from_utf8(body).expect("decode forbidden system kill response");

    assert!(status_line.contains("403"), "{status_line}");
    assert!(body.contains("gateway.honeypot.system.kill"));
    assert_eq!(*system_terminate_requests.lock().await, 0);

    let _ = child.start_kill();
    let _ = child.wait().await;
    proxy_handle.abort();
    let _ = proxy_handle.await;
}

async fn start_mock_proxy(
    state: MockProxyState,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<u32>>,
) {
    start_mock_proxy_on_addr(state, SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await
}

async fn start_mock_proxy_on_addr(
    state: MockProxyState,
    addr: SocketAddr,
) -> (
    SocketAddr,
    tokio::task::JoinHandle<()>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<Vec<String>>>,
    Arc<Mutex<u32>>,
) {
    let observed_tokens = Arc::clone(&state.observed_tokens);
    let terminated_sessions = Arc::clone(&state.terminated_sessions);
    let quarantined_sessions = Arc::clone(&state.quarantined_sessions);
    let system_terminate_requests = Arc::clone(&state.system_terminate_requests);
    let listener = TcpListener::bind(addr).await.expect("bind mock proxy listener");
    let addr = listener.local_addr().expect("read mock proxy address");

    let router = Router::new()
        .route("/jet/honeypot/bootstrap", get(mock_bootstrap))
        .route("/jet/honeypot/events", get(mock_events))
        .route("/jet/honeypot/session/{id}/stream-token", post(mock_stream_token))
        .route("/jet/session/{id}/keyboard", post(mock_keyboard))
        .route("/jet/session/{id}/propose", post(mock_propose))
        .route("/jet/session/{id}/vote", post(mock_vote))
        .route("/jet/session/system/terminate", post(mock_system_terminate))
        .route("/jet/session/{id}/quarantine", post(mock_quarantine))
        .route("/jet/session/{id}/terminate", post(mock_terminate))
        .with_state(state);

    let handle = tokio::spawn(async move {
        axum::serve(listener, router).await.expect("serve mock proxy");
    });

    (
        addr,
        handle,
        observed_tokens,
        terminated_sessions,
        quarantined_sessions,
        system_terminate_requests,
    )
}

fn mock_state(
    bootstrap: BootstrapResponse,
    events_body: String,
    stream_tokens: HashMap<String, StreamTokenResponse>,
) -> MockProxyState {
    MockProxyState {
        bootstrap: Arc::new(Mutex::new(bootstrap)),
        events_body: Arc::new(Mutex::new(events_body)),
        stream_tokens: Arc::new(Mutex::new(stream_tokens)),
        observed_tokens: Arc::new(Mutex::new(Vec::new())),
        terminated_sessions: Arc::new(Mutex::new(Vec::new())),
        quarantined_sessions: Arc::new(Mutex::new(Vec::new())),
        system_terminate_requests: Arc::new(Mutex::new(0)),
    }
}

async fn set_bootstrap(state: &MockProxyState, bootstrap: BootstrapResponse) {
    *state.bootstrap.lock().await = bootstrap;
}

async fn set_events_body(state: &MockProxyState, events_body: String) {
    *state.events_body.lock().await = events_body;
}

fn authed_path(path: &str, token: &str) -> String {
    let separator = if path.contains('?') { '&' } else { '?' };
    format!("{path}{separator}token={token}")
}

async fn mock_bootstrap(State(state): State<MockProxyState>, headers: HeaderMap) -> Json<BootstrapResponse> {
    record_token(&state, &headers).await;
    Json(state.bootstrap.lock().await.clone())
}

async fn mock_events(State(state): State<MockProxyState>, headers: HeaderMap) -> impl IntoResponse {
    record_token(&state, &headers).await;

    let body = state.events_body.lock().await.clone();
    let mut response = Response::new(Body::from(body));
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
    state
        .observed_tokens
        .lock()
        .await
        .push(format!("STREAM_TOKEN:{session_id}"));

    match state.stream_tokens.lock().await.get(&session_id).cloned() {
        Some(response) => (StatusCode::OK, Json(response)).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn mock_propose(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CommandProposalRequest>,
) -> impl IntoResponse {
    record_token(&state, &headers).await;
    let command_text = request.command_text.trim().to_owned();
    state
        .observed_tokens
        .lock()
        .await
        .push(format!("PROPOSE:{session_id}:{command_text}"));

    let proposal_state = if command_text.is_empty() {
        CommandProposalState::Rejected
    } else {
        CommandProposalState::Deferred
    };
    let decision_reason = if command_text.is_empty() {
        "empty_command"
    } else {
        "disabled_by_policy"
    };

    (
        StatusCode::OK,
        Json(CommandProposalResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "proposal-corr".to_owned(),
            proposal_id: "proposal-1".to_owned(),
            recorded_at: "2026-03-26T12:00:30Z".to_owned(),
            session_id,
            command_text,
            proposal_state,
            decision_reason: decision_reason.to_owned(),
            executed: false,
        }),
    )
        .into_response()
}

async fn mock_keyboard(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<KeyboardCaptureRequest>,
) -> impl IntoResponse {
    record_token(&state, &headers).await;
    let requested_key_count = u32::try_from(request.key_sequence.chars().count()).unwrap_or(u32::MAX);
    state
        .observed_tokens
        .lock()
        .await
        .push(format!("KEYBOARD:{session_id}:{requested_key_count}"));

    (
        StatusCode::OK,
        Json(KeyboardCaptureResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "keyboard-corr".to_owned(),
            capture_id: "keyboard-1".to_owned(),
            recorded_at: "2026-03-26T12:01:30Z".to_owned(),
            session_id,
            requested_key_count,
            capture_state: KeyboardCaptureState::DisabledByPolicy,
            decision_reason: "disabled_by_policy".to_owned(),
            executed: false,
        }),
    )
        .into_response()
}

async fn mock_vote(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    Json(request): Json<CommandVoteRequest>,
) -> impl IntoResponse {
    record_token(&state, &headers).await;
    let proposal_id = request.proposal_id.trim().to_owned();
    let vote_label = match request.vote {
        CommandVoteChoice::Approve => "approve",
        CommandVoteChoice::Reject => "reject",
    };
    state
        .observed_tokens
        .lock()
        .await
        .push(format!("VOTE:{session_id}:{proposal_id}:{vote_label}"));

    let (vote_state, decision_reason) = match request.vote {
        CommandVoteChoice::Approve => (CommandVoteState::Deferred, "disabled_by_policy"),
        CommandVoteChoice::Reject => (CommandVoteState::Rejected, "rejected_by_operator"),
    };

    (
        StatusCode::OK,
        Json(CommandVoteResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "vote-corr".to_owned(),
            vote_id: "vote-1".to_owned(),
            recorded_at: "2026-03-26T12:01:00Z".to_owned(),
            session_id,
            proposal_id,
            vote: request.vote,
            vote_state,
            decision_reason: decision_reason.to_owned(),
            executed: false,
        }),
    )
        .into_response()
}

async fn mock_terminate(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    record_token(&state, &headers).await;
    state.terminated_sessions.lock().await.push(session_id);
    StatusCode::OK
}

async fn mock_quarantine(
    State(state): State<MockProxyState>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> impl IntoResponse {
    record_token(&state, &headers).await;
    state.quarantined_sessions.lock().await.push(session_id);
    StatusCode::OK
}

async fn mock_system_terminate(State(state): State<MockProxyState>, headers: HeaderMap) -> impl IntoResponse {
    record_token(&state, &headers).await;
    *state.system_terminate_requests.lock().await += 1;
    StatusCode::OK
}

async fn record_token(state: &MockProxyState, headers: &HeaderMap) {
    if let Some(value) = headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()) {
        state.observed_tokens.lock().await.push(value.to_owned());
    }
}

fn honeypot_scope_token(scope: &str) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"scope","jti":"00000000-0000-0000-0000-000000000099","iat":1733669999,"exp":3331553599,"nbf":1733669999,"scope":"{scope}"}}"#
    ));

    format!("{header}.{payload}.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ")
}
