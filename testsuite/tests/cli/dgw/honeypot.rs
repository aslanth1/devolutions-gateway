use anyhow::Context as _;
use axum::extract::State;
use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;
use axum::routing::get;
use axum::{Json, Router};
use base64::prelude::*;
use honeypot_contracts::control_plane::{HealthResponse as ControlPlaneHealthResponse, ServiceState};
use honeypot_contracts::frontend::BootstrapResponse;
use testsuite::cli::{dgw_tokio_cmd, wait_for_tcp_port};
use testsuite::dgw_config::{DgwConfig, HoneypotConfig};
use uuid::Uuid;

const HONEYPOT_WATCH_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDMiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Qud2F0Y2gifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_WILDCARD_SCOPE_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJqdGkiOiI5YTdkZWRhOC1jNmM2LTQ1YzAtODZlYi01MGJiMzI4YWFjMjMiLCJleHAiOjAsInNjb3BlIjoiKiJ9.dTazZemDS08Fy13Hx7wxDoOxQ2oNFaaEYMSFDQHCWiUdlYv4NMQh6N_GQok3wdiSJf384fvLKccYe1fipRepLlinUAqcEum68ngvGuUVP78xYb_vC3ZDqFi6nvd1BLp621XgzsCbOyBZHhLXHgzwVNTpnbt9laTTaHh8_rSYLaujBOpidWS6vKIZqOE66beqygSprPt3y0LYFTQWGYq21jJ73uW6htdWrmXbDUUjdvG7ymnKb-7Scs5y03jjSTr4QB1rH_3Z8DsfuuxFCIBd8V2yu192PrWooAdMKboLSjvmdFiD509lljoaNoGLBv9hmmQyiLQr-rsUllXBD6UpTQ";
const TEST_CONTROL_PLANE_SERVICE_TOKEN: &str = "proxy-health-test-token";

#[derive(Clone)]
struct TestControlPlaneHealthState {
    response: ControlPlaneHealthResponse,
}

struct TestControlPlaneHealthServer {
    endpoint: String,
    server: tokio::task::JoinHandle<()>,
}

impl TestControlPlaneHealthServer {
    async fn spawn(service_state: ServiceState, degraded_reasons: Vec<String>) -> anyhow::Result<Self> {
        Self::spawn_on_addr(("127.0.0.1", 0), service_state, degraded_reasons).await
    }

    async fn spawn_on_addr(
        addr: impl tokio::net::ToSocketAddrs,
        service_state: ServiceState,
        degraded_reasons: Vec<String>,
    ) -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .context("bind fake control-plane health listener")?;
        let addr = listener.local_addr().context("read fake control-plane address")?;
        let state = TestControlPlaneHealthState {
            response: ControlPlaneHealthResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: "corr-health".to_owned(),
                service_state,
                kvm_available: true,
                trusted_image_count: 1,
                active_lease_count: 0,
                quarantined_lease_count: 0,
                degraded_reasons,
            },
        };
        let router = Router::new()
            .route("/api/v1/health", get(fake_control_plane_health_handler))
            .with_state(state);
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve fake control-plane health endpoint");
        });

        Ok(Self {
            endpoint: format!("http://{addr}/"),
            server,
        })
    }

    async fn shutdown(self) {
        self.server.abort();
        let _ = self.server.await;
    }
}

async fn fake_control_plane_health_handler(
    State(state): State<TestControlPlaneHealthState>,
    headers: HeaderMap,
) -> Json<ControlPlaneHealthResponse> {
    assert_eq!(
        headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
        Some("Bearer proxy-health-test-token")
    );

    Json(state.response)
}

#[tokio::test]
async fn honeypot_bootstrap_route_is_disabled_by_default() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, _body) = get_json_response(
        config_handle.http_port(),
        "/jet/honeypot/bootstrap",
        HONEYPOT_WATCH_SCOPE_TOKEN,
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn proxy_health_legacy_plaintext_stays_unchanged_when_honeypot_is_disabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = send_http_request(
        config_handle.http_port(),
        "GET",
        "/jet/health",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("200"), "{status_line}");
    assert!(
        std::str::from_utf8(&body)
            .context("decode plaintext health body")?
            .contains("is alive and healthy"),
        "unexpected body: {}",
        std::str::from_utf8(&body).unwrap_or("<non-utf8>")
    );

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn proxy_health_reports_ready_when_honeypot_control_plane_is_ready() -> anyhow::Result<()> {
    let control_plane = TestControlPlaneHealthServer::spawn(ServiceState::Ready, Vec::new()).await?;
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .control_plane_endpoint(Some(control_plane.endpoint.clone()))
                .control_plane_service_bearer_token(Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()))
                .control_plane_request_timeout_secs(1)
                .control_plane_connect_timeout_secs(1)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = send_http_request_with_headers(
        config_handle.http_port(),
        "GET",
        "/jet/health",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[("Accept", "application/json")],
        &[],
    )
    .await?;
    let payload: serde_json::Value = serde_json::from_slice(&body).context("parse ready health payload")?;

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(payload["honeypot"]["honeypot_enabled"], true);
    assert_eq!(payload["honeypot"]["service_state"], "ready");
    assert_eq!(payload["honeypot"]["control_plane_reachable"], true);
    assert_eq!(payload["honeypot"]["control_plane_service_state"], "ready");

    let _ = process.start_kill();
    let _ = process.wait().await;
    control_plane.shutdown().await;

    Ok(())
}

#[tokio::test]
async fn proxy_health_reports_unavailable_when_honeypot_control_plane_is_unreachable() -> anyhow::Result<()> {
    let unreachable_endpoint = {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).context("bind temp port")?;
        let addr = listener.local_addr().context("read temp port")?;
        format!("http://{addr}/")
    };
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .control_plane_endpoint(Some(unreachable_endpoint))
                .control_plane_service_bearer_token(Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()))
                .control_plane_request_timeout_secs(1)
                .control_plane_connect_timeout_secs(1)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = send_http_request_with_headers(
        config_handle.http_port(),
        "GET",
        "/jet/health",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[("Accept", "application/json")],
        &[],
    )
    .await?;
    let payload: serde_json::Value = serde_json::from_slice(&body).context("parse unavailable health payload")?;

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(payload["honeypot"]["service_state"], "unavailable");
    assert_eq!(payload["honeypot"]["control_plane_reachable"], false);
    assert!(payload["honeypot"]["control_plane_service_state"].is_null());
    assert_eq!(payload["honeypot"]["degraded_reasons"][0], "control_plane_unavailable");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn proxy_health_recovers_after_control_plane_outage() -> anyhow::Result<()> {
    let reserved_listener =
        std::net::TcpListener::bind(("127.0.0.1", 0)).context("bind reserved control-plane port")?;
    let control_plane_addr = reserved_listener
        .local_addr()
        .context("read reserved control-plane address")?;
    drop(reserved_listener);

    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .control_plane_endpoint(Some(format!("http://{control_plane_addr}/")))
                .control_plane_service_bearer_token(Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()))
                .control_plane_request_timeout_secs(1)
                .control_plane_connect_timeout_secs(1)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = send_http_request_with_headers(
        config_handle.http_port(),
        "GET",
        "/jet/health",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[("Accept", "application/json")],
        &[],
    )
    .await?;
    let payload: serde_json::Value =
        serde_json::from_slice(&body).context("parse initial unavailable health payload")?;

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(payload["honeypot"]["service_state"], "unavailable");
    assert_eq!(payload["honeypot"]["control_plane_reachable"], false);
    assert!(payload["honeypot"]["control_plane_service_state"].is_null());
    assert_eq!(payload["honeypot"]["degraded_reasons"][0], "control_plane_unavailable");

    let control_plane =
        TestControlPlaneHealthServer::spawn_on_addr(control_plane_addr, ServiceState::Ready, Vec::new()).await?;

    let mut recovered = None;
    for _ in 0..20 {
        let (status_line, body) = send_http_request_with_headers(
            config_handle.http_port(),
            "GET",
            "/jet/health",
            HONEYPOT_WATCH_SCOPE_TOKEN,
            None,
            &[("Accept", "application/json")],
            &[],
        )
        .await?;
        let payload: serde_json::Value = serde_json::from_slice(&body).context("parse recovered health payload")?;

        if status_line.contains("200")
            && payload["honeypot"]["service_state"] == "ready"
            && payload["honeypot"]["control_plane_reachable"] == true
            && payload["honeypot"]["control_plane_service_state"] == "ready"
        {
            recovered = Some((status_line, payload));
            break;
        }

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }

    let (status_line, payload) = recovered.context("proxy health did not recover after control-plane startup")?;
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(payload["honeypot"]["service_state"], "ready");
    assert_eq!(payload["honeypot"]["control_plane_reachable"], true);
    assert_eq!(payload["honeypot"]["control_plane_service_state"], "ready");
    assert_eq!(
        payload["honeypot"]["degraded_reasons"],
        serde_json::Value::Array(Vec::new())
    );

    let _ = process.start_kill();
    let _ = process.wait().await;
    control_plane.shutdown().await;

    Ok(())
}

#[tokio::test]
async fn proxy_health_reports_degraded_when_honeypot_control_plane_is_degraded() -> anyhow::Result<()> {
    let control_plane =
        TestControlPlaneHealthServer::spawn(ServiceState::Degraded, vec!["control_plane_degraded".to_owned()]).await?;
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .control_plane_endpoint(Some(control_plane.endpoint.clone()))
                .control_plane_service_bearer_token(Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()))
                .control_plane_request_timeout_secs(1)
                .control_plane_connect_timeout_secs(1)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = send_http_request_with_headers(
        config_handle.http_port(),
        "GET",
        "/jet/health",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[("Accept", "application/json")],
        &[],
    )
    .await?;
    let payload: serde_json::Value = serde_json::from_slice(&body).context("parse degraded health payload")?;

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(payload["honeypot"]["service_state"], "degraded");
    assert_eq!(payload["honeypot"]["control_plane_reachable"], true);
    assert_eq!(payload["honeypot"]["control_plane_service_state"], "degraded");
    assert_eq!(payload["honeypot"]["degraded_reasons"][0], "control_plane_degraded");

    let _ = process.start_kill();
    let _ = process.wait().await;
    control_plane.shutdown().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_bootstrap_route_returns_typed_bootstrap_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, body) = get_json_response(
        config_handle.http_port(),
        "/jet/honeypot/bootstrap",
        HONEYPOT_WATCH_SCOPE_TOKEN,
    )
    .await?;
    let bootstrap: BootstrapResponse = serde_json::from_slice(&body).context("parse bootstrap response")?;

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(bootstrap.schema_version, honeypot_contracts::SCHEMA_VERSION);
    assert!(bootstrap.correlation_id.starts_with("honeypot-bootstrap-"));
    assert_eq!(bootstrap.replay_cursor, "0");
    assert!(bootstrap.sessions.is_empty());

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_bootstrap_route_uses_the_configured_path() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .frontend_bootstrap_path(Some("/custom/honeypot/bootstrap".to_owned()))
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (default_status, _) = get_json_response(
        config_handle.http_port(),
        "/jet/honeypot/bootstrap",
        HONEYPOT_WATCH_SCOPE_TOKEN,
    )
    .await?;
    let (custom_status, custom_body) = get_json_response(
        config_handle.http_port(),
        "/custom/honeypot/bootstrap",
        HONEYPOT_WATCH_SCOPE_TOKEN,
    )
    .await?;
    let bootstrap: BootstrapResponse = serde_json::from_slice(&custom_body).context("parse bootstrap response")?;

    assert!(default_status.contains("404"), "{default_status}");
    assert!(custom_status.contains("200"), "{custom_status}");
    assert_eq!(bootstrap.schema_version, honeypot_contracts::SCHEMA_VERSION);

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_events_route_is_disabled_by_default() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "GET",
        "/jet/honeypot/events?cursor=0",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_events_route_requires_cursor_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "GET",
        "/jet/honeypot/events",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("409"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_events_route_rejects_expired_cursor_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "GET",
        "/jet/honeypot/events?cursor=99",
        HONEYPOT_WATCH_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("409"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_token_route_is_disabled_by_default() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let session_id = Uuid::new_v4();
    let request = serde_json::json!({
        "schema_version": honeypot_contracts::SCHEMA_VERSION,
        "request_id": "req-disabled",
        "session_id": session_id.to_string(),
    });
    let path = format!("/jet/honeypot/session/{session_id}/stream-token");
    let request_bytes = serde_json::to_vec(&request).context("serialize disabled stream-token request")?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "POST",
        path.as_str(),
        HONEYPOT_WILDCARD_SCOPE_TOKEN,
        Some("application/json"),
        &request_bytes,
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_token_route_rejects_unknown_session_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let session_id = Uuid::new_v4();
    let request = serde_json::json!({
        "schema_version": honeypot_contracts::SCHEMA_VERSION,
        "request_id": "req-unknown-session",
        "session_id": session_id.to_string(),
    });
    let path = format!("/jet/honeypot/session/{session_id}/stream-token");
    let request_bytes = serde_json::to_vec(&request).context("serialize unknown-session stream-token request")?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "POST",
        path.as_str(),
        HONEYPOT_WILDCARD_SCOPE_TOKEN,
        Some("application/json"),
        &request_bytes,
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_token_route_rejects_mismatched_session_id() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let path_session_id = Uuid::new_v4();
    let request_session_id = Uuid::new_v4();
    let request = serde_json::json!({
        "schema_version": honeypot_contracts::SCHEMA_VERSION,
        "request_id": "req-mismatched-session",
        "session_id": request_session_id.to_string(),
    });
    let path = format!("/jet/honeypot/session/{path_session_id}/stream-token");
    let request_bytes = serde_json::to_vec(&request).context("serialize mismatched stream-token request")?;

    let (status_line, _body) = send_http_request(
        config_handle.http_port(),
        "POST",
        path.as_str(),
        HONEYPOT_WILDCARD_SCOPE_TOKEN,
        Some("application/json"),
        &request_bytes,
    )
    .await?;

    assert!(status_line.contains("400"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_route_is_disabled_by_default() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let session_id = Uuid::new_v4();
    let path = format!("/jet/honeypot/session/{session_id}/stream?stream_id=stream-1");
    let (status_line, _body) = send_http_request_with_retry(
        config_handle.http_port(),
        "GET",
        &path,
        HONEYPOT_WILDCARD_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_route_rejects_unknown_session_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let session_id = Uuid::new_v4();
    let path = format!("/jet/honeypot/session/{session_id}/stream?stream_id=stream-1");
    let (status_line, _body) = send_http_request_with_retry(
        config_handle.http_port(),
        "GET",
        &path,
        HONEYPOT_WILDCARD_SCOPE_TOKEN,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_terminate_route_accepts_honeypot_kill_scope_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/terminate");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_terminate_route_rejects_honeypot_kill_scope_when_disabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/terminate");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("403"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_terminate_route_respects_kill_switch() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .enable_session_kill(false)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/terminate");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("409"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_quarantine_route_is_hidden_when_honeypot_is_disabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/quarantine");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_quarantine_route_accepts_honeypot_kill_scope_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/quarantine");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_quarantine_route_requires_honeypot_kill_scope() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let watch_scope_token = honeypot_scope_token("gateway.honeypot.watch");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/quarantine");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &watch_scope_token, None, &[]).await?;

    assert!(status_line.contains("403"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_session_quarantine_route_respects_kill_switch() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .enable_session_kill(false)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let session_id = Uuid::new_v4();
    let path = format!("/jet/session/{session_id}/quarantine");
    let (status_line, _body) =
        send_http_request_with_retry(config_handle.http_port(), "POST", &path, &kill_scope_token, None, &[]).await?;

    assert!(status_line.contains("409"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_system_terminate_route_accepts_system_kill_scope_when_enabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let system_kill_scope_token = honeypot_scope_token("gateway.honeypot.system.kill");
    let (status_line, body) = send_http_request_with_retry(
        config_handle.http_port(),
        "POST",
        "/jet/session/system/terminate",
        &system_kill_scope_token,
        None,
        &[],
    )
    .await?;
    let payload: serde_json::Value = serde_json::from_slice(&body).context("parse system terminate response")?;

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(payload["system_kill_active"], true);

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_system_terminate_route_requires_system_kill_scope() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(HoneypotConfig::builder().enabled(true).build())
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let session_kill_scope_token = honeypot_scope_token("gateway.honeypot.session.kill");
    let (status_line, _body) = send_http_request_with_retry(
        config_handle.http_port(),
        "POST",
        "/jet/session/system/terminate",
        &session_kill_scope_token,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("403"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_system_terminate_route_respects_kill_switch() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .honeypot(
            HoneypotConfig::builder()
                .enabled(true)
                .enable_system_kill(false)
                .build(),
        )
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let system_kill_scope_token = honeypot_scope_token("gateway.honeypot.system.kill");
    let (status_line, _body) = send_http_request_with_retry(
        config_handle.http_port(),
        "POST",
        "/jet/session/system/terminate",
        &system_kill_scope_token,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("409"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_system_terminate_route_is_hidden_when_honeypot_is_disabled() -> anyhow::Result<()> {
    let config_handle = DgwConfig::builder()
        .disable_token_validation(true)
        .build()
        .init()
        .context("init config")?;

    let mut process = dgw_tokio_cmd()
        .env("DGATEWAY_CONFIG_PATH", config_handle.config_dir())
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("start gateway")?;

    wait_for_tcp_port(config_handle.http_port()).await?;

    let kill_scope_token = honeypot_scope_token("gateway.honeypot.system.kill");
    let (status_line, _body) = send_http_request_with_retry(
        config_handle.http_port(),
        "POST",
        "/jet/session/system/terminate",
        &kill_scope_token,
        None,
        &[],
    )
    .await?;

    assert!(status_line.contains("404"), "{status_line}");

    let _ = process.start_kill();
    let _ = process.wait().await;

    Ok(())
}

async fn get_json_response(http_port: u16, path: &str, token: &str) -> anyhow::Result<(String, Vec<u8>)> {
    send_http_request(http_port, "GET", path, token, None, &[]).await
}

async fn send_http_request(
    http_port: u16,
    method: &str,
    path: &str,
    token: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> anyhow::Result<(String, Vec<u8>)> {
    send_http_request_with_headers(http_port, method, path, token, content_type, &[], body).await
}

async fn send_http_request_with_headers(
    http_port: u16,
    method: &str,
    path: &str,
    token: &str,
    content_type: Option<&str>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> anyhow::Result<(String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut request = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: 127.0.0.1:{http_port}\r\n\
         Authorization: Bearer {token}\r\n\
         Connection: close\r\n"
    );

    for (name, value) in headers {
        request.push_str(format!("{name}: {value}\r\n").as_str());
    }

    if let Some(content_type) = content_type {
        request.push_str(format!("Content-Type: {content_type}\r\n").as_str());
    }

    request.push_str(format!("Content-Length: {}\r\n", body.len()).as_str());
    request.push_str("\r\n");

    let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", http_port))
        .await
        .with_context(|| format!("connect to gateway HTTP port {http_port}"))?;
    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("send {method} request to {path}"))?;
    if !body.is_empty() {
        stream
            .write_all(body)
            .await
            .with_context(|| format!("send {method} request body to {path}"))?;
    }

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .with_context(|| format!("read {method} response from {path}"))?;

    let body_offset = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("split response headers and body")?;
    let headers = &response[..body_offset];
    let body = response[(body_offset + 4)..].to_vec();
    let status_line = std::str::from_utf8(headers)
        .context("decode response headers")?
        .lines()
        .next()
        .context("extract response status line")?
        .to_owned();

    Ok((status_line, body))
}

async fn send_http_request_with_retry(
    http_port: u16,
    method: &str,
    path: &str,
    token: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut last_error = None;

    for attempt in 0..3 {
        match send_http_request(http_port, method, path, token, content_type, body).await {
            Ok(response) => return Ok(response),
            Err(error) if error.to_string().contains("split response headers and body") && attempt < 2 => {
                last_error = Some(error);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            Err(error) => return Err(error),
        }
    }

    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("request retry unexpectedly exhausted")))
}

fn honeypot_scope_token(scope: &str) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"scope","jti":"00000000-0000-0000-0000-000000000003","iat":1733669999,"exp":3331553599,"nbf":1733669999,"scope":"{scope}"}}"#
    ));

    format!("{header}.{payload}.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ")
}
