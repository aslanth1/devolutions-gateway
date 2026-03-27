use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::extract::{Path, Query, State};
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::routing::{get, post};
use axum::{Json, response::Response};
use devolutions_gateway::credential::{
    AppCredential, AppCredentialMapping, CredentialBinding, CredentialProvisionRequest, Password,
};
use devolutions_gateway::session::{
    ConnectionModeDetails, SessionInfo, SessionKillReason, SessionManagerTask, remove_session_in_progress,
};
use devolutions_gateway::token::{ApplicationProtocol, Protocol, RecordingPolicy, SessionTtl, extract_jti};
use devolutions_gateway::{DgwState, MockHandles};
use devolutions_gateway_task::Task as _;
use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, AttackerProtocol, CaptureSourceKind, LeaseState, PoolState, RecycleState,
    RecycleVmRequest, RecycleVmResponse, ReleaseState, ReleaseVmRequest, ReleaseVmResponse, StreamEndpointRequest,
    StreamEndpointResponse,
};
use honeypot_contracts::events::{EventEnvelope, EventPayload, KillScope, SessionState, StreamState};
use honeypot_contracts::frontend::{BootstrapResponse, BootstrapSession};
use honeypot_contracts::stream::{StreamTokenRequest, StreamTokenResponse, StreamTransport};
use http_body_util::BodyExt as _;
use serde_json::Value;
use tower::ServiceExt as _;
use uuid::Uuid;

const CONTROL_PLANE_SERVICE_TOKEN: &str = "visibility-test-token";
const LEASE_ID: &str = "lease-visibility";
const VM_NAME: &str = "honeypot-visibility";
const GUEST_RDP_ADDR: &str = "10.0.0.25";
const GUEST_RDP_PORT: u16 = 3389;
const ATTESTATION_REF: &str = "attestation:visibility";
const CAPTURE_SOURCE_REF: &str = "recording://visibility/source";
const PROVISIONER_PUBLIC_KEY_DATA: &str = "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB";
const PROVISIONER_PRIVATE_KEY_DATA: &str = "mMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDi+6os6SXWlahu3qy7Vc71WySAIDB68QazqSQ2MlAHCQac8pguY0XUT9p/XIKhx9Wf86c9/17jH6VdXJnoswMnEXG75rF2A6rct3f3YnWIARt+/CXJEWcRcU4k3LKWqDdtjou+dYcv9dlzNV0wP3Fh+raw71uDfGNFbizuv0QRg4WOpVPdUXOcf2JYlW1xIQq6SZL/e4qg7qUaFpy+7QeGNdd2CrRHzO9HhdEn0Vyd/R/1imhz6LovzQ1WOtEJ5U4f4t3/Z8D1uhyl8tqtxWobdGNL6qA62nIJzSNZUUXjNoZDstQMWQQhgguQgJ4wyfaWXb2GZk3OwnNkn2zo2hyBAgMBAAECggEBAKCO0GOQUDmoB0rVrG2fVxPrcrhHDMQKNmljnb/Qexde5RSj7c3yXvS9v5sTvzvc9Vl9qrGKMH6MZhbSZ/RYnERIbKEzoBgQpA4YoX2WYfjgf6ilh7zg2H1YHqSokJNNTlfq2yLQU94zE6wQ9WgpmHRsOkqSJbOuizITqyj+lpGjl8dBAeOCD9HsnOGQiwsQD+joZ3yDRdFKSaBBtbklTYDyAmPvmp2G5A00UIo7KeOcNv59MPHnFBxMj0/z+QPKlqLQMsjL8vQX5DU2t/K4jdFHWGL8NZcz7KsCfh2Aa0vWEnroRzPPhKuBSBtaykbvfTcGrvRioesPq3EUdUqjQSECgYEA52UlMYeRYiTWsGq69lFWSlBjlRKhEMpg0Tp05z7J/A9X+ytB+6dZ37hk5asq84adRp7pnCEHV3SbczGq5ULFQBEqtFWPlD348zB8xxdBpAw3NAkVVDpAXBREhxXOnQm7MMmaXLH6d4Gv4kc6jKTC62w7cUUSlkIhlWSw5pSuVh0CgYEA+x5rJ4MQ6A/OKh058QY3ydRJw/sV54oxIFIIuJDw4I4eMsJ5Ht7MW5Pl1VQj+XuJRgMeqgZMQIIAcf5JNXqcesswVwdXy4awtw3TZV1Hi47Or7qHrFA/DtG4lNeDtyaWNuOtNnGw+LuqEmuu8BsWhB7yTHWJW7z+k6qO90CnArUCgYEA5ew66NwsObkhGmrzG432kCEQ0i+Qm358dWoAf0aErVERuyFgjw3a39H5b7yFETXRUTrWJa0r/lp/nBbeGLAgD2j/ZfEemc56cCrd0XXqY3c/4xSjfO3kxZnd/dxNUP06Y1/vYev3VIgonE7qfpW4mPUSm5pmvac4d5l1rahPEoECgYBUvAToRj+ULpEggNAmVjTI88sYSEcx492DzGqI7M961jm2Ywy/r+pBFHy/KS8iZd8CMtdMA+gC9Fr2HBnT49WdUaa0FxQ25vIGMrIcSAd2Pe/cOBLDwCgm9flUsAwP5wNU7ipqbp6Kr7hJkvBqsJk+Z7rWteptfC5i4XBwWe6A6QJ/Ddv+9vZe89uMdq+PThhELBHK+twZKawpKXYvzKlvPfMVisY+m9m37t7wK8PJexWOI9loVif6+ZIdWpXXntwrz94hYld/6+qK+sSt8EGmcJpAAI3zkp/ZMXhio0fy27sPaTlKlS6GNx/gPXRj6NHg/nu6lMmQ/EpLi1lyExPc8Q";
const CREDENTIAL_TEST_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAxMTEifQ.c2ln";
const WILDCARD_BEARER: &str = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJqdGkiOiI5YTdkZWRhOC1jNmM2LTQ1YzAtODZlYi01MGJiMzI4YWFjMjMiLCJleHAiOjAsInNjb3BlIjoiKiJ9.dTazZemDS08Fy13Hx7wxDoOxQ2oNFaaEYMSFDQHCWiUdlYv4NMQh6N_GQok3wdiSJf384fvLKccYe1fipRepLlinUAqcEum68ngvGuUVP78xYb_vC3ZDqFi6nvd1BLp621XgzsCbOyBZHhLXHgzwVNTpnbt9laTTaHh8_rSYLaujBOpidWS6vKIZqOE66beqygSprPt3y0LYFTQWGYq21jJ73uW6htdWrmXbDUUjdvG7ymnKb-7Scs5y03jjSTr4QB1rH_3Z8DsfuuxFCIBd8V2yu192PrWooAdMKboLSjvmdFiD509lljoaNoGLBv9hmmQyiLQr-rsUllXBD6UpTQ";

#[derive(Clone, Default)]
struct FakeControlPlaneObservedCalls {
    released: Arc<tokio::sync::Mutex<Vec<(String, ReleaseVmRequest)>>>,
    recycled: Arc<tokio::sync::Mutex<Vec<(String, RecycleVmRequest)>>>,
}

struct HandlesGuard {
    shutdown_handle: devolutions_gateway_task::ShutdownHandle,
}

impl Drop for HandlesGuard {
    fn drop(&mut self) {
        self.shutdown_handle.signal();
    }
}

struct FakeControlPlaneServer {
    endpoint: String,
    handle: tokio::task::JoinHandle<()>,
    calls: FakeControlPlaneObservedCalls,
}

impl FakeControlPlaneServer {
    async fn spawn() -> anyhow::Result<Self> {
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .context("bind fake control-plane listener")?;
        let addr = listener.local_addr().context("read fake control-plane address")?;
        let calls = FakeControlPlaneObservedCalls::default();
        let router = Router::new()
            .route("/api/v1/vm/acquire", post(fake_acquire_handler))
            .route("/api/v1/vm/{vm_lease_id}/release", post(fake_release_handler))
            .route("/api/v1/vm/{vm_lease_id}/recycle", post(fake_recycle_handler))
            .route("/api/v1/vm/{vm_lease_id}/stream", get(fake_stream_handler));
        let router = router.with_state(calls.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve fake control-plane visibility router");
        });

        Ok(Self {
            endpoint: format!("http://{addr}/"),
            handle,
            calls,
        })
    }

    async fn shutdown(self) {
        self.handle.abort();
        let _ = self.handle.await;
    }
}

async fn fake_acquire_handler(headers: HeaderMap, Json(request): Json<AcquireVmRequest>) -> Json<AcquireVmResponse> {
    assert_eq!(
        headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
        Some("Bearer visibility-test-token")
    );
    assert_eq!(request.requested_pool, "default");
    assert_eq!(
        request.stream_policy,
        honeypot_contracts::control_plane::StreamPolicy::GatewayRecording
    );
    assert_eq!(request.attacker_protocol, AttackerProtocol::Rdp);

    Json(AcquireVmResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: "corr-acquire-visibility".to_owned(),
        vm_lease_id: LEASE_ID.to_owned(),
        vm_name: VM_NAME.to_owned(),
        guest_rdp_addr: GUEST_RDP_ADDR.to_owned(),
        guest_rdp_port: GUEST_RDP_PORT,
        lease_state: LeaseState::Ready,
        lease_expires_at: "2026-03-26T12:10:00Z".to_owned(),
        backend_credential_ref: request.backend_credential_ref,
        attestation_ref: ATTESTATION_REF.to_owned(),
    })
}

async fn fake_stream_handler(
    Path(vm_lease_id): Path<String>,
    headers: HeaderMap,
    Query(request): Query<StreamEndpointRequest>,
) -> Json<StreamEndpointResponse> {
    assert_eq!(
        headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
        Some("Bearer visibility-test-token")
    );
    assert_eq!(vm_lease_id, LEASE_ID);
    assert_eq!(request.preferred_transport, StreamTransport::Websocket);

    Json(StreamEndpointResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: "corr-stream-visibility".to_owned(),
        vm_lease_id,
        capture_source_kind: CaptureSourceKind::GatewayRecording,
        capture_source_ref: CAPTURE_SOURCE_REF.to_owned(),
        source_ready: true,
        expires_at: "2026-03-26T12:05:00Z".to_owned(),
    })
}

async fn fake_release_handler(
    Path(vm_lease_id): Path<String>,
    State(calls): State<FakeControlPlaneObservedCalls>,
    headers: HeaderMap,
    Json(request): Json<ReleaseVmRequest>,
) -> Json<ReleaseVmResponse> {
    assert_eq!(
        headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
        Some("Bearer visibility-test-token")
    );
    assert_eq!(vm_lease_id, LEASE_ID);
    calls.released.lock().await.push((vm_lease_id.clone(), request.clone()));

    Json(ReleaseVmResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: "corr-release-visibility".to_owned(),
        vm_lease_id,
        release_state: ReleaseState::Released,
        recycle_required: true,
    })
}

async fn fake_recycle_handler(
    Path(vm_lease_id): Path<String>,
    State(calls): State<FakeControlPlaneObservedCalls>,
    headers: HeaderMap,
    Json(request): Json<RecycleVmRequest>,
) -> Json<RecycleVmResponse> {
    assert_eq!(
        headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
        Some("Bearer visibility-test-token")
    );
    assert_eq!(vm_lease_id, LEASE_ID);
    calls.recycled.lock().await.push((vm_lease_id.clone(), request.clone()));

    Json(RecycleVmResponse {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        correlation_id: "corr-recycle-visibility".to_owned(),
        vm_lease_id,
        recycle_state: RecycleState::Recycled,
        pool_state: PoolState::Ready,
        quarantined: false,
    })
}

async fn make_router(control_plane_endpoint: &str) -> anyhow::Result<(Router, DgwState, HandlesGuard)> {
    let config = format!(
        r#"{{
    "ProvisionerPublicKeyData": {{
        "Value": "{PROVISIONER_PUBLIC_KEY_DATA}"
    }},
    "ProvisionerPrivateKeyData": {{
        "Value": "{PROVISIONER_PRIVATE_KEY_DATA}"
    }},
    "Listeners": [
        {{
            "InternalUrl": "tcp://*:8080",
            "ExternalUrl": "tcp://*:8080"
        }},
        {{
            "InternalUrl": "http://*:7171",
            "ExternalUrl": "https://*:7171"
        }}
    ],
    "Honeypot": {{
        "Enabled": true,
        "ControlPlane": {{
            "Endpoint": "{control_plane_endpoint}",
            "ServiceBearerToken": "{CONTROL_PLANE_SERVICE_TOKEN}",
            "RequestTimeoutSecs": 5,
            "ConnectTimeoutSecs": 2
        }}
    }},
    "__debug__": {{
        "disable_token_validation": true
    }}
}}"#
    );

    let (state, handles) = DgwState::mock(&config)?;
    let MockHandles {
        session_manager_rx,
        shutdown_handle,
        ..
    } = handles;

    let manager = SessionManagerTask::new(state.sessions.clone(), session_manager_rx, state.recordings.clone());
    let shutdown_signal = state.shutdown_signal.clone();
    tokio::spawn(async move {
        let _ = manager.run(shutdown_signal).await;
    });

    let app = devolutions_gateway::make_http_service(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

    Ok((app, state, HandlesGuard { shutdown_handle }))
}

fn live_session(session_id: Uuid) -> SessionInfo {
    SessionInfo::builder()
        .id(session_id)
        .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
        .recording_policy(RecordingPolicy::None)
        .time_to_live(SessionTtl::Unlimited)
        .details(ConnectionModeDetails::Rdv)
        .build()
}

async fn start_live_session(state: &DgwState, session: &SessionInfo) -> anyhow::Result<()> {
    state
        .sessions
        .new_session(session.clone(), Arc::new(tokio::sync::Notify::new()), None)
        .await
        .context("register live honeypot session")?;
    state
        .honeypot
        .record_session_started(session)
        .await
        .context("record honeypot session start")?;
    state
        .sessions
        .sync_honeypot_metadata(session.id)
        .await
        .context("sync started honeypot metadata")?;

    Ok(())
}

async fn start_live_session_with_kill_cleanup(state: &DgwState, session: &SessionInfo) -> anyhow::Result<()> {
    let notify_kill = Arc::new(tokio::sync::Notify::new());
    let sessions = state.sessions.clone();
    let subscriber_tx = state.subscriber_tx.clone();
    let session_id = session.id;
    let notify_waiter = Arc::clone(&notify_kill);

    state
        .sessions
        .new_session(session.clone(), notify_kill, None)
        .await
        .context("register kill-cleanup honeypot session")?;
    state
        .honeypot
        .record_session_started(session)
        .await
        .context("record honeypot session start for kill-cleanup")?;
    state
        .sessions
        .sync_honeypot_metadata(session.id)
        .await
        .context("sync started honeypot metadata for kill-cleanup")?;

    tokio::spawn(async move {
        notify_waiter.notified().await;
        let _ = remove_session_in_progress(&sessions, &subscriber_tx, session_id).await;
    });

    Ok(())
}

fn get_request(uri: &str) -> anyhow::Result<Request<Body>> {
    Ok(Request::builder()
        .method("GET")
        .uri(uri)
        .header(AUTHORIZATION, WILDCARD_BEARER)
        .body(Body::empty())?)
}

fn post_json_request<T: serde::Serialize>(uri: &str, body: &T) -> anyhow::Result<Request<Body>> {
    Ok(Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, WILDCARD_BEARER)
        .header(CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(body)?))?)
}

fn post_request(uri: &str) -> anyhow::Result<Request<Body>> {
    Ok(Request::builder()
        .method("POST")
        .uri(uri)
        .header(AUTHORIZATION, WILDCARD_BEARER)
        .body(Body::empty())?)
}

async fn collect_response_body(response: Response) -> anyhow::Result<Vec<u8>> {
    Ok(response.into_body().collect().await?.to_bytes().to_vec())
}

async fn collect_sse_replay(response: Response, minimum_events: usize) -> anyhow::Result<String> {
    let mut body = response.into_body();
    let mut buffer = String::new();

    for _ in 0..16 {
        let frame = tokio::time::timeout(Duration::from_secs(1), body.frame())
            .await
            .context("wait for SSE replay frame")?;
        let Some(frame) = frame else {
            break;
        };
        let frame = frame.context("read SSE replay frame")?;
        let Ok(data) = frame.into_data() else {
            continue;
        };
        buffer.push_str(std::str::from_utf8(&data).context("decode SSE replay chunk")?);
        if buffer.matches("\ndata: ").count() + usize::from(buffer.starts_with("data: ")) >= minimum_events {
            break;
        }
    }

    Ok(buffer)
}

fn parse_sse_events(body: &str) -> anyhow::Result<Vec<EventEnvelope>> {
    body.split("\n\n")
        .filter_map(|chunk| {
            let data = chunk
                .lines()
                .filter_map(|line| line.strip_prefix("data: "))
                .collect::<Vec<_>>()
                .join("\n");
            if data.is_empty() { None } else { Some(data) }
        })
        .map(|data| serde_json::from_str::<EventEnvelope>(&data).context("parse SSE event envelope"))
        .collect()
}

fn find_bootstrap_session<'a>(
    bootstrap: &'a BootstrapResponse,
    session_id: &str,
) -> anyhow::Result<&'a BootstrapSession> {
    bootstrap
        .sessions
        .iter()
        .find(|session| session.session_id == session_id)
        .with_context(|| format!("find bootstrap session {session_id}"))
}

fn credential_mapping() -> AppCredentialMapping {
    AppCredentialMapping {
        proxy: AppCredential::UsernamePassword {
            username: "attacker".to_owned(),
            password: Password::from("proxy-password"),
        },
        target: AppCredential::UsernamePassword {
            username: "Administrator".to_owned(),
            password: Password::from("target-password"),
        },
    }
}

#[tokio::test]
async fn honeypot_session_visibility_and_replay_are_coherent() -> anyhow::Result<()> {
    let control_plane = FakeControlPlaneServer::spawn().await?;
    let (app, state, _guard) = make_router(&control_plane.endpoint).await?;
    let session_id = Uuid::new_v4();
    let session = live_session(session_id);

    start_live_session(&state, &session).await?;

    let stream_token_request = StreamTokenRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("visibility-stream-token-{session_id}"),
        session_id: session_id.to_string(),
    };
    let response = app
        .clone()
        .oneshot(post_json_request(
            &format!("/jet/honeypot/session/{session_id}/stream-token"),
            &stream_token_request,
        )?)
        .await
        .context("request stream token through honeypot proxy route")?;
    assert_eq!(response.status(), StatusCode::OK);
    let stream_token: StreamTokenResponse =
        serde_json::from_slice(&collect_response_body(response).await?).context("decode stream token response")?;

    let response = app
        .clone()
        .oneshot(get_request("/jet/sessions")?)
        .await
        .context("request running sessions list")?;
    assert_eq!(response.status(), StatusCode::OK);
    let sessions: Value =
        serde_json::from_slice(&collect_response_body(response).await?).context("decode running sessions response")?;
    let session_entry = sessions
        .as_array()
        .and_then(|entries| {
            entries
                .iter()
                .find(|entry| entry["association_id"].as_str() == Some(stream_token.session_id.as_str()))
        })
        .context("find running session in /jet/sessions")?;

    assert_eq!(session_entry["honeypot"]["state"], "ready");
    assert_eq!(session_entry["honeypot"]["assignment"]["vm_lease_id"], LEASE_ID);
    assert_eq!(session_entry["honeypot"]["assignment"]["vm_name"], VM_NAME);
    assert_eq!(session_entry["honeypot"]["stream"]["state"], "ready");
    assert_eq!(
        session_entry["honeypot"]["stream"]["stream_id"],
        Value::String(stream_token.stream_id.clone())
    );
    assert_eq!(
        session_entry["honeypot"]["stream"]["stream_endpoint"],
        Value::String(stream_token.stream_endpoint.clone())
    );

    let response = app
        .clone()
        .oneshot(get_request("/jet/honeypot/bootstrap")?)
        .await
        .context("request honeypot bootstrap")?;
    assert_eq!(response.status(), StatusCode::OK);
    let bootstrap: BootstrapResponse =
        serde_json::from_slice(&collect_response_body(response).await?).context("decode honeypot bootstrap")?;
    let bootstrap_session = find_bootstrap_session(&bootstrap, &stream_token.session_id)?;
    let preview = bootstrap_session
        .stream_preview
        .as_ref()
        .context("stream preview should be present in bootstrap")?;

    assert_eq!(bootstrap_session.state, SessionState::Ready);
    assert_eq!(bootstrap_session.stream_state, StreamState::Ready);
    assert_eq!(bootstrap_session.vm_lease_id.as_deref(), Some(LEASE_ID));
    assert_eq!(preview.stream_id, stream_token.stream_id);
    assert_eq!(preview.transport, stream_token.transport);
    assert_eq!(preview.stream_endpoint, stream_token.stream_endpoint);
    assert_eq!(preview.token_expires_at, stream_token.expires_at);

    let response = app
        .oneshot(get_request("/jet/honeypot/events?cursor=0")?)
        .await
        .context("request honeypot event replay")?;
    assert_eq!(response.status(), StatusCode::OK);
    let sse_body = collect_sse_replay(response, 3).await?;
    let replay = parse_sse_events(&sse_body)?;

    assert_eq!(replay.len(), 3, "{sse_body}");
    assert_eq!(
        replay
            .iter()
            .map(|event| event.global_cursor.as_str())
            .collect::<Vec<_>>(),
        vec!["1", "2", "3"]
    );
    assert_eq!(
        bootstrap.replay_cursor,
        replay.last().expect("replay event").global_cursor
    );
    assert!(
        replay
            .iter()
            .all(|event| event.session_id.as_deref() == Some(stream_token.session_id.as_str()))
    );

    match &replay[0].payload {
        EventPayload::SessionStarted { session_state, .. } => {
            assert_eq!(*session_state, SessionState::Connected);
        }
        payload => panic!("expected session.started payload, got {payload:?}"),
    }

    match &replay[1].payload {
        EventPayload::SessionAssigned {
            vm_name,
            guest_rdp_addr,
            attestation_ref,
            ..
        } => {
            assert_eq!(replay[1].vm_lease_id.as_deref(), Some(LEASE_ID));
            assert_eq!(vm_name, VM_NAME);
            assert_eq!(guest_rdp_addr, &format!("{GUEST_RDP_ADDR}:{GUEST_RDP_PORT}"));
            assert_eq!(attestation_ref, ATTESTATION_REF);
        }
        payload => panic!("expected session.assigned payload, got {payload:?}"),
    }

    match &replay[2].payload {
        EventPayload::SessionStreamReady {
            transport,
            stream_endpoint,
            stream_state,
            ..
        } => {
            assert_eq!(replay[2].vm_lease_id.as_deref(), Some(LEASE_ID));
            assert_eq!(replay[2].stream_id.as_deref(), Some(stream_token.stream_id.as_str()));
            assert_eq!(*transport, stream_token.transport);
            assert_eq!(stream_endpoint, &stream_token.stream_endpoint);
            assert_eq!(*stream_state, StreamState::Ready);
        }
        payload => panic!("expected session.stream.ready payload, got {payload:?}"),
    }

    control_plane.shutdown().await;

    Ok(())
}

#[tokio::test]
async fn honeypot_terminate_recycles_vm_and_cleans_up_live_state() -> anyhow::Result<()> {
    let control_plane = FakeControlPlaneServer::spawn().await?;
    let (app, state, _guard) = make_router(&control_plane.endpoint).await?;
    let session_id = Uuid::new_v4();
    let session = live_session(session_id);
    let credential_token_id = extract_jti(CREDENTIAL_TEST_TOKEN).context("extract credential token id")?;

    start_live_session_with_kill_cleanup(&state, &session).await?;

    let response = app
        .clone()
        .oneshot(get_request("/jet/sessions")?)
        .await
        .context("request running sessions before terminate")?;
    assert_eq!(response.status(), StatusCode::OK);
    let sessions_before: Value = serde_json::from_slice(&collect_response_body(response).await?)
        .context("decode running sessions before terminate")?;
    assert!(sessions_before.as_array().is_some_and(|entries| {
        entries
            .iter()
            .any(|entry| entry["association_id"].as_str() == Some(session_id.to_string().as_str()))
    }));

    let response = app
        .clone()
        .oneshot(get_request("/jet/honeypot/bootstrap")?)
        .await
        .context("request bootstrap before terminate")?;
    assert_eq!(response.status(), StatusCode::OK);
    let bootstrap_before: BootstrapResponse =
        serde_json::from_slice(&collect_response_body(response).await?).context("decode bootstrap before terminate")?;
    let bootstrap_session = find_bootstrap_session(&bootstrap_before, &session_id.to_string())?;
    assert_eq!(bootstrap_session.state, SessionState::Assigned);
    assert_eq!(bootstrap_session.vm_lease_id.as_deref(), Some(LEASE_ID));

    state
        .credential_store
        .provision(CredentialProvisionRequest {
            token: CREDENTIAL_TEST_TOKEN.to_owned(),
            mapping: Some(credential_mapping()),
            time_to_live: time::Duration::minutes(15),
            binding: Some(CredentialBinding {
                session_id: Some(session_id),
                vm_lease_id: Some(LEASE_ID.to_owned()),
                credential_mapping_id: Some(format!("honeypot-credential-map-{LEASE_ID}")),
                backend_credential_ref: Some(format!("honeypot-backend-credential:{session_id}")),
            }),
        })
        .context("provision bound credential mapping for cleanup test")?;
    assert!(
        state.credential_store.get(credential_token_id).is_some(),
        "credential entry should exist before terminate"
    );

    let response = app
        .clone()
        .oneshot(post_request(&format!("/jet/session/{session_id}/terminate"))?)
        .await
        .context("request terminate route")?;
    assert_eq!(response.status(), StatusCode::OK);

    let mut session_removed = false;
    for _ in 0..20 {
        let response = app
            .clone()
            .oneshot(get_request("/jet/sessions")?)
            .await
            .context("request running sessions after terminate")?;
        assert_eq!(response.status(), StatusCode::OK);
        let sessions_after: Value = serde_json::from_slice(&collect_response_body(response).await?)
            .context("decode running sessions after terminate")?;

        if sessions_after.as_array().is_some_and(|entries| {
            entries
                .iter()
                .all(|entry| entry["association_id"].as_str() != Some(session_id.to_string().as_str()))
        }) {
            session_removed = true;
            break;
        }

        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(session_removed, "session should be removed from /jet/sessions");
    assert!(
        state.credential_store.get(credential_token_id).is_none(),
        "credential entry should be revoked after terminate"
    );

    let response = app
        .clone()
        .oneshot(get_request("/jet/honeypot/bootstrap")?)
        .await
        .context("request bootstrap after terminate")?;
    assert_eq!(response.status(), StatusCode::OK);
    let bootstrap_after: BootstrapResponse =
        serde_json::from_slice(&collect_response_body(response).await?).context("decode bootstrap after terminate")?;
    assert!(
        bootstrap_after
            .sessions
            .iter()
            .all(|entry| entry.session_id != session_id.to_string()),
        "terminated session should not remain in bootstrap"
    );

    let (released, recycled) = {
        let mut observed = None;
        for _ in 0..20 {
            let released = control_plane.calls.released.lock().await.clone();
            let recycled = control_plane.calls.recycled.lock().await.clone();
            if released.len() == 1 && recycled.len() == 1 {
                observed = Some((released, recycled));
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        observed.context("wait for release and recycle calls")?
    };
    assert_eq!(released.len(), 1);
    assert_eq!(recycled.len(), 1);
    assert_eq!(released[0].0, LEASE_ID);
    assert_eq!(released[0].1.session_id, session_id.to_string());
    assert_eq!(released[0].1.release_reason, "session_killed");
    assert_eq!(released[0].1.terminal_outcome, "killed");
    assert_eq!(recycled[0].0, LEASE_ID);
    assert_eq!(recycled[0].1.session_id, session_id.to_string());
    assert_eq!(recycled[0].1.recycle_reason, "session_killed");
    assert!(recycled[0].1.quarantine_on_failure);
    assert!(!recycled[0].1.force_quarantine);

    let response = app
        .oneshot(get_request("/jet/honeypot/events?cursor=0")?)
        .await
        .context("request replay after terminate")?;
    assert_eq!(response.status(), StatusCode::OK);
    let sse_body = collect_sse_replay(response, 5).await?;
    let replay = parse_sse_events(&sse_body)?;

    assert_eq!(replay.len(), 5, "{sse_body}");
    assert!(matches!(replay[0].payload, EventPayload::SessionStarted { .. }));
    assert!(matches!(replay[1].payload, EventPayload::SessionAssigned { .. }));
    match &replay[2].payload {
        EventPayload::SessionKilled {
            kill_scope,
            kill_reason,
            ..
        } => {
            assert_eq!(*kill_scope, KillScope::Session);
            assert_eq!(kill_reason, SessionKillReason::OperatorRequested.as_reason_code());
        }
        payload => panic!("expected session.killed payload, got {payload:?}"),
    }
    match &replay[3].payload {
        EventPayload::SessionRecycleRequested {
            recycle_reason,
            requested_by,
            ..
        } => {
            assert_eq!(recycle_reason, "session_killed");
            assert_eq!(requested_by, "proxy");
        }
        payload => panic!("expected session.recycle.requested payload, got {payload:?}"),
    }
    match &replay[4].payload {
        EventPayload::HostRecycled {
            recycle_state,
            quarantined,
            ..
        } => {
            assert_eq!(*recycle_state, RecycleState::Recycled);
            assert!(!quarantined);
        }
        payload => panic!("expected host.recycled payload, got {payload:?}"),
    }

    control_plane.shutdown().await;

    Ok(())
}
