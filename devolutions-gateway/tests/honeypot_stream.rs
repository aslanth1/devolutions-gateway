#![allow(unused_crate_dependencies)]
#![allow(clippy::unwrap_used)]

use std::net::SocketAddr;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::header::{AUTHORIZATION, LOCATION};
use axum::http::{Request, StatusCode};
use devolutions_gateway::session::{
    ConnectionModeDetails, HoneypotSessionMetadata, HoneypotStreamMetadata, SessionInfo, SessionManagerTask,
};
use devolutions_gateway::token::{
    ApplicationProtocol, JrecTokenClaims, Protocol, RecordingOperation, RecordingPolicy, SessionTtl,
};
use devolutions_gateway::{DgwState, MockHandles};
use devolutions_gateway_task::{ChildTask, Task};
use honeypot_contracts::events::{SessionState, StreamState};
use honeypot_contracts::stream::StreamTransport;
use picky::jose::jws::RawJws;
use time::OffsetDateTime;
use tower::ServiceExt as _;
use uuid::Uuid;

const CONFIG: &str = r#"{
    "ProvisionerPublicKeyData": {
        "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HhjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
    },
    "ProvisionerPrivateKeyData": {
        "Value": "mMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDi+6os6SXWlahu3qy7Vc71WySAIDB68QazqSQ2MlAHCQac8pguY0XUT9p/XIKhx9Wf86c9/17jH6VdXJnoswMnEXG75rF2A6rct3f3YnWIARt+/CXJEWcRcU4k3LKWqDdtjou+dYcv9dlzNV0wP3Fh+raw71uDfGNFbizuv0QRg4WOpVPdUXOcf2JYlW1xIQq6SZL/e4qg7qUaFpy+7QeGNdd2CrRHzO9HhdEn0Vyd/R/1imhz6LovzQ1WOtEJ5U4f4t3/Z8D1uhyl8tqtxWobdGNL6qA62nIJzSNZUUXjNoZDstQMWQQhgguQgJ4wyfaWXb2GZk3OwnNkn2zo2hyBAgMBAAECggEBAKCO0GOQUDmoB0rVrG2fVxPrcrhHDMQKNmljnb/Qexde5RSj7c3yXvS9v5sTvzvc9Vl9qrGKMH6MZhbSZ/RYnERIbKEzoBgQpA4YoX2WYfjgf6ilh7zg2H1YHqSokJNNTlfq2yLQU94zE6wQ9WgpmHRsOkqSJbOuizITqyj+lpGjl8dBAeOCD9HsnOGQiwsQD+joZ3yDRdFKSaBBtbklTYDyAmPvmp2G5A00UIo7KeOcNv59MPHnFBxMj0/z+QPKlqLQMsjL8vQX5DU2t/K4jdFHWGL8NZcz7KsCfh2Aa0vWEnroRzPPhKuBSBtaykbvfTcGrvRioesPq3EUdUqjQSECgYEA52UlMYeRYiTWsGq69lFWSlBjlRKhEMpg0Tp05z7J/A9X+ytB+6dZ37hk5asq84adRp7pnCEHV3SbczGq5ULFQBEqtFWPlD348zB8xxdBpAw3NAkVVDpAXBREhxXOnQm7MMmaXLH6d4Gv4kc6jKTC62w7cUUSlkIhlWSw5pSuVh0CgYEA+x5rJ4MQ6A/OKh058QY3ydRJw/sV54oxIFIIuJDw4I4eMsJ5Ht7MW5Pl1VQj+XuJRgMeqgZMQIIAcf5JNXqcesswVwdXy4awtw3TZV1Hi47Or7qHrFA/DtG4lNeDtyaWNuOtNnGw+LuqEmuu8BsWhB7yTHWJW7z+k6qO90CnArUCgYEA5ew66NwsObkhGmrzG432kCEQ0i+Qm358dWoAf0aErVERuyFgjw3a39H5b7yFETXRUTrWJa0r/lp/nBbeGLAgD2j/ZfEemc56cCrd0XXqY3c/4xSjfO3kxZnd/dxNUP06Y1/vYev3VIgonE7qfpW4mPUSm5pmvac4d5l1rahPEoECgYBUvAToRj+ULpEggNAmVjTI88sYSEcx492DzGqI7M961jm2Ywy/r+pBFHy/KS8iZd8CMtdMA+gC9Fr2HBnT49WdUaa0FxQ25vIGMrIcSAd2Pe/cOBLDwCgm9flUsAwP5wNU7ipqbp6Kr7hJkvBqsJk+Z7rWteptfC5i4XBwWe6A6QJ/Ddv+9vZe89uMdq+PThhELBHK+twZKawpKXYvzKlvPfMVisY+m9m37t7wK8PJexWOI9loVif6+ZIdWpXXntwrz94hYld/6+qK+sSt8EGmcJpAAI3zkp/ZMXhio0fy27sPaTlKlS6GNx/gPXRj6NHg/nu6lMmQ/EpLi1lyExPc8Q"
    },
    "Listeners": [
        {
            "InternalUrl": "tcp://*:8080",
            "ExternalUrl": "tcp://*:8080"
        },
        {
            "InternalUrl": "http://*:7171",
            "ExternalUrl": "https://*:7171"
        }
    ],
    "Honeypot": {
        "Enabled": true
    },
    "__debug__": {
        "disable_token_validation": true
    }
}"#;

const WILDCARD_BEARER: &str = "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImN0eSI6IlNDT1BFIn0.eyJqdGkiOiI5YTdkZWRhOC1jNmM2LTQ1YzAtODZlYi01MGJiMzI4YWFjMjMiLCJleHAiOjAsInNjb3BlIjoiKiJ9.dTazZemDS08Fy13Hx7wxDoOxQ2oNFaaEYMSFDQHCWiUdlYv4NMQh6N_GQok3wdiSJf384fvLKccYe1fipRepLlinUAqcEum68ngvGuUVP78xYb_vC3ZDqFi6nvd1BLp621XgzsCbOyBZHhLXHgzwVNTpnbt9laTTaHh8_rSYLaujBOpidWS6vKIZqOE66beqygSprPt3y0LYFTQWGYq21jJ73uW6htdWrmXbDUUjdvG7ymnKb-7Scs5y03jjSTr4QB1rH_3Z8DsfuuxFCIBd8V2yu192PrWooAdMKboLSjvmdFiD509lljoaNoGLBv9hmmQyiLQr-rsUllXBD6UpTQ";

struct HandlesGuard {
    shutdown_handle: devolutions_gateway_task::ShutdownHandle,
}

impl Drop for HandlesGuard {
    fn drop(&mut self) {
        self.shutdown_handle.signal();
    }
}

async fn make_router() -> anyhow::Result<(Router, DgwState, HandlesGuard)> {
    let (state, handles) = DgwState::mock(CONFIG)?;
    let MockHandles {
        session_manager_rx,
        shutdown_handle,
        ..
    } = handles;

    let manager = SessionManagerTask::new(state.sessions.clone(), session_manager_rx, state.recordings.clone());
    ChildTask::spawn({
        let shutdown_signal = state.shutdown_signal.clone();
        async move { manager.run(shutdown_signal).await }
    })
    .detach();

    let app = devolutions_gateway::make_http_service(state.clone())
        .layer(MockConnectInfo(SocketAddr::from(([0, 0, 0, 0], 3000))));

    Ok((app, state, HandlesGuard { shutdown_handle }))
}

fn stream_request(session_id: Uuid, stream_id: &str) -> Request<Body> {
    Request::builder()
        .method("GET")
        .uri(format!(
            "/jet/honeypot/session/{session_id}/stream?stream_id={stream_id}"
        ))
        .header(AUTHORIZATION, WILDCARD_BEARER)
        .body(Body::empty())
        .expect("build stream request")
}

fn test_session(session_id: Uuid, state: SessionState, stream_id: &str, stream_endpoint: &str) -> SessionInfo {
    let token_expires_at = (OffsetDateTime::now_utc() + time::Duration::minutes(5))
        .format(&time::format_description::well_known::Rfc3339)
        .expect("format token expiry");

    SessionInfo::builder()
        .id(session_id)
        .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
        .recording_policy(RecordingPolicy::None)
        .time_to_live(SessionTtl::Unlimited)
        .honeypot(HoneypotSessionMetadata {
            state,
            attacker_source: None,
            assignment: None,
            stream: Some(HoneypotStreamMetadata {
                state: StreamState::Ready,
                stream_id: Some(stream_id.to_owned()),
                transport: Some(StreamTransport::Websocket),
                stream_endpoint: Some(stream_endpoint.to_owned()),
                token_expires_at: Some(token_expires_at),
            }),
            terminal: None,
        })
        .details(ConnectionModeDetails::Rdv)
        .build()
}

async fn insert_session(state: &DgwState, session: SessionInfo) -> anyhow::Result<()> {
    state
        .sessions
        .new_session(session.clone(), Arc::new(tokio::sync::Notify::new()), None)
        .await?;
    let inserted = state.sessions.get_session_info(session.id).await?;
    assert!(inserted.is_some(), "session should be available to the router");
    Ok(())
}

#[tokio::test]
async fn honeypot_stream_redirect_stays_proxy_owned_and_signs_session_bound_jrec_token() -> anyhow::Result<()> {
    let (app, state, _guard) = make_router().await?;
    let session_id = Uuid::new_v4();
    let raw_backend_stream = "wss://backend.internal/qmp/capture/session-a";
    insert_session(
        &state,
        test_session(session_id, SessionState::Ready, "stream-a", raw_backend_stream),
    )
    .await?;

    let response = app.oneshot(stream_request(session_id, "stream-a")).await?;
    assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);

    let location = response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .expect("redirect location")
        .to_owned();
    assert!(location.starts_with("/jet/jrec/play?"), "{location}");
    assert!(!location.contains(raw_backend_stream), "{location}");
    assert!(!location.contains("backend.internal"), "{location}");

    let url = url::Url::parse(&format!("http://gateway.local{location}"))?;
    assert_eq!(url.path(), "/jet/jrec/play");
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "sessionId")
            .map(|(_, value)| value.into_owned()),
        Some(session_id.to_string())
    );
    assert_eq!(
        url.query_pairs()
            .find(|(key, _)| key == "isActive")
            .map(|(_, value)| value.into_owned()),
        Some("true".to_owned())
    );

    let token = url
        .query_pairs()
        .find(|(key, _)| key == "token")
        .map(|(_, value)| value.into_owned())
        .expect("jrec token query parameter");
    let raw_jws = RawJws::decode(&token).expect("decode jrec token");
    let claims: JrecTokenClaims = serde_json::from_slice(raw_jws.peek_payload()).expect("decode jrec token claims");
    let raw_claims: serde_json::Value = serde_json::from_slice(raw_jws.peek_payload()).expect("decode raw jrec claims");

    assert_eq!(claims.jet_aid, session_id);
    assert_eq!(claims.jet_rop, RecordingOperation::Pull);
    assert!(raw_claims["exp"].as_i64().expect("numeric exp claim") > OffsetDateTime::now_utc().unix_timestamp());

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_route_rejects_cross_session_stream_id_reuse() -> anyhow::Result<()> {
    let (app, state, _guard) = make_router().await?;
    let session_a = Uuid::new_v4();
    let session_b = Uuid::new_v4();
    insert_session(
        &state,
        test_session(
            session_a,
            SessionState::Ready,
            "stream-a",
            "wss://backend.internal/qmp/capture/session-a",
        ),
    )
    .await?;
    insert_session(
        &state,
        test_session(
            session_b,
            SessionState::Ready,
            "stream-b",
            "wss://backend.internal/qmp/capture/session-b",
        ),
    )
    .await?;

    let response = app.oneshot(stream_request(session_b, "stream-a")).await?;
    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}

#[tokio::test]
async fn honeypot_stream_route_rejects_terminal_sessions_even_with_stream_metadata() -> anyhow::Result<()> {
    let (app, state, _guard) = make_router().await?;
    let session_id = Uuid::new_v4();
    insert_session(
        &state,
        test_session(
            session_id,
            SessionState::Disconnected,
            "stream-terminal",
            "wss://backend.internal/qmp/capture/session-terminal",
        ),
    )
    .await?;

    let response = app.oneshot(stream_request(session_id, "stream-terminal")).await?;

    assert_eq!(response.status(), StatusCode::NOT_FOUND);

    Ok(())
}
