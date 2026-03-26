use crate::Versioned;
use crate::auth::TokenScope;
use crate::control_plane::{AcquireVmRequest, AttackerProtocol, HealthResponse, ServiceState, StreamPolicy};
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::{EventEnvelope, EventPayload, SessionState, StreamState};
use crate::frontend::{BootstrapResponse, BootstrapSession};
use crate::stream::{StreamPreview, StreamTokenResponse, StreamTransport};

#[test]
fn token_scopes_serialize_to_frozen_strings() {
    let watch = serde_json::to_string(&TokenScope::Watch).expect("serialize watch scope");
    let kill = serde_json::to_string(&TokenScope::SessionKill).expect("serialize kill scope");

    assert_eq!(watch, "\"gateway.honeypot.watch\"");
    assert_eq!(kill, "\"gateway.honeypot.session.kill\"");
}

#[test]
fn health_response_round_trips_and_validates_schema() {
    let response = HealthResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-1".to_owned(),
        service_state: ServiceState::Ready,
        kvm_available: true,
        trusted_image_count: 1,
        active_lease_count: 0,
        quarantined_lease_count: 0,
        degraded_reasons: Vec::new(),
    };

    response
        .ensure_supported_schema()
        .expect("schema_version 1 should be supported");
    let json = serde_json::to_string(&response).expect("serialize health response");
    let decoded: HealthResponse = serde_json::from_str(&json).expect("deserialize health response");

    assert_eq!(decoded, response);
}

#[test]
fn acquire_vm_request_rejects_unsupported_schema() {
    let request = AcquireVmRequest {
        schema_version: crate::SCHEMA_VERSION + 1,
        request_id: "req-1".to_owned(),
        session_id: "session-1".to_owned(),
        requested_pool: "default".to_owned(),
        requested_ready_timeout_secs: 30,
        stream_policy: StreamPolicy::GatewayRecording,
        backend_credential_ref: "cred-ref".to_owned(),
        attacker_protocol: AttackerProtocol::Rdp,
    };

    let error = request
        .ensure_supported_schema()
        .expect_err("schema_version 2 should be rejected");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn event_envelope_serializes_event_kind_and_ordering_fields() {
    let event = EventEnvelope {
        schema_version: crate::SCHEMA_VERSION,
        event_id: "event-1".to_owned(),
        correlation_id: "corr-1".to_owned(),
        emitted_at: "2026-03-26T00:00:00Z".to_owned(),
        session_id: Some("session-1".to_owned()),
        vm_lease_id: Some("lease-1".to_owned()),
        stream_id: None,
        global_cursor: "cursor-1".to_owned(),
        session_seq: 1,
        payload: EventPayload::SessionStarted {
            attacker_addr: "203.0.113.10:54422".to_owned(),
            listener_id: "listener-1".to_owned(),
            started_at: "2026-03-26T00:00:00Z".to_owned(),
            session_state: SessionState::Connected,
        },
    };

    let json = serde_json::to_string(&event).expect("serialize event");
    let decoded: EventEnvelope = serde_json::from_str(&json).expect("deserialize event");

    assert!(json.contains("\"event_kind\":\"session.started\""), "{json}");
    assert_eq!(decoded.session_seq, 1);
    assert_eq!(decoded, event);
}

#[test]
fn bootstrap_and_stream_token_round_trip() {
    let bootstrap = BootstrapResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-2".to_owned(),
        generated_at: "2026-03-26T00:00:00Z".to_owned(),
        replay_cursor: "cursor-2".to_owned(),
        sessions: vec![BootstrapSession {
            session_id: "session-1".to_owned(),
            vm_lease_id: Some("lease-1".to_owned()),
            state: SessionState::Assigned,
            last_event_id: "event-2".to_owned(),
            last_session_seq: 2,
            stream_state: StreamState::Ready,
            stream_preview: Some(StreamPreview {
                stream_id: "stream-1".to_owned(),
                transport: StreamTransport::Websocket,
                stream_endpoint: "/jet/honeypot/session/session-1/stream".to_owned(),
                token_expires_at: "2026-03-26T00:01:00Z".to_owned(),
            }),
        }],
    };

    let token = StreamTokenResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-3".to_owned(),
        session_id: "session-1".to_owned(),
        vm_lease_id: "lease-1".to_owned(),
        stream_id: "stream-1".to_owned(),
        stream_endpoint: "/jet/honeypot/session/session-1/stream".to_owned(),
        transport: StreamTransport::Websocket,
        issued_at: "2026-03-26T00:00:00Z".to_owned(),
        expires_at: "2026-03-26T00:01:00Z".to_owned(),
    };

    let bootstrap_json = serde_json::to_string(&bootstrap).expect("serialize bootstrap");
    let token_json = serde_json::to_string(&token).expect("serialize stream token");

    let decoded_bootstrap: BootstrapResponse = serde_json::from_str(&bootstrap_json).expect("deserialize bootstrap");
    let decoded_token: StreamTokenResponse = serde_json::from_str(&token_json).expect("deserialize stream token");

    assert_eq!(decoded_bootstrap, bootstrap);
    assert_eq!(decoded_token, token);
}

#[test]
fn error_response_round_trips() {
    let error = ErrorResponse::new("corr-4", ErrorCode::HostUnavailable, "host is degraded", true);
    let json = serde_json::to_string(&error).expect("serialize error response");
    let decoded: ErrorResponse = serde_json::from_str(&json).expect("deserialize error response");

    assert_eq!(decoded, error);
}
