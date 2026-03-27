use crate::Versioned;
use crate::auth::TokenScope;
use crate::control_plane::{
    AcquireVmRequest, AttackerProtocol, HealthResponse, RecycleState, RecycleVmRequest, ServiceState, StreamPolicy,
};
use crate::error::{ErrorCode, ErrorResponse};
use crate::events::{EventEnvelope, EventPayload, KillScope, SessionState, StreamState, TerminalOutcome};
use crate::frontend::{
    BootstrapResponse, BootstrapSession, CommandProposalRequest, CommandProposalResponse, CommandProposalState,
    CommandVoteChoice, CommandVoteRequest, CommandVoteResponse, CommandVoteState, KeyboardCaptureRequest,
    KeyboardCaptureResponse, KeyboardCaptureState,
};
use crate::stream::{StreamPreview, StreamTokenRequest, StreamTokenResponse, StreamTransport};

fn sample_event_envelope(payload: EventPayload) -> EventEnvelope {
    EventEnvelope {
        schema_version: crate::SCHEMA_VERSION,
        event_id: "event-1".to_owned(),
        correlation_id: "corr-1".to_owned(),
        emitted_at: "2026-03-26T00:00:00Z".to_owned(),
        session_id: Some("session-1".to_owned()),
        vm_lease_id: Some("lease-1".to_owned()),
        stream_id: Some("stream-1".to_owned()),
        global_cursor: "cursor-1".to_owned(),
        session_seq: 1,
        payload,
    }
}

fn sample_event_document(payload: serde_json::Value) -> serde_json::Value {
    let mut event = serde_json::json!({
        "schema_version": crate::SCHEMA_VERSION,
        "event_id": "event-1",
        "correlation_id": "corr-1",
        "emitted_at": "2026-03-26T00:00:00Z",
        "session_id": "session-1",
        "vm_lease_id": "lease-1",
        "stream_id": "stream-1",
        "global_cursor": "cursor-1",
        "session_seq": 1
    });
    let event_object = event.as_object_mut().expect("event envelope must be an object");
    let payload_object = payload.as_object().expect("payload must be an object");
    event_object.extend(payload_object.clone());
    event
}

#[test]
fn token_scopes_serialize_to_frozen_strings() {
    let watch = serde_json::to_string(&TokenScope::Watch).expect("serialize watch scope");
    let kill = serde_json::to_string(&TokenScope::SessionKill).expect("serialize kill scope");
    let propose = serde_json::to_string(&TokenScope::CommandPropose).expect("serialize propose scope");
    let approve = serde_json::to_string(&TokenScope::CommandApprove).expect("serialize approve scope");

    assert_eq!(watch, "\"gateway.honeypot.watch\"");
    assert_eq!(kill, "\"gateway.honeypot.session.kill\"");
    assert_eq!(propose, "\"gateway.honeypot.command.propose\"");
    assert_eq!(approve, "\"gateway.honeypot.command.approve\"");
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
fn command_proposal_request_rejects_unsupported_schema() {
    let request = CommandProposalRequest {
        schema_version: crate::SCHEMA_VERSION + 1,
        request_id: "proposal-req-1".to_owned(),
        command_text: "whoami".to_owned(),
    };

    let error = request
        .ensure_supported_schema()
        .expect_err("schema_version 2 should be rejected");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn command_proposal_response_round_trips_placeholder_state() {
    let response = CommandProposalResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-proposal-1".to_owned(),
        proposal_id: "proposal-1".to_owned(),
        recorded_at: "2026-03-26T00:00:30Z".to_owned(),
        session_id: "session-1".to_owned(),
        command_text: "cmd.exe /c whoami".to_owned(),
        proposal_state: CommandProposalState::Deferred,
        decision_reason: "disabled_by_policy".to_owned(),
        executed: false,
    };

    response
        .ensure_supported_schema()
        .expect("schema_version 1 should be supported");
    let json = serde_json::to_string(&response).expect("serialize command proposal response");
    let decoded: CommandProposalResponse = serde_json::from_str(&json).expect("deserialize command proposal response");

    assert_eq!(decoded, response);
}

#[test]
fn command_vote_request_rejects_unsupported_schema() {
    let request = CommandVoteRequest {
        schema_version: crate::SCHEMA_VERSION + 1,
        request_id: "vote-req-1".to_owned(),
        proposal_id: "proposal-1".to_owned(),
        vote: CommandVoteChoice::Approve,
    };

    let error = request
        .ensure_supported_schema()
        .expect_err("schema_version 2 should be rejected");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn command_vote_response_round_trips_placeholder_state() {
    let response = CommandVoteResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-vote-1".to_owned(),
        vote_id: "vote-1".to_owned(),
        recorded_at: "2026-03-26T00:00:45Z".to_owned(),
        session_id: "session-1".to_owned(),
        proposal_id: "proposal-1".to_owned(),
        vote: CommandVoteChoice::Approve,
        vote_state: CommandVoteState::Deferred,
        decision_reason: "disabled_by_policy".to_owned(),
        executed: false,
    };

    response
        .ensure_supported_schema()
        .expect("schema_version 1 should be supported");
    let json = serde_json::to_string(&response).expect("serialize command vote response");
    let decoded: CommandVoteResponse = serde_json::from_str(&json).expect("deserialize command vote response");

    assert_eq!(decoded, response);
}

#[test]
fn keyboard_capture_request_rejects_unsupported_schema() {
    let request = KeyboardCaptureRequest {
        schema_version: crate::SCHEMA_VERSION + 1,
        request_id: "keyboard-req-1".to_owned(),
        key_sequence: "abc".to_owned(),
    };

    let error = request
        .ensure_supported_schema()
        .expect_err("schema_version 2 should be rejected");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn keyboard_capture_response_round_trips_placeholder_state() {
    let response = KeyboardCaptureResponse {
        schema_version: crate::SCHEMA_VERSION,
        correlation_id: "corr-keyboard-1".to_owned(),
        capture_id: "keyboard-1".to_owned(),
        recorded_at: "2026-03-26T00:01:00Z".to_owned(),
        session_id: "session-1".to_owned(),
        requested_key_count: 3,
        capture_state: KeyboardCaptureState::DisabledByPolicy,
        decision_reason: "disabled_by_policy".to_owned(),
        executed: false,
    };

    response
        .ensure_supported_schema()
        .expect("schema_version 1 should be supported");
    let json = serde_json::to_string(&response).expect("serialize keyboard capture response");
    let decoded: KeyboardCaptureResponse = serde_json::from_str(&json).expect("deserialize keyboard capture response");

    assert_eq!(decoded, response);
}

#[test]
fn recycle_vm_request_round_trips_force_quarantine_flag() {
    let request = RecycleVmRequest {
        schema_version: crate::SCHEMA_VERSION,
        request_id: "req-recycle-1".to_owned(),
        session_id: "session-1".to_owned(),
        recycle_reason: "operator_quarantine".to_owned(),
        quarantine_on_failure: true,
        force_quarantine: true,
    };

    let json = serde_json::to_string(&request).expect("serialize recycle request");
    let decoded: RecycleVmRequest = serde_json::from_str(&json).expect("deserialize recycle request");

    assert_eq!(decoded, request);
}

#[test]
fn event_envelope_serializes_event_kind_and_ordering_fields() {
    let event = sample_event_envelope(EventPayload::SessionStarted {
        attacker_addr: "203.0.113.10:54422".to_owned(),
        listener_id: "listener-1".to_owned(),
        started_at: "2026-03-26T00:00:00Z".to_owned(),
        session_state: SessionState::Connected,
    });

    let json = serde_json::to_string(&event).expect("serialize event");
    let decoded: EventEnvelope = serde_json::from_str(&json).expect("deserialize event");

    assert!(json.contains("\"event_kind\":\"session.started\""), "{json}");
    assert_eq!(decoded.session_seq, 1);
    assert_eq!(decoded, event);
}

#[test]
fn event_payload_variants_round_trip_with_frozen_event_kinds() {
    let cases = vec![
        (
            "session.started",
            EventPayload::SessionStarted {
                attacker_addr: "203.0.113.10:54422".to_owned(),
                listener_id: "listener-1".to_owned(),
                started_at: "2026-03-26T00:00:00Z".to_owned(),
                session_state: SessionState::Connected,
            },
        ),
        (
            "session.assigned",
            EventPayload::SessionAssigned {
                assigned_at: "2026-03-26T00:00:05Z".to_owned(),
                vm_name: "vm-1".to_owned(),
                guest_rdp_addr: "10.0.0.15:3389".to_owned(),
                attestation_ref: "attestation-1".to_owned(),
            },
        ),
        (
            "session.stream.ready",
            EventPayload::SessionStreamReady {
                ready_at: "2026-03-26T00:00:10Z".to_owned(),
                transport: StreamTransport::Websocket,
                stream_endpoint: "/jet/honeypot/session/session-1/stream?stream_id=stream-1".to_owned(),
                token_expires_at: "2026-03-26T00:01:00Z".to_owned(),
                stream_state: StreamState::Ready,
            },
        ),
        (
            "session.ended",
            EventPayload::SessionEnded {
                ended_at: "2026-03-26T00:02:00Z".to_owned(),
                terminal_outcome: TerminalOutcome::Disconnected,
                disconnect_reason: "attacker_closed_socket".to_owned(),
                recycle_expected: true,
            },
        ),
        (
            "session.killed",
            EventPayload::SessionKilled {
                killed_at: "2026-03-26T00:02:10Z".to_owned(),
                kill_scope: KillScope::Session,
                killed_by_operator_id: "operator-1".to_owned(),
                kill_reason: "manual_review".to_owned(),
            },
        ),
        (
            "session.recycle.requested",
            EventPayload::SessionRecycleRequested {
                requested_at: "2026-03-26T00:02:15Z".to_owned(),
                recycle_reason: "disconnect".to_owned(),
                requested_by: "proxy".to_owned(),
            },
        ),
        (
            "host.recycled",
            EventPayload::HostRecycled {
                completed_at: "2026-03-26T00:02:30Z".to_owned(),
                recycle_state: RecycleState::Recycled,
                quarantined: false,
                quarantine_reason: None,
            },
        ),
        (
            "session.stream.failed",
            EventPayload::SessionStreamFailed {
                failed_at: "2026-03-26T00:00:12Z".to_owned(),
                failure_code: ErrorCode::StreamUnavailable,
                retryable: true,
                stream_state: StreamState::Failed,
            },
        ),
        (
            "proxy.status.degraded",
            EventPayload::ProxyStatusDegraded {
                degraded_at: "2026-03-26T00:03:00Z".to_owned(),
                reason_code: "control_plane_unavailable".to_owned(),
                affected_session_ids: vec!["session-1".to_owned(), "session-2".to_owned()],
            },
        ),
    ];

    for (event_kind, payload) in cases {
        let event = sample_event_envelope(payload);
        let json = serde_json::to_string(&event).expect("serialize event envelope");
        let decoded: EventEnvelope = serde_json::from_str(&json).expect("deserialize event envelope");

        assert!(json.contains(&format!("\"event_kind\":\"{event_kind}\"")), "{json}");
        assert_eq!(decoded, event);
    }
}

#[test]
fn event_envelope_rejects_unknown_event_kind() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.teleported"
    })))
    .expect_err("unknown event kinds must be rejected");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn event_envelope_rejects_missing_required_payload_fields() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.assigned",
        "assigned_at": "2026-03-26T00:00:05Z",
        "vm_name": "vm-1",
        "guest_rdp_addr": "10.0.0.15:3389"
    })))
    .expect_err("event payloads must reject missing required fields");

    assert!(error.to_string().contains("attestation_ref"), "{error}");
}

#[test]
fn event_envelope_rejects_invalid_session_state() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.started",
        "attacker_addr": "203.0.113.10:54422",
        "listener_id": "listener-1",
        "started_at": "2026-03-26T00:00:00Z",
        "session_state": "booting"
    })))
    .expect_err("session_state must reject unsupported enum values");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn event_envelope_rejects_invalid_stream_state() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.stream.ready",
        "ready_at": "2026-03-26T00:00:10Z",
        "transport": "websocket",
        "stream_endpoint": "/jet/honeypot/session/session-1/stream?stream_id=stream-1",
        "token_expires_at": "2026-03-26T00:01:00Z",
        "stream_state": "streaming"
    })))
    .expect_err("stream_state must reject unsupported enum values");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn event_envelope_rejects_invalid_terminal_outcome() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.ended",
        "ended_at": "2026-03-26T00:02:00Z",
        "terminal_outcome": "timed_out",
        "disconnect_reason": "socket_closed",
        "recycle_expected": true
    })))
    .expect_err("terminal_outcome must reject unsupported enum values");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn event_envelope_rejects_invalid_kill_scope() {
    let error = serde_json::from_value::<EventEnvelope>(sample_event_document(serde_json::json!({
        "event_kind": "session.killed",
        "killed_at": "2026-03-26T00:02:10Z",
        "kill_scope": "operator",
        "killed_by_operator_id": "operator-1",
        "kill_reason": "manual_review"
    })))
    .expect_err("kill_scope must reject unsupported enum values");

    assert!(error.to_string().contains("unknown variant"), "{error}");
}

#[test]
fn event_envelope_rejects_unsupported_schema() {
    let event = EventEnvelope {
        schema_version: crate::SCHEMA_VERSION + 1,
        ..sample_event_envelope(EventPayload::SessionStarted {
            attacker_addr: "203.0.113.10:54422".to_owned(),
            listener_id: "listener-1".to_owned(),
            started_at: "2026-03-26T00:00:00Z".to_owned(),
            session_state: SessionState::Connected,
        })
    };

    let error = event
        .ensure_supported_schema()
        .expect_err("event envelope should reject unsupported schema versions");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
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
                stream_endpoint: "/jet/honeypot/session/session-1/stream?stream_id=stream-1".to_owned(),
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
        stream_endpoint: "/jet/honeypot/session/session-1/stream?stream_id=stream-1".to_owned(),
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
fn bootstrap_response_rejects_unsupported_schema() {
    let response = BootstrapResponse {
        schema_version: crate::SCHEMA_VERSION + 1,
        correlation_id: "corr-bootstrap".to_owned(),
        generated_at: "2026-03-26T00:00:00Z".to_owned(),
        replay_cursor: "cursor-bootstrap".to_owned(),
        sessions: Vec::new(),
    };

    let error = response
        .ensure_supported_schema()
        .expect_err("bootstrap response should reject unsupported schema versions");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn stream_token_request_rejects_unsupported_schema() {
    let request = StreamTokenRequest {
        schema_version: crate::SCHEMA_VERSION + 1,
        request_id: "req-stream-1".to_owned(),
        session_id: "session-1".to_owned(),
    };

    let error = request
        .ensure_supported_schema()
        .expect_err("stream token request should reject unsupported schema versions");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}

#[test]
fn error_response_round_trips_and_validates_schema() {
    let error = ErrorResponse::new("corr-4", ErrorCode::HostUnavailable, "host is degraded", true);
    let json = serde_json::to_string(&error).expect("serialize error response");
    let decoded: ErrorResponse = serde_json::from_str(&json).expect("deserialize error response");

    assert_eq!(decoded, error);
}

#[test]
fn error_response_rejects_unsupported_schema() {
    let response = ErrorResponse {
        schema_version: crate::SCHEMA_VERSION + 1,
        ..ErrorResponse::new("corr-5", ErrorCode::InvalidRequest, "invalid", false)
    };

    let error = response
        .ensure_supported_schema()
        .expect_err("error response should reject unsupported schema versions");

    assert_eq!(error.found, crate::SCHEMA_VERSION + 1);
}
