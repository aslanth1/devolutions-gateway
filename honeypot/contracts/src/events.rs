use serde::{Deserialize, Serialize};

use crate::control_plane::RecycleState;
use crate::error::ErrorCode;
use crate::impl_versioned;
use crate::stream::StreamTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    WaitingForLease,
    Assigned,
    StreamReady,
    Ended,
    Killed,
    RecycleRequested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamState {
    Pending,
    Ready,
    Failed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Completed,
    Disconnected,
    NoLease,
    BootTimeout,
    Killed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillScope {
    Session,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EventEnvelope {
    pub schema_version: u32,
    pub event_id: String,
    pub correlation_id: String,
    pub emitted_at: String,
    pub session_id: Option<String>,
    pub vm_lease_id: Option<String>,
    pub stream_id: Option<String>,
    pub global_cursor: String,
    pub session_seq: u64,
    #[serde(flatten)]
    pub payload: EventPayload,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event_kind")]
pub enum EventPayload {
    #[serde(rename = "session.started")]
    SessionStarted {
        attacker_addr: String,
        listener_id: String,
        started_at: String,
        session_state: SessionState,
    },
    #[serde(rename = "session.assigned")]
    SessionAssigned {
        assigned_at: String,
        vm_name: String,
        guest_rdp_addr: String,
        attestation_ref: String,
    },
    #[serde(rename = "session.stream.ready")]
    SessionStreamReady {
        ready_at: String,
        transport: StreamTransport,
        stream_endpoint: String,
        token_expires_at: String,
        stream_state: StreamState,
    },
    #[serde(rename = "session.ended")]
    SessionEnded {
        ended_at: String,
        terminal_outcome: TerminalOutcome,
        disconnect_reason: String,
        recycle_expected: bool,
    },
    #[serde(rename = "session.killed")]
    SessionKilled {
        killed_at: String,
        kill_scope: KillScope,
        killed_by_operator_id: String,
        kill_reason: String,
    },
    #[serde(rename = "session.recycle.requested")]
    SessionRecycleRequested {
        requested_at: String,
        recycle_reason: String,
        requested_by: String,
    },
    #[serde(rename = "host.recycled")]
    HostRecycled {
        completed_at: String,
        recycle_state: RecycleState,
        quarantined: bool,
        quarantine_reason: Option<String>,
    },
    #[serde(rename = "session.stream.failed")]
    SessionStreamFailed {
        failed_at: String,
        failure_code: ErrorCode,
        retryable: bool,
        stream_state: StreamState,
    },
    #[serde(rename = "proxy.status.degraded")]
    ProxyStatusDegraded {
        degraded_at: String,
        reason_code: String,
        affected_session_ids: Vec<String>,
    },
}

impl_versioned!(EventEnvelope);
