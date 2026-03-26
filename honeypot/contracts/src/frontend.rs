use serde::{Deserialize, Serialize};

use crate::events::{SessionState, StreamState};
use crate::impl_versioned;
use crate::stream::StreamPreview;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub generated_at: String,
    pub replay_cursor: String,
    pub sessions: Vec<BootstrapSession>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapSession {
    pub session_id: String,
    pub vm_lease_id: Option<String>,
    pub state: SessionState,
    pub last_event_id: String,
    pub last_session_seq: u64,
    pub stream_state: StreamState,
    pub stream_preview: Option<StreamPreview>,
}

impl_versioned!(BootstrapResponse);
