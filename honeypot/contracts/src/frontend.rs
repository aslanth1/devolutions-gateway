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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandProposalState {
    Deferred,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandProposalRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub command_text: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandProposalResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub proposal_id: String,
    pub recorded_at: String,
    pub session_id: String,
    pub command_text: String,
    pub proposal_state: CommandProposalState,
    pub decision_reason: String,
    pub executed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandVoteChoice {
    Approve,
    Reject,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandVoteState {
    Deferred,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandVoteRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub proposal_id: String,
    pub vote: CommandVoteChoice,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandVoteResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vote_id: String,
    pub recorded_at: String,
    pub session_id: String,
    pub proposal_id: String,
    pub vote: CommandVoteChoice,
    pub vote_state: CommandVoteState,
    pub decision_reason: String,
    pub executed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyboardCaptureState {
    DisabledByPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardCaptureRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub key_sequence: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyboardCaptureResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub capture_id: String,
    pub recorded_at: String,
    pub session_id: String,
    pub requested_key_count: u32,
    pub capture_state: KeyboardCaptureState,
    pub decision_reason: String,
    pub executed: bool,
}

impl_versioned!(
    BootstrapResponse,
    CommandProposalRequest,
    CommandProposalResponse,
    CommandVoteRequest,
    CommandVoteResponse,
    KeyboardCaptureRequest,
    KeyboardCaptureResponse
);
