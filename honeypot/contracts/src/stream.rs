use serde::{Deserialize, Serialize};

use crate::impl_versioned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTransport {
    Sse,
    Websocket,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPreview {
    pub stream_id: String,
    pub transport: StreamTransport,
    pub stream_endpoint: String,
    pub token_expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamTokenRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamTokenResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub session_id: String,
    pub vm_lease_id: String,
    pub stream_id: String,
    pub stream_endpoint: String,
    pub transport: StreamTransport,
    pub issued_at: String,
    pub expires_at: String,
}

impl_versioned!(StreamTokenRequest, StreamTokenResponse);
