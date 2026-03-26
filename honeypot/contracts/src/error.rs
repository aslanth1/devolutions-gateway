use serde::{Deserialize, Serialize};

use crate::impl_versioned;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    AuthFailed,
    Unauthorized,
    Forbidden,
    InvalidRequest,
    NoCapacity,
    ImageUntrusted,
    HostUnavailable,
    BootTimeout,
    LeaseConflict,
    LeaseNotFound,
    LeaseStateConflict,
    ResetFailed,
    RecycleFailed,
    Quarantined,
    StreamUnavailable,
    CursorExpired,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub error_code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl ErrorResponse {
    pub fn new(
        correlation_id: impl Into<String>,
        error_code: ErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Self {
        Self {
            schema_version: crate::SCHEMA_VERSION,
            correlation_id: correlation_id.into(),
            error_code,
            message: message.into(),
            retryable,
        }
    }
}

impl_versioned!(ErrorResponse);
