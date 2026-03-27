use serde::{Deserialize, Serialize};

use crate::impl_versioned;
use crate::stream::StreamTransport;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttackerProtocol {
    Rdp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StreamPolicy {
    #[serde(rename = "gateway-recording")]
    GatewayRecording,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    WaitingForBoot,
    Ready,
    Assigned,
    Releasing,
    Recycling,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseState {
    Released,
    Recycling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResetState {
    Resetting,
    ResetComplete,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecycleState {
    Recycling,
    Recycled,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PoolState {
    Ready,
    Degraded,
    Quarantined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceState {
    Ready,
    Degraded,
    Unsafe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureSourceKind {
    #[serde(rename = "gateway-recording")]
    GatewayRecording,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireVmRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub requested_pool: String,
    pub requested_ready_timeout_secs: u32,
    pub stream_policy: StreamPolicy,
    pub backend_credential_ref: String,
    pub attacker_protocol: AttackerProtocol,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcquireVmResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vm_lease_id: String,
    pub vm_name: String,
    pub guest_rdp_addr: String,
    pub guest_rdp_port: u16,
    pub lease_state: LeaseState,
    pub lease_expires_at: String,
    pub backend_credential_ref: String,
    pub attestation_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseVmRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub release_reason: String,
    pub terminal_outcome: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseVmResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vm_lease_id: String,
    pub release_state: ReleaseState,
    pub recycle_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetVmRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub reset_reason: String,
    pub force: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResetVmResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vm_lease_id: String,
    pub reset_state: ResetState,
    pub quarantine_required: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecycleVmRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub recycle_reason: String,
    pub quarantine_on_failure: bool,
    pub force_quarantine: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecycleVmResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vm_lease_id: String,
    pub recycle_state: RecycleState,
    pub pool_state: PoolState,
    pub quarantined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthRequest {
    pub schema_version: u32,
    pub request_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub service_state: ServiceState,
    pub kvm_available: bool,
    pub trusted_image_count: usize,
    pub active_lease_count: usize,
    pub quarantined_lease_count: usize,
    pub degraded_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEndpointRequest {
    pub schema_version: u32,
    pub request_id: String,
    pub session_id: String,
    pub preferred_transport: StreamTransport,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamEndpointResponse {
    pub schema_version: u32,
    pub correlation_id: String,
    pub vm_lease_id: String,
    pub capture_source_kind: CaptureSourceKind,
    pub capture_source_ref: String,
    pub source_ready: bool,
    pub expires_at: String,
}

impl_versioned!(
    AcquireVmRequest,
    AcquireVmResponse,
    ReleaseVmRequest,
    ReleaseVmResponse,
    ResetVmRequest,
    ResetVmResponse,
    RecycleVmRequest,
    RecycleVmResponse,
    HealthRequest,
    HealthResponse,
    StreamEndpointRequest,
    StreamEndpointResponse,
);
