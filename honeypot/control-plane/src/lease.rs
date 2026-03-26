use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use honeypot_contracts::Versioned as _;
use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, CaptureSourceKind, LeaseState, PoolState, RecycleState, RecycleVmRequest,
    RecycleVmResponse, ReleaseState, ReleaseVmRequest, ReleaseVmResponse, ResetState, ResetVmRequest, ResetVmResponse,
    StreamEndpointRequest, StreamEndpointResponse,
};
use honeypot_contracts::error::ErrorCode;
use serde::{Deserialize, Serialize};

use crate::config::PathConfig;

const DEFAULT_GUEST_RDP_ADDR: &str = "127.0.0.1";
const DEFAULT_GUEST_RDP_PORT: u16 = 3389;
const DEFAULT_STREAM_TTL_SECS: u64 = 60;

#[derive(Debug)]
pub(crate) struct LeaseRegistry {
    leases: HashMap<String, LeaseSnapshot>,
    next_lease_sequence: u64,
}

impl LeaseRegistry {
    pub(crate) fn load(paths: &PathConfig) -> anyhow::Result<Self> {
        let mut leases = HashMap::new();
        let mut next_lease_sequence = 1;

        for snapshot_path in json_files(&paths.lease_store)? {
            let snapshot = read_snapshot(&snapshot_path)?;
            next_lease_sequence = next_lease_sequence.max(parse_lease_sequence(&snapshot.vm_lease_id) + 1);
            leases.insert(snapshot.vm_lease_id.clone(), snapshot);
        }

        Ok(Self {
            leases,
            next_lease_sequence,
        })
    }

    pub(crate) fn acquire(
        &mut self,
        paths: &PathConfig,
        request: &AcquireVmRequest,
    ) -> Result<AcquireVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        if self.leases.values().any(|lease| lease.session_id == request.session_id) {
            return Err(LeaseError::lease_conflict(format!(
                "session {} already owns a lease",
                request.session_id
            )));
        }

        let trusted_images = trusted_images(paths).map_err(LeaseError::host_unavailable)?;
        if trusted_images.is_empty() {
            return Err(LeaseError::no_capacity("no trusted image manifests are available"));
        }

        let busy_vm_names = self
            .leases
            .values()
            .map(|lease| lease.vm_name.as_str())
            .collect::<HashSet<_>>();

        let trusted_image = trusted_images
            .into_iter()
            .find(|image| !busy_vm_names.contains(image.vm_name.as_str()))
            .ok_or_else(|| LeaseError::no_capacity("all trusted images are currently assigned"))?;

        let vm_lease_id = self.next_lease_id();
        let lease_expires_at = now_plus_secs(u64::from(request.requested_ready_timeout_secs).max(60));

        let snapshot = LeaseSnapshot {
            vm_lease_id: vm_lease_id.clone(),
            vm_name: trusted_image.vm_name.clone(),
            session_id: request.session_id.clone(),
            guest_rdp_addr: DEFAULT_GUEST_RDP_ADDR.to_owned(),
            guest_rdp_port: trusted_image.guest_rdp_port,
            backend_credential_ref: request.backend_credential_ref.clone(),
            attestation_ref: trusted_image.attestation_ref,
            lease_state: LeaseState::Assigned,
            capture_source_ref: format!("gateway-recording://{}", trusted_image.vm_name),
        };

        persist_active_snapshot(paths, &snapshot).map_err(LeaseError::host_unavailable)?;
        self.leases.insert(vm_lease_id.clone(), snapshot.clone());

        Ok(AcquireVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: make_correlation_id("acquire"),
            vm_lease_id,
            vm_name: snapshot.vm_name,
            guest_rdp_addr: snapshot.guest_rdp_addr,
            guest_rdp_port: snapshot.guest_rdp_port,
            lease_state: snapshot.lease_state,
            lease_expires_at,
            backend_credential_ref: snapshot.backend_credential_ref,
            attestation_ref: snapshot.attestation_ref,
        })
    }

    pub(crate) fn release(
        &mut self,
        paths: &PathConfig,
        vm_lease_id: &str,
        request: &ReleaseVmRequest,
    ) -> Result<ReleaseVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let snapshot = self.require_assigned_lease(vm_lease_id, &request.session_id)?;
        snapshot.lease_state = LeaseState::Releasing;
        persist_active_snapshot(paths, snapshot).map_err(LeaseError::host_unavailable)?;

        Ok(ReleaseVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: make_correlation_id("release"),
            vm_lease_id: snapshot.vm_lease_id.clone(),
            release_state: ReleaseState::Recycling,
            recycle_required: true,
        })
    }

    pub(crate) fn reset(
        &mut self,
        paths: &PathConfig,
        vm_lease_id: &str,
        request: &ResetVmRequest,
    ) -> Result<ResetVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let force_quarantine = request.reset_reason.contains("simulate_failure");

        if force_quarantine {
            let snapshot = self.remove_lease(vm_lease_id, &request.session_id)?;
            let mut snapshot = snapshot;
            snapshot.lease_state = LeaseState::Quarantined;
            move_snapshot_to_quarantine(paths, &snapshot).map_err(LeaseError::host_unavailable)?;

            return Ok(ResetVmResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: make_correlation_id("reset"),
                vm_lease_id: snapshot.vm_lease_id,
                reset_state: ResetState::Quarantined,
                quarantine_required: true,
            });
        }

        let snapshot = self.require_assigned_lease(vm_lease_id, &request.session_id)?;
        persist_active_snapshot(paths, snapshot).map_err(LeaseError::host_unavailable)?;

        Ok(ResetVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: make_correlation_id("reset"),
            vm_lease_id: snapshot.vm_lease_id.clone(),
            reset_state: ResetState::ResetComplete,
            quarantine_required: false,
        })
    }

    pub(crate) fn recycle(
        &mut self,
        paths: &PathConfig,
        vm_lease_id: &str,
        request: &RecycleVmRequest,
    ) -> Result<RecycleVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let snapshot = self.remove_lease(vm_lease_id, &request.session_id)?;
        let should_quarantine = request.recycle_reason.contains("simulate_failure") && request.quarantine_on_failure;

        if should_quarantine {
            let mut snapshot = snapshot;
            snapshot.lease_state = LeaseState::Quarantined;
            move_snapshot_to_quarantine(paths, &snapshot).map_err(LeaseError::host_unavailable)?;

            return Ok(RecycleVmResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: make_correlation_id("recycle"),
                vm_lease_id: snapshot.vm_lease_id,
                recycle_state: RecycleState::Quarantined,
                pool_state: PoolState::Quarantined,
                quarantined: true,
            });
        }

        remove_active_snapshot(paths, &snapshot.vm_lease_id).map_err(LeaseError::host_unavailable)?;

        Ok(RecycleVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: make_correlation_id("recycle"),
            vm_lease_id: snapshot.vm_lease_id,
            recycle_state: RecycleState::Recycled,
            pool_state: PoolState::Ready,
            quarantined: false,
        })
    }

    pub(crate) fn stream_endpoint(
        &self,
        vm_lease_id: &str,
        request: &StreamEndpointRequest,
    ) -> Result<StreamEndpointResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let snapshot = self
            .leases
            .get(vm_lease_id)
            .ok_or_else(|| LeaseError::lease_not_found(format!("lease {vm_lease_id} was not found")))?;

        if snapshot.session_id != request.session_id {
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not assigned to session {}",
                request.session_id
            )));
        }

        if !matches!(snapshot.lease_state, LeaseState::Assigned | LeaseState::Ready) {
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not in a streamable state"
            )));
        }

        Ok(StreamEndpointResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: make_correlation_id("stream-endpoint"),
            vm_lease_id: snapshot.vm_lease_id.clone(),
            capture_source_kind: CaptureSourceKind::GatewayRecording,
            capture_source_ref: snapshot.capture_source_ref.clone(),
            source_ready: true,
            expires_at: now_plus_secs(DEFAULT_STREAM_TTL_SECS),
        })
    }

    fn next_lease_id(&mut self) -> String {
        let lease_id = format!("lease-{:08}", self.next_lease_sequence);
        self.next_lease_sequence += 1;
        lease_id
    }

    fn require_assigned_lease(
        &mut self,
        vm_lease_id: &str,
        session_id: &str,
    ) -> Result<&mut LeaseSnapshot, LeaseError> {
        let snapshot = self
            .leases
            .get_mut(vm_lease_id)
            .ok_or_else(|| LeaseError::lease_not_found(format!("lease {vm_lease_id} was not found")))?;

        if snapshot.session_id != session_id {
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not assigned to session {session_id}"
            )));
        }

        if !matches!(snapshot.lease_state, LeaseState::Assigned | LeaseState::Releasing) {
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not mutable in state {:?}",
                snapshot.lease_state
            )));
        }

        Ok(snapshot)
    }

    fn remove_lease(&mut self, vm_lease_id: &str, session_id: &str) -> Result<LeaseSnapshot, LeaseError> {
        let snapshot = self
            .leases
            .remove(vm_lease_id)
            .ok_or_else(|| LeaseError::lease_not_found(format!("lease {vm_lease_id} was not found")))?;

        if snapshot.session_id != session_id {
            self.leases.insert(vm_lease_id.to_owned(), snapshot);
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not assigned to session {session_id}"
            )));
        }

        if !matches!(snapshot.lease_state, LeaseState::Assigned | LeaseState::Releasing) {
            self.leases.insert(vm_lease_id.to_owned(), snapshot.clone());
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not recyclable in state {:?}",
                snapshot.lease_state
            )));
        }

        Ok(snapshot)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LeaseSnapshot {
    vm_lease_id: String,
    vm_name: String,
    session_id: String,
    guest_rdp_addr: String,
    guest_rdp_port: u16,
    backend_credential_ref: String,
    attestation_ref: String,
    lease_state: LeaseState,
    capture_source_ref: String,
}

#[derive(Debug, Clone)]
struct TrustedImage {
    vm_name: String,
    attestation_ref: String,
    guest_rdp_port: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct LeaseError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

impl LeaseError {
    fn invalid_request(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::InvalidRequest,
            message: message.into(),
            retryable: false,
        }
    }

    fn no_capacity(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::NoCapacity,
            message: message.into(),
            retryable: true,
        }
    }

    fn host_unavailable(error: impl Into<anyhow::Error>) -> Self {
        Self {
            code: ErrorCode::HostUnavailable,
            message: format!("{:#}", error.into()),
            retryable: true,
        }
    }

    fn lease_conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::LeaseConflict,
            message: message.into(),
            retryable: false,
        }
    }

    fn lease_not_found(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::LeaseNotFound,
            message: message.into(),
            retryable: false,
        }
    }

    fn lease_state_conflict(message: impl Into<String>) -> Self {
        Self {
            code: ErrorCode::LeaseStateConflict,
            message: message.into(),
            retryable: false,
        }
    }
}

fn trusted_images(paths: &PathConfig) -> anyhow::Result<Vec<TrustedImage>> {
    let mut manifests = json_files(&paths.manifest_dir())?;
    manifests.sort();

    manifests
        .into_iter()
        .enumerate()
        .map(|(index, manifest_path)| {
            let stem = manifest_path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("gold-image");
            let offset = u16::try_from(index).unwrap_or(0);

            Ok(TrustedImage {
                vm_name: format!("honeypot-{stem}"),
                attestation_ref: manifest_path.display().to_string(),
                guest_rdp_port: DEFAULT_GUEST_RDP_PORT.saturating_add(offset),
            })
        })
        .collect()
}

fn json_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let entries = fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        if is_json_file(&path) {
            paths.push(path);
        }
    }

    Ok(paths)
}

fn is_json_file(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json")
}

fn read_snapshot(path: &Path) -> anyhow::Result<LeaseSnapshot> {
    let data = fs::read_to_string(path).with_context(|| format!("read lease snapshot {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("parse lease snapshot {}", path.display()))
}

fn persist_active_snapshot(paths: &PathConfig, snapshot: &LeaseSnapshot) -> anyhow::Result<()> {
    let data = serde_json::to_vec_pretty(snapshot).context("serialize active lease snapshot")?;
    fs::write(active_snapshot_path(paths, &snapshot.vm_lease_id), data)
        .with_context(|| format!("write active lease snapshot for {}", snapshot.vm_lease_id))
}

fn move_snapshot_to_quarantine(paths: &PathConfig, snapshot: &LeaseSnapshot) -> anyhow::Result<()> {
    remove_active_snapshot(paths, &snapshot.vm_lease_id)?;
    let data = serde_json::to_vec_pretty(snapshot).context("serialize quarantined lease snapshot")?;
    fs::write(quarantine_snapshot_path(paths, &snapshot.vm_lease_id), data)
        .with_context(|| format!("write quarantined lease snapshot for {}", snapshot.vm_lease_id))
}

fn remove_active_snapshot(paths: &PathConfig, vm_lease_id: &str) -> anyhow::Result<()> {
    let path = active_snapshot_path(paths, vm_lease_id);
    if path.exists() {
        fs::remove_file(&path).with_context(|| format!("remove active lease snapshot {}", path.display()))?;
    }

    Ok(())
}

fn active_snapshot_path(paths: &PathConfig, vm_lease_id: &str) -> PathBuf {
    paths.lease_store.join(format!("{vm_lease_id}.json"))
}

fn quarantine_snapshot_path(paths: &PathConfig, vm_lease_id: &str) -> PathBuf {
    paths.quarantine_store.join(format!("{vm_lease_id}.json"))
}

fn parse_lease_sequence(vm_lease_id: &str) -> u64 {
    vm_lease_id.trim_start_matches("lease-").parse::<u64>().unwrap_or(0)
}

fn now_plus_secs(seconds: u64) -> String {
    let expiry = std::time::SystemTime::now() + std::time::Duration::from_secs(seconds);
    humantime::format_rfc3339_seconds(expiry).to_string()
}

fn make_correlation_id(prefix: &str) -> String {
    static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let next_id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}-{next_id}")
}
