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

use crate::backend_credentials::{BackendCredentialResolveError, BackendCredentialStore};
use crate::config::{ControlPlaneConfig, PathConfig};
use crate::image::{trusted_images, validate_trusted_image_identity};
use crate::qemu::QemuLaunchPlan;
use crate::vm::{
    cleanup_orphaned_vm, create_vm, destroy_vm, reset_vm as reset_vm_runtime, runtime_looks_active, start_vm, stop_vm,
};

const DEFAULT_GUEST_RDP_ADDR: &str = "127.0.0.1";
const DEFAULT_STREAM_TTL_SECS: u64 = 60;

#[derive(Debug)]
pub(crate) struct LeaseRegistry {
    leases: HashMap<String, LeaseSnapshot>,
    next_lease_sequence: u64,
}

impl LeaseRegistry {
    pub(crate) fn load(
        config: &ControlPlaneConfig,
        backend_credentials: &dyn BackendCredentialStore,
    ) -> anyhow::Result<Self> {
        let mut leases = HashMap::new();
        let mut next_lease_sequence = 1;

        for snapshot_path in json_files(&config.paths.lease_store)? {
            let snapshot = read_snapshot(&snapshot_path)?;
            next_lease_sequence = next_lease_sequence.max(parse_lease_sequence(&snapshot.vm_lease_id) + 1);

            if let Some(snapshot) = reconcile_loaded_snapshot(config, backend_credentials, snapshot)? {
                leases.insert(snapshot.vm_lease_id.clone(), snapshot);
            }
        }

        cleanup_untracked_runtime_artifacts(&config.paths, &leases)?;

        Ok(Self {
            leases,
            next_lease_sequence,
        })
    }

    pub(crate) fn acquire(
        &mut self,
        config: &ControlPlaneConfig,
        backend_credentials: &dyn BackendCredentialStore,
        request: &AcquireVmRequest,
    ) -> Result<AcquireVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;
        if request.requested_pool.trim().is_empty() {
            return Err(LeaseError::invalid_request("requested_pool must not be empty"));
        }
        let _backend_credential = backend_credentials
            .resolve(&request.backend_credential_ref)
            .map_err(LeaseError::from_backend_credential_resolve)?;

        if self.leases.values().any(|lease| lease.session_id == request.session_id) {
            return Err(LeaseError::lease_conflict(format!(
                "session {} already owns a lease",
                request.session_id
            )));
        }

        cleanup_untracked_runtime_artifacts(&config.paths, &self.leases).map_err(LeaseError::host_unavailable)?;

        let trusted_images = trusted_images(&config.paths).map_err(LeaseError::host_unavailable)?;
        let trusted_images = trusted_images
            .into_iter()
            .filter(|trusted_image| trusted_image.pool_name == request.requested_pool)
            .collect::<Vec<_>>();
        if trusted_images.is_empty() {
            return Err(LeaseError::no_capacity(format!(
                "requested pool {} has no trusted images available",
                request.requested_pool
            )));
        }

        let busy_vm_names = self
            .leases
            .values()
            .map(|lease| lease.vm_name.clone())
            .collect::<HashSet<_>>();

        let vm_lease_id = self.next_lease_id();
        let lease_expires_at = now_plus_secs(u64::from(request.requested_ready_timeout_secs).max(60));
        let mut selected = None;
        let mut last_launch_error = None;

        for trusted_image in trusted_images {
            if busy_vm_names.contains(&trusted_image.vm_name) {
                continue;
            }

            match QemuLaunchPlan::build(
                config,
                &vm_lease_id,
                &trusted_image.vm_name,
                &trusted_image.base_image_path,
                trusted_image.guest_rdp_port,
            ) {
                Ok(launch_plan) => {
                    selected = Some((trusted_image, launch_plan));
                    break;
                }
                Err(error) => last_launch_error = Some(error),
            }
        }

        let (trusted_image, launch_plan) = match selected {
            Some(selected) => selected,
            None => {
                if let Some(error) = last_launch_error {
                    return Err(LeaseError::host_unavailable(error));
                }

                return Err(LeaseError::no_capacity(format!(
                    "all trusted images in pool {} are currently assigned",
                    request.requested_pool
                )));
            }
        };

        let snapshot = LeaseSnapshot {
            vm_lease_id: vm_lease_id.clone(),
            pool_name: trusted_image.pool_name.clone(),
            vm_name: trusted_image.vm_name.clone(),
            session_id: request.session_id.clone(),
            guest_rdp_addr: DEFAULT_GUEST_RDP_ADDR.to_owned(),
            guest_rdp_port: trusted_image.guest_rdp_port,
            backend_credential_ref: request.backend_credential_ref.clone(),
            attestation_ref: trusted_image.attestation_ref,
            lease_state: LeaseState::Assigned,
            capture_source_ref: format!("gateway-recording://{}", trusted_image.vm_name),
            launch_plan: LeaseLaunchPlanSnapshot::from(launch_plan),
            runtime_state: LeaseRuntimeState::Prepared,
        };

        let mut snapshot = snapshot;
        create_vm(&snapshot.launch_plan).map_err(LeaseError::host_unavailable)?;
        start_vm(config, &snapshot.launch_plan).map_err(LeaseError::host_unavailable)?;
        snapshot.runtime_state = LeaseRuntimeState::Running;

        persist_active_snapshot(&config.paths, &snapshot).map_err(LeaseError::host_unavailable)?;
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
        config: &ControlPlaneConfig,
        vm_lease_id: &str,
        request: &ReleaseVmRequest,
    ) -> Result<ReleaseVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let snapshot = self.require_assigned_lease(vm_lease_id, &request.session_id)?;
        snapshot.lease_state = LeaseState::Releasing;
        persist_active_snapshot(&config.paths, snapshot).map_err(LeaseError::host_unavailable)?;

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
        config: &ControlPlaneConfig,
        backend_credentials: &dyn BackendCredentialStore,
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
            let _ = stop_vm(config, &snapshot.launch_plan);
            snapshot.runtime_state = LeaseRuntimeState::Stopped;
            backend_credentials
                .revoke(&snapshot.backend_credential_ref)
                .map_err(LeaseError::host_unavailable)?;
            move_snapshot_to_quarantine(&config.paths, &snapshot).map_err(LeaseError::host_unavailable)?;

            return Ok(ResetVmResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: make_correlation_id("reset"),
                vm_lease_id: snapshot.vm_lease_id,
                reset_state: ResetState::Quarantined,
                quarantine_required: true,
            });
        }

        let snapshot = self.require_assigned_lease(vm_lease_id, &request.session_id)?;
        reset_vm_runtime(config, &snapshot.launch_plan).map_err(LeaseError::host_unavailable)?;
        snapshot.runtime_state = LeaseRuntimeState::Running;
        persist_active_snapshot(&config.paths, snapshot).map_err(LeaseError::host_unavailable)?;

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
        config: &ControlPlaneConfig,
        backend_credentials: &dyn BackendCredentialStore,
        vm_lease_id: &str,
        request: &RecycleVmRequest,
    ) -> Result<RecycleVmResponse, LeaseError> {
        request
            .ensure_supported_schema()
            .map_err(|error| LeaseError::invalid_request(error.to_string()))?;

        let should_quarantine = request.recycle_reason.contains("simulate_failure") && request.quarantine_on_failure;

        if should_quarantine {
            let snapshot = self.remove_lease(vm_lease_id, &request.session_id)?;
            let mut snapshot = snapshot;
            snapshot.lease_state = LeaseState::Quarantined;
            let _ = stop_vm(config, &snapshot.launch_plan);
            snapshot.runtime_state = LeaseRuntimeState::Stopped;
            backend_credentials
                .revoke(&snapshot.backend_credential_ref)
                .map_err(LeaseError::host_unavailable)?;
            move_snapshot_to_quarantine(&config.paths, &snapshot).map_err(LeaseError::host_unavailable)?;

            return Ok(RecycleVmResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: make_correlation_id("recycle"),
                vm_lease_id: snapshot.vm_lease_id,
                recycle_state: RecycleState::Quarantined,
                pool_state: PoolState::Quarantined,
                quarantined: true,
            });
        }

        {
            let snapshot = self.require_assigned_lease(vm_lease_id, &request.session_id)?;
            if matches!(snapshot.runtime_state, LeaseRuntimeState::Running) {
                stop_vm(config, &snapshot.launch_plan).map_err(LeaseError::host_unavailable)?;
                snapshot.runtime_state = LeaseRuntimeState::Stopped;
                persist_active_snapshot(&config.paths, snapshot).map_err(LeaseError::host_unavailable)?;
            }

            destroy_vm(&snapshot.launch_plan).map_err(LeaseError::host_unavailable)?;
        }

        let snapshot = self.remove_lease(vm_lease_id, &request.session_id)?;

        if validate_trusted_image_identity(
            &config.paths,
            &snapshot.pool_name,
            &snapshot.vm_name,
            &snapshot.attestation_ref,
            &snapshot.launch_plan.base_image_path,
        )
        .is_err()
        {
            let mut snapshot = snapshot;
            snapshot.lease_state = LeaseState::Quarantined;
            snapshot.runtime_state = LeaseRuntimeState::Stopped;
            backend_credentials
                .revoke(&snapshot.backend_credential_ref)
                .map_err(LeaseError::host_unavailable)?;
            move_snapshot_to_quarantine(&config.paths, &snapshot).map_err(LeaseError::host_unavailable)?;

            return Ok(RecycleVmResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: make_correlation_id("recycle"),
                vm_lease_id: snapshot.vm_lease_id,
                recycle_state: RecycleState::Quarantined,
                pool_state: PoolState::Quarantined,
                quarantined: true,
            });
        }

        backend_credentials
            .revoke(&snapshot.backend_credential_ref)
            .map_err(LeaseError::host_unavailable)?;
        remove_active_snapshot(&config.paths, &snapshot.vm_lease_id).map_err(LeaseError::host_unavailable)?;

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

        if !matches!(snapshot.runtime_state, LeaseRuntimeState::Running) {
            return Err(LeaseError::lease_state_conflict(format!(
                "lease {vm_lease_id} is not in a running state"
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
    #[serde(default = "default_pool_name")]
    pool_name: String,
    vm_name: String,
    session_id: String,
    guest_rdp_addr: String,
    guest_rdp_port: u16,
    backend_credential_ref: String,
    attestation_ref: String,
    lease_state: LeaseState,
    capture_source_ref: String,
    launch_plan: LeaseLaunchPlanSnapshot,
    #[serde(default)]
    runtime_state: LeaseRuntimeState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub(crate) enum LeaseRuntimeState {
    #[default]
    Prepared,
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct LeaseLaunchPlanSnapshot {
    pub(crate) qemu_binary_path: PathBuf,
    pub(crate) vm_name: String,
    pub(crate) runtime_dir: PathBuf,
    pub(crate) base_image_path: PathBuf,
    pub(crate) overlay_path: PathBuf,
    pub(crate) pid_file_path: PathBuf,
    pub(crate) qmp_socket_path: PathBuf,
    pub(crate) qga_socket_path: Option<PathBuf>,
    pub(crate) argv: Vec<String>,
}

impl From<QemuLaunchPlan> for LeaseLaunchPlanSnapshot {
    fn from(plan: QemuLaunchPlan) -> Self {
        Self {
            qemu_binary_path: plan.qemu_binary_path,
            vm_name: plan.vm_name,
            runtime_dir: plan.runtime_dir,
            base_image_path: plan.base_image_path,
            overlay_path: plan.overlay_path,
            pid_file_path: plan.pid_file_path,
            qmp_socket_path: plan.qmp_socket_path,
            qga_socket_path: plan.qga_socket_path,
            argv: plan.argv,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LeaseError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
}

fn default_pool_name() -> String {
    "default".to_owned()
}

impl LeaseError {
    fn from_backend_credential_resolve(error: BackendCredentialResolveError) -> Self {
        match error {
            BackendCredentialResolveError::MissingReference { backend_credential_ref } => {
                Self::invalid_request(format!(
                    "backend credential ref {backend_credential_ref} was not found in the configured backend credential store"
                ))
            }
            BackendCredentialResolveError::Unavailable(error) => Self::host_unavailable(error),
        }
    }

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

fn reconcile_loaded_snapshot(
    config: &ControlPlaneConfig,
    backend_credentials: &dyn BackendCredentialStore,
    snapshot: LeaseSnapshot,
) -> anyhow::Result<Option<LeaseSnapshot>> {
    match runtime_looks_active(&snapshot.launch_plan) {
        Ok(true) => Ok(Some(snapshot)),
        Ok(false) => {
            quarantine_orphaned_snapshot(config, backend_credentials, snapshot)?;
            Ok(None)
        }
        Err(error) => {
            let mut snapshot = snapshot;
            snapshot.lease_state = LeaseState::Quarantined;
            snapshot.runtime_state = LeaseRuntimeState::Stopped;
            backend_credentials
                .revoke(&snapshot.backend_credential_ref)
                .context("revoke backend credential ref for orphaned lease")?;
            cleanup_orphaned_vm(config, &snapshot.launch_plan).with_context(|| {
                format!(
                    "reclaim runtime artifacts for orphaned lease {} after runtime inspection failure: {error:#}",
                    snapshot.vm_lease_id
                )
            })?;
            move_snapshot_to_quarantine(&config.paths, &snapshot)?;
            Ok(None)
        }
    }
}

fn quarantine_orphaned_snapshot(
    config: &ControlPlaneConfig,
    backend_credentials: &dyn BackendCredentialStore,
    snapshot: LeaseSnapshot,
) -> anyhow::Result<()> {
    let mut snapshot = snapshot;
    snapshot.lease_state = LeaseState::Quarantined;
    snapshot.runtime_state = LeaseRuntimeState::Stopped;
    backend_credentials
        .revoke(&snapshot.backend_credential_ref)
        .context("revoke backend credential ref for orphaned lease")?;
    cleanup_orphaned_vm(config, &snapshot.launch_plan)
        .with_context(|| format!("reclaim runtime artifacts for orphaned lease {}", snapshot.vm_lease_id))?;
    move_snapshot_to_quarantine(&config.paths, &snapshot)
}

fn persist_active_snapshot(paths: &PathConfig, snapshot: &LeaseSnapshot) -> anyhow::Result<()> {
    let data = serde_json::to_vec_pretty(snapshot).context("serialize active lease snapshot")?;
    fs::write(active_snapshot_path(paths, &snapshot.vm_lease_id), data)
        .with_context(|| format!("write active lease snapshot for {}", snapshot.vm_lease_id))
}

fn move_snapshot_to_quarantine(paths: &PathConfig, snapshot: &LeaseSnapshot) -> anyhow::Result<()> {
    remove_active_snapshot(paths, &snapshot.vm_lease_id)?;
    move_runtime_artifacts_to_quarantine(paths, snapshot)?;
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

fn cleanup_untracked_runtime_artifacts(
    paths: &PathConfig,
    leases: &HashMap<String, LeaseSnapshot>,
) -> anyhow::Result<()> {
    let tracked_lease_ids = leases.keys().cloned().collect::<HashSet<_>>();

    let entries = fs::read_dir(&paths.lease_store)
        .with_context(|| format!("read lease store {}", paths.lease_store.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", paths.lease_store.display()))?;
        let path = entry.path();
        let file_name = entry.file_name();
        let file_name = file_name.to_string_lossy();

        if path.is_dir() {
            if !tracked_lease_ids.contains(file_name.as_ref()) {
                fs::remove_dir_all(&path).with_context(|| format!("remove orphan runtime dir {}", path.display()))?;
            }
            continue;
        }

        if !path.is_file() {
            continue;
        }

        let lease_id = if is_json_file(&path) {
            file_name.strip_suffix(".json").unwrap_or_else(|| file_name.as_ref())
        } else {
            ""
        };

        if !tracked_lease_ids.contains(lease_id) && !is_json_file(&path) {
            fs::remove_file(&path).with_context(|| format!("remove orphan lease-store artifact {}", path.display()))?;
        }
    }

    cleanup_untracked_socket_dir(&paths.qmp_dir, &tracked_lease_ids)?;

    if let Some(qga_dir) = &paths.qga_dir {
        if !qga_dir.exists() {
            return Ok(());
        }
        cleanup_untracked_socket_dir(qga_dir, &tracked_lease_ids)?;
    }

    Ok(())
}

fn cleanup_untracked_socket_dir(root: &Path, tracked_lease_ids: &HashSet<String>) -> anyhow::Result<()> {
    let entries = fs::read_dir(root).with_context(|| format!("read runtime socket dir {}", root.display()))?;
    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        let tracked = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .is_some_and(|lease_id| tracked_lease_ids.contains(lease_id));
        if tracked {
            continue;
        }

        fs::remove_file(&path).with_context(|| format!("remove orphan runtime socket {}", path.display()))?;
    }

    Ok(())
}

fn move_runtime_artifacts_to_quarantine(paths: &PathConfig, snapshot: &LeaseSnapshot) -> anyhow::Result<()> {
    cleanup_runtime_socket(&snapshot.launch_plan.qmp_socket_path)?;

    if let Some(qga_socket_path) = &snapshot.launch_plan.qga_socket_path {
        cleanup_runtime_socket(qga_socket_path)?;
    }

    let pid_file_path = &snapshot.launch_plan.pid_file_path;
    if pid_file_path.exists() {
        fs::remove_file(pid_file_path).with_context(|| format!("remove pid file {}", pid_file_path.display()))?;
    }

    let runtime_dir = &snapshot.launch_plan.runtime_dir;
    if runtime_dir.exists() {
        let quarantine_runtime_dir = paths.quarantine_store.join(format!("{}-runtime", snapshot.vm_lease_id));
        if quarantine_runtime_dir.exists() {
            fs::remove_dir_all(&quarantine_runtime_dir)
                .with_context(|| format!("clear quarantine runtime dir {}", quarantine_runtime_dir.display()))?;
        }
        fs::rename(runtime_dir, &quarantine_runtime_dir).with_context(|| {
            format!(
                "move runtime dir {} to quarantine {}",
                runtime_dir.display(),
                quarantine_runtime_dir.display()
            )
        })?;
    }

    Ok(())
}

fn cleanup_runtime_socket(path: &Path) -> anyhow::Result<()> {
    if path.exists() {
        fs::remove_file(path).with_context(|| format!("remove runtime socket {}", path.display()))?;
    }

    Ok(())
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
