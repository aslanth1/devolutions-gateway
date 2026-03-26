mod auth;
mod backend_credentials;
pub mod config;
pub mod health;
mod image;
mod lease;
mod qemu;
mod vm;

use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use axum::extract::{Path as AxumPath, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::{
    Json, Router,
    routing::{get, post},
};
use honeypot_contracts::Versioned as _;
use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, HealthResponse, RecycleVmRequest, RecycleVmResponse, ReleaseVmRequest,
    ReleaseVmResponse, ResetVmRequest, ResetVmResponse, StreamEndpointRequest, StreamEndpointResponse,
};
use honeypot_contracts::error::{ErrorCode, ErrorResponse};
use serde::Deserialize;
use tokio::net::TcpListener;

use self::auth::{AuthError, ControlPlaneAuth};
use self::backend_credentials::{BackendCredentialStore, build_backend_credential_store};
use self::config::ControlPlaneConfig;
use self::health::ServiceState;
use self::image::trusted_images;
use self::lease::{LeaseError, LeaseRegistry};
use self::qemu::validate_qemu_runtime_contract;

#[derive(Debug)]
pub struct ControlPlaneRuntime {
    config: ControlPlaneConfig,
    auth: ControlPlaneAuth,
    backend_credentials: Arc<dyn BackendCredentialStore>,
    leases: Mutex<LeaseRegistry>,
}

impl ControlPlaneRuntime {
    pub fn new(config: ControlPlaneConfig) -> anyhow::Result<Self> {
        let backend_credentials = build_backend_credential_store(&config).context("build backend credential store")?;
        validate_startup_contract(&config, backend_credentials.as_ref())
            .context("validate control-plane startup contract")?;
        let auth = ControlPlaneAuth::from_config(&config.auth).context("build control-plane auth gate")?;
        let leases =
            LeaseRegistry::load(&config, backend_credentials.as_ref()).context("load control-plane lease registry")?;
        Ok(Self {
            config,
            auth,
            backend_credentials,
            leases: Mutex::new(leases),
        })
    }

    pub fn health_response(&self) -> HealthResponse {
        let inspection = inspect_runtime(&self.config, self.backend_credentials.as_ref());

        let service_state = if !inspection.unsafe_reasons.is_empty() {
            ServiceState::Unsafe
        } else if !inspection.degraded_reasons.is_empty() {
            ServiceState::Degraded
        } else {
            ServiceState::Ready
        };

        let mut degraded_reasons = inspection.unsafe_reasons;
        degraded_reasons.extend(inspection.degraded_reasons);

        HealthResponse {
            schema_version: 1,
            correlation_id: make_health_correlation_id(),
            service_state,
            kvm_available: inspection.kvm_available,
            trusted_image_count: inspection.trusted_image_count,
            active_lease_count: inspection.active_lease_count,
            quarantined_lease_count: inspection.quarantined_lease_count,
            degraded_reasons,
        }
    }

    pub fn bind_addr(&self) -> std::net::SocketAddr {
        self.config.http.bind_addr
    }

    fn authorize_request(&self, headers: &HeaderMap) -> Result<(), ControlPlaneApiError> {
        self.auth.authorize(headers).map_err(ControlPlaneApiError::from)
    }
}

#[derive(Debug, Default)]
struct RuntimeInspection {
    kvm_available: bool,
    trusted_image_count: usize,
    active_lease_count: usize,
    quarantined_lease_count: usize,
    unsafe_reasons: Vec<String>,
    degraded_reasons: Vec<String>,
}

pub async fn run_control_plane(config: ControlPlaneConfig) -> anyhow::Result<()> {
    let runtime = Arc::new(ControlPlaneRuntime::new(config)?);
    let bind_addr = runtime.bind_addr();

    let router = Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/vm/acquire", post(acquire_vm_handler))
        .route("/api/v1/vm/{vm_lease_id}/release", post(release_vm_handler))
        .route("/api/v1/vm/{vm_lease_id}/reset", post(reset_vm_handler))
        .route("/api/v1/vm/{vm_lease_id}/recycle", post(recycle_vm_handler))
        .route("/api/v1/vm/{vm_lease_id}/stream", get(stream_endpoint_handler))
        .with_state(runtime);

    let listener = TcpListener::bind(bind_addr)
        .await
        .with_context(|| format!("bind control-plane listener at {bind_addr}"))?;

    tracing::info!(%bind_addr, "honeypot control-plane listening");

    axum::serve(listener, router)
        .await
        .context("serve honeypot control-plane")
}

#[derive(Debug, Default, Deserialize)]
struct HealthQuery {
    schema_version: Option<u32>,
}

async fn health_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    Query(query): Query<HealthQuery>,
) -> Result<Json<HealthResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    if let Some(schema_version) = query.schema_version {
        let request = honeypot_contracts::control_plane::HealthRequest {
            schema_version,
            request_id: "health".to_owned(),
        };
        request
            .ensure_supported_schema()
            .map_err(|error| ControlPlaneApiError::invalid_request(error.to_string()))?;
    }

    Ok(Json(runtime.health_response()))
}

async fn acquire_vm_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    Json(request): Json<AcquireVmRequest>,
) -> Result<Json<AcquireVmResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    let mut leases = runtime.lock_leases()?;
    let response = leases
        .acquire(&runtime.config, runtime.backend_credentials.as_ref(), &request)
        .map_err(ControlPlaneApiError::from)?;
    Ok(Json(response))
}

async fn release_vm_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    AxumPath(vm_lease_id): AxumPath<String>,
    Json(request): Json<ReleaseVmRequest>,
) -> Result<Json<ReleaseVmResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    let mut leases = runtime.lock_leases()?;
    let response = leases
        .release(&runtime.config, &vm_lease_id, &request)
        .map_err(ControlPlaneApiError::from)?;
    Ok(Json(response))
}

async fn reset_vm_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    AxumPath(vm_lease_id): AxumPath<String>,
    Json(request): Json<ResetVmRequest>,
) -> Result<Json<ResetVmResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    let mut leases = runtime.lock_leases()?;
    let response = leases
        .reset(
            &runtime.config,
            runtime.backend_credentials.as_ref(),
            &vm_lease_id,
            &request,
        )
        .map_err(ControlPlaneApiError::from)?;
    Ok(Json(response))
}

async fn recycle_vm_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    AxumPath(vm_lease_id): AxumPath<String>,
    Json(request): Json<RecycleVmRequest>,
) -> Result<Json<RecycleVmResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    let mut leases = runtime.lock_leases()?;
    let response = leases
        .recycle(
            &runtime.config,
            runtime.backend_credentials.as_ref(),
            &vm_lease_id,
            &request,
        )
        .map_err(ControlPlaneApiError::from)?;
    Ok(Json(response))
}

async fn stream_endpoint_handler(
    State(runtime): State<Arc<ControlPlaneRuntime>>,
    headers: HeaderMap,
    AxumPath(vm_lease_id): AxumPath<String>,
    Query(request): Query<StreamEndpointRequest>,
) -> Result<Json<StreamEndpointResponse>, ControlPlaneApiError> {
    runtime.authorize_request(&headers)?;

    let leases = runtime.lock_leases()?;
    let response = leases
        .stream_endpoint(&vm_lease_id, &request)
        .map_err(ControlPlaneApiError::from)?;
    Ok(Json(response))
}

fn validate_startup_contract(
    config: &ControlPlaneConfig,
    backend_credentials: &dyn BackendCredentialStore,
) -> anyhow::Result<()> {
    ensure_dir("data_dir", &config.paths.data_dir)?;
    ensure_dir("image_store", &config.paths.image_store)?;
    ensure_dir("manifest_dir", &config.paths.manifest_dir())?;
    ensure_dir("lease_store", &config.paths.lease_store)?;
    ensure_dir("quarantine_store", &config.paths.quarantine_store)?;
    ensure_dir("qmp_dir", &config.paths.qmp_dir)?;
    ensure_dir("secret_dir", &config.paths.secret_dir)?;
    ensure_exists("kvm_path", &config.paths.kvm_path)?;
    validate_qemu_runtime_contract(config)?;
    backend_credentials
        .validate_startup_contract()
        .context("validate backend credential store contract")?;
    trusted_images(&config.paths).context("validate trusted image attestation manifests")?;

    if config.runtime.enable_guest_agent {
        let qga_dir = config.paths.qga_dir()?;
        ensure_dir("qga_dir", &qga_dir)?;
    }

    Ok(())
}

fn inspect_runtime(config: &ControlPlaneConfig, backend_credentials: &dyn BackendCredentialStore) -> RuntimeInspection {
    let mut inspection = RuntimeInspection {
        kvm_available: config.paths.kvm_path.exists(),
        ..RuntimeInspection::default()
    };
    if !inspection.kvm_available {
        inspection
            .unsafe_reasons
            .push(format!("missing_kvm_path:{}", config.paths.kvm_path.display()));
    }

    inspect_dir("data_dir", &config.paths.data_dir, &mut inspection);
    inspect_dir("image_store", &config.paths.image_store, &mut inspection);
    inspect_dir("lease_store", &config.paths.lease_store, &mut inspection);
    inspect_dir("quarantine_store", &config.paths.quarantine_store, &mut inspection);
    inspect_dir("qmp_dir", &config.paths.qmp_dir, &mut inspection);
    inspect_dir("secret_dir", &config.paths.secret_dir, &mut inspection);
    inspect_file("qemu_binary_path", &config.runtime.qemu.binary_path, &mut inspection);
    if let Err(error) = backend_credentials.validate_startup_contract() {
        inspection
            .unsafe_reasons
            .push(format!("invalid_backend_credentials:{error:#}"));
    }

    let manifest_dir = config.paths.manifest_dir();
    inspect_dir("manifest_dir", &manifest_dir, &mut inspection);
    match trusted_images(&config.paths) {
        Ok(trusted_images) => {
            inspection.trusted_image_count = trusted_images.len();
            if inspection.unsafe_reasons.is_empty() && inspection.trusted_image_count == 0 {
                inspection.degraded_reasons.push("no_trusted_images".to_owned());
            }
        }
        Err(error) => inspection
            .unsafe_reasons
            .push(format!("invalid_trusted_images:{error:#}")),
    }

    inspection.active_lease_count = count_entries(&config.paths.lease_store, only_json_files);
    inspection.quarantined_lease_count = count_entries(&config.paths.quarantine_store, only_json_files);

    if config.runtime.enable_guest_agent {
        match config.paths.qga_dir() {
            Ok(qga_dir) => inspect_dir("qga_dir", &qga_dir, &mut inspection),
            Err(error) => inspection.unsafe_reasons.push(format!("invalid_qga_dir:{error:#}")),
        }
    }

    inspection
}

fn inspect_dir(label: &str, path: &Path, inspection: &mut RuntimeInspection) {
    if !path.exists() {
        inspection
            .unsafe_reasons
            .push(format!("missing_{label}:{}", path.display()));
    } else if !path.is_dir() {
        inspection
            .unsafe_reasons
            .push(format!("invalid_{label}:{}", path.display()));
    }
}

fn inspect_file(label: &str, path: &Path, inspection: &mut RuntimeInspection) {
    if !path.exists() {
        inspection
            .unsafe_reasons
            .push(format!("missing_{label}:{}", path.display()));
    } else if !path.is_file() {
        inspection
            .unsafe_reasons
            .push(format!("invalid_{label}:{}", path.display()));
    }
}

fn ensure_dir(label: &str, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(path.exists(), "{label} does not exist at {}", path.display());
    anyhow::ensure!(path.is_dir(), "{label} is not a directory at {}", path.display());
    Ok(())
}

fn ensure_exists(label: &str, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(path.exists(), "{label} does not exist at {}", path.display());
    Ok(())
}

fn count_entries(path: &Path, include: fn(&Path) -> bool) -> usize {
    fs::read_dir(path)
        .ok()
        .into_iter()
        .flat_map(|entries| entries.filter_map(Result::ok))
        .map(|entry| entry.path())
        .filter(|entry_path| include(entry_path))
        .count()
}

fn only_json_files(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json")
}

fn make_health_correlation_id() -> String {
    let millis = match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    };

    format!("health-{millis}")
}

impl ControlPlaneRuntime {
    fn lock_leases(&self) -> Result<std::sync::MutexGuard<'_, LeaseRegistry>, ControlPlaneApiError> {
        self.leases
            .lock()
            .map_err(|_| ControlPlaneApiError::host_unavailable("lease registry is poisoned"))
    }
}

#[derive(Debug)]
struct ControlPlaneApiError {
    status: StatusCode,
    body: ErrorResponse,
}

impl ControlPlaneApiError {
    fn new(status: StatusCode, error_code: ErrorCode, message: impl Into<String>, retryable: bool) -> Self {
        Self {
            status,
            body: ErrorResponse::new(make_health_correlation_id(), error_code, message, retryable),
        }
    }

    fn invalid_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ErrorCode::InvalidRequest, message, false)
    }

    fn host_unavailable(message: impl Into<String>) -> Self {
        Self::new(
            StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::HostUnavailable,
            message,
            true,
        )
    }
}

impl From<LeaseError> for ControlPlaneApiError {
    fn from(error: LeaseError) -> Self {
        let status = match error.code {
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::LeaseNotFound => StatusCode::NOT_FOUND,
            ErrorCode::LeaseConflict | ErrorCode::LeaseStateConflict | ErrorCode::Quarantined => StatusCode::CONFLICT,
            ErrorCode::NoCapacity
            | ErrorCode::HostUnavailable
            | ErrorCode::BootTimeout
            | ErrorCode::ResetFailed
            | ErrorCode::RecycleFailed
            | ErrorCode::StreamUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::AuthFailed | ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::ImageUntrusted | ErrorCode::CursorExpired => StatusCode::CONFLICT,
        };

        Self::new(status, error.code, error.message, error.retryable)
    }
}

impl From<AuthError> for ControlPlaneApiError {
    fn from(error: AuthError) -> Self {
        let message = error.message();

        match error {
            AuthError::MissingToken | AuthError::InvalidToken(_) => {
                Self::new(StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized, message, false)
            }
            AuthError::Forbidden { .. } => Self::new(StatusCode::FORBIDDEN, ErrorCode::Forbidden, message, false),
        }
    }
}

impl IntoResponse for ControlPlaneApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}
