use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use camino::Utf8PathBuf;
use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, AttackerProtocol, HealthRequest, HealthResponse, RecycleVmRequest,
    RecycleVmResponse, ReleaseVmRequest, ReleaseVmResponse, ResetVmRequest, ResetVmResponse,
    ServiceState as ControlPlaneServiceState, StreamEndpointRequest, StreamEndpointResponse, StreamPolicy,
};
use honeypot_contracts::error::{ErrorCode, ErrorResponse};
use honeypot_contracts::events::{EventEnvelope, EventPayload, SessionState, StreamState, TerminalOutcome};
use honeypot_contracts::frontend::{BootstrapResponse, BootstrapSession};
use honeypot_contracts::stream::{StreamPreview, StreamTokenResponse, StreamTransport};
use parking_lot::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::broadcast;

use crate::config::{
    Conf, HoneypotControlPlaneConf, HoneypotFrontendConf, HoneypotKillSwitchConf, HoneypotStreamConf,
    HoneypotStreamSourceKind,
};
use crate::credential::{AppCredentialMapping, CredentialBinding, CredentialProvisionRequest, CredentialStoreHandle};
use crate::session::{
    HoneypotAttackerSource, HoneypotSessionMetadataPatch, HoneypotStreamMetadata, HoneypotTerminalMetadata,
    HoneypotVmAssignment, RunningSessions, SessionInfo, SessionKillMetadata, SessionKillReason,
};
use crate::token::{ApplicationProtocol, Protocol, SessionTtl};

const HONEYPOT_EVENT_BUFFER_CAPACITY: usize = 256;
const HONEYPOT_DEFAULT_POOL: &str = "default";
const HONEYPOT_BACKEND_CREDENTIALS_PATH: &str = "/run/secrets/honeypot/proxy/backend-credentials.json";
const HONEYPOT_CREDENTIAL_MAPPING_TTL_SECS: i64 = 60 * 60 * 2;

#[derive(Clone)]
pub enum HoneypotMode {
    Disabled,
    Enabled(Arc<HoneypotRuntime>),
}

impl HoneypotMode {
    pub fn from_conf(conf: &Conf, credential_store: CredentialStoreHandle) -> anyhow::Result<Self> {
        if !conf.honeypot.enabled {
            return Ok(Self::Disabled);
        }

        Ok(Self::Enabled(Arc::new(HoneypotRuntime::from_conf(
            conf,
            credential_store,
        )?)))
    }

    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled(_))
    }

    pub fn runtime(&self) -> Option<&HoneypotRuntime> {
        match self {
            Self::Disabled => None,
            Self::Enabled(runtime) => Some(runtime),
        }
    }

    pub async fn record_session_started(&self, session: &SessionInfo) -> anyhow::Result<()> {
        if let Some(runtime) = self.runtime() {
            runtime.record_session_started(session).await?;
        }

        Ok(())
    }

    pub async fn record_session_ended(
        &self,
        session: &SessionInfo,
        kill: Option<SessionKillMetadata>,
    ) -> anyhow::Result<()> {
        if let Some(runtime) = self.runtime() {
            runtime.record_session_ended(session, kill).await?;
        }

        Ok(())
    }

    pub async fn prepare_rdp_session(
        &self,
        session_id: uuid::Uuid,
        application_protocol: ApplicationProtocol,
        time_to_live: SessionTtl,
        token: &str,
        attacker_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        if let Some(runtime) = self.runtime() {
            runtime
                .prepare_rdp_session(session_id, application_protocol, time_to_live, token, attacker_addr)
                .await?;
        }

        Ok(())
    }

    pub async fn abort_prepared_session(&self, session_id: uuid::Uuid) -> anyhow::Result<()> {
        if let Some(runtime) = self.runtime() {
            runtime.abort_prepared_session(session_id).await?;
        }

        Ok(())
    }

    pub fn ensure_new_session_allowed(&self, session_id: uuid::Uuid) -> anyhow::Result<()> {
        if let Some(runtime) = self.runtime() {
            runtime.ensure_new_session_allowed(session_id)?;
        }

        Ok(())
    }

    pub fn activate_system_kill(&self) {
        if let Some(runtime) = self.runtime() {
            runtime.activate_system_kill();
        }
    }

    pub fn session_metadata_patch(&self, session_id: uuid::Uuid) -> Option<HoneypotSessionMetadataPatch> {
        self.runtime()
            .and_then(|runtime| runtime.session_metadata_patch(session_id))
    }

    pub async fn health_snapshot(&self) -> Option<HoneypotProxyHealthSnapshot> {
        match self {
            Self::Disabled => None,
            Self::Enabled(runtime) => Some(runtime.health_snapshot().await),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotProxyServiceState {
    Ready,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotDependencyServiceState {
    Ready,
    Degraded,
    Unsafe,
}

impl From<ControlPlaneServiceState> for HoneypotDependencyServiceState {
    fn from(value: ControlPlaneServiceState) -> Self {
        match value {
            ControlPlaneServiceState::Ready => Self::Ready,
            ControlPlaneServiceState::Degraded => Self::Degraded,
            ControlPlaneServiceState::Unsafe => Self::Unsafe,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotProxyHealthSnapshot {
    pub service_state: HoneypotProxyServiceState,
    pub control_plane_reachable: bool,
    pub control_plane_service_state: Option<HoneypotDependencyServiceState>,
    pub degraded_reasons: Vec<String>,
}

#[derive(Clone)]
pub struct HoneypotRuntime {
    frontend: HoneypotFrontendRuntime,
    stream: HoneypotStreamRuntime,
    kill_switch: HoneypotKillSwitchRuntime,
    control_plane: Option<HoneypotControlPlaneClient>,
    credential_store: CredentialStoreHandle,
    backend_credentials: HoneypotBackendCredentialResolver,
    requested_ready_timeout_secs: u32,
    events: Arc<Mutex<HoneypotEventJournal>>,
}

impl HoneypotRuntime {
    fn from_conf(conf: &Conf, credential_store: CredentialStoreHandle) -> anyhow::Result<Self> {
        let (event_tx, _) = broadcast::channel(HONEYPOT_EVENT_BUFFER_CAPACITY);

        Ok(Self {
            frontend: HoneypotFrontendRuntime::from_conf(&conf.honeypot.frontend),
            stream: HoneypotStreamRuntime::from_conf(&conf.honeypot.stream),
            kill_switch: HoneypotKillSwitchRuntime::from_conf(&conf.honeypot.kill_switch),
            control_plane: HoneypotControlPlaneClient::from_conf(&conf.honeypot.control_plane)?,
            credential_store,
            backend_credentials: HoneypotBackendCredentialResolver::new(
                conf.debug
                    .honeypot_backend_credentials_file
                    .clone()
                    .unwrap_or_else(|| Utf8PathBuf::from(HONEYPOT_BACKEND_CREDENTIALS_PATH)),
            ),
            requested_ready_timeout_secs: u32::try_from(conf.honeypot.control_plane.request_timeout.as_secs())
                .unwrap_or(u32::MAX)
                .max(1),
            events: Arc::new(Mutex::new(HoneypotEventJournal::new(event_tx))),
        })
    }

    pub fn bootstrap_path(&self) -> &str {
        self.frontend.bootstrap_path.as_ref()
    }

    pub fn events_path(&self) -> &str {
        self.frontend.events_path.as_ref()
    }

    pub fn control_plane(&self) -> Option<&HoneypotControlPlaneClient> {
        self.control_plane.as_ref()
    }

    pub async fn health_snapshot(&self) -> HoneypotProxyHealthSnapshot {
        let Some(client) = self.control_plane.as_ref() else {
            return HoneypotProxyHealthSnapshot {
                service_state: HoneypotProxyServiceState::Unavailable,
                control_plane_reachable: false,
                control_plane_service_state: None,
                degraded_reasons: vec!["control_plane_not_configured".to_owned()],
            };
        };

        let request = HealthRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("honeypot-health-{}", uuid::Uuid::new_v4()),
        };

        match client.health(&request).await {
            Ok(response) => {
                let dependency_state = HoneypotDependencyServiceState::from(response.service_state);
                let mut degraded_reasons = response.degraded_reasons;
                if degraded_reasons.is_empty() {
                    match dependency_state {
                        HoneypotDependencyServiceState::Ready => {}
                        HoneypotDependencyServiceState::Degraded => {
                            degraded_reasons.push("control_plane_degraded".to_owned());
                        }
                        HoneypotDependencyServiceState::Unsafe => {
                            degraded_reasons.push("control_plane_unsafe".to_owned());
                        }
                    }
                }

                let service_state = match dependency_state {
                    HoneypotDependencyServiceState::Ready => HoneypotProxyServiceState::Ready,
                    HoneypotDependencyServiceState::Degraded => HoneypotProxyServiceState::Degraded,
                    HoneypotDependencyServiceState::Unsafe => HoneypotProxyServiceState::Unavailable,
                };

                HoneypotProxyHealthSnapshot {
                    service_state,
                    control_plane_reachable: true,
                    control_plane_service_state: Some(dependency_state),
                    degraded_reasons,
                }
            }
            Err(error) => {
                let (reason_code, reachable) = health_failure(&error);
                HoneypotProxyHealthSnapshot {
                    service_state: HoneypotProxyServiceState::Unavailable,
                    control_plane_reachable: reachable,
                    control_plane_service_state: None,
                    degraded_reasons: vec![reason_code.to_owned()],
                }
            }
        }
    }

    pub fn activate_system_kill(&self) {
        self.kill_switch.activate_system_kill();
        self.events
            .lock()
            .push_proxy_status_degraded(Vec::new(), "system_kill_active");
    }

    fn ensure_new_session_allowed(&self, session_id: uuid::Uuid) -> anyhow::Result<()> {
        if self.kill_switch.halt_new_sessions() {
            self.events
                .lock()
                .push_proxy_status_degraded(vec![session_id.to_string()], "system_kill_active");
            anyhow::bail!("honeypot intake halted by system kill");
        }

        Ok(())
    }

    pub fn bootstrap_response(&self, sessions: RunningSessions) -> BootstrapResponse {
        let mut sessions = sessions.into_values().collect::<Vec<_>>();
        sessions.sort_by_key(|session| session.start_timestamp);

        let journal = self.events.lock();

        BootstrapResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("honeypot-bootstrap-{}", uuid::Uuid::new_v4()),
            generated_at: now_rfc3339(),
            replay_cursor: journal.latest_cursor(),
            sessions: sessions
                .into_iter()
                .map(|session| journal.bootstrap_session(&session))
                .collect(),
        }
    }

    pub fn stream_from_cursor(
        &self,
        cursor: &str,
    ) -> Result<(Vec<EventEnvelope>, broadcast::Receiver<EventEnvelope>), HoneypotCursorError> {
        self.events.lock().subscribe_from_cursor(cursor)
    }

    pub fn session_metadata_patch(&self, session_id: uuid::Uuid) -> Option<HoneypotSessionMetadataPatch> {
        self.events.lock().session_metadata_patch(&session_id.to_string())
    }

    pub async fn prepare_rdp_session(
        &self,
        session_id: uuid::Uuid,
        application_protocol: ApplicationProtocol,
        time_to_live: SessionTtl,
        token: &str,
        attacker_addr: SocketAddr,
    ) -> anyhow::Result<()> {
        self.ensure_new_session_allowed(session_id)?;

        let Some(attacker_protocol) = attacker_protocol_for_protocol(application_protocol) else {
            return Ok(());
        };

        if self.events.lock().session_binding(&session_id.to_string()).is_some() {
            return Ok(());
        }

        let Some(client) = self.control_plane.as_ref() else {
            return Ok(());
        };

        let session_id = session_id.to_string();
        let request = AcquireVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("honeypot-acquire-{session_id}"),
            session_id: session_id.clone(),
            requested_pool: HONEYPOT_DEFAULT_POOL.to_owned(),
            requested_ready_timeout_secs: self.requested_ready_timeout_secs,
            stream_policy: stream_policy(self.stream.source_kind),
            backend_credential_ref: format!("honeypot-backend-credential:{session_id}"),
            attacker_protocol,
        };

        let response = match client.acquire_vm(&request).await {
            Ok(response) => response,
            Err(error) => {
                let (reason_code, terminal_outcome) = acquire_failure(&error);
                let mut events = self.events.lock();
                events.push_proxy_status_degraded(vec![session_id.clone()], reason_code);
                events.push_prepare_terminal(&session_id, attacker_addr, terminal_outcome, reason_code);
                return Err(anyhow::Error::new(error)).context("acquire honeypot vm");
            }
        };

        let credential_mapping = self
            .backend_credentials
            .resolve(&response.backend_credential_ref)
            .with_context(|| format!("resolve backend credential ref {}", response.backend_credential_ref))?;
        let binding = HoneypotSessionBinding::from_acquire_response(&response, attacker_addr);

        if let Err(error) =
            self.provision_session_credentials(&session_id, token, time_to_live, &binding, credential_mapping)
        {
            self.cleanup_failed_prepare(&session_id, &binding).await;
            return Err(error);
        }

        self.events.lock().bind_session(&session_id, binding);

        Ok(())
    }

    pub async fn record_session_started(&self, session: &SessionInfo) -> anyhow::Result<()> {
        let session_id = session.id.to_string();
        let prepared_binding = { self.events.lock().session_binding(&session_id) };
        if let Some(binding) = prepared_binding {
            let mut events = self.events.lock();
            events.push_session_started(session, &binding.attacker_addr);
            events.push_session_assigned(&session_id, &binding);
            return Ok(());
        }

        self.events.lock().push_session_started(session, "unknown");

        let Some(client) = self.control_plane.as_ref() else {
            return Ok(());
        };

        let Some(attacker_protocol) = attacker_protocol_for_session(session) else {
            return Ok(());
        };

        let request = AcquireVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("honeypot-acquire-{session_id}"),
            session_id: session_id.clone(),
            requested_pool: HONEYPOT_DEFAULT_POOL.to_owned(),
            requested_ready_timeout_secs: self.requested_ready_timeout_secs,
            stream_policy: stream_policy(self.stream.source_kind),
            backend_credential_ref: format!("honeypot-backend-credential:{session_id}"),
            attacker_protocol,
        };

        match client.acquire_vm(&request).await {
            Ok(response) => {
                let binding =
                    HoneypotSessionBinding::from_acquire_response(&response, SocketAddr::from(([0, 0, 0, 0], 0)));
                let mut events = self.events.lock();
                events.bind_session(&session_id, binding.clone());
                events.push_session_assigned(&session_id, &binding);
                Ok(())
            }
            Err(error) => {
                let (reason_code, terminal_outcome) = acquire_failure(&error);
                let mut events = self.events.lock();
                events.push_proxy_status_degraded(vec![session_id.clone()], reason_code);
                match terminal_outcome {
                    TerminalOutcome::BootTimeout => events.push_boot_timeout(session, reason_code),
                    _ => events.push_no_lease(session, reason_code),
                }
                Err(anyhow::Error::new(error)).context("acquire honeypot vm")
            }
        }
    }

    pub async fn record_session_ended(
        &self,
        session: &SessionInfo,
        kill: Option<SessionKillMetadata>,
    ) -> anyhow::Result<()> {
        let session_id = session.id.to_string();
        let binding = self.events.lock().take_session_binding(&session_id);
        let recycle_expected = binding.is_some();
        let was_killed = kill.is_some();
        {
            let mut events = self.events.lock();
            if let Some(kill) = kill {
                events.push_session_killed(session, kill);
            } else {
                events.push_session_ended(session, recycle_expected);
            }
        }

        let Some(binding) = binding else {
            return Ok(());
        };

        self.revoke_session_credentials(session.id, &binding);

        let Some(client) = self.control_plane.as_ref() else {
            self.events
                .lock()
                .push_proxy_status_degraded(vec![session_id], "control_plane_unavailable_during_release");
            return Ok(());
        };

        let (recycle_reason, force_quarantine) = match kill.map(|kill| kill.reason) {
            Some(SessionKillReason::OperatorQuarantine) => ("operator_quarantine", true),
            Some(_) => ("session_killed", false),
            None => ("proxy_forwarding_ended", false),
        };

        let release_request = ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("honeypot-release-{}", binding.vm_lease_id),
            session_id: session.id.to_string(),
            release_reason: recycle_reason.to_owned(),
            terminal_outcome: if was_killed {
                "killed".to_owned()
            } else {
                "disconnected".to_owned()
            },
        };

        if let Err(error) = client.release_vm(&binding.vm_lease_id, &release_request).await {
            self.events
                .lock()
                .push_proxy_status_degraded(vec![session_id], release_failure(&error));
            return Ok(());
        }

        self.events.lock().push_session_recycle_requested(
            &session.id.to_string(),
            &binding.vm_lease_id,
            recycle_reason,
            "proxy",
        );

        let recycle_response = match client
            .recycle_vm(
                &binding.vm_lease_id,
                &RecycleVmRequest {
                    schema_version: honeypot_contracts::SCHEMA_VERSION,
                    request_id: format!("honeypot-recycle-{}", binding.vm_lease_id),
                    session_id: session.id.to_string(),
                    recycle_reason: recycle_reason.to_owned(),
                    quarantine_on_failure: true,
                    force_quarantine,
                },
            )
            .await
        {
            Ok(response) => response,
            Err(error) => {
                self.events
                    .lock()
                    .push_proxy_status_degraded(vec![session.id.to_string()], recycle_failure(&error));
                return Ok(());
            }
        };

        self.events
            .lock()
            .push_host_recycled(&session.id.to_string(), &binding.vm_lease_id, &recycle_response);

        Ok(())
    }

    pub async fn abort_prepared_session(&self, session_id: uuid::Uuid) -> anyhow::Result<()> {
        let session_id = session_id.to_string();
        let Some(binding) = self.events.lock().take_session_binding(&session_id) else {
            return Ok(());
        };

        self.revoke_session_credentials(
            uuid::Uuid::parse_str(&session_id).expect("session ID was created from uuid"),
            &binding,
        );
        self.cleanup_failed_prepare(&session_id, &binding).await;

        Ok(())
    }

    pub async fn issue_stream_token(&self, session: &SessionInfo) -> Result<StreamTokenResponse, HoneypotStreamError> {
        let session_id = session.id.to_string();
        let binding = self
            .events
            .lock()
            .session_binding(&session_id)
            .ok_or(HoneypotStreamError::NoActiveLease)?;

        let Some(client) = self.control_plane.as_ref() else {
            return Err(HoneypotStreamError::ControlPlaneUnavailable);
        };

        let endpoint = client
            .stream_endpoint(
                &binding.vm_lease_id,
                &StreamEndpointRequest {
                    schema_version: honeypot_contracts::SCHEMA_VERSION,
                    request_id: format!("honeypot-stream-endpoint-{session_id}"),
                    session_id: session_id.clone(),
                    preferred_transport: self.stream.transport,
                },
            )
            .await
            .map_err(|error| {
                let (reason_code, failure_code, retryable) = stream_failure(&error);
                let mut events = self.events.lock();
                events.push_proxy_status_degraded(vec![session_id.clone()], reason_code);
                events.push_session_stream_failed(
                    &session_id,
                    Some(binding.vm_lease_id.clone()),
                    failure_code,
                    retryable,
                );
                if matches!(error.error_code(), Some(ErrorCode::StreamUnavailable)) {
                    HoneypotStreamError::StreamUnavailable
                } else {
                    HoneypotStreamError::control_plane(error)
                }
            })?;

        if !endpoint.source_ready {
            self.events.lock().push_session_stream_failed(
                &session_id,
                Some(binding.vm_lease_id.clone()),
                ErrorCode::StreamUnavailable,
                true,
            );
            return Err(HoneypotStreamError::StreamUnavailable);
        }

        let issued_at = now_rfc3339();
        let stream_binding = self
            .events
            .lock()
            .store_stream_binding(&session_id, endpoint.expires_at);

        let response = StreamTokenResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("honeypot-stream-token-{}", uuid::Uuid::new_v4()),
            session_id: session_id.clone(),
            vm_lease_id: binding.vm_lease_id.clone(),
            stream_id: stream_binding.stream_id.clone(),
            stream_endpoint: stream_binding.stream_endpoint.clone(),
            transport: self.stream.transport,
            issued_at: issued_at.clone(),
            expires_at: stream_binding.token_expires_at.clone(),
        };

        self.events.lock().push_session_stream_ready(
            &session_id,
            &binding.vm_lease_id,
            &stream_binding,
            response.transport,
            issued_at,
        );

        Ok(response)
    }

    fn provision_session_credentials(
        &self,
        session_id: &str,
        token: &str,
        time_to_live: SessionTtl,
        binding: &HoneypotSessionBinding,
        mapping: AppCredentialMapping,
    ) -> anyhow::Result<()> {
        self.credential_store.provision(CredentialProvisionRequest {
            token: token.to_owned(),
            mapping: Some(mapping),
            time_to_live: credential_mapping_ttl(time_to_live),
            binding: Some(CredentialBinding {
                session_id: Some(uuid::Uuid::parse_str(session_id).expect("session ID was created from uuid")),
                vm_lease_id: Some(binding.vm_lease_id.clone()),
                credential_mapping_id: Some(binding.credential_mapping_id.clone()),
                backend_credential_ref: Some(binding.backend_credential_ref.clone()),
            }),
        })?;

        Ok(())
    }

    fn revoke_session_credentials(&self, session_id: uuid::Uuid, binding: &HoneypotSessionBinding) {
        let removed = self.credential_store.remove_by_session_id(session_id);

        if removed.is_empty() {
            let _ = self.credential_store.remove_by_vm_lease_id(&binding.vm_lease_id);
        }
    }

    async fn cleanup_failed_prepare(&self, session_id: &str, binding: &HoneypotSessionBinding) {
        let Some(client) = self.control_plane.as_ref() else {
            return;
        };

        let release_request = ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("honeypot-release-{}", binding.vm_lease_id),
            session_id: session_id.to_owned(),
            release_reason: "prepare_failed".to_owned(),
            terminal_outcome: "prepare_failed".to_owned(),
        };
        let _ = client.release_vm(&binding.vm_lease_id, &release_request).await;
        let _ = client
            .recycle_vm(
                &binding.vm_lease_id,
                &RecycleVmRequest {
                    schema_version: honeypot_contracts::SCHEMA_VERSION,
                    request_id: format!("honeypot-recycle-{}", binding.vm_lease_id),
                    session_id: session_id.to_owned(),
                    recycle_reason: "prepare_failed".to_owned(),
                    quarantine_on_failure: true,
                    force_quarantine: false,
                },
            )
            .await;
    }
}

#[derive(Clone)]
struct HoneypotFrontendRuntime {
    bootstrap_path: Arc<str>,
    events_path: Arc<str>,
}

impl HoneypotFrontendRuntime {
    fn from_conf(conf: &HoneypotFrontendConf) -> Self {
        Self {
            bootstrap_path: Arc::<str>::from(conf.bootstrap_path.as_str()),
            events_path: Arc::<str>::from(conf.events_path.as_str()),
        }
    }
}

#[derive(Clone)]
struct HoneypotStreamRuntime {
    source_kind: HoneypotStreamSourceKind,
    transport: StreamTransport,
}

impl HoneypotStreamRuntime {
    fn from_conf(conf: &HoneypotStreamConf) -> Self {
        let transport = match conf.source_kind {
            HoneypotStreamSourceKind::GatewayRecording => StreamTransport::Websocket,
        };

        Self {
            source_kind: conf.source_kind,
            transport,
        }
    }
}

#[derive(Clone)]
struct HoneypotKillSwitchRuntime {
    halt_new_sessions_on_system_kill: bool,
    state: Arc<Mutex<HoneypotKillSwitchState>>,
}

impl HoneypotKillSwitchRuntime {
    fn from_conf(conf: &HoneypotKillSwitchConf) -> Self {
        Self {
            halt_new_sessions_on_system_kill: conf.halt_new_sessions_on_system_kill,
            state: Arc::new(Mutex::new(HoneypotKillSwitchState::default())),
        }
    }

    fn activate_system_kill(&self) {
        self.state.lock().system_kill_active = true;
    }

    fn halt_new_sessions(&self) -> bool {
        self.halt_new_sessions_on_system_kill && self.state.lock().system_kill_active
    }
}

#[derive(Debug, Default)]
struct HoneypotKillSwitchState {
    system_kill_active: bool,
}

#[derive(Clone)]
struct HoneypotBackendCredentialResolver {
    path: Arc<Utf8PathBuf>,
}

impl HoneypotBackendCredentialResolver {
    fn new(path: impl Into<Utf8PathBuf>) -> Self {
        Self {
            path: Arc::new(path.into()),
        }
    }

    fn resolve(&self, backend_credential_ref: &str) -> anyhow::Result<AppCredentialMapping> {
        let contents = std::fs::read_to_string(self.path.as_std_path())
            .with_context(|| format!("read backend credential file {}", self.path))?;
        let mappings = serde_json::from_str::<HashMap<String, AppCredentialMapping>>(&contents)
            .with_context(|| format!("parse backend credential file {}", self.path))?;

        mappings.get(backend_credential_ref).cloned().with_context(|| {
            format!(
                "backend credential ref {backend_credential_ref} not found in {}",
                self.path
            )
        })
    }
}

struct HoneypotEventJournal {
    events: VecDeque<EventEnvelope>,
    session_bindings: HashMap<String, HoneypotSessionBinding>,
    session_sequences: HashMap<String, u64>,
    sender: broadcast::Sender<EventEnvelope>,
}

impl HoneypotEventJournal {
    fn new(sender: broadcast::Sender<EventEnvelope>) -> Self {
        Self {
            events: VecDeque::with_capacity(HONEYPOT_EVENT_BUFFER_CAPACITY),
            session_bindings: HashMap::new(),
            session_sequences: HashMap::new(),
            sender,
        }
    }

    fn subscribe_from_cursor(
        &self,
        cursor: &str,
    ) -> Result<(Vec<EventEnvelope>, broadcast::Receiver<EventEnvelope>), HoneypotCursorError> {
        let cursor = cursor.parse::<u64>().map_err(|_| HoneypotCursorError::CursorExpired)?;
        let receiver = self.sender.subscribe();

        if self.events.is_empty() {
            return if cursor == 0 {
                Ok((Vec::new(), receiver))
            } else {
                Err(HoneypotCursorError::CursorExpired)
            };
        }

        let oldest = self
            .events
            .front()
            .and_then(|event| event.global_cursor.parse::<u64>().ok())
            .unwrap_or(0);
        let newest = self
            .events
            .back()
            .and_then(|event| event.global_cursor.parse::<u64>().ok())
            .unwrap_or(0);

        if cursor < oldest.saturating_sub(1) || cursor > newest {
            return Err(HoneypotCursorError::CursorExpired);
        }

        Ok((
            self.events
                .iter()
                .filter(|event| event.global_cursor.parse::<u64>().ok().unwrap_or(0) > cursor)
                .cloned()
                .collect(),
            receiver,
        ))
    }

    fn latest_cursor(&self) -> String {
        self.events
            .back()
            .map(|event| event.global_cursor.clone())
            .unwrap_or_else(|| "0".to_owned())
    }

    fn session_metadata_patch(&self, session_id: &str) -> Option<HoneypotSessionMetadataPatch> {
        let binding = self.session_bindings.get(session_id);
        let session_events = self
            .events
            .iter()
            .filter(|event| event.session_id.as_deref() == Some(session_id))
            .collect::<Vec<_>>();

        if binding.is_none() && session_events.is_empty() {
            return None;
        }

        let mut patch = HoneypotSessionMetadataPatch {
            state: Some(if binding.is_some() {
                SessionState::Assigned
            } else {
                SessionState::Connected
            }),
            ..Default::default()
        };

        for event in session_events {
            match &event.payload {
                EventPayload::SessionStarted {
                    attacker_addr,
                    listener_id,
                    session_state,
                    ..
                } => {
                    patch.state = Some(*session_state);
                    patch.attacker_source = Some(HoneypotAttackerSource {
                        attacker_addr: attacker_addr.clone(),
                        listener_id: listener_id.clone(),
                    });
                }
                EventPayload::SessionAssigned {
                    vm_name,
                    guest_rdp_addr,
                    attestation_ref,
                    ..
                } => {
                    patch.state = Some(SessionState::Assigned);
                    patch.assignment = event.vm_lease_id.clone().map(|vm_lease_id| HoneypotVmAssignment {
                        vm_lease_id,
                        vm_name: vm_name.clone(),
                        guest_rdp_addr: guest_rdp_addr.clone(),
                        attestation_ref: attestation_ref.clone(),
                        backend_credential_ref: None,
                    });
                }
                EventPayload::SessionStreamReady {
                    transport,
                    stream_endpoint,
                    token_expires_at,
                    stream_state,
                    ..
                } => {
                    patch.state = Some(SessionState::Ready);
                    patch.stream = Some(HoneypotStreamMetadata {
                        state: *stream_state,
                        stream_id: event.stream_id.clone(),
                        transport: Some(*transport),
                        stream_endpoint: Some(stream_endpoint.clone()),
                        token_expires_at: Some(token_expires_at.clone()),
                    });
                }
                EventPayload::SessionEnded {
                    terminal_outcome,
                    disconnect_reason,
                    ..
                } => {
                    patch.state = Some(SessionState::Disconnected);
                    patch.terminal = Some(HoneypotTerminalMetadata {
                        outcome: *terminal_outcome,
                        disconnect_reason: Some(disconnect_reason.clone()),
                        kill_scope: None,
                        killed_by_operator_id: None,
                        kill_reason: None,
                    });
                }
                EventPayload::SessionKilled {
                    kill_scope,
                    killed_by_operator_id,
                    kill_reason,
                    ..
                } => {
                    patch.state = Some(SessionState::Killed);
                    patch.terminal = Some(HoneypotTerminalMetadata {
                        outcome: TerminalOutcome::Killed,
                        disconnect_reason: None,
                        kill_scope: Some(*kill_scope),
                        killed_by_operator_id: Some(killed_by_operator_id.clone()),
                        kill_reason: Some(kill_reason.clone()),
                    });
                }
                EventPayload::SessionRecycleRequested { .. } => {
                    patch.state = Some(SessionState::RecycleRequested);
                }
                EventPayload::HostRecycled { .. } => {
                    patch.state = Some(SessionState::Recycled);
                }
                EventPayload::SessionStreamFailed { stream_state, .. } => {
                    let mut stream = patch.stream.take().unwrap_or(HoneypotStreamMetadata {
                        state: *stream_state,
                        stream_id: None,
                        transport: None,
                        stream_endpoint: None,
                        token_expires_at: None,
                    });
                    stream.state = *stream_state;
                    patch.stream = Some(stream);
                }
                EventPayload::ProxyStatusDegraded { .. } => {}
            }
        }

        if let Some(binding) = binding {
            patch.attacker_source = Some(HoneypotAttackerSource {
                attacker_addr: binding.attacker_addr.clone(),
                listener_id: "gateway".to_owned(),
            });
            patch.assignment = Some(HoneypotVmAssignment {
                vm_lease_id: binding.vm_lease_id.clone(),
                vm_name: binding.vm_name.clone(),
                guest_rdp_addr: format!("{}:{}", binding.guest_rdp_addr, binding.guest_rdp_port),
                attestation_ref: binding.attestation_ref.clone(),
                backend_credential_ref: Some(binding.backend_credential_ref.clone()),
            });

            if let Some(stream) = &binding.stream {
                let mut metadata = patch.stream.take().unwrap_or(HoneypotStreamMetadata {
                    state: StreamState::Ready,
                    stream_id: None,
                    transport: None,
                    stream_endpoint: None,
                    token_expires_at: None,
                });
                metadata.stream_id = Some(stream.stream_id.clone());
                metadata.stream_endpoint = Some(stream.stream_endpoint.clone());
                metadata.token_expires_at = Some(stream.token_expires_at.clone());
                patch.stream = Some(metadata);
            }
        }

        Some(patch)
    }

    fn bootstrap_session(&self, session: &SessionInfo) -> BootstrapSession {
        let session_id = session.id.to_string();
        let latest = self.latest_event_for_session(&session_id);
        let binding = self.session_bindings.get(&session_id);
        let metadata = session.honeypot.as_ref();

        let mut vm_lease_id = metadata
            .and_then(|metadata| {
                metadata
                    .assignment
                    .as_ref()
                    .map(|assignment| assignment.vm_lease_id.clone())
            })
            .or_else(|| binding.map(|binding| binding.vm_lease_id.clone()));
        let mut state = metadata.map(|metadata| metadata.state).unwrap_or_else(|| {
            if vm_lease_id.is_some() {
                SessionState::Assigned
            } else {
                SessionState::Connected
            }
        });
        let mut last_event_id = format!("bootstrap:{}", session.id);
        let mut last_session_seq = 0;
        let mut stream_state = metadata
            .and_then(|metadata| metadata.stream.as_ref().map(|stream| stream.state))
            .unwrap_or(StreamState::Pending);
        let mut stream_preview = metadata
            .and_then(|metadata| metadata.stream.as_ref())
            .and_then(|stream| {
                Some(StreamPreview {
                    stream_id: stream.stream_id.clone()?,
                    transport: stream.transport?,
                    stream_endpoint: stream.stream_endpoint.clone()?,
                    token_expires_at: stream.token_expires_at.clone()?,
                })
            });

        if let Some(event) = latest {
            if vm_lease_id.is_none() {
                vm_lease_id = event.vm_lease_id.clone();
            }
            last_event_id = event.event_id.clone();
            last_session_seq = event.session_seq;

            match &event.payload {
                EventPayload::SessionStarted {
                    session_state: event_state,
                    ..
                } if metadata.is_none() => state = *event_state,
                EventPayload::SessionAssigned { .. } if metadata.is_none() => state = SessionState::Assigned,
                EventPayload::SessionStreamReady {
                    transport,
                    stream_endpoint,
                    token_expires_at,
                    stream_state: ready_state,
                    ..
                } => {
                    if metadata.is_none() {
                        state = SessionState::Ready;
                    }
                    stream_state = metadata
                        .and_then(|metadata| metadata.stream.as_ref().map(|stream| stream.state))
                        .unwrap_or(*ready_state);
                    if stream_preview.is_none()
                        && let Some(stream_id) = event.stream_id.clone()
                    {
                        stream_preview = Some(StreamPreview {
                            stream_id,
                            transport: *transport,
                            stream_endpoint: stream_endpoint.clone(),
                            token_expires_at: token_expires_at.clone(),
                        });
                    }
                }
                EventPayload::SessionEnded { .. } if metadata.is_none() => state = SessionState::Disconnected,
                EventPayload::SessionKilled { .. } if metadata.is_none() => state = SessionState::Killed,
                EventPayload::SessionRecycleRequested { .. } if metadata.is_none() => {
                    state = SessionState::RecycleRequested
                }
                EventPayload::HostRecycled { .. } if metadata.is_none() => state = SessionState::Recycled,
                EventPayload::SessionStreamFailed {
                    stream_state: failed_state,
                    ..
                } => {
                    stream_state = metadata
                        .and_then(|metadata| metadata.stream.as_ref().map(|stream| stream.state))
                        .unwrap_or(*failed_state);
                }
                EventPayload::ProxyStatusDegraded { .. } => {}
                EventPayload::SessionStarted { .. }
                | EventPayload::SessionAssigned { .. }
                | EventPayload::SessionEnded { .. }
                | EventPayload::SessionKilled { .. }
                | EventPayload::SessionRecycleRequested { .. }
                | EventPayload::HostRecycled { .. } => {}
            }
        }

        BootstrapSession {
            session_id,
            vm_lease_id,
            state,
            last_event_id,
            last_session_seq,
            stream_state,
            stream_preview,
        }
    }

    fn push_session_started(&mut self, session: &SessionInfo, attacker_addr: &str) {
        self.push_event(
            Some(session.id.to_string()),
            None,
            None,
            EventPayload::SessionStarted {
                attacker_addr: attacker_addr.to_owned(),
                listener_id: "gateway".to_owned(),
                started_at: format_rfc3339(session.start_timestamp),
                session_state: SessionState::Connected,
            },
        );
    }

    fn push_session_assigned(&mut self, session_id: &str, binding: &HoneypotSessionBinding) {
        self.push_event(
            Some(session_id.to_owned()),
            Some(binding.vm_lease_id.clone()),
            None,
            EventPayload::SessionAssigned {
                assigned_at: now_rfc3339(),
                vm_name: binding.vm_name.clone(),
                guest_rdp_addr: format!("{}:{}", binding.guest_rdp_addr, binding.guest_rdp_port),
                attestation_ref: binding.attestation_ref.clone(),
            },
        );
    }

    fn push_terminal_event(
        &mut self,
        session: &SessionInfo,
        terminal_outcome: TerminalOutcome,
        disconnect_reason: &str,
        recycle_expected: bool,
    ) {
        self.push_event(
            Some(session.id.to_string()),
            None,
            None,
            EventPayload::SessionEnded {
                ended_at: now_rfc3339(),
                terminal_outcome,
                disconnect_reason: disconnect_reason.to_owned(),
                recycle_expected,
            },
        );
    }

    fn push_no_lease(&mut self, session: &SessionInfo, disconnect_reason: &str) {
        self.push_terminal_event(session, TerminalOutcome::NoLease, disconnect_reason, false);
    }

    fn push_boot_timeout(&mut self, session: &SessionInfo, disconnect_reason: &str) {
        self.push_terminal_event(session, TerminalOutcome::BootTimeout, disconnect_reason, false);
    }

    fn push_prepare_terminal(
        &mut self,
        session_id: &str,
        attacker_addr: SocketAddr,
        terminal_outcome: TerminalOutcome,
        disconnect_reason: &str,
    ) {
        self.push_event(
            Some(session_id.to_owned()),
            None,
            None,
            EventPayload::SessionStarted {
                attacker_addr: attacker_addr.to_string(),
                listener_id: "gateway".to_owned(),
                started_at: now_rfc3339(),
                session_state: SessionState::Connected,
            },
        );
        self.push_event(
            Some(session_id.to_owned()),
            None,
            None,
            EventPayload::SessionEnded {
                ended_at: now_rfc3339(),
                terminal_outcome,
                disconnect_reason: disconnect_reason.to_owned(),
                recycle_expected: false,
            },
        );
    }

    fn push_session_ended(&mut self, session: &SessionInfo, recycle_expected: bool) {
        self.push_event(
            Some(session.id.to_string()),
            None,
            None,
            EventPayload::SessionEnded {
                ended_at: now_rfc3339(),
                terminal_outcome: TerminalOutcome::Disconnected,
                disconnect_reason: "proxy_forwarding_ended".to_owned(),
                recycle_expected,
            },
        );
    }

    fn push_session_killed(&mut self, session: &SessionInfo, kill: SessionKillMetadata) {
        self.push_event(
            Some(session.id.to_string()),
            None,
            None,
            EventPayload::SessionKilled {
                killed_at: now_rfc3339(),
                kill_scope: kill.scope,
                killed_by_operator_id: kill
                    .operator_id
                    .map(|operator_id| operator_id.to_string())
                    .unwrap_or_else(|| "gateway".to_owned()),
                kill_reason: kill.reason.as_reason_code().to_owned(),
            },
        );
    }

    fn push_session_stream_ready(
        &mut self,
        session_id: &str,
        vm_lease_id: &str,
        stream: &HoneypotStreamBinding,
        transport: StreamTransport,
        ready_at: String,
    ) {
        self.push_event(
            Some(session_id.to_owned()),
            Some(vm_lease_id.to_owned()),
            Some(stream.stream_id.clone()),
            EventPayload::SessionStreamReady {
                ready_at,
                transport,
                stream_endpoint: stream.stream_endpoint.clone(),
                token_expires_at: stream.token_expires_at.clone(),
                stream_state: StreamState::Ready,
            },
        );
    }

    fn push_session_stream_failed(
        &mut self,
        session_id: &str,
        vm_lease_id: Option<String>,
        failure_code: ErrorCode,
        retryable: bool,
    ) {
        self.push_event(
            Some(session_id.to_owned()),
            vm_lease_id,
            None,
            EventPayload::SessionStreamFailed {
                failed_at: now_rfc3339(),
                failure_code,
                retryable,
                stream_state: StreamState::Failed,
            },
        );
    }

    fn push_session_recycle_requested(
        &mut self,
        session_id: &str,
        vm_lease_id: &str,
        recycle_reason: &str,
        requested_by: &str,
    ) {
        self.push_event(
            Some(session_id.to_owned()),
            Some(vm_lease_id.to_owned()),
            None,
            EventPayload::SessionRecycleRequested {
                requested_at: now_rfc3339(),
                recycle_reason: recycle_reason.to_owned(),
                requested_by: requested_by.to_owned(),
            },
        );
    }

    fn push_host_recycled(&mut self, session_id: &str, vm_lease_id: &str, response: &RecycleVmResponse) {
        self.push_event(
            Some(session_id.to_owned()),
            Some(vm_lease_id.to_owned()),
            None,
            EventPayload::HostRecycled {
                completed_at: now_rfc3339(),
                recycle_state: response.recycle_state,
                quarantined: response.quarantined,
                quarantine_reason: if response.quarantined {
                    Some("control_plane_recycled_into_quarantine".to_owned())
                } else {
                    None
                },
            },
        );
    }

    fn push_proxy_status_degraded(&mut self, affected_session_ids: Vec<String>, reason_code: &str) {
        self.push_event(
            None,
            None,
            None,
            EventPayload::ProxyStatusDegraded {
                degraded_at: now_rfc3339(),
                reason_code: reason_code.to_owned(),
                affected_session_ids,
            },
        );
    }

    fn bind_session(&mut self, session_id: &str, binding: HoneypotSessionBinding) {
        self.session_bindings.insert(session_id.to_owned(), binding);
    }

    fn session_binding(&self, session_id: &str) -> Option<HoneypotSessionBinding> {
        self.session_bindings.get(session_id).cloned()
    }

    fn take_session_binding(&mut self, session_id: &str) -> Option<HoneypotSessionBinding> {
        self.session_bindings.remove(session_id)
    }

    fn store_stream_binding(&mut self, session_id: &str, token_expires_at: String) -> HoneypotStreamBinding {
        let binding = self
            .session_bindings
            .get_mut(session_id)
            .expect("stream binding requires an active session lease");
        let stream = binding.stream.get_or_insert_with(HoneypotStreamBinding::new);
        stream.stream_endpoint = honeypot_stream_endpoint(session_id, &stream.stream_id);
        stream.token_expires_at = token_expires_at;
        stream.clone()
    }

    fn push_event(
        &mut self,
        session_id: Option<String>,
        vm_lease_id: Option<String>,
        stream_id: Option<String>,
        payload: EventPayload,
    ) -> EventEnvelope {
        let next_cursor = self
            .events
            .back()
            .and_then(|event| event.global_cursor.parse::<u64>().ok())
            .unwrap_or(0)
            + 1;
        let inherited = session_id
            .as_deref()
            .and_then(|id| self.latest_event_for_session(id))
            .cloned();
        let session_seq = session_id
            .as_ref()
            .map(|id| {
                let next = self.session_sequences.get(id).copied().unwrap_or(0) + 1;
                self.session_sequences.insert(id.clone(), next);
                next
            })
            .unwrap_or(0);

        let event = EventEnvelope {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            event_id: format!("honeypot-event-{next_cursor}"),
            correlation_id: format!("honeypot-correlation-{}", uuid::Uuid::new_v4()),
            emitted_at: now_rfc3339(),
            session_id,
            vm_lease_id: vm_lease_id.or_else(|| inherited.as_ref().and_then(|event| event.vm_lease_id.clone())),
            stream_id: stream_id.or_else(|| inherited.as_ref().and_then(|event| event.stream_id.clone())),
            global_cursor: next_cursor.to_string(),
            session_seq,
            payload,
        };

        if self.events.len() == HONEYPOT_EVENT_BUFFER_CAPACITY {
            self.events.pop_front();
        }

        self.events.push_back(event.clone());
        let _ = self.sender.send(event.clone());

        event
    }

    fn latest_event_for_session(&self, session_id: &str) -> Option<&EventEnvelope> {
        self.events
            .iter()
            .rev()
            .find(|event| event.session_id.as_deref() == Some(session_id))
    }
}

#[derive(Debug, Clone)]
struct HoneypotSessionBinding {
    vm_lease_id: String,
    vm_name: String,
    guest_rdp_addr: String,
    guest_rdp_port: u16,
    attestation_ref: String,
    backend_credential_ref: String,
    credential_mapping_id: String,
    attacker_addr: String,
    stream: Option<HoneypotStreamBinding>,
}

impl HoneypotSessionBinding {
    fn from_acquire_response(response: &AcquireVmResponse, attacker_addr: SocketAddr) -> Self {
        Self {
            vm_lease_id: response.vm_lease_id.clone(),
            vm_name: response.vm_name.clone(),
            guest_rdp_addr: response.guest_rdp_addr.clone(),
            guest_rdp_port: response.guest_rdp_port,
            attestation_ref: response.attestation_ref.clone(),
            backend_credential_ref: response.backend_credential_ref.clone(),
            credential_mapping_id: format!("honeypot-credential-map-{}", response.vm_lease_id),
            attacker_addr: attacker_addr.to_string(),
            stream: None,
        }
    }
}

#[derive(Debug, Clone)]
struct HoneypotStreamBinding {
    stream_id: String,
    stream_endpoint: String,
    token_expires_at: String,
}

impl HoneypotStreamBinding {
    fn new() -> Self {
        Self {
            stream_id: format!("stream-{}", uuid::Uuid::new_v4()),
            stream_endpoint: String::new(),
            token_expires_at: String::new(),
        }
    }
}

fn honeypot_stream_endpoint(session_id: &str, stream_id: &str) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("stream_id", stream_id);

    format!("/jet/honeypot/session/{session_id}/stream?{}", query.finish())
}

#[derive(Debug, Clone, Copy)]
pub enum HoneypotCursorError {
    CursorExpired,
}

#[derive(Debug)]
pub enum HoneypotStreamError {
    NoActiveLease,
    ControlPlaneUnavailable,
    ControlPlane(HoneypotControlPlaneRequestError),
    StreamUnavailable,
}

impl HoneypotStreamError {
    fn control_plane(error: HoneypotControlPlaneRequestError) -> Self {
        Self::ControlPlane(error)
    }
}

#[derive(Debug)]
pub enum HoneypotControlPlaneRequestError {
    Api(ErrorResponse),
    Transport(anyhow::Error),
}

impl HoneypotControlPlaneRequestError {
    fn api(error: ErrorResponse) -> Self {
        Self::Api(error)
    }

    fn transport(error: anyhow::Error) -> Self {
        Self::Transport(error)
    }

    fn error_code(&self) -> Option<ErrorCode> {
        match self {
            Self::Api(error) => Some(error.error_code),
            Self::Transport(_) => None,
        }
    }
}

impl std::fmt::Display for HoneypotControlPlaneRequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Api(error) => write!(f, "control-plane API error {:?}: {}", error.error_code, error.message),
            Self::Transport(error) => write!(f, "{error}"),
        }
    }
}

impl std::error::Error for HoneypotControlPlaneRequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Api(_) => None,
            Self::Transport(error) => Some(error.as_ref()),
        }
    }
}

#[derive(Clone)]
pub struct HoneypotControlPlaneClient {
    endpoint: url::Url,
    service_bearer_token: String,
    client: reqwest::Client,
}

impl HoneypotControlPlaneClient {
    fn from_conf(conf: &HoneypotControlPlaneConf) -> anyhow::Result<Option<Self>> {
        let Some(endpoint) = conf.endpoint.clone() else {
            return Ok(None);
        };

        let client = reqwest::Client::builder()
            .connect_timeout(conf.connect_timeout)
            .timeout(conf.request_timeout)
            .build()
            .context("build honeypot control-plane client")?;

        let service_bearer_token = resolve_service_bearer_token(conf)?;

        Ok(Some(Self {
            endpoint,
            service_bearer_token,
            client,
        }))
    }

    pub fn endpoint(&self) -> &url::Url {
        &self.endpoint
    }

    pub async fn acquire_vm(
        &self,
        request: &AcquireVmRequest,
    ) -> Result<AcquireVmResponse, HoneypotControlPlaneRequestError> {
        self.post_json("api/v1/vm/acquire", request).await
    }

    pub async fn release_vm(
        &self,
        vm_lease_id: &str,
        request: &ReleaseVmRequest,
    ) -> Result<ReleaseVmResponse, HoneypotControlPlaneRequestError> {
        self.post_json(&format!("api/v1/vm/{vm_lease_id}/release"), request)
            .await
    }

    pub async fn reset_vm(
        &self,
        vm_lease_id: &str,
        request: &ResetVmRequest,
    ) -> Result<ResetVmResponse, HoneypotControlPlaneRequestError> {
        self.post_json(&format!("api/v1/vm/{vm_lease_id}/reset"), request).await
    }

    pub async fn recycle_vm(
        &self,
        vm_lease_id: &str,
        request: &RecycleVmRequest,
    ) -> Result<RecycleVmResponse, HoneypotControlPlaneRequestError> {
        self.post_json(&format!("api/v1/vm/{vm_lease_id}/recycle"), request)
            .await
    }

    pub async fn health(&self, request: &HealthRequest) -> Result<HealthResponse, HoneypotControlPlaneRequestError> {
        self.get_json("api/v1/health", request).await
    }

    pub async fn stream_endpoint(
        &self,
        vm_lease_id: &str,
        request: &StreamEndpointRequest,
    ) -> Result<StreamEndpointResponse, HoneypotControlPlaneRequestError> {
        self.get_json(&format!("api/v1/vm/{vm_lease_id}/stream"), request).await
    }

    async fn post_json<Request, Response>(
        &self,
        path: &str,
        request: &Request,
    ) -> Result<Response, HoneypotControlPlaneRequestError>
    where
        Request: serde::Serialize + ?Sized,
        Response: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .post(self.url(path).map_err(HoneypotControlPlaneRequestError::transport)?)
            .bearer_auth(&self.service_bearer_token)
            .json(request)
            .send()
            .await
            .map_err(|error| {
                HoneypotControlPlaneRequestError::transport(
                    anyhow::Error::new(error).context(format!("send POST request to control-plane path {path}")),
                )
            })?;

        let response = ensure_control_plane_success("POST", path, response).await?;

        response.json::<Response>().await.map_err(|error| {
            HoneypotControlPlaneRequestError::transport(
                anyhow::Error::new(error).context(format!("decode control-plane POST response for path {path}")),
            )
        })
    }

    async fn get_json<Request, Response>(
        &self,
        path: &str,
        request: &Request,
    ) -> Result<Response, HoneypotControlPlaneRequestError>
    where
        Request: serde::Serialize + ?Sized,
        Response: serde::de::DeserializeOwned,
    {
        let response = self
            .client
            .get(self.url(path).map_err(HoneypotControlPlaneRequestError::transport)?)
            .bearer_auth(&self.service_bearer_token)
            .query(request)
            .send()
            .await
            .map_err(|error| {
                HoneypotControlPlaneRequestError::transport(
                    anyhow::Error::new(error).context(format!("send GET request to control-plane path {path}")),
                )
            })?;

        let response = ensure_control_plane_success("GET", path, response).await?;

        response.json::<Response>().await.map_err(|error| {
            HoneypotControlPlaneRequestError::transport(
                anyhow::Error::new(error).context(format!("decode control-plane GET response for path {path}")),
            )
        })
    }

    fn url(&self, path: &str) -> anyhow::Result<url::Url> {
        self.endpoint
            .join(path)
            .with_context(|| format!("join control-plane endpoint {} with path {path}", self.endpoint))
    }
}

async fn ensure_control_plane_success(
    method: &str,
    path: &str,
    response: reqwest::Response,
) -> Result<reqwest::Response, HoneypotControlPlaneRequestError> {
    let status = response.status();
    if status.is_success() {
        return Ok(response);
    }

    let body = response.bytes().await.map_err(|error| {
        HoneypotControlPlaneRequestError::transport(
            anyhow::Error::new(error).context(format!("read control-plane {method} error body for path {path}")),
        )
    })?;

    match serde_json::from_slice::<ErrorResponse>(&body) {
        Ok(error) => Err(HoneypotControlPlaneRequestError::api(error)),
        Err(parse_error) => {
            let body = String::from_utf8_lossy(&body).into_owned();
            Err(HoneypotControlPlaneRequestError::transport(anyhow::anyhow!(
                "control-plane {method} request failed for path {path} with {status}: {body} ({parse_error})"
            )))
        }
    }
}

fn acquire_failure(reason: &HoneypotControlPlaneRequestError) -> (&'static str, TerminalOutcome) {
    match reason.error_code() {
        Some(ErrorCode::NoCapacity) => ("no_capacity", TerminalOutcome::NoLease),
        Some(ErrorCode::HostUnavailable) => ("control_plane_host_unavailable", TerminalOutcome::NoLease),
        Some(ErrorCode::BootTimeout) => ("boot_timeout", TerminalOutcome::BootTimeout),
        _ => ("control_plane_acquire_failed", TerminalOutcome::NoLease),
    }
}

fn release_failure(reason: &HoneypotControlPlaneRequestError) -> &'static str {
    match reason.error_code() {
        Some(ErrorCode::HostUnavailable) => "control_plane_unavailable_during_release",
        Some(ErrorCode::LeaseNotFound) => "lease_not_found_during_release",
        Some(ErrorCode::LeaseStateConflict) => "lease_state_conflict_during_release",
        _ => "control_plane_release_failed",
    }
}

fn recycle_failure(reason: &HoneypotControlPlaneRequestError) -> &'static str {
    match reason.error_code() {
        Some(ErrorCode::RecycleFailed) => "recycle_failed",
        Some(ErrorCode::HostUnavailable) => "control_plane_unavailable_during_recycle",
        Some(ErrorCode::Quarantined) => "recycle_quarantined",
        _ => "control_plane_recycle_failed",
    }
}

fn stream_failure(reason: &HoneypotControlPlaneRequestError) -> (&'static str, ErrorCode, bool) {
    match reason {
        HoneypotControlPlaneRequestError::Api(error) => match error.error_code {
            ErrorCode::StreamUnavailable => ("stream_unavailable", ErrorCode::StreamUnavailable, error.retryable),
            ErrorCode::HostUnavailable => (
                "control_plane_stream_host_unavailable",
                ErrorCode::HostUnavailable,
                error.retryable,
            ),
            ErrorCode::BootTimeout => ("boot_timeout", ErrorCode::BootTimeout, error.retryable),
            other => ("control_plane_stream_failed", other, error.retryable),
        },
        HoneypotControlPlaneRequestError::Transport(_) => {
            ("control_plane_stream_endpoint_failed", ErrorCode::HostUnavailable, true)
        }
    }
}

fn health_failure(reason: &HoneypotControlPlaneRequestError) -> (&'static str, bool) {
    match reason {
        HoneypotControlPlaneRequestError::Api(error) => match error.error_code {
            ErrorCode::AuthFailed | ErrorCode::Unauthorized | ErrorCode::Forbidden => {
                ("control_plane_auth_failed", true)
            }
            ErrorCode::HostUnavailable => ("control_plane_host_unavailable", true),
            ErrorCode::InvalidRequest => ("control_plane_health_invalid_request", true),
            _ => ("control_plane_health_failed", true),
        },
        HoneypotControlPlaneRequestError::Transport(_) => ("control_plane_unavailable", false),
    }
}

fn resolve_service_bearer_token(conf: &HoneypotControlPlaneConf) -> anyhow::Result<String> {
    if let Some(path) = conf.service_bearer_token_file.as_deref() {
        return read_required_secret_file(path, "Honeypot.ControlPlane.ServiceBearerTokenFile");
    }

    conf.service_bearer_token
        .clone()
        .context("honeypot control-plane endpoint requires Honeypot.ControlPlane.ServiceBearerTokenFile or Honeypot.ControlPlane.ServiceBearerToken")
}

fn read_required_secret_file(path: &Path, field_name: &str) -> anyhow::Result<String> {
    let secret = std::fs::read_to_string(path).with_context(|| format!("read {field_name} from {}", path.display()))?;
    let secret = secret.trim();

    anyhow::ensure!(
        !secret.is_empty(),
        "{field_name} at {} must not be empty",
        path.display(),
    );

    Ok(secret.to_owned())
}

fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

fn format_rfc3339(timestamp: OffsetDateTime) -> String {
    timestamp
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_owned())
}

fn stream_policy(source_kind: HoneypotStreamSourceKind) -> StreamPolicy {
    match source_kind {
        HoneypotStreamSourceKind::GatewayRecording => StreamPolicy::GatewayRecording,
    }
}

fn attacker_protocol_for_session(session: &SessionInfo) -> Option<AttackerProtocol> {
    attacker_protocol_for_protocol(session.application_protocol.clone())
}

fn attacker_protocol_for_protocol(application_protocol: ApplicationProtocol) -> Option<AttackerProtocol> {
    match application_protocol {
        ApplicationProtocol::Known(Protocol::Rdp) => Some(AttackerProtocol::Rdp),
        _ => None,
    }
}

fn credential_mapping_ttl(time_to_live: SessionTtl) -> time::Duration {
    match time_to_live {
        SessionTtl::Unlimited => time::Duration::seconds(HONEYPOT_CREDENTIAL_MAPPING_TTL_SECS),
        SessionTtl::Limited { minutes } => time::Duration::seconds(
            i64::try_from(minutes.get())
                .unwrap_or(HONEYPOT_CREDENTIAL_MAPPING_TTL_SECS)
                .saturating_mul(60)
                .min(HONEYPOT_CREDENTIAL_MAPPING_TTL_SECS),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::net::Ipv4Addr;
    use std::path::PathBuf;
    use std::sync::Arc;

    use axum::extract::{Path, Query, State};
    use axum::http::header::AUTHORIZATION;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use honeypot_contracts::control_plane::{
        AcquireVmRequest, AcquireVmResponse, CaptureSourceKind, HealthRequest, HealthResponse, LeaseState, PoolState,
        RecycleState, RecycleVmRequest, RecycleVmResponse, ReleaseState, ReleaseVmRequest, ReleaseVmResponse,
        ServiceState, StreamEndpointRequest, StreamEndpointResponse,
    };
    use honeypot_contracts::error::{ErrorCode, ErrorResponse};
    use honeypot_contracts::events::{EventPayload, SessionState, StreamState, TerminalOutcome};
    use honeypot_contracts::stream::StreamTransport;
    use parking_lot::Mutex;
    use tokio::net::TcpListener;
    use tokio::sync::broadcast;
    use uuid::Uuid;

    use super::{
        HoneypotBackendCredentialResolver, HoneypotControlPlaneClient, HoneypotEventJournal, HoneypotFrontendRuntime,
        HoneypotKillSwitchRuntime, HoneypotRuntime, HoneypotStreamError, HoneypotStreamRuntime,
    };
    use crate::config::{
        HoneypotBrowserTransport, HoneypotControlPlaneConf, HoneypotFrontendConf, HoneypotKillSwitchConf,
        HoneypotStreamConf,
    };
    use crate::credential::{AppCredential, AppCredentialMapping, CredentialStoreHandle, Password};
    use crate::session::{
        ConnectionModeDetails, HoneypotSessionMetadata, HoneypotStreamMetadata, HoneypotVmAssignment, SessionInfo,
        SessionKillMetadata, SessionKillReason,
    };
    use crate::token::{ApplicationProtocol, Protocol, RecordingPolicy, SessionTtl};

    const TEST_CONTROL_PLANE_SERVICE_TOKEN: &str = "test-control-plane-service-token";
    const TEST_PREPARED_SESSION_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDMifQ.c2ln";

    fn assert_service_token(headers: &HeaderMap) {
        assert_eq!(
            headers.get(AUTHORIZATION).and_then(|value| value.to_str().ok()),
            Some("Bearer test-control-plane-service-token")
        );
    }

    fn username_password(username: &str, password: &str) -> AppCredential {
        AppCredential::UsernamePassword {
            username: username.to_owned(),
            password: Password::from(password),
        }
    }

    fn backend_mapping(proxy_username: &str, target_username: &str) -> AppCredentialMapping {
        AppCredentialMapping {
            proxy: username_password(proxy_username, "attacker-password"),
            target: username_password(target_username, "backend-password"),
        }
    }

    fn unique_temp_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("dgw-honeypot-{name}-{}", Uuid::new_v4()))
    }

    fn control_plane_test_error_status(error_code: ErrorCode) -> StatusCode {
        match error_code {
            ErrorCode::AuthFailed | ErrorCode::Unauthorized => StatusCode::UNAUTHORIZED,
            ErrorCode::Forbidden => StatusCode::FORBIDDEN,
            ErrorCode::InvalidRequest => StatusCode::BAD_REQUEST,
            ErrorCode::LeaseNotFound => StatusCode::NOT_FOUND,
            ErrorCode::LeaseConflict | ErrorCode::LeaseStateConflict | ErrorCode::Quarantined => StatusCode::CONFLICT,
            ErrorCode::NoCapacity
            | ErrorCode::ImageUntrusted
            | ErrorCode::HostUnavailable
            | ErrorCode::BootTimeout
            | ErrorCode::ResetFailed
            | ErrorCode::RecycleFailed
            | ErrorCode::StreamUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            ErrorCode::CursorExpired => StatusCode::CONFLICT,
        }
    }

    fn test_error_response(error_code: ErrorCode, message: &str, retryable: bool) -> ErrorResponse {
        ErrorResponse::new(format!("corr-test-{error_code:?}"), error_code, message, retryable)
    }

    #[tokio::test]
    async fn control_plane_client_reads_typed_health_response() {
        async fn health_handler(headers: HeaderMap) -> Json<HealthResponse> {
            assert_service_token(&headers);
            Json(HealthResponse {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                correlation_id: "corr-1".to_owned(),
                service_state: ServiceState::Ready,
                kvm_available: true,
                trusted_image_count: 1,
                active_lease_count: 0,
                quarantined_lease_count: 0,
                degraded_reasons: Vec::new(),
            })
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read test listener address");
        let server = tokio::spawn(async move {
            let router = Router::new().route("/api/v1/health", get(health_handler));
            axum::serve(listener, router).await.expect("serve test control-plane");
        });

        let conf = HoneypotControlPlaneConf {
            endpoint: Some(format!("http://{addr}/").parse().expect("parse endpoint")),
            request_timeout: std::time::Duration::from_secs(5),
            connect_timeout: std::time::Duration::from_secs(2),
            service_bearer_token: Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()),
            service_bearer_token_file: None,
        };

        let client = HoneypotControlPlaneClient::from_conf(&conf)
            .expect("build client")
            .expect("enabled client");

        let health = client
            .health(&HealthRequest {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                request_id: "req-1".to_owned(),
            })
            .await
            .expect("read health response");

        assert_eq!(client.endpoint().as_str(), format!("http://{addr}/"));
        assert_eq!(health.service_state, ServiceState::Ready);
        assert_eq!(health.trusted_image_count, 1);

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn control_plane_client_reads_service_token_from_secret_file() {
        let token_path = unique_temp_path("control-plane-service-token");
        std::fs::write(&token_path, format!("{TEST_CONTROL_PLANE_SERVICE_TOKEN}\n"))
            .expect("write control-plane service token");

        let conf = HoneypotControlPlaneConf {
            endpoint: Some("http://control-plane.internal/".parse().expect("parse endpoint")),
            request_timeout: std::time::Duration::from_secs(5),
            connect_timeout: std::time::Duration::from_secs(2),
            service_bearer_token: None,
            service_bearer_token_file: Some(token_path),
        };

        let client = HoneypotControlPlaneClient::from_conf(&conf)
            .expect("build client")
            .expect("enabled client");

        assert_eq!(client.service_bearer_token, TEST_CONTROL_PLANE_SERVICE_TOKEN);

        std::fs::remove_file(
            conf.service_bearer_token_file
                .as_ref()
                .expect("configured control-plane service token file"),
        )
        .expect("remove control-plane service token");
    }

    #[test]
    fn control_plane_client_rejects_missing_service_token_file() {
        let token_path = unique_temp_path("missing-control-plane-service-token");
        let conf = HoneypotControlPlaneConf {
            endpoint: Some("http://control-plane.internal/".parse().expect("parse endpoint")),
            request_timeout: std::time::Duration::from_secs(5),
            connect_timeout: std::time::Duration::from_secs(2),
            service_bearer_token: None,
            service_bearer_token_file: Some(token_path),
        };

        let error = match HoneypotControlPlaneClient::from_conf(&conf) {
            Ok(_) => panic!("missing service token file should fail"),
            Err(error) => error,
        };

        assert!(format!("{error:#}").contains("ServiceBearerTokenFile"), "{error:#}");
    }

    #[tokio::test]
    async fn bootstrap_response_includes_stream_preview_after_token_issue() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        let token = harness
            .runtime
            .issue_stream_token(&session)
            .await
            .expect("issue stream token");
        assert_eq!(token.transport, StreamTransport::Websocket);
        assert_eq!(
            token.stream_endpoint,
            format!(
                "/jet/honeypot/session/{}/stream?stream_id={}",
                session.id, token.stream_id
            )
        );

        let session = SessionInfo {
            honeypot: harness.runtime.session_metadata_patch(session.id).map(|patch| {
                let mut metadata = HoneypotSessionMetadata::default();
                if let Some(state) = patch.state {
                    metadata.state = state;
                }
                metadata.attacker_source = patch.attacker_source;
                metadata.assignment = patch.assignment;
                metadata.stream = patch.stream;
                metadata.terminal = patch.terminal;
                metadata
            }),
            ..session
        };

        let session_id = session.id;
        let mut sessions = HashMap::new();
        sessions.insert(session_id, session);

        let bootstrap = harness.runtime.bootstrap_response(sessions);

        assert_eq!(bootstrap.replay_cursor, "3");
        assert_eq!(bootstrap.sessions.len(), 1);
        assert_eq!(bootstrap.sessions[0].session_id, session_id.to_string());
        assert_eq!(
            bootstrap.sessions[0].vm_lease_id.as_deref(),
            Some(token.vm_lease_id.as_str())
        );
        assert_eq!(bootstrap.sessions[0].state, SessionState::Ready);
        assert_eq!(bootstrap.sessions[0].stream_state, StreamState::Ready);
        assert_eq!(
            bootstrap.sessions[0]
                .stream_preview
                .as_ref()
                .map(|preview| preview.stream_endpoint.as_str()),
            Some(token.stream_endpoint.as_str())
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn issue_stream_token_returns_proxy_owned_websocket_endpoint() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        let token = harness
            .runtime
            .issue_stream_token(&session)
            .await
            .expect("issue stream token");

        assert_eq!(token.transport, StreamTransport::Websocket);
        assert_eq!(
            token.stream_endpoint,
            format!(
                "/jet/honeypot/session/{}/stream?stream_id={}",
                session.id, token.stream_id
            )
        );
        assert_eq!(token.vm_lease_id, format!("lease-{}", session.id));

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn session_metadata_patch_reflects_connected_state_before_assignment() {
        let runtime = test_runtime_without_control_plane();
        let session = test_session();

        runtime
            .record_session_started(&session)
            .await
            .expect("record started session");

        let patch = runtime
            .session_metadata_patch(session.id)
            .expect("connected session metadata patch");

        assert_eq!(patch.state, Some(SessionState::Connected));
        assert_eq!(
            patch.attacker_source.as_ref().map(|source| source.listener_id.as_str()),
            Some("gateway")
        );
    }

    #[tokio::test]
    async fn session_metadata_patch_reflects_assignment_and_stream_state() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");

        let assigned = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("assigned session metadata patch");
        assert_eq!(assigned.state, Some(SessionState::Assigned));
        assert_eq!(
            assigned
                .assignment
                .as_ref()
                .map(|assignment| assignment.vm_lease_id.as_str()),
            Some(format!("lease-{}", session.id).as_str())
        );
        assert_eq!(
            assigned
                .attacker_source
                .as_ref()
                .map(|source| source.listener_id.as_str()),
            Some("gateway")
        );

        let token = harness
            .runtime
            .issue_stream_token(&session)
            .await
            .expect("issue stream token");

        let streamed = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("stream-ready session metadata patch");
        assert_eq!(streamed.state, Some(SessionState::Ready));
        assert_eq!(
            streamed.stream.as_ref().map(|stream| stream.state),
            Some(StreamState::Ready)
        );
        assert_eq!(
            streamed.stream.as_ref().and_then(|stream| stream.stream_id.as_deref()),
            Some(token.stream_id.as_str())
        );

        harness.shutdown().await;
    }

    #[test]
    fn bootstrap_response_uses_canonical_session_metadata() {
        let runtime = test_runtime_without_control_plane();
        let session = SessionInfo::builder()
            .id(Uuid::new_v4())
            .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
            .recording_policy(RecordingPolicy::None)
            .time_to_live(SessionTtl::Unlimited)
            .honeypot(HoneypotSessionMetadata {
                state: SessionState::Ready,
                attacker_source: None,
                assignment: Some(HoneypotVmAssignment {
                    vm_lease_id: "lease-bootstrap".to_owned(),
                    vm_name: "honeypot-bootstrap".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3389".to_owned(),
                    attestation_ref: "attestation:bootstrap".to_owned(),
                    backend_credential_ref: Some("backend-ref".to_owned()),
                }),
                stream: Some(HoneypotStreamMetadata {
                    state: StreamState::Ready,
                    stream_id: Some("stream-bootstrap".to_owned()),
                    transport: Some(StreamTransport::Websocket),
                    stream_endpoint: Some(
                        "/jet/honeypot/session/session-bootstrap/stream?stream_id=stream-bootstrap".to_owned(),
                    ),
                    token_expires_at: Some("2030-01-01T00:00:00Z".to_owned()),
                }),
                terminal: None,
            })
            .details(ConnectionModeDetails::Rdv)
            .build();

        let mut sessions = HashMap::new();
        sessions.insert(session.id, session);

        let bootstrap = runtime.bootstrap_response(sessions);

        assert_eq!(bootstrap.sessions.len(), 1);
        assert_eq!(bootstrap.sessions[0].state, SessionState::Ready);
        assert_eq!(bootstrap.sessions[0].vm_lease_id.as_deref(), Some("lease-bootstrap"));
        assert_eq!(bootstrap.sessions[0].stream_state, StreamState::Ready);
        assert_eq!(
            bootstrap.sessions[0]
                .stream_preview
                .as_ref()
                .map(|preview| preview.stream_id.as_str()),
            Some("stream-bootstrap")
        );
    }

    #[tokio::test]
    async fn event_stream_replays_from_cursor() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        let token = harness
            .runtime
            .issue_stream_token(&session)
            .await
            .expect("issue stream token");

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");

        assert_eq!(replay.len(), 3);
        assert!(matches!(replay[0].payload, EventPayload::SessionStarted { .. }));
        assert!(matches!(replay[1].payload, EventPayload::SessionAssigned { .. }));
        assert!(matches!(replay[2].payload, EventPayload::SessionStreamReady { .. }));
        assert_eq!(replay[2].stream_id.as_deref(), Some(token.stream_id.as_str()));

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn session_end_releases_and_recycles_the_active_lease() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .runtime
            .record_session_ended(&session, None)
            .await
            .expect("record ended session");

        assert_eq!(
            harness.state.released.lock().as_slice(),
            &[format!("lease-{}", session.id)]
        );
        assert_eq!(
            harness.state.recycled.lock().as_slice(),
            &[format!("lease-{}", session.id)]
        );

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");
        assert_eq!(replay.len(), 5);
        assert!(matches!(replay[0].payload, EventPayload::SessionStarted { .. }));
        assert!(matches!(replay[1].payload, EventPayload::SessionAssigned { .. }));
        assert!(matches!(
            replay[2].payload,
            EventPayload::SessionEnded {
                recycle_expected: true,
                ..
            }
        ));
        assert!(matches!(
            replay[3].payload,
            EventPayload::SessionRecycleRequested { .. }
        ));
        assert!(matches!(replay[4].payload, EventPayload::HostRecycled { .. }));

        let recycled = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("recycled session metadata patch");
        assert_eq!(recycled.state, Some(SessionState::Recycled));
        assert_eq!(
            recycled.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::Disconnected)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn record_session_started_maps_no_capacity_to_no_lease_and_degraded_state() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();
        harness
            .state
            .set_acquire_error(ErrorCode::NoCapacity, "no capacity", false);

        let error = harness
            .runtime
            .record_session_started(&session)
            .await
            .expect_err("no-capacity acquire should fail");
        assert!(format!("{error:#}").contains("acquire honeypot vm"));

        let replay = harness.runtime.stream_from_cursor("0").expect("valid cursor").0;
        assert_eq!(replay.len(), 3);
        assert!(matches!(replay[0].payload, EventPayload::SessionStarted { .. }));
        assert!(matches!(
            &replay[1].payload,
            EventPayload::ProxyStatusDegraded { reason_code, .. } if reason_code == "no_capacity"
        ));
        assert!(matches!(
            &replay[2].payload,
            EventPayload::SessionEnded {
                terminal_outcome: TerminalOutcome::NoLease,
                disconnect_reason,
                recycle_expected: false,
                ..
            } if disconnect_reason == "no_capacity"
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after no-capacity failure");
        assert_eq!(patch.state, Some(SessionState::Disconnected));
        assert_eq!(
            patch.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::NoLease)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn record_session_started_maps_boot_timeout_to_boot_timeout_terminal_state() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();
        harness
            .state
            .set_acquire_error(ErrorCode::BootTimeout, "boot timed out", true);

        let error = harness
            .runtime
            .record_session_started(&session)
            .await
            .expect_err("boot-timeout acquire should fail");
        assert!(format!("{error:#}").contains("acquire honeypot vm"));

        let replay = harness.runtime.stream_from_cursor("0").expect("valid cursor").0;
        assert_eq!(replay.len(), 3);
        assert!(matches!(
            &replay[1].payload,
            EventPayload::ProxyStatusDegraded { reason_code, .. } if reason_code == "boot_timeout"
        ));
        assert!(matches!(
            &replay[2].payload,
            EventPayload::SessionEnded {
                terminal_outcome: TerminalOutcome::BootTimeout,
                disconnect_reason,
                recycle_expected: false,
                ..
            } if disconnect_reason == "boot_timeout"
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after boot-timeout failure");
        assert_eq!(patch.state, Some(SessionState::Disconnected));
        assert_eq!(
            patch.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::BootTimeout)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn record_session_ended_returns_ok_when_release_fails_and_degrades() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .state
            .set_release_error(ErrorCode::HostUnavailable, "host unavailable", true);

        harness
            .runtime
            .record_session_ended(&session, None)
            .await
            .expect("release failure should not fail proxy teardown");

        assert!(harness.state.released.lock().is_empty());
        assert!(harness.state.recycled.lock().is_empty());

        let replay = harness.runtime.stream_from_cursor("0").expect("valid cursor").0;
        assert_eq!(replay.len(), 4);
        assert!(matches!(
            &replay[3].payload,
            EventPayload::ProxyStatusDegraded { reason_code, .. }
                if reason_code == "control_plane_unavailable_during_release"
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after release failure");
        assert_eq!(patch.state, Some(SessionState::Disconnected));
        assert_eq!(
            patch.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::Disconnected)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn record_session_ended_keeps_recycle_requested_state_when_recycle_fails() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .state
            .set_recycle_error(ErrorCode::RecycleFailed, "recycle failed", true);

        harness
            .runtime
            .record_session_ended(&session, None)
            .await
            .expect("recycle failure should not fail proxy teardown");

        assert_eq!(
            harness.state.released.lock().as_slice(),
            &[format!("lease-{}", session.id)]
        );
        assert!(harness.state.recycled.lock().is_empty());

        let replay = harness.runtime.stream_from_cursor("0").expect("valid cursor").0;
        assert_eq!(replay.len(), 5);
        assert!(matches!(
            replay[3].payload,
            EventPayload::SessionRecycleRequested { .. }
        ));
        assert!(matches!(
            &replay[4].payload,
            EventPayload::ProxyStatusDegraded { reason_code, .. } if reason_code == "recycle_failed"
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after recycle failure");
        assert_eq!(patch.state, Some(SessionState::RecycleRequested));
        assert_eq!(
            patch.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::Disconnected)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn issue_stream_token_marks_stream_failed_when_control_plane_stream_is_unavailable() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .state
            .set_stream_error(ErrorCode::StreamUnavailable, "stream unavailable", true);

        let error = harness
            .runtime
            .issue_stream_token(&session)
            .await
            .expect_err("stream-unavailable control-plane response should fail token issue");
        assert!(matches!(error, HoneypotStreamError::StreamUnavailable));

        let replay = harness.runtime.stream_from_cursor("0").expect("valid cursor").0;
        assert_eq!(replay.len(), 4);
        assert!(matches!(
            &replay[2].payload,
            EventPayload::ProxyStatusDegraded { reason_code, .. } if reason_code == "stream_unavailable"
        ));
        assert!(matches!(
            &replay[3].payload,
            EventPayload::SessionStreamFailed {
                failure_code: ErrorCode::StreamUnavailable,
                retryable: true,
                stream_state: StreamState::Failed,
                ..
            }
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after stream failure");
        assert_eq!(patch.state, Some(SessionState::Assigned));
        assert_eq!(
            patch.stream.as_ref().map(|stream| stream.state),
            Some(StreamState::Failed)
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn session_kill_emits_session_killed_before_recycle() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .runtime
            .record_session_ended(
                &session,
                Some(SessionKillMetadata {
                    scope: honeypot_contracts::events::KillScope::Session,
                    operator_id: Some(Uuid::nil()),
                    reason: SessionKillReason::OperatorRequested,
                }),
            )
            .await
            .expect("record killed session");

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");
        assert_eq!(replay.len(), 5);
        assert!(matches!(replay[2].payload, EventPayload::SessionKilled { .. }));

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn quarantine_kill_requests_force_quarantine_recycle_and_marks_events() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .runtime
            .record_session_ended(&session, Some(SessionKillMetadata::operator_quarantine(Uuid::nil())))
            .await
            .expect("record quarantined session");

        let recycle_requests = harness.state.recycle_requests.lock().clone();
        assert_eq!(recycle_requests.len(), 1);
        assert_eq!(recycle_requests[0].recycle_reason, "operator_quarantine");
        assert!(recycle_requests[0].force_quarantine);

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");
        assert_eq!(replay.len(), 5);
        assert!(matches!(
            &replay[2].payload,
            EventPayload::SessionKilled { kill_reason, .. } if kill_reason == "operator_quarantine"
        ));
        assert!(matches!(
            &replay[3].payload,
            EventPayload::SessionRecycleRequested { recycle_reason, .. } if recycle_reason == "operator_quarantine"
        ));
        assert!(matches!(
            &replay[4].payload,
            EventPayload::HostRecycled {
                recycle_state: RecycleState::Quarantined,
                quarantined: true,
                ..
            }
        ));

        let patch = harness
            .runtime
            .session_metadata_patch(session.id)
            .expect("session metadata after quarantine");
        assert_eq!(patch.state, Some(SessionState::Recycled));
        assert_eq!(
            patch
                .terminal
                .as_ref()
                .and_then(|terminal| terminal.kill_reason.as_deref()),
            Some("operator_quarantine")
        );

        harness.shutdown().await;
    }

    #[tokio::test]
    async fn prepared_rdp_session_provisions_credentials_before_session_start() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();
        harness.write_backend_credentials(session.id);

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.prepare_rdp_session(
                session.id,
                session.application_protocol.clone(),
                session.time_to_live,
                TEST_PREPARED_SESSION_TOKEN,
                "127.0.0.1:4444".parse().expect("parse attacker addr"),
            ),
        )
        .await
        .expect("prepare honeypot session should not time out")
        .expect("prepare honeypot session");

        let token_id = crate::token::extract_jti(TEST_PREPARED_SESSION_TOKEN).expect("extract token ID");
        let entry = harness
            .runtime
            .credential_store
            .get(token_id)
            .expect("credential entry should exist after preparation");
        let binding = entry.binding.as_ref().expect("binding metadata should exist");

        assert_eq!(binding.session_id, Some(session.id));
        assert_eq!(
            binding.vm_lease_id.as_deref(),
            Some(format!("lease-{}", session.id).as_str())
        );
        assert_eq!(
            binding.backend_credential_ref.as_deref(),
            Some(format!("honeypot-backend-credential:{}", session.id).as_str())
        );

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.record_session_started(&session),
        )
        .await
        .expect("record started session should not time out")
        .expect("record started session");

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");
        assert_eq!(replay.len(), 2);
        assert!(matches!(replay[0].payload, EventPayload::SessionStarted { .. }));
        assert!(matches!(replay[1].payload, EventPayload::SessionAssigned { .. }));

        tokio::time::timeout(std::time::Duration::from_secs(5), harness.shutdown())
            .await
            .expect("shutdown should not time out");
    }

    #[tokio::test]
    async fn prepared_session_credentials_are_revoked_on_session_end() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();
        harness.write_backend_credentials(session.id);

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.prepare_rdp_session(
                session.id,
                session.application_protocol.clone(),
                session.time_to_live,
                TEST_PREPARED_SESSION_TOKEN,
                "127.0.0.1:5555".parse().expect("parse attacker addr"),
            ),
        )
        .await
        .expect("prepare honeypot session should not time out")
        .expect("prepare honeypot session");
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.record_session_started(&session),
        )
        .await
        .expect("record started session should not time out")
        .expect("record started session");

        let token_id = crate::token::extract_jti(TEST_PREPARED_SESSION_TOKEN).expect("extract token ID");
        assert!(harness.runtime.credential_store.get(token_id).is_some());

        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.record_session_ended(&session, None),
        )
        .await
        .expect("record ended session should not time out")
        .expect("record ended session");

        assert!(harness.runtime.credential_store.get(token_id).is_none());

        tokio::time::timeout(std::time::Duration::from_secs(5), harness.shutdown())
            .await
            .expect("shutdown should not time out");
    }

    #[tokio::test]
    async fn system_kill_halts_new_prepared_sessions_when_configured() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();
        harness.write_backend_credentials(session.id);
        harness.runtime.activate_system_kill();

        let error = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            harness.runtime.prepare_rdp_session(
                session.id,
                session.application_protocol.clone(),
                session.time_to_live,
                TEST_PREPARED_SESSION_TOKEN,
                "127.0.0.1:6666".parse().expect("parse attacker addr"),
            ),
        )
        .await
        .expect("prepare honeypot session should not time out")
        .expect_err("system kill should halt new session preparation");

        assert!(format!("{error:#}").contains("honeypot intake halted by system kill"));
        assert!(harness.state.acquired.lock().is_empty());
        assert!(harness.state.released.lock().is_empty());
        assert!(harness.state.recycled.lock().is_empty());

        tokio::time::timeout(std::time::Duration::from_secs(5), harness.shutdown())
            .await
            .expect("shutdown should not time out");
    }

    #[tokio::test]
    async fn expired_cursor_is_rejected() {
        let runtime = test_runtime_without_control_plane();
        let session = test_session();

        runtime
            .record_session_started(&session)
            .await
            .expect("record started session");

        assert!(runtime.stream_from_cursor("99").is_err());
        assert!(runtime.stream_from_cursor("bogus").is_err());
    }

    #[tokio::test]
    async fn system_kill_emits_system_scoped_session_killed_before_recycle() {
        let harness = test_runtime_with_control_plane().await;
        let session = test_session();

        harness
            .runtime
            .record_session_started(&session)
            .await
            .expect("record started session");
        harness
            .runtime
            .record_session_ended(&session, Some(SessionKillMetadata::system_operator(Uuid::nil())))
            .await
            .expect("record system-killed session");

        let (replay, _receiver) = harness.runtime.stream_from_cursor("0").expect("valid cursor");
        assert_eq!(replay.len(), 5);
        assert!(matches!(
            replay[2].payload,
            EventPayload::SessionKilled {
                kill_scope: honeypot_contracts::events::KillScope::System,
                ..
            }
        ));

        harness.shutdown().await;
    }

    fn test_runtime_without_control_plane() -> HoneypotRuntime {
        let (sender, _) = broadcast::channel(32);
        let backend_credentials_root = unique_temp_path("credentials-no-control-plane");
        std::fs::create_dir_all(&backend_credentials_root).expect("create backend credentials root");
        let backend_credentials_path = backend_credentials_root.join("backend-credentials.json");
        std::fs::write(&backend_credentials_path, "{}").expect("write empty backend credentials map");

        HoneypotRuntime {
            frontend: HoneypotFrontendRuntime::from_conf(&HoneypotFrontendConf {
                public_url: None,
                bootstrap_path: "/jet/honeypot/bootstrap".to_owned(),
                events_path: "/jet/honeypot/events".to_owned(),
            }),
            stream: HoneypotStreamRuntime::from_conf(&HoneypotStreamConf {
                source_kind: crate::config::HoneypotStreamSourceKind::GatewayRecording,
                browser_transport: HoneypotBrowserTransport::Sse,
                token_ttl: std::time::Duration::from_secs(42),
            }),
            control_plane: None,
            credential_store: CredentialStoreHandle::new(),
            backend_credentials: HoneypotBackendCredentialResolver::new(
                camino::Utf8PathBuf::from_path_buf(backend_credentials_path)
                    .expect("backend credential path should be UTF-8"),
            ),
            kill_switch: HoneypotKillSwitchRuntime::from_conf(&HoneypotKillSwitchConf::default()),
            requested_ready_timeout_secs: 5,
            events: Arc::new(Mutex::new(HoneypotEventJournal::new(sender))),
        }
    }

    async fn test_runtime_with_control_plane() -> TestRuntimeHarness {
        let state = TestControlPlaneState::default();
        let credential_store = CredentialStoreHandle::new();
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("read test listener address");
        let router = Router::new()
            .route("/api/v1/health", get(test_health_handler))
            .route("/api/v1/vm/acquire", post(test_acquire_handler))
            .route("/api/v1/vm/{vm_lease_id}/release", post(test_release_handler))
            .route("/api/v1/vm/{vm_lease_id}/recycle", post(test_recycle_handler))
            .route("/api/v1/vm/{vm_lease_id}/stream", get(test_stream_handler))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, router).await.expect("serve test control-plane");
        });
        let (sender, _) = broadcast::channel(32);
        let backend_credentials_root = unique_temp_path("credentials");
        std::fs::create_dir_all(&backend_credentials_root).expect("create backend credentials root");
        let backend_credentials_path = backend_credentials_root.join("backend-credentials.json");
        std::fs::write(&backend_credentials_path, "{}").expect("write empty backend credentials map");

        TestRuntimeHarness {
            runtime: HoneypotRuntime {
                frontend: HoneypotFrontendRuntime::from_conf(&HoneypotFrontendConf {
                    public_url: None,
                    bootstrap_path: "/jet/honeypot/bootstrap".to_owned(),
                    events_path: "/jet/honeypot/events".to_owned(),
                }),
                stream: HoneypotStreamRuntime::from_conf(&HoneypotStreamConf {
                    source_kind: crate::config::HoneypotStreamSourceKind::GatewayRecording,
                    browser_transport: HoneypotBrowserTransport::Sse,
                    token_ttl: std::time::Duration::from_secs(42),
                }),
                kill_switch: HoneypotKillSwitchRuntime::from_conf(&HoneypotKillSwitchConf::default()),
                control_plane: Some(
                    HoneypotControlPlaneClient::from_conf(&HoneypotControlPlaneConf {
                        endpoint: Some(format!("http://{addr}/").parse().expect("parse endpoint")),
                        request_timeout: std::time::Duration::from_secs(5),
                        connect_timeout: std::time::Duration::from_secs(2),
                        service_bearer_token: Some(TEST_CONTROL_PLANE_SERVICE_TOKEN.to_owned()),
                        service_bearer_token_file: None,
                    })
                    .expect("build client")
                    .expect("enabled client"),
                ),
                credential_store,
                backend_credentials: HoneypotBackendCredentialResolver::new(
                    camino::Utf8PathBuf::from_path_buf(backend_credentials_path.clone())
                        .expect("backend credential path should be UTF-8"),
                ),
                requested_ready_timeout_secs: 5,
                events: Arc::new(Mutex::new(HoneypotEventJournal::new(sender))),
            },
            state,
            backend_credentials_path,
            backend_credentials_root,
            server,
        }
    }

    async fn test_health_handler(headers: HeaderMap) -> Json<HealthResponse> {
        assert_service_token(&headers);

        Json(HealthResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: "corr-health".to_owned(),
            service_state: ServiceState::Ready,
            kvm_available: true,
            trusted_image_count: 1,
            active_lease_count: 0,
            quarantined_lease_count: 0,
            degraded_reasons: Vec::new(),
        })
    }

    async fn test_acquire_handler(
        State(state): State<TestControlPlaneState>,
        headers: HeaderMap,
        Json(request): Json<AcquireVmRequest>,
    ) -> Response {
        assert_service_token(&headers);

        if let Some(error) = state.acquire_error.lock().clone() {
            return (control_plane_test_error_status(error.error_code), Json(error)).into_response();
        }

        state.acquired.lock().push(request.session_id.clone());

        Json(AcquireVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("corr-acquire-{}", request.session_id),
            vm_lease_id: format!("lease-{}", request.session_id),
            vm_name: format!("honeypot-{}", request.session_id),
            guest_rdp_addr: "127.0.0.1".to_owned(),
            guest_rdp_port: 3389,
            lease_state: LeaseState::Assigned,
            lease_expires_at: "2030-01-01T00:00:00Z".to_owned(),
            backend_credential_ref: request.backend_credential_ref,
            attestation_ref: "attestation:test".to_owned(),
        })
        .into_response()
    }

    async fn test_release_handler(
        State(state): State<TestControlPlaneState>,
        headers: HeaderMap,
        Path(vm_lease_id): Path<String>,
        Json(_request): Json<ReleaseVmRequest>,
    ) -> Response {
        assert_service_token(&headers);

        if let Some(error) = state.release_error.lock().clone() {
            return (control_plane_test_error_status(error.error_code), Json(error)).into_response();
        }

        state.released.lock().push(vm_lease_id.clone());

        Json(ReleaseVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("corr-release-{vm_lease_id}"),
            vm_lease_id,
            release_state: ReleaseState::Recycling,
            recycle_required: true,
        })
        .into_response()
    }

    async fn test_recycle_handler(
        State(state): State<TestControlPlaneState>,
        headers: HeaderMap,
        Path(vm_lease_id): Path<String>,
        Json(request): Json<RecycleVmRequest>,
    ) -> Response {
        assert_service_token(&headers);

        if let Some(error) = state.recycle_error.lock().clone() {
            return (control_plane_test_error_status(error.error_code), Json(error)).into_response();
        }

        state.recycle_requests.lock().push(request.clone());
        state.recycled.lock().push(vm_lease_id.clone());

        Json(RecycleVmResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("corr-recycle-{vm_lease_id}"),
            vm_lease_id,
            recycle_state: if request.force_quarantine {
                RecycleState::Quarantined
            } else {
                RecycleState::Recycled
            },
            pool_state: if request.force_quarantine {
                PoolState::Quarantined
            } else {
                PoolState::Ready
            },
            quarantined: request.force_quarantine,
        })
        .into_response()
    }

    async fn test_stream_handler(
        State(state): State<TestControlPlaneState>,
        headers: HeaderMap,
        Path(vm_lease_id): Path<String>,
        Query(_request): Query<StreamEndpointRequest>,
    ) -> Response {
        assert_service_token(&headers);

        if let Some(error) = state.stream_error.lock().clone() {
            return (control_plane_test_error_status(error.error_code), Json(error)).into_response();
        }

        Json(StreamEndpointResponse {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            correlation_id: format!("corr-stream-{vm_lease_id}"),
            vm_lease_id: vm_lease_id.clone(),
            capture_source_kind: CaptureSourceKind::GatewayRecording,
            capture_source_ref: format!("gateway-recording://{vm_lease_id}"),
            source_ready: true,
            expires_at: "2030-01-01T00:00:00Z".to_owned(),
        })
        .into_response()
    }

    #[derive(Clone, Default)]
    struct TestControlPlaneState {
        acquired: Arc<Mutex<Vec<String>>>,
        released: Arc<Mutex<Vec<String>>>,
        recycled: Arc<Mutex<Vec<String>>>,
        recycle_requests: Arc<Mutex<Vec<RecycleVmRequest>>>,
        acquire_error: Arc<Mutex<Option<ErrorResponse>>>,
        release_error: Arc<Mutex<Option<ErrorResponse>>>,
        recycle_error: Arc<Mutex<Option<ErrorResponse>>>,
        stream_error: Arc<Mutex<Option<ErrorResponse>>>,
    }

    impl TestControlPlaneState {
        fn set_acquire_error(&self, error_code: ErrorCode, message: &str, retryable: bool) {
            *self.acquire_error.lock() = Some(test_error_response(error_code, message, retryable));
        }

        fn set_release_error(&self, error_code: ErrorCode, message: &str, retryable: bool) {
            *self.release_error.lock() = Some(test_error_response(error_code, message, retryable));
        }

        fn set_recycle_error(&self, error_code: ErrorCode, message: &str, retryable: bool) {
            *self.recycle_error.lock() = Some(test_error_response(error_code, message, retryable));
        }

        fn set_stream_error(&self, error_code: ErrorCode, message: &str, retryable: bool) {
            *self.stream_error.lock() = Some(test_error_response(error_code, message, retryable));
        }
    }

    struct TestRuntimeHarness {
        runtime: HoneypotRuntime,
        state: TestControlPlaneState,
        backend_credentials_path: PathBuf,
        backend_credentials_root: PathBuf,
        server: tokio::task::JoinHandle<()>,
    }

    impl TestRuntimeHarness {
        fn write_backend_credentials(&self, session_id: Uuid) {
            let mappings = serde_json::json!({
                format!("honeypot-backend-credential:{session_id}"): backend_mapping("attacker", "Administrator")
            });
            std::fs::write(
                &self.backend_credentials_path,
                serde_json::to_vec_pretty(&mappings).expect("serialize backend mappings"),
            )
            .expect("write backend credential mappings");
        }

        async fn shutdown(self) {
            self.server.abort();
            let _ = self.server.await;
            let _ = std::fs::remove_dir_all(self.backend_credentials_root);
        }
    }

    fn test_session() -> SessionInfo {
        SessionInfo::builder()
            .id(Uuid::new_v4())
            .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
            .recording_policy(RecordingPolicy::None)
            .time_to_live(SessionTtl::Unlimited)
            .details(ConnectionModeDetails::Rdv)
            .build()
    }
}
