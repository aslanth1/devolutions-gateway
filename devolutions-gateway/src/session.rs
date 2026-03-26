use core::fmt;
use std::cmp;
use std::collections::{BinaryHeap, HashMap};
use std::pin::pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use futures::future::Either;
use honeypot_contracts::events::{KillScope, SessionState, StreamState, TerminalOutcome};
use honeypot_contracts::stream::StreamTransport;
use tap::prelude::*;
use time::OffsetDateTime;
use tokio::sync::{Notify, mpsc, oneshot};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::recording::RecordingMessageSender;
use crate::subscriber;
use crate::target_addr::TargetAddr;
use crate::token::{ApplicationProtocol, ReconnectionPolicy, RecordingPolicy, SessionTtl};

#[derive(Debug, Serialize, Clone)]
#[serde(tag = "connection_mode")]
#[serde(rename_all = "lowercase")]
pub enum ConnectionModeDetails {
    Rdv,
    Fwd { destination_host: TargetAddr },
}

#[derive(Debug, Serialize, Clone, TypedBuilder)]
pub struct SessionInfo {
    #[serde(rename = "association_id")]
    pub id: Uuid,
    pub application_protocol: ApplicationProtocol,
    #[builder(setter(transform = |value: RecordingPolicy| value != RecordingPolicy::None))]
    pub recording_policy: bool,
    #[builder(default = false)] // Not enforced yet, so it’s okay to not set it at all for now.
    pub filtering_policy: bool,
    #[builder(setter(skip), default = OffsetDateTime::now_utc())]
    #[serde(with = "time::serde::rfc3339")]
    pub start_timestamp: OffsetDateTime,
    pub time_to_live: SessionTtl,
    #[builder(default, setter(strip_option))]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub honeypot: Option<HoneypotSessionMetadata>,
    #[serde(flatten)]
    pub details: ConnectionModeDetails,
}

impl SessionInfo {
    fn apply_honeypot_patch(&mut self, patch: HoneypotSessionMetadataPatch) {
        let honeypot = self.honeypot.get_or_insert_with(HoneypotSessionMetadata::default);

        if let Some(state) = patch.state {
            honeypot.state = state;
        }

        if let Some(attacker_source) = patch.attacker_source {
            honeypot.attacker_source = Some(attacker_source);
        }

        if let Some(assignment) = patch.assignment {
            honeypot.assignment = Some(assignment);
        }

        if let Some(stream) = patch.stream {
            honeypot.stream = Some(stream);
        }

        if let Some(terminal) = patch.terminal {
            honeypot.terminal = Some(terminal);
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct HoneypotSessionMetadata {
    pub state: SessionState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attacker_source: Option<HoneypotAttackerSource>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignment: Option<HoneypotVmAssignment>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<HoneypotStreamMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terminal: Option<HoneypotTerminalMetadata>,
}

impl Default for HoneypotSessionMetadata {
    fn default() -> Self {
        Self {
            state: SessionState::Connected,
            attacker_source: None,
            assignment: None,
            stream: None,
            terminal: None,
        }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct HoneypotAttackerSource {
    pub attacker_addr: String,
    pub listener_id: String,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct HoneypotVmAssignment {
    pub vm_lease_id: String,
    pub vm_name: String,
    pub guest_rdp_addr: String,
    pub attestation_ref: String,
    pub backend_credential_ref: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct HoneypotStreamMetadata {
    pub state: StreamState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<StreamTransport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_endpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_expires_at: Option<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct HoneypotTerminalMetadata {
    pub outcome: TerminalOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disconnect_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_scope: Option<KillScope>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub killed_by_operator_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kill_reason: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct HoneypotSessionMetadataPatch {
    pub state: Option<SessionState>,
    pub attacker_source: Option<HoneypotAttackerSource>,
    pub assignment: Option<HoneypotVmAssignment>,
    pub stream: Option<HoneypotStreamMetadata>,
    pub terminal: Option<HoneypotTerminalMetadata>,
}

#[instrument(skip_all)]
pub async fn add_session_in_progress(
    sessions: &SessionMessageSender,
    subscriber_tx: &subscriber::SubscriberSender,
    info: SessionInfo,
    notify_kill: Arc<Notify>,
    disconnect_interest: Option<DisconnectInterest>,
) -> anyhow::Result<()> {
    if let Err(error) = sessions.honeypot().ensure_new_session_allowed(info.id) {
        let _ = sessions.honeypot().abort_prepared_session(info.id).await;
        return Err(error).context("couldn't admit honeypot session");
    }

    let honeypot_session = info.clone();
    let association_id = info.id;

    sessions
        .new_session(info, notify_kill, disconnect_interest)
        .await
        .context("couldn't register new session")?;

    if let Err(error) = sessions.honeypot().record_session_started(&honeypot_session).await {
        let _ = sessions.sync_honeypot_metadata(association_id).await;
        let removed_session = sessions
            .remove_session(association_id)
            .await
            .ok()
            .flatten()
            .unwrap_or_else(|| honeypot_session.clone());

        let message = subscriber::Message::session_ended(removed_session);

        if let Err(send_error) = subscriber_tx.try_send(message) {
            warn!(%send_error, "Failed to send subscriber message");
        }

        return Err(error).context("couldn't initialize honeypot session state");
    }

    let _ = sessions.sync_honeypot_metadata(association_id).await;
    let subscriber_session = sessions
        .get_session_info(association_id)
        .await
        .ok()
        .flatten()
        .unwrap_or(honeypot_session);

    let message = subscriber::Message::session_started(subscriber_session);

    if let Err(error) = subscriber_tx.try_send(message) {
        warn!(%error, "Failed to send subscriber message");
    }

    Ok(())
}

#[instrument(skip_all)]
pub async fn remove_session_in_progress(
    sessions: &SessionMessageSender,
    subscriber_tx: &subscriber::SubscriberSender,
    id: Uuid,
) -> anyhow::Result<()> {
    let kill = sessions
        .get_disconnected_info(id)
        .await
        .ok()
        .flatten()
        .and_then(|info| info.kill);

    let terminal_patch = HoneypotSessionMetadataPatch {
        state: Some(if kill.is_some() {
            SessionState::Killed
        } else {
            SessionState::Disconnected
        }),
        terminal: Some(HoneypotTerminalMetadata {
            outcome: if kill.is_some() {
                TerminalOutcome::Killed
            } else {
                TerminalOutcome::Disconnected
            },
            disconnect_reason: Some("proxy_forwarding_ended".to_owned()),
            kill_scope: kill.map(|kill| kill.scope),
            killed_by_operator_id: kill
                .and_then(|kill| kill.operator_id)
                .map(|operator_id| operator_id.to_string()),
            kill_reason: kill.map(|kill| kill.reason.as_reason_code().to_owned()),
        }),
        ..Default::default()
    };
    let _ = sessions.update_honeypot_metadata(id, terminal_patch).await;

    let removed_session = sessions
        .remove_session(id)
        .await
        .context("couldn't remove running session")?;

    if let Some(session) = removed_session {
        let message = subscriber::Message::session_ended(session.clone());

        if let Err(error) = subscriber_tx.try_send(message) {
            warn!(%error, "Failed to send subscriber message");
        }

        if let Err(error) = sessions.honeypot().record_session_ended(&session, kill).await {
            warn!(
                error = format!("{error:#}"),
                "Failed to finalize honeypot session state"
            );
        }
    }

    Ok(())
}

pub type RunningSessions = HashMap<Uuid, SessionInfo>;

#[must_use]
pub enum KillResult {
    Success,
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKillReason {
    OperatorRequested,
    SessionTtlExpired,
    RecordingPolicyViolated,
    GatewayRequested,
}

impl SessionKillReason {
    pub fn as_reason_code(self) -> &'static str {
        match self {
            Self::OperatorRequested => "operator_requested",
            Self::SessionTtlExpired => "session_ttl_expired",
            Self::RecordingPolicyViolated => "recording_policy_violated",
            Self::GatewayRequested => "gateway_requested",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionKillMetadata {
    pub scope: KillScope,
    pub operator_id: Option<Uuid>,
    pub reason: SessionKillReason,
}

impl SessionKillMetadata {
    pub fn operator(operator_id: Uuid) -> Self {
        Self {
            scope: KillScope::Session,
            operator_id: Some(operator_id),
            reason: SessionKillReason::OperatorRequested,
        }
    }

    pub fn system_operator(operator_id: Uuid) -> Self {
        Self {
            scope: KillScope::System,
            operator_id: Some(operator_id),
            reason: SessionKillReason::OperatorRequested,
        }
    }

    pub fn gateway(reason: SessionKillReason) -> Self {
        Self {
            scope: KillScope::Session,
            operator_id: None,
            reason,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct DisconnectInterest {
    pub window: Duration,
}

impl DisconnectInterest {
    pub fn from_reconnection_policy(policy: ReconnectionPolicy) -> Option<DisconnectInterest> {
        match policy {
            ReconnectionPolicy::Disallowed => None,
            ReconnectionPolicy::Allowed { window_in_seconds } => Some(DisconnectInterest {
                window: Duration::from_secs(u64::from(window_in_seconds.get())),
            }),
        }
    }

    fn kill_tracking_window() -> DisconnectInterest {
        DisconnectInterest {
            window: Duration::from_secs(60),
        }
    }
}

#[derive(Clone, Copy)]
pub struct DisconnectedInfo {
    pub id: Uuid,
    pub kill: Option<SessionKillMetadata>,
    pub date: OffsetDateTime,
    pub interest: DisconnectInterest,
    pub count: u8,
}

enum SessionManagerMessage {
    New {
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
    },
    GetInfo {
        id: Uuid,
        channel: oneshot::Sender<Option<SessionInfo>>,
    },
    Remove {
        id: Uuid,
        channel: oneshot::Sender<Option<SessionInfo>>,
    },
    Kill {
        id: Uuid,
        kill: SessionKillMetadata,
        channel: oneshot::Sender<KillResult>,
    },
    KillAll {
        kill: SessionKillMetadata,
        channel: oneshot::Sender<usize>,
    },
    GetDisconnectedInfo {
        id: Uuid,
        channel: oneshot::Sender<Option<DisconnectedInfo>>,
    },
    UpdateHoneypot {
        id: Uuid,
        patch: HoneypotSessionMetadataPatch,
        channel: oneshot::Sender<bool>,
    },
    GetRunning {
        channel: oneshot::Sender<RunningSessions>,
    },
    GetCount {
        channel: oneshot::Sender<usize>,
    },
}

impl fmt::Debug for SessionManagerMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionManagerMessage::New {
                info,
                notify_kill: _,
                disconnect_interest,
            } => f
                .debug_struct("New")
                .field("info", info)
                .field("disconnect_interest", disconnect_interest)
                .finish_non_exhaustive(),
            SessionManagerMessage::GetInfo { id, channel: _ } => {
                f.debug_struct("GetInfo").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Remove { id, channel: _ } => {
                f.debug_struct("Remove").field("id", id).finish_non_exhaustive()
            }
            SessionManagerMessage::Kill {
                id,
                kill: _,
                channel: _,
            } => f.debug_struct("Kill").field("id", id).finish_non_exhaustive(),
            SessionManagerMessage::KillAll { kill: _, channel: _ } => f.debug_struct("KillAll").finish_non_exhaustive(),
            SessionManagerMessage::GetDisconnectedInfo { id, channel: _ } => f
                .debug_struct("GetDisconnectedInfo")
                .field("id", id)
                .finish_non_exhaustive(),
            SessionManagerMessage::UpdateHoneypot { id, patch, channel: _ } => f
                .debug_struct("UpdateHoneypot")
                .field("id", id)
                .field("patch", patch)
                .finish_non_exhaustive(),
            SessionManagerMessage::GetRunning { channel: _ } => f.debug_struct("GetRunning").finish_non_exhaustive(),
            SessionManagerMessage::GetCount { channel: _ } => f.debug_struct("GetCount").finish_non_exhaustive(),
        }
    }
}

#[derive(Clone)]
pub struct SessionMessageSender {
    tx: mpsc::Sender<SessionManagerMessage>,
    honeypot: crate::honeypot::HoneypotMode,
}

impl SessionMessageSender {
    pub fn honeypot(&self) -> &crate::honeypot::HoneypotMode {
        &self.honeypot
    }

    pub async fn new_session(
        &self,
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
    ) -> anyhow::Result<()> {
        self.tx
            .send(SessionManagerMessage::New {
                info,
                notify_kill,
                disconnect_interest,
            })
            .await
            .ok()
            .context("couldn't send New message")
    }

    pub async fn get_session_info(&self, id: Uuid) -> anyhow::Result<Option<SessionInfo>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::GetInfo { id, channel: tx })
            .await
            .ok()
            .context("couldn't send GetInfo message")?;
        rx.await.context("couldn't receive info for session")
    }

    pub async fn remove_session(&self, id: Uuid) -> anyhow::Result<Option<SessionInfo>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::Remove { id, channel: tx })
            .await
            .ok()
            .context("couldn't send Remove message")?;
        rx.await.context("couldn't receive info for removed session")
    }

    pub async fn kill_session(&self, id: Uuid) -> anyhow::Result<KillResult> {
        self.kill_session_with_metadata(id, SessionKillMetadata::gateway(SessionKillReason::GatewayRequested))
            .await
    }

    pub async fn kill_session_with_metadata(&self, id: Uuid, kill: SessionKillMetadata) -> anyhow::Result<KillResult> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::Kill { id, kill, channel: tx })
            .await
            .ok()
            .context("couldn't send Kill message")?;
        rx.await.context("couldn't receive kill result")
    }

    pub async fn kill_all_sessions_with_metadata(&self, kill: SessionKillMetadata) -> anyhow::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::KillAll { kill, channel: tx })
            .await
            .ok()
            .context("couldn't send KillAll message")?;
        rx.await.context("couldn't receive bulk kill result")
    }

    pub async fn get_disconnected_info(&self, id: Uuid) -> anyhow::Result<Option<DisconnectedInfo>> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::GetDisconnectedInfo { id, channel: tx })
            .await
            .ok()
            .context("couldn't send GetDisconnectedInfo message")?;
        rx.await.context("couldn't receive disconnected info for session")
    }

    pub async fn update_honeypot_metadata(
        &self,
        id: Uuid,
        patch: HoneypotSessionMetadataPatch,
    ) -> anyhow::Result<bool> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::UpdateHoneypot { id, patch, channel: tx })
            .await
            .ok()
            .context("couldn't send UpdateHoneypot message")?;
        rx.await.context("couldn't receive honeypot session update result")
    }

    pub async fn sync_honeypot_metadata(&self, id: Uuid) -> anyhow::Result<bool> {
        let Some(patch) = self.honeypot.session_metadata_patch(id) else {
            return Ok(false);
        };

        self.update_honeypot_metadata(id, patch).await
    }

    pub async fn get_running_sessions(&self) -> anyhow::Result<RunningSessions> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::GetRunning { channel: tx })
            .await
            .ok()
            .context("couldn't send GetRunning message")?;
        rx.await.context("couldn't receive running session list")
    }

    pub async fn get_running_session_count(&self) -> anyhow::Result<usize> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(SessionManagerMessage::GetCount { channel: tx })
            .await
            .ok()
            .context("couldn't send GetRunning message")?;
        rx.await.context("couldn't receive running session count")
    }
}

pub struct SessionMessageReceiver(mpsc::Receiver<SessionManagerMessage>);

pub fn session_manager_channel(
    honeypot: crate::honeypot::HoneypotMode,
) -> (SessionMessageSender, SessionMessageReceiver) {
    mpsc::channel(64).pipe(|(tx, rx)| (SessionMessageSender { tx, honeypot }, SessionMessageReceiver(rx)))
}

struct WithTtlInfo {
    deadline: tokio::time::Instant,
    session_id: Uuid,
}

impl PartialEq for WithTtlInfo {
    fn eq(&self, other: &Self) -> bool {
        self.deadline.eq(&other.deadline) && self.session_id.eq(&other.session_id)
    }
}

impl Eq for WithTtlInfo {}

impl PartialOrd for WithTtlInfo {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for WithTtlInfo {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.deadline.cmp(&other.deadline) {
            cmp::Ordering::Less => cmp::Ordering::Greater,
            cmp::Ordering::Equal => self.session_id.cmp(&other.session_id),
            cmp::Ordering::Greater => cmp::Ordering::Less,
        }
    }
}

pub struct SessionManagerTask {
    tx: SessionMessageSender,
    rx: SessionMessageReceiver,
    all_running: RunningSessions,
    all_notify_kill: HashMap<Uuid, Arc<Notify>>,
    recording_manager_handle: RecordingMessageSender,
    disconnect_interest: HashMap<Uuid, DisconnectInterest>,
    disconnected_info: HashMap<Uuid, DisconnectedInfo>,
}

impl SessionManagerTask {
    pub fn init(recording_manager_handle: RecordingMessageSender, honeypot: crate::honeypot::HoneypotMode) -> Self {
        let (tx, rx) = session_manager_channel(honeypot);

        Self::new(tx, rx, recording_manager_handle)
    }

    pub fn new(
        tx: SessionMessageSender,
        rx: SessionMessageReceiver,
        recording_manager_handle: RecordingMessageSender,
    ) -> Self {
        Self {
            tx,
            rx,
            all_running: HashMap::new(),
            all_notify_kill: HashMap::new(),
            recording_manager_handle,
            disconnect_interest: HashMap::new(),
            disconnected_info: HashMap::new(),
        }
    }

    pub fn handle(&self) -> SessionMessageSender {
        self.tx.clone()
    }

    fn handle_new(
        &mut self,
        info: SessionInfo,
        notify_kill: Arc<Notify>,
        disconnect_interest: Option<DisconnectInterest>,
    ) {
        let id = info.id;

        self.all_running.insert(id, info);
        self.all_notify_kill.insert(id, notify_kill);

        if let Some(interest) = disconnect_interest {
            self.disconnect_interest.insert(id, interest);
        }
    }

    fn handle_get_info(&mut self, id: Uuid) -> Option<SessionInfo> {
        self.all_running.get(&id).cloned()
    }

    fn handle_remove(&mut self, id: Uuid) -> Option<SessionInfo> {
        let removed_session = self.all_running.remove(&id);

        let _ = self.all_notify_kill.remove(&id);

        if let Some(interest) = self.disconnect_interest.remove(&id) {
            self.update_disconnected_info(id, interest, None);
        }

        removed_session
    }

    fn handle_kill(&mut self, id: Uuid, kill: SessionKillMetadata) -> KillResult {
        let interest = self
            .disconnect_interest
            .get(&id)
            .copied()
            .unwrap_or_else(DisconnectInterest::kill_tracking_window);
        self.update_disconnected_info(id, interest, Some(kill));

        match self.all_notify_kill.get(&id) {
            Some(notify_kill) => {
                notify_kill.notify_waiters();
                KillResult::Success
            }
            None => KillResult::NotFound,
        }
    }

    fn handle_kill_all(&mut self, kill: SessionKillMetadata) -> usize {
        let running_ids = self.all_notify_kill.keys().copied().collect::<Vec<_>>();

        running_ids
            .into_iter()
            .filter(|id| matches!(self.handle_kill(*id, kill), KillResult::Success))
            .count()
    }

    fn handle_get_disconnected_info(&mut self, id: Uuid) -> Option<DisconnectedInfo> {
        self.disconnected_info.get(&id).copied()
    }

    fn handle_update_honeypot(&mut self, id: Uuid, patch: HoneypotSessionMetadataPatch) -> bool {
        let Some(session) = self.all_running.get_mut(&id) else {
            return false;
        };

        session.apply_honeypot_patch(patch);
        true
    }

    /// Try to insert disconnected info. Nothing will happen in the info are already inserted.
    fn update_disconnected_info(&mut self, id: Uuid, interest: DisconnectInterest, kill: Option<SessionKillMetadata>) {
        self.disconnected_info
            .entry(id)
            .and_modify(|info| {
                if let Some(kill) = kill {
                    info.kill.get_or_insert(kill);
                }

                if kill.is_none() {
                    info.date = OffsetDateTime::now_utc();
                    info.interest = interest;
                    info.count += 1;
                }
            })
            .or_insert_with(|| DisconnectedInfo {
                id,
                kill,
                date: OffsetDateTime::now_utc(),
                interest,
                count: if kill.is_some() { 0 } else { 1 },
            });
    }
}

#[async_trait]
impl Task for SessionManagerTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "session manager";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        session_manager_task(self, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn session_manager_task(
    mut manager: SessionManagerTask,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    const DISCONNECTED_INFO_CLEANUP_INTERVAL: Duration = Duration::from_secs(60 * 5); // 5 minutes

    debug!("Task started");

    let mut with_ttl = BinaryHeap::<WithTtlInfo>::new();
    let auto_kill_sleep = tokio::time::sleep_until(tokio::time::Instant::now());
    tokio::pin!(auto_kill_sleep);
    (&mut auto_kill_sleep).await; // Consume initial sleep.

    let mut cleanup_interval = tokio::time::interval(DISCONNECTED_INFO_CLEANUP_INTERVAL);

    loop {
        tokio::select! {
            () = &mut auto_kill_sleep, if !with_ttl.is_empty() => {
                let to_kill = with_ttl.pop().expect("we check for non-emptiness before entering this block");

                match manager.handle_kill(
                    to_kill.session_id,
                    SessionKillMetadata::gateway(SessionKillReason::SessionTtlExpired),
                ) {
                    KillResult::Success => {
                        info!(session.id = %to_kill.session_id, "Session killed because it reached its max duration");
                    }
                    KillResult::NotFound => {
                        debug!(session.id = %to_kill.session_id, "Session already ended");
                    }
                }

                // Re-arm the Sleep instance with the next deadline if required.
                if let Some(next) = with_ttl.peek() {
                    auto_kill_sleep.as_mut().reset(next.deadline)
                }
            }
            msg = manager.rx.0.recv() => {
                let Some(msg) = msg else {
                    warn!("All senders are dead");
                    break;
                };

                debug!(?msg, "Received message");

                match msg {
                    SessionManagerMessage::New { info, notify_kill, disconnect_interest } => {
                        if let SessionTtl::Limited { minutes } = info.time_to_live {
                            let now = tokio::time::Instant::now();
                            let duration = Duration::from_secs(minutes.get() * 60);
                            let deadline = now + duration;

                            with_ttl.push(WithTtlInfo {
                                deadline,
                                session_id: info.id,
                            });

                            // Reset the Sleep instance if the new deadline is sooner or it is already elapsed.
                            if auto_kill_sleep.is_elapsed() || deadline < auto_kill_sleep.deadline() {
                                auto_kill_sleep.as_mut().reset(deadline);
                            }

                            debug!(session.id = %info.id, minutes = minutes.get(), "Limited TTL session registered");
                        }

                        if info.recording_policy {
                            let task = EnsureRecordingPolicyTask {
                                session_id: info.id,
                                session_manager_handle: manager.tx.clone(),
                                recording_manager_handle: manager.recording_manager_handle.clone(),
                            };

                            devolutions_gateway_task::spawn_task(task, shutdown_signal.clone()).detach();

                            debug!(session.id = %info.id, "Session with recording policy registered");
                        }

                        manager.handle_new(info, notify_kill, disconnect_interest);
                    }
                    SessionManagerMessage::GetInfo { id, channel } => {
                        let session_info = manager.handle_get_info(id);
                        let _ = channel.send(session_info);
                    }
                    SessionManagerMessage::Remove { id, channel } => {
                        let removed_session = manager.handle_remove(id);
                        let _ = channel.send(removed_session);
                    }
                    SessionManagerMessage::Kill { id, kill, channel } => {
                        let kill_result = manager.handle_kill(id, kill);
                        let _ = channel.send(kill_result);
                    }
                    SessionManagerMessage::KillAll { kill, channel } => {
                        let killed_count = manager.handle_kill_all(kill);
                        let _ = channel.send(killed_count);
                    }
                    SessionManagerMessage::GetDisconnectedInfo { id, channel } => {
                        let disconnected_info = manager.handle_get_disconnected_info(id);
                        let _ = channel.send(disconnected_info);
                    }
                    SessionManagerMessage::UpdateHoneypot { id, patch, channel } => {
                        let updated = manager.handle_update_honeypot(id, patch);
                        let _ = channel.send(updated);
                    }
                    SessionManagerMessage::GetRunning { channel } => {
                        let _ = channel.send(manager.all_running.clone());
                    }
                    SessionManagerMessage::GetCount { channel } => {
                        let _ = channel.send(manager.all_running.len());
                    }
                }
            }
            _ = cleanup_interval.tick() => {
                trace!(table_size = manager.disconnected_info.len(), "Cleanup disconnected info table");
                let now = OffsetDateTime::now_utc();
                manager.disconnected_info.retain(|_, info| now < info.date + info.interest.window);
                trace!(table_size = manager.disconnected_info.len(), "Disconnected info table cleanup complete");
            }
            () = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task is stopping; kill all running sessions");

    for notify_kill in manager.all_notify_kill.values() {
        notify_kill.notify_waiters();
    }

    debug!("Task is stopping; wait for leftover messages");

    loop {
        // Here, we await with a timeout because this task holds a handle to the
        // recording manager, but the recording manager itself also holds a handle to
        // the session manager. As long as the other end doesn’t drop the handle, the
        // recv future will never resolve. We simply assume there are no leftover messages
        // to process after one second of inactivity.
        let msg = match futures::future::select(
            pin!(manager.rx.0.recv()),
            pin!(tokio::time::sleep(Duration::from_secs(1))),
        )
        .await
        {
            Either::Left((Some(msg), _)) => msg,
            Either::Left((None, _)) => break,
            Either::Right(_) => break,
        };

        debug!(?msg, "Received message");
        match msg {
            SessionManagerMessage::Remove { id, channel } => {
                let removed_session = manager.handle_remove(id);
                let _ = channel.send(removed_session);
            }
            SessionManagerMessage::Kill { channel, .. } => {
                let _ = channel.send(KillResult::Success);
            }
            SessionManagerMessage::KillAll { channel, .. } => {
                let _ = channel.send(manager.all_notify_kill.len());
            }
            _ => {}
        }
    }

    debug!("Task terminated");

    Ok(())
}

struct EnsureRecordingPolicyTask {
    session_id: Uuid,
    session_manager_handle: SessionMessageSender,
    recording_manager_handle: RecordingMessageSender,
}

#[async_trait]
impl Task for EnsureRecordingPolicyTask {
    type Output = ();

    const NAME: &'static str = "ensure recording policy";

    async fn run(self, mut shutdown_signal: ShutdownSignal) -> Self::Output {
        let sleep = tokio::time::sleep(Duration::from_secs(10));
        let shutdown_signal = shutdown_signal.wait();

        match futures::future::select(pin!(sleep), pin!(shutdown_signal)).await {
            Either::Left(_) => {}
            Either::Right(_) => return,
        }

        let is_recording = self
            .recording_manager_handle
            .get_state(self.session_id)
            .await
            .ok()
            .flatten()
            .is_some();

        if is_recording {
            let _ = self
                .recording_manager_handle
                .update_recording_policy(self.session_id, true)
                .await;
        } else {
            match self
                .session_manager_handle
                .kill_session_with_metadata(
                    self.session_id,
                    SessionKillMetadata::gateway(SessionKillReason::RecordingPolicyViolated),
                )
                .await
            {
                Ok(KillResult::Success) => {
                    warn!(
                        session.id = %self.session_id,
                        reason = "recording policy violated",
                        "Session killed",
                    );
                }
                Ok(KillResult::NotFound) => {
                    trace!(session.id = %self.session_id, "Session already ended");
                }
                Err(error) => {
                    debug!(session.id = %self.session_id, error = format!("{error:#}"), "Couldn’t kill the session");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recording::recording_message_channel;
    use crate::token::{ApplicationProtocol, Protocol, RecordingPolicy};

    fn test_session() -> SessionInfo {
        SessionInfo::builder()
            .id(Uuid::new_v4())
            .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
            .recording_policy(RecordingPolicy::None)
            .time_to_live(SessionTtl::Unlimited)
            .details(ConnectionModeDetails::Rdv)
            .build()
    }

    fn test_manager() -> SessionManagerTask {
        let (recording_manager_handle, _recording_manager_rx) = recording_message_channel();
        let (tx, rx) = session_manager_channel(crate::honeypot::HoneypotMode::Disabled);
        SessionManagerTask::new(tx, rx, recording_manager_handle)
    }

    #[test]
    fn session_manager_updates_running_honeypot_metadata() {
        let mut manager = test_manager();
        let session = test_session();

        manager.handle_new(session.clone(), Arc::new(Notify::new()), None);

        let updated = manager.handle_update_honeypot(
            session.id,
            HoneypotSessionMetadataPatch {
                state: Some(SessionState::Assigned),
                attacker_source: Some(HoneypotAttackerSource {
                    attacker_addr: "127.0.0.1:3389".to_owned(),
                    listener_id: "gateway".to_owned(),
                }),
                assignment: Some(HoneypotVmAssignment {
                    vm_lease_id: "lease-1".to_owned(),
                    vm_name: "honeypot-1".to_owned(),
                    guest_rdp_addr: "10.0.0.10:3389".to_owned(),
                    attestation_ref: "attestation:test".to_owned(),
                    backend_credential_ref: Some("backend-ref".to_owned()),
                }),
                ..Default::default()
            },
        );

        assert!(updated);

        let info = manager
            .handle_get_info(session.id)
            .expect("running session should exist");
        let honeypot = info.honeypot.expect("honeypot metadata should be set");

        assert_eq!(honeypot.state, SessionState::Assigned);
        assert_eq!(
            honeypot
                .attacker_source
                .as_ref()
                .map(|source| source.attacker_addr.as_str()),
            Some("127.0.0.1:3389")
        );
        assert_eq!(
            honeypot
                .assignment
                .as_ref()
                .map(|assignment| assignment.vm_lease_id.as_str()),
            Some("lease-1")
        );
    }

    #[test]
    fn session_manager_remove_returns_terminal_honeypot_metadata() {
        let mut manager = test_manager();
        let session = test_session();

        manager.handle_new(session.clone(), Arc::new(Notify::new()), None);
        assert!(manager.handle_update_honeypot(
            session.id,
            HoneypotSessionMetadataPatch {
                state: Some(SessionState::Killed),
                terminal: Some(HoneypotTerminalMetadata {
                    outcome: TerminalOutcome::Killed,
                    disconnect_reason: None,
                    kill_scope: Some(KillScope::System),
                    killed_by_operator_id: Some(Uuid::nil().to_string()),
                    kill_reason: Some("operator_requested".to_owned()),
                }),
                ..Default::default()
            },
        ));

        let removed = manager.handle_remove(session.id).expect("removed session should exist");
        let honeypot = removed.honeypot.expect("honeypot metadata should survive removal");

        assert_eq!(honeypot.state, SessionState::Killed);
        assert_eq!(
            honeypot.terminal.as_ref().map(|terminal| terminal.outcome),
            Some(TerminalOutcome::Killed)
        );
        assert_eq!(
            honeypot.terminal.as_ref().and_then(|terminal| terminal.kill_scope),
            Some(KillScope::System)
        );
    }
}
