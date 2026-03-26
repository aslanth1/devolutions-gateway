use std::time::Duration;

use anyhow::Context as _;
use async_trait::async_trait;
use devolutions_gateway_task::{ChildTask, ShutdownSignal, Task};
use time::OffsetDateTime;
use tokio::sync::mpsc;
use tokio::time::sleep;

use crate::config::ConfHandle;
use crate::config::dto::Subscriber;
use crate::session::SessionMessageSender;

pub type SubscriberSender = mpsc::Sender<Message>;
pub type SubscriberReceiver = mpsc::Receiver<Message>;

pub fn subscriber_channel() -> (SubscriberSender, SubscriberReceiver) {
    mpsc::channel(64)
}

pub type SubscriberSessionInfo = crate::session::SessionInfo;

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
#[allow(clippy::enum_variant_names)]
enum MessageInner {
    #[serde(rename = "session.started")]
    SessionStarted { session: SubscriberSessionInfo },
    #[serde(rename = "session.ended")]
    SessionEnded { session: SubscriberSessionInfo },
    #[serde(rename = "session.list")]
    SessionList { session_list: Vec<SubscriberSessionInfo> },
}

#[derive(Debug, Serialize)]
pub struct Message {
    #[serde(with = "time::serde::rfc3339")]
    timestamp: OffsetDateTime,
    #[serde(flatten)]
    inner: MessageInner,
}

impl Message {
    pub fn session_started(session: SubscriberSessionInfo) -> Self {
        Self {
            timestamp: session.start_timestamp,
            inner: MessageInner::SessionStarted { session },
        }
    }

    pub fn session_ended(session: SubscriberSessionInfo) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
            inner: MessageInner::SessionEnded { session },
        }
    }

    pub fn session_list(session_list: Vec<SubscriberSessionInfo>) -> Self {
        Self {
            timestamp: OffsetDateTime::now_utc(),
            inner: MessageInner::SessionList { session_list },
        }
    }
}

#[instrument(skip(subscriber, proxy_conf))]
pub async fn send_message(
    subscriber: &Subscriber,
    message: &Message,
    proxy_conf: &crate::config::dto::ProxyConf,
) -> anyhow::Result<()> {
    use std::time::Duration;

    use backoff::backoff::Backoff as _;

    const RETRY_INITIAL_INTERVAL: Duration = Duration::from_secs(3); // initial retry interval on failure
    const RETRY_MAX_ELAPSED_TIME: Duration = Duration::from_secs(60 * 3); // retry for at most 3 minutes
    const RETRY_MULTIPLIER: f64 = 1.75; // 75% increase per back off retry

    let mut backoff = backoff::ExponentialBackoffBuilder::default()
        .with_initial_interval(RETRY_INITIAL_INTERVAL)
        .with_max_elapsed_time(Some(RETRY_MAX_ELAPSED_TIME))
        .with_multiplier(RETRY_MULTIPLIER)
        .build();

    // Build client with proxy support for the subscriber URL.
    let proxy_config = proxy_conf.to_proxy_config();
    let client =
        http_client_proxy::get_or_create_cached_client(reqwest::Client::builder(), &subscriber.url, &proxy_config)
            .context("failed to build HTTP client with proxy configuration")?;

    let op = || async {
        let response = client
            .post(subscriber.url.clone())
            .header("Authorization", format!("Bearer {}", subscriber.token))
            .json(message)
            .send()
            .await
            .context("failed to post message at the subscriber URL")
            .map_err(backoff::Error::permanent)?;

        let status = response.status();

        if status.is_client_error() {
            // A client error suggest the request will never succeed no matter how many times we try
            Err(backoff::Error::permanent(anyhow::anyhow!(
                "subscriber responded with a client error status: {status}"
            )))
        } else if status.is_server_error() {
            // However, server errors are mostly transient
            Err(backoff::Error::transient(anyhow::anyhow!(
                "subscriber responded with a server error status: {status}"
            )))
        } else {
            Ok::<(), backoff::Error<anyhow::Error>>(())
        }
    };

    loop {
        match op().await {
            Ok(()) => break,
            Err(backoff::Error::Permanent(e)) => return Err(e),
            Err(backoff::Error::Transient { err, retry_after }) => {
                match retry_after.or_else(|| backoff.next_backoff()) {
                    Some(duration) => {
                        debug!(
                            error = format!("{err:#}"),
                            retry_after = format!("{}s", duration.as_secs()),
                            "a transient error occured"
                        );
                        sleep(duration).await;
                    }
                    None => return Err(err),
                }
            }
        };
    }

    trace!("Message successfully sent to subscriber");

    Ok(())
}

pub struct SubscriberPollingTask {
    pub sessions: SessionMessageSender,
    pub subscriber: SubscriberSender,
}

#[async_trait]
impl Task for SubscriberPollingTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "subscriber polling";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        subscriber_polling_task(self.sessions, self.subscriber, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn subscriber_polling_task(
    sessions: SessionMessageSender,
    subscriber: SubscriberSender,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 20); // once per 20 minutes

    debug!("Task started");

    loop {
        trace!("Send session list message");

        match sessions.get_running_sessions().await {
            Ok(sessions) => {
                let session_list = sessions.into_values().collect();

                let message = Message::session_list(session_list);

                subscriber
                    .send(message)
                    .await
                    .map_err(|e| anyhow::anyhow!("subscriber task ended: {e}"))?;
            }
            Err(e) => {
                warn!(error = format!("{e:#}"), "Couldn't retrieve running session list");
            }
        }

        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }
    }

    debug!("Task terminated");

    Ok(())
}

pub struct SubscriberTask {
    pub conf_handle: ConfHandle,
    pub rx: SubscriberReceiver,
}

#[async_trait]
impl Task for SubscriberTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "subscriber";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        subscriber_task(self.conf_handle, self.rx, shutdown_signal).await
    }
}

#[instrument(skip_all)]
async fn subscriber_task(
    conf_handle: ConfHandle,
    mut rx: SubscriberReceiver,
    mut shutdown_signal: ShutdownSignal,
) -> anyhow::Result<()> {
    debug!("Task started");

    let mut conf = conf_handle.get_conf();

    loop {
        tokio::select! {
            _ = conf_handle.change_notified() => {
                conf = conf_handle.get_conf();
            }
            msg = rx.recv() => {
                let Some(msg) = msg else {
                    debug!("All senders are dead");
                    break;
                };

                if let Some(subscriber) = conf.subscriber.clone() {
                    debug!(?msg, %subscriber.url, "Send message");

                    let proxy_conf = conf.proxy.clone();
                    ChildTask::spawn(async move {
                        if let Err(error) = send_message(&subscriber, &msg, &proxy_conf).await {
                            warn!(error = format!("{error:#}"), "Couldn't send message to the subscriber");
                        }
                    })
                    .detach();
                } else {
                    trace!(?msg, "Subscriber is not configured, ignore message");
                }
            }
            _ = shutdown_signal.wait() => {
                break;
            }
        }
    }

    if let Some(subscriber) = conf.subscriber.clone() {
        debug!("Task is stopping; notify the subscriber that there is no session running anymore");

        let msg = Message::session_list(Vec::new());
        debug!(?msg, %subscriber.url, "Send message");

        if let Err(error) = send_message(&subscriber, &msg, &conf.proxy).await {
            warn!(error = format!("{error:#}"), "Couldn't send message to the subscriber");
        }
    }

    debug!("Task is stopping; wait for leftover messages");

    while rx.recv().await.is_some() {}

    debug!("Task terminated");

    Ok(())
}

#[cfg(test)]
mod tests {
    use honeypot_contracts::events::{SessionState, StreamState, TerminalOutcome};
    use honeypot_contracts::stream::StreamTransport;
    use serde_json::json;
    use uuid::Uuid;

    use super::Message;
    use crate::session::{
        ConnectionModeDetails, HoneypotSessionMetadata, HoneypotStreamMetadata, HoneypotTerminalMetadata,
        HoneypotVmAssignment, SessionInfo,
    };
    use crate::token::{ApplicationProtocol, Protocol, RecordingPolicy, SessionTtl};

    fn test_session() -> SessionInfo {
        SessionInfo::builder()
            .id(Uuid::parse_str("00000000-0000-0000-0000-000000000123").expect("valid session id"))
            .application_protocol(ApplicationProtocol::Known(Protocol::Rdp))
            .recording_policy(RecordingPolicy::None)
            .time_to_live(SessionTtl::Unlimited)
            .honeypot(HoneypotSessionMetadata {
                state: SessionState::Ready,
                attacker_source: None,
                assignment: Some(HoneypotVmAssignment {
                    vm_lease_id: "lease-123".to_owned(),
                    vm_name: "honeypot-123".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3389".to_owned(),
                    attestation_ref: "attestation:123".to_owned(),
                    backend_credential_ref: Some("backend-credential-123".to_owned()),
                }),
                stream: Some(HoneypotStreamMetadata {
                    state: StreamState::Ready,
                    stream_id: Some("stream-123".to_owned()),
                    transport: Some(StreamTransport::Sse),
                    stream_endpoint: Some("https://streams.example/session-123".to_owned()),
                    token_expires_at: Some("2030-01-01T00:05:00Z".to_owned()),
                }),
                terminal: Some(HoneypotTerminalMetadata {
                    outcome: TerminalOutcome::Disconnected,
                    disconnect_reason: Some("proxy_forwarding_ended".to_owned()),
                    kill_scope: None,
                    killed_by_operator_id: None,
                    kill_reason: None,
                }),
            })
            .details(ConnectionModeDetails::Rdv)
            .build()
    }

    #[test]
    fn session_started_message_serializes_full_honeypot_snapshot() {
        let session = test_session();
        let expected_start_timestamp = session
            .start_timestamp
            .format(&time::format_description::well_known::Rfc3339);
        let message = serde_json::to_value(Message::session_started(session)).expect("serialize subscriber message");

        assert_eq!(message["kind"], json!("session.started"));
        assert_eq!(
            message["session"]["association_id"],
            json!("00000000-0000-0000-0000-000000000123")
        );
        assert_eq!(message["session"]["honeypot"]["state"], json!("ready"));
        assert_eq!(
            message["session"]["honeypot"]["assignment"]["vm_lease_id"],
            json!("lease-123")
        );
        assert_eq!(
            message["timestamp"],
            json!(expected_start_timestamp.expect("format start timestamp"))
        );
    }

    #[test]
    fn session_list_message_serializes_honeypot_terminal_state() {
        let session = test_session();
        let message =
            serde_json::to_value(Message::session_list(vec![session])).expect("serialize subscriber session list");

        assert_eq!(message["kind"], json!("session.list"));
        assert_eq!(
            message["session_list"][0]["honeypot"]["stream"]["stream_id"],
            json!("stream-123")
        );
        assert_eq!(
            message["session_list"][0]["honeypot"]["terminal"]["outcome"],
            json!("disconnected")
        );
    }
}
