use core::fmt;
use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use devolutions_gateway_task::{ShutdownSignal, Task};
use parking_lot::Mutex;
use serde::{de, ser};
use uuid::Uuid;

/// Credential at the application protocol level
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AppCredential {
    #[serde(rename = "username-password")]
    UsernamePassword { username: String, password: Password },
}

/// Application protocol level credential mapping
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppCredentialMapping {
    #[serde(rename = "proxy_credential")]
    pub proxy: AppCredential,
    #[serde(rename = "target_credential")]
    pub target: AppCredential,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialBinding {
    pub session_id: Option<Uuid>,
    pub vm_lease_id: Option<String>,
    pub credential_mapping_id: Option<String>,
    pub backend_credential_ref: Option<String>,
}

#[derive(Debug)]
pub struct CredentialProvisionRequest {
    pub token: String,
    pub mapping: Option<AppCredentialMapping>,
    pub time_to_live: time::Duration,
    pub binding: Option<CredentialBinding>,
}

#[derive(Debug, Clone)]
pub struct CredentialStoreHandle(Arc<Mutex<CredentialStore>>);

impl Default for CredentialStoreHandle {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStoreHandle {
    pub fn new() -> Self {
        Self(Arc::new(Mutex::new(CredentialStore::new())))
    }

    pub fn insert(
        &self,
        token: String,
        mapping: Option<AppCredentialMapping>,
        time_to_live: time::Duration,
    ) -> anyhow::Result<Option<ArcCredentialEntry>> {
        self.provision(CredentialProvisionRequest {
            token,
            mapping,
            time_to_live,
            binding: None,
        })
    }

    pub fn provision(&self, request: CredentialProvisionRequest) -> anyhow::Result<Option<ArcCredentialEntry>> {
        self.0.lock().provision(request)
    }

    pub fn get(&self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.0.lock().get(token_id)
    }

    pub fn remove(&self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.0.lock().remove(token_id)
    }

    pub fn remove_by_session_id(&self, session_id: Uuid) -> Vec<ArcCredentialEntry> {
        self.0.lock().remove_by_session_id(session_id)
    }

    pub fn remove_by_vm_lease_id(&self, vm_lease_id: &str) -> Vec<ArcCredentialEntry> {
        self.0.lock().remove_by_vm_lease_id(vm_lease_id)
    }
}

#[derive(Debug)]
struct CredentialStore {
    entries: HashMap<Uuid, ArcCredentialEntry>,
}

#[derive(Debug)]
pub struct CredentialEntry {
    pub token: String,
    pub mapping: Option<AppCredentialMapping>,
    pub expires_at: time::OffsetDateTime,
    pub binding: Option<CredentialBinding>,
}

pub type ArcCredentialEntry = Arc<CredentialEntry>;

impl CredentialStore {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
        }
    }

    fn provision(&mut self, request: CredentialProvisionRequest) -> anyhow::Result<Option<ArcCredentialEntry>> {
        let CredentialProvisionRequest {
            token,
            mapping,
            time_to_live,
            binding,
        } = request;

        let jti = crate::token::extract_jti(&token).context("failed to extract token ID")?;

        let entry = CredentialEntry {
            token,
            mapping,
            expires_at: time::OffsetDateTime::now_utc() + time_to_live,
            binding,
        };

        let previous_entry = self.entries.insert(jti, Arc::new(entry));

        Ok(previous_entry)
    }

    fn get(&self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.entries.get(&token_id).map(Arc::clone)
    }

    fn remove(&mut self, token_id: Uuid) -> Option<ArcCredentialEntry> {
        self.entries.remove(&token_id)
    }

    fn remove_by_session_id(&mut self, session_id: Uuid) -> Vec<ArcCredentialEntry> {
        self.remove_matching(|entry| entry.binding.as_ref().and_then(|binding| binding.session_id) == Some(session_id))
    }

    fn remove_by_vm_lease_id(&mut self, vm_lease_id: &str) -> Vec<ArcCredentialEntry> {
        self.remove_matching(|entry| {
            entry
                .binding
                .as_ref()
                .and_then(|binding| binding.vm_lease_id.as_deref())
                == Some(vm_lease_id)
        })
    }

    fn remove_matching(&mut self, mut predicate: impl FnMut(&CredentialEntry) -> bool) -> Vec<ArcCredentialEntry> {
        let matching_ids = self
            .entries
            .iter()
            .filter_map(|(token_id, entry)| predicate(entry).then_some(*token_id))
            .collect::<Vec<_>>();

        matching_ids
            .into_iter()
            .filter_map(|token_id| self.entries.remove(&token_id))
            .collect()
    }
}

#[derive(PartialEq, Eq, Clone, zeroize::Zeroize)]
pub struct Password(String);

impl Password {
    /// Do not copy the return value without wrapping into some "Zeroize"able structure
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl From<&str> for Password {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl From<String> for Password {
    fn from(value: String) -> Self {
        Self(value)
    }
}

impl fmt::Debug for Password {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Password").finish_non_exhaustive()
    }
}

impl<'de> de::Deserialize<'de> for Password {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct V;

        impl de::Visitor<'_> for V {
            type Value = Password;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a string")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Ok(Password(v.to_owned()))
            }
        }

        let password = deserializer.deserialize_string(V)?;

        Ok(password)
    }
}

impl ser::Serialize for Password {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

pub struct CleanupTask {
    pub handle: CredentialStoreHandle,
}

#[async_trait]
impl Task for CleanupTask {
    type Output = anyhow::Result<()>;

    const NAME: &'static str = "credential store cleanup";

    async fn run(self, shutdown_signal: ShutdownSignal) -> Self::Output {
        cleanup_task(self.handle, shutdown_signal).await;
        Ok(())
    }
}

#[instrument(skip_all)]
async fn cleanup_task(handle: CredentialStoreHandle, mut shutdown_signal: ShutdownSignal) {
    use tokio::time::{Duration, sleep};

    const TASK_INTERVAL: Duration = Duration::from_secs(60 * 15); // 15 minutes

    debug!("Task started");

    loop {
        tokio::select! {
            _ = sleep(TASK_INTERVAL) => {}
            _ = shutdown_signal.wait() => {
                break;
            }
        }

        let now = time::OffsetDateTime::now_utc();

        handle.0.lock().entries.retain(|_, src| now < src.expires_at);
    }

    debug!("Task terminated");
}

#[cfg(test)]
mod tests {
    use super::{
        AppCredential, AppCredentialMapping, CredentialBinding, CredentialProvisionRequest, CredentialStoreHandle,
        Password,
    };
    use uuid::Uuid;

    fn username_password(username: &str, password: &str) -> AppCredential {
        AppCredential::UsernamePassword {
            username: username.to_owned(),
            password: Password::from(password),
        }
    }

    fn test_mapping(proxy_username: &str, target_username: &str) -> AppCredentialMapping {
        AppCredentialMapping {
            proxy: username_password(proxy_username, "proxy-password"),
            target: username_password(target_username, "target-password"),
        }
    }

    const TEST_TOKEN_A: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDEifQ.c2ln";
    const TEST_TOKEN_B: &str = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtpZC0xIiwidHlwIjoiSldUIn0.eyJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDIifQ.c2ln";

    #[test]
    fn provision_with_binding_can_be_removed_by_session() {
        let store = CredentialStoreHandle::new();
        let session_id = Uuid::new_v4();

        store
            .provision(CredentialProvisionRequest {
                token: TEST_TOKEN_A.to_owned(),
                mapping: Some(test_mapping("attacker-a", "backend-a")),
                time_to_live: time::Duration::minutes(15),
                binding: Some(CredentialBinding {
                    session_id: Some(session_id),
                    vm_lease_id: Some("lease-a".to_owned()),
                    credential_mapping_id: Some("mapping-a".to_owned()),
                    backend_credential_ref: Some("cred-ref-a".to_owned()),
                }),
            })
            .expect("provision credential mapping");

        let removed = store.remove_by_session_id(session_id);

        assert_eq!(removed.len(), 1);
        assert!(
            store
                .get(Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("parse token id"))
                .is_none()
        );
    }

    #[test]
    fn remove_by_vm_lease_id_only_removes_matching_bindings() {
        let store = CredentialStoreHandle::new();

        for (token, lease_id, mapping_id) in [
            (TEST_TOKEN_A, "lease-a", "mapping-a"),
            (TEST_TOKEN_B, "lease-b", "mapping-b"),
        ] {
            store
                .provision(CredentialProvisionRequest {
                    token: token.to_owned(),
                    mapping: Some(test_mapping(mapping_id, "backend")),
                    time_to_live: time::Duration::minutes(15),
                    binding: Some(CredentialBinding {
                        session_id: Some(Uuid::new_v4()),
                        vm_lease_id: Some(lease_id.to_owned()),
                        credential_mapping_id: Some(mapping_id.to_owned()),
                        backend_credential_ref: Some(format!("cred-ref-{lease_id}")),
                    }),
                })
                .expect("provision credential mapping");
        }

        let removed = store.remove_by_vm_lease_id("lease-b");

        assert_eq!(removed.len(), 1);
        assert!(
            store
                .get(Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("parse token id"))
                .is_some()
        );
        assert!(
            store
                .get(Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("parse token id"))
                .is_none()
        );
    }
}
