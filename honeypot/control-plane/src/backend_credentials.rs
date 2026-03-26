use std::collections::HashMap;
use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use devolutions_gateway::credential::AppCredentialMapping;

use crate::config::{BackendCredentialStoreAdapter, ControlPlaneConfig};

pub(crate) trait BackendCredentialStore: fmt::Debug + Send + Sync {
    fn validate_startup_contract(&self) -> anyhow::Result<()>;
    fn resolve(&self, backend_credential_ref: &str) -> Result<AppCredentialMapping, BackendCredentialResolveError>;
    fn revoke(&self, backend_credential_ref: &str) -> anyhow::Result<()>;
}

pub(crate) fn build_backend_credential_store(
    config: &ControlPlaneConfig,
) -> anyhow::Result<Arc<dyn BackendCredentialStore>> {
    match config.backend_credentials.adapter {
        BackendCredentialStoreAdapter::File => Ok(Arc::new(FileBackendCredentialStore::new(
            config.backend_credentials.file_path(&config.paths),
        ))),
    }
}

#[derive(Debug)]
pub(crate) enum BackendCredentialResolveError {
    MissingReference { backend_credential_ref: String },
    Unavailable(anyhow::Error),
}

#[derive(Debug, Clone)]
struct FileBackendCredentialStore {
    path: PathBuf,
}

impl FileBackendCredentialStore {
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    fn load_mappings(&self) -> anyhow::Result<HashMap<String, AppCredentialMapping>> {
        let contents = std::fs::read_to_string(&self.path)
            .with_context(|| format!("read backend credential store {}", self.path.display()))?;
        anyhow::ensure!(
            !contents.trim().is_empty(),
            "backend credential store at {} must not be empty",
            self.path.display(),
        );

        serde_json::from_str(&contents)
            .with_context(|| format!("parse backend credential store {}", self.path.display()))
    }
}

impl BackendCredentialStore for FileBackendCredentialStore {
    fn validate_startup_contract(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.path.exists(),
            "backend credential store does not exist at {}",
            self.path.display(),
        );
        anyhow::ensure!(
            self.path.is_file(),
            "backend credential store is not a file at {}",
            self.path.display(),
        );
        let _ = self.load_mappings()?;
        Ok(())
    }

    fn resolve(&self, backend_credential_ref: &str) -> Result<AppCredentialMapping, BackendCredentialResolveError> {
        let mappings = self
            .load_mappings()
            .map_err(BackendCredentialResolveError::Unavailable)?;

        mappings
            .get(backend_credential_ref)
            .cloned()
            .ok_or_else(|| BackendCredentialResolveError::MissingReference {
                backend_credential_ref: backend_credential_ref.to_owned(),
            })
    }

    fn revoke(&self, _backend_credential_ref: &str) -> anyhow::Result<()> {
        Ok(())
    }
}

impl fmt::Display for BackendCredentialResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingReference { backend_credential_ref } => {
                write!(
                    f,
                    "backend credential ref {backend_credential_ref} was not found in the configured backend credential store"
                )
            }
            Self::Unavailable(error) => write!(f, "{error:#}"),
        }
    }
}

impl std::error::Error for BackendCredentialResolveError {}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use devolutions_gateway::credential::{AppCredential, AppCredentialMapping, Password};

    use super::*;

    fn example_mapping() -> AppCredentialMapping {
        AppCredentialMapping {
            proxy: AppCredential::UsernamePassword {
                username: "attacker".to_owned(),
                password: Password::from("proxy-password"),
            },
            target: AppCredential::UsernamePassword {
                username: "backend".to_owned(),
                password: Password::from("target-password"),
            },
        }
    }

    #[test]
    fn file_backend_credential_store_resolves_json_mappings() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = tempdir.path().join("backend-credentials.json");
        let mapping = example_mapping();
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&serde_json::json!({
                "backend-credential-default": mapping,
            }))
            .expect("serialize mapping"),
        )
        .expect("write credential store");

        let store = FileBackendCredentialStore::new(path);
        store
            .validate_startup_contract()
            .expect("validate file-backed credential store");
        let resolved = store
            .resolve("backend-credential-default")
            .expect("resolve backend credential ref");
        match resolved.target {
            AppCredential::UsernamePassword { username, password } => {
                assert_eq!(username, "backend");
                assert_eq!(password.expose_secret(), "target-password");
            }
        }
    }

    #[test]
    fn file_backend_credential_store_rejects_empty_files() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let path = tempdir.path().join("backend-credentials.json");
        std::fs::write(&path, "\n").expect("write empty file");

        let error = FileBackendCredentialStore::new(path)
            .validate_startup_contract()
            .expect_err("empty backend credential file should fail closed");

        assert!(format!("{error:#}").contains("must not be empty"), "{error:#}");
    }

    #[derive(Debug, Default)]
    struct RecordingStore {
        resolved: Mutex<Vec<String>>,
        revoked: Mutex<Vec<String>>,
    }

    impl BackendCredentialStore for RecordingStore {
        fn validate_startup_contract(&self) -> anyhow::Result<()> {
            Ok(())
        }

        fn resolve(&self, backend_credential_ref: &str) -> Result<AppCredentialMapping, BackendCredentialResolveError> {
            self.resolved
                .lock()
                .expect("lock resolved refs")
                .push(backend_credential_ref.to_owned());
            Ok(example_mapping())
        }

        fn revoke(&self, backend_credential_ref: &str) -> anyhow::Result<()> {
            self.revoked
                .lock()
                .expect("lock revoked refs")
                .push(backend_credential_ref.to_owned());
            Ok(())
        }
    }

    fn exercise_adapter_boundary(store: &dyn BackendCredentialStore) {
        store
            .resolve("backend-credential-default")
            .expect("resolve through adapter boundary");
        store
            .revoke("backend-credential-default")
            .expect("revoke through adapter boundary");
    }

    #[test]
    fn backend_credential_store_trait_is_replaceable_and_testable() {
        let store = RecordingStore::default();
        exercise_adapter_boundary(&store);

        assert_eq!(
            store.resolved.lock().expect("lock resolved refs").as_slice(),
            ["backend-credential-default"]
        );
        assert_eq!(
            store.revoked.lock().expect("lock revoked refs").as_slice(),
            ["backend-credential-default"]
        );
    }
}
