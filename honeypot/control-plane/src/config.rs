use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

pub const CONTROL_PLANE_CONFIG_ENV: &str = "HONEYPOT_CONTROL_PLANE_CONFIG";
pub const DEFAULT_CONTROL_PLANE_CONFIG_PATH: &str = "/etc/honeypot/control-plane/config.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    pub http: HttpConfig,
    pub runtime: RuntimeConfig,
    pub paths: PathConfig,
}

impl ControlPlaneConfig {
    pub fn load_from_env() -> anyhow::Result<Self> {
        let config_path = std::env::var_os(CONTROL_PLANE_CONFIG_ENV)
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONTROL_PLANE_CONFIG_PATH));

        Self::load_from_path(&config_path)
    }

    pub fn load_from_path(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path)
            .with_context(|| format!("read control-plane config at {}", path.display()))?;
        toml::from_str(&data).with_context(|| format!("parse control-plane config at {}", path.display()))
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct HttpConfig {
    pub bind_addr: SocketAddr,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 8080)),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    pub enable_guest_agent: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct PathConfig {
    pub data_dir: PathBuf,
    pub image_store: PathBuf,
    pub manifest_dir: Option<PathBuf>,
    pub lease_store: PathBuf,
    pub quarantine_store: PathBuf,
    pub qmp_dir: PathBuf,
    pub qga_dir: Option<PathBuf>,
    pub secret_dir: PathBuf,
    pub kvm_path: PathBuf,
}

impl PathConfig {
    pub fn manifest_dir(&self) -> PathBuf {
        self.manifest_dir
            .clone()
            .unwrap_or_else(|| self.image_store.join("manifests"))
    }

    pub fn qga_dir(&self) -> anyhow::Result<PathBuf> {
        self.qga_dir
            .clone()
            .context("guest agent is enabled, but qga_dir is not configured")
    }
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            data_dir: PathBuf::from("/var/lib/honeypot/control-plane"),
            image_store: PathBuf::from("/var/lib/honeypot/images"),
            manifest_dir: None,
            lease_store: PathBuf::from("/var/lib/honeypot/leases"),
            quarantine_store: PathBuf::from("/var/lib/honeypot/quarantine"),
            qmp_dir: PathBuf::from("/run/honeypot/qmp"),
            qga_dir: Some(PathBuf::from("/run/honeypot/qga")),
            secret_dir: PathBuf::from("/run/secrets/honeypot/control-plane"),
            kvm_path: PathBuf::from("/dev/kvm"),
        }
    }
}
