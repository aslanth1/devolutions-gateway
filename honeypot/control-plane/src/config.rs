use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

pub const CONTROL_PLANE_CONFIG_ENV: &str = "HONEYPOT_CONTROL_PLANE_CONFIG";
pub const DEFAULT_CONTROL_PLANE_CONFIG_PATH: &str = "/etc/honeypot/control-plane/config.toml";

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default)]
pub struct ControlPlaneConfig {
    pub http: HttpConfig,
    pub auth: AuthConfig,
    pub backend_credentials: BackendCredentialStoreConfig,
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
pub struct AuthConfig {
    pub service_token_validation_disabled: bool,
    pub proxy_verifier_public_key_pem: Option<String>,
    pub proxy_verifier_public_key_pem_file: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct BackendCredentialStoreConfig {
    pub adapter: BackendCredentialStoreAdapter,
    pub file_path: Option<PathBuf>,
}

impl BackendCredentialStoreConfig {
    pub fn file_path(&self, paths: &PathConfig) -> PathBuf {
        self.file_path
            .clone()
            .unwrap_or_else(|| paths.secret_dir.join("backend-credentials.json"))
    }
}

impl Default for BackendCredentialStoreConfig {
    fn default() -> Self {
        Self {
            adapter: BackendCredentialStoreAdapter::File,
            file_path: None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendCredentialStoreAdapter {
    File,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuntimeConfig {
    pub enable_guest_agent: bool,
    pub lifecycle_driver: VmLifecycleDriver,
    pub stop_timeout_secs: u64,
    pub limits: RuntimeLimitsConfig,
    pub qemu: QemuConfig,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            enable_guest_agent: false,
            lifecycle_driver: VmLifecycleDriver::Process,
            stop_timeout_secs: 5,
            limits: RuntimeLimitsConfig::default(),
            qemu: QemuConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct RuntimeLimitsConfig {
    pub max_vcpu_count: u8,
    pub max_memory_mib: u32,
    pub max_overlay_size_mib: u64,
    pub max_stop_timeout_secs: u64,
}

impl RuntimeLimitsConfig {
    pub fn max_overlay_size_bytes(&self) -> anyhow::Result<u64> {
        self.max_overlay_size_mib
            .checked_mul(1024 * 1024)
            .context("runtime.limits.max_overlay_size_mib is too large")
    }
}

impl Default for RuntimeLimitsConfig {
    fn default() -> Self {
        Self {
            max_vcpu_count: 8,
            max_memory_mib: 16 * 1024,
            max_overlay_size_mib: 64 * 1024,
            max_stop_timeout_secs: 15,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VmLifecycleDriver {
    Process,
    Simulated,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QemuConfig {
    pub binary_path: PathBuf,
    pub machine_type: String,
    pub accelerator: QemuAccelerator,
    pub cpu_model: String,
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub rtc_base: QemuRtcBase,
    pub firmware_mode: QemuFirmwareMode,
    pub disk_interface: QemuDiskInterface,
    pub network: QemuNetworkConfig,
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            binary_path: PathBuf::from("/usr/bin/qemu-system-x86_64"),
            machine_type: "q35".to_owned(),
            accelerator: QemuAccelerator::Kvm,
            cpu_model: "host".to_owned(),
            vcpu_count: 4,
            memory_mib: 8192,
            rtc_base: QemuRtcBase::Utc,
            firmware_mode: QemuFirmwareMode::None,
            disk_interface: QemuDiskInterface::VirtioBlkPci,
            network: QemuNetworkConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuAccelerator {
    Kvm,
}

impl QemuAccelerator {
    pub fn as_qemu_value(self) -> &'static str {
        match self {
            Self::Kvm => "kvm",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuDiskInterface {
    VirtioBlkPci,
    AhciIde,
}

impl QemuDiskInterface {
    pub fn as_qemu_device(self) -> &'static str {
        match self {
            Self::VirtioBlkPci => "virtio-blk-pci",
            Self::AhciIde => "ahci_ide",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct QemuNetworkConfig {
    pub mode: QemuNetworkMode,
    pub netdev_id: String,
    pub device_model: QemuNetworkDeviceModel,
    pub host_loopback_addr: IpAddr,
}

impl Default for QemuNetworkConfig {
    fn default() -> Self {
        Self {
            mode: QemuNetworkMode::User,
            netdev_id: "net0".to_owned(),
            device_model: QemuNetworkDeviceModel::VirtioNetPci,
            host_loopback_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuNetworkMode {
    User,
}

impl QemuNetworkMode {
    pub fn as_qemu_value(self) -> &'static str {
        match self {
            Self::User => "user",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuNetworkDeviceModel {
    VirtioNetPci,
    E1000,
}

impl QemuNetworkDeviceModel {
    pub fn as_qemu_device(self) -> &'static str {
        match self {
            Self::VirtioNetPci => "virtio-net-pci",
            Self::E1000 => "e1000",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuRtcBase {
    Utc,
    Localtime,
}

impl QemuRtcBase {
    pub fn as_qemu_value(self) -> &'static str {
        match self {
            Self::Utc => "utc",
            Self::Localtime => "localtime",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QemuFirmwareMode {
    None,
    UefiPflash,
}

impl QemuFirmwareMode {
    pub fn requires_pflash(self) -> bool {
        match self {
            Self::None => false,
            Self::UefiPflash => true,
        }
    }
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

#[cfg(test)]
mod tests {
    use std::io::Write as _;

    use tempfile::NamedTempFile;

    use super::ControlPlaneConfig;

    fn write_temp_config(contents: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().expect("create temp config");
        file.write_all(contents.as_bytes()).expect("write temp config");
        file
    }

    #[test]
    fn control_plane_config_rejects_invalid_bind_addr() {
        let file = write_temp_config(
            r#"
[http]
bind_addr = "not-a-socket"
"#,
        );

        let error = ControlPlaneConfig::load_from_path(file.path()).expect_err("invalid bind_addr must be rejected");
        let rendered = format!("{error:#}");

        assert!(rendered.contains("parse control-plane config"), "{rendered}");
        assert!(
            rendered.contains("bind_addr") || rendered.contains("socket"),
            "{rendered}"
        );
    }

    #[test]
    fn control_plane_config_rejects_invalid_lifecycle_driver() {
        let file = write_temp_config(
            r#"
[runtime]
lifecycle_driver = "shell"
"#,
        );

        let error =
            ControlPlaneConfig::load_from_path(file.path()).expect_err("invalid lifecycle_driver must be rejected");
        let rendered = format!("{error:#}");

        assert!(rendered.contains("parse control-plane config"), "{rendered}");
        assert!(
            rendered.contains("lifecycle_driver") || rendered.contains("unknown variant"),
            "{rendered}"
        );
    }
}
