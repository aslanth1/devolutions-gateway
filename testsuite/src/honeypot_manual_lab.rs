use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::net::{Ipv4Addr, TcpStream};
#[cfg(unix)]
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context as _, bail, ensure};
use base64::prelude::*;
use honeypot_contracts::Versioned as _;
use honeypot_contracts::control_plane::{RecycleVmRequest, ReleaseVmRequest};
use honeypot_contracts::frontend::BootstrapResponse;
use honeypot_contracts::stream::{StreamTokenRequest, StreamTokenResponse};
use honeypot_control_plane::config::ControlPlaneConfig;
use honeypot_control_plane::{ConsumeTrustedImageState, ConsumeTrustedImageValidationMode, ConsumedTrustedImage};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::honeypot_control_plane::{
    CANONICAL_TINY11_IMAGE_STORE_ROOT, HoneypotControlPlaneTestConfig, HoneypotInteropStoreEvidence,
    Tiny11LabCleanStateProbe, Tiny11LabGateBlocker, Tiny11LabGateInputs, Tiny11LabGateOutcome, Tiny11LabRuntimeInput,
    evaluate_tiny11_lab_gate, find_unused_port, write_honeypot_control_plane_config,
};
use crate::honeypot_frontend::{HoneypotFrontendTestConfig, write_honeypot_frontend_config};
use crate::honeypot_release::{HONEYPOT_PROXY_CONFIG_PATH, repo_relative_path};
use crate::honeypot_tiers::{HONEYPOT_LAB_E2E_ENV, HONEYPOT_TIER_GATE_ENV, HoneypotTestTier, require_honeypot_tier};

const MANUAL_LAB_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_HOST_COUNT: usize = 3;
const MANUAL_LAB_ROOT_RELATIVE_PATH: &str = "target/manual-lab";
const MANUAL_LAB_ACTIVE_STATE_RELATIVE_PATH: &str = "target/manual-lab/active.json";
const MANUAL_LAB_SELECTED_SOURCE_MANIFEST_RELATIVE_PATH: &str = "target/manual-lab/selected-source-manifest.json";
const MANUAL_LAB_ENSURE_ARTIFACTS_HINT: &str = "make manual-lab-ensure-artifacts";
const MANUAL_LAB_ENSURE_WEBPLAYER_HINT: &str = "make manual-lab-ensure-webplayer";
const MANUAL_LAB_SELFTEST_HINT: &str = "make manual-lab-selftest";
const MANUAL_LAB_SELFTEST_SHOW_PROFILE_HINT: &str = "make manual-lab-show-profile";
const MANUAL_LAB_TARGET_ROOT_RELATIVE_PATH: &str = "target";
const MANUAL_LAB_CONTROL_PLANE_CONFIG_RELATIVE_PATH: &str =
    "honeypot/docker/config/control-plane/manual-lab-bootstrap.toml";
const MANUAL_LAB_CONTROL_PLANE_CONFIG_ENV: &str = "MANUAL_LAB_CONTROL_PLANE_CONFIG";
const MANUAL_LAB_DRIVER_PROXY_USERNAME: &str = "operator";
const MANUAL_LAB_DRIVER_PROXY_PASSWORD: &str = "attacker-password";
const MANUAL_LAB_CONTROL_PLANE_SCOPE: &str = "gateway.honeypot.control-plane";
const MANUAL_LAB_WILDCARD_SCOPE: &str = "*";
const MANUAL_LAB_CHROME_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_CHROME";
const MANUAL_LAB_XVFB_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_XVFB";
const MANUAL_LAB_XEPHYR_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_XEPHYR";
const MANUAL_LAB_SESSION_COUNT_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT";
const MANUAL_LAB_SELECTED_SOURCE_MANIFEST_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST";
const MANUAL_LAB_FRONTEND_CONFIG_ENV: &str = "HONEYPOT_FRONTEND_CONFIG_PATH";
const HONEYPOT_BS_ROWS_ENV: &str = "DGW_HONEYPOT_BS_ROWS";
const HONEYPOT_INTEROP_IMAGE_STORE_ENV: &str = "DGW_HONEYPOT_INTEROP_IMAGE_STORE";
const HONEYPOT_INTEROP_MANIFEST_DIR_ENV: &str = "DGW_HONEYPOT_INTEROP_MANIFEST_DIR";
const HONEYPOT_INTEROP_QEMU_BINARY_ENV: &str = "DGW_HONEYPOT_INTEROP_QEMU_BINARY";
const HONEYPOT_INTEROP_KVM_PATH_ENV: &str = "DGW_HONEYPOT_INTEROP_KVM_PATH";
const HONEYPOT_INTEROP_RDP_USERNAME_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_USERNAME";
const HONEYPOT_INTEROP_RDP_PASSWORD_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_PASSWORD";
const HONEYPOT_INTEROP_RDP_DOMAIN_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_DOMAIN";
const HONEYPOT_INTEROP_RDP_SECURITY_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_SECURITY";
const HONEYPOT_INTEROP_READY_TIMEOUT_SECS_ENV: &str = "DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS";
const HONEYPOT_INTEROP_XFREERDP_PATH_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_PATH";
const HONEYPOT_INTEROP_XFREERDP_GFX_MODE_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_GFX_MODE";
const HONEYPOT_INTEROP_XFREERDP_RDPGFX_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_RDPGFX";
const GATEWAY_WEBAPP_PATH_ENV: &str = "DGATEWAY_WEBAPP_PATH";
const GATEWAY_WEBPLAYER_PATH_ENV: &str = "DGATEWAY_WEBPLAYER_PATH";
const MANUAL_LAB_SOURCE_MANIFEST_DISCOVERY_PATHS: [&str; 2] = [
    "artifacts/bundle/bundle-manifest.json",
    "artifacts/live-proof/source-bundle/bundle-manifest.json",
];
const MANUAL_LAB_HTTP_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MANUAL_LAB_HTTP_TIMEOUT: Duration = Duration::from_secs(30);
const MANUAL_LAB_SERVICE_READY_TIMEOUT_FLOOR_SECS: u16 = 60;
const MANUAL_LAB_STREAM_READY_TIMEOUT: Duration = Duration::from_secs(45);
const MANUAL_LAB_TEARDOWN_TIMEOUT: Duration = Duration::from_secs(30);
const MANUAL_LAB_CONTROL_PLANE_DRAIN_TIMEOUT: Duration = Duration::from_secs(90);
const MANUAL_LAB_DISPLAY_READY_TIMEOUT: Duration = Duration::from_secs(5);

static GATEWAY_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path(manual_lab_manifest_path("Cargo.toml"))
        .bin("devolutions-gateway")
        .current_release()
        .current_target()
        .run()
        .expect("build devolutions-gateway")
        .path()
        .to_path_buf()
});

static HONEYPOT_CONTROL_PLANE_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path(manual_lab_manifest_path("honeypot/control-plane/Cargo.toml"))
        .bin("honeypot-control-plane")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot-control-plane")
        .path()
        .to_path_buf()
});

static HONEYPOT_FRONTEND_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path(manual_lab_manifest_path("honeypot/frontend/Cargo.toml"))
        .bin("honeypot-frontend")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot-frontend")
        .path()
        .to_path_buf()
});

static HONEYPOT_MANUAL_LAB_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path(manual_lab_manifest_path("testsuite/Cargo.toml"))
        .bin("honeypot-manual-lab")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot-manual-lab")
        .path()
        .to_path_buf()
});

const PROVISIONER_PRIVATE_KEY_DATA: &str = "mMIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDi+6os6SXWlahu3qy7Vc71WySAIDB68QazqSQ2MlAHCQac8pguY0XUT9p/XIKhx9Wf86c9/17jH6VdXJnoswMnEXG75rF2A6rct3f3YnWIARt+/CXJEWcRcU4k3LKWqDdtjou+dYcv9dlzNV0wP3Fh+raw71uDfGNFbizuv0QRg4WOpVPdUXOcf2JYlW1xIQq6SZL/e4qg7qUaFpy+7QeGNdd2CrRHzO9HhdEn0Vyd/R/1imhz6LovzQ1WOtEJ5U4f4t3/Z8D1uhyl8tqtxWobdGNL6qA62nIJzSNZUUXjNoZDstQMWQQhgguQgJ4wyfaWXb2GZk3OwnNkn2zo2hyBAgMBAAECggEBAKCO0GOQUDmoB0rVrG2fVxPrcrhHDMQKNmljnb/Qexde5RSj7c3yXvS9v5sTvzvc9Vl9qrGKMH6MZhbSZ/RYnERIbKEzoBgQpA4YoX2WYfjgf6ilh7zg2H1YHqSokJNNTlfq2yLQU94zE6wQ9WgpmHRsOkqSJbOuizITqyj+lpGjl8dBAeOCD9HsnOGQiwsQD+joZ3yDRdFKSaBBtbklTYDyAmPvmp2G5A00UIo7KeOcNv59MPHnFBxMj0/z+QPKlqLQMsjL8vQX5DU2t/K4jdFHWGL8NZcz7KsCfh2Aa0vWEnroRzPPhKuBSBtaykbvfTcGrvRioesPq3EUdUqjQSECgYEA52UlMYeRYiTWsGq69lFWSlBjlRKhEMpg0Tp05z7J/A9X+ytB+6dZ37hk5asq84adRp7pnCEHV3SbczGq5ULFQBEqtFWPlD348zB8xxdBpAw3NAkVVDpAXBREhxXOnQm7MMmaXLH6d4Gv4kc6jKTC62w7cUUSlkIhlWSw5pSuVh0CgYEA+x5rJ4MQ6A/OKh058QY3ydRJw/sV54oxIFIIuJDw4I4eMsJ5Ht7MW5Pl1VQj+XuJRgMeqgZMQIIAcf5JNXqcesswVwdXy4awtw3TZV1Hi47Or7qHrFA/DtG4lNeDtyaWNuOtNnGw+LuqEmuu8BsWhB7yTHWJW7z+k6qO90CnArUCgYEA5ew66NwsObkhGmrzG432kCEQ0i+Qm358dWoAf0aErVERuyFgjw3a39H5b7yFETXRUTrWJa0r/lp/nBbeGLAgD2j/ZfEemc56cCrd0XXqY3c/4xSjfO3kxZnd/dxNUP06Y1/vYev3VIgonE7qfpW4mPUSm5pmvac4d5l1rahPEoECgYBUvAToRj+ULpEggNAmVjTI88sYSEcx492DzGqI7M961jm2Ywy/r+pBFHy/KS8iZd8CMtdMA+gC9Fr2HBnT49WdUaa0FxQ25vIGMrIcSAd2Pe/cOBLDwCgm9flUsAwP5wNU7ipqbp6Kr7hJkvBqsJk+Z7rWteptfC5i4XBwWe6A6QJ/Ddv+9vZe89uMdq+PThhELBHK+twZKawpKXYvzKlvPfMVisY+m9m37t7wK8PJexWOI9loVif6+ZIdWpXXntwrz94hYld/6+qK+sSt8EGmcJpAAI3zkp/ZMXhio0fy27sPaTlKlS6GNx/gPXRj6NHg/nu6lMmQ/EpLi1lyExPc8Q";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManualLabUpOptions {
    pub open_browser: bool,
}

impl Default for ManualLabUpOptions {
    fn default() -> Self {
        Self { open_browser: true }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ManualLabBootstrapOptions {
    pub execute: bool,
    pub source_manifest_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabRememberSourceManifestStatus {
    Remembered,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualLabRememberSourceManifestReport {
    pub status: ManualLabRememberSourceManifestStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    pub selection_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl ManualLabRememberSourceManifestReport {
    fn remembered(selection_path: PathBuf, source_manifest_path: PathBuf, source_manifest_digest: String) -> Self {
        Self {
            status: ManualLabRememberSourceManifestStatus::Remembered,
            blocker: None,
            selection_path,
            source_manifest_path: Some(source_manifest_path),
            source_manifest_digest: Some(source_manifest_digest),
            detail: Some(
                "remembered source manifest for repeated manual bootstrap runs".to_owned(),
            ),
            remediation: Some(
                "rerun `make manual-lab-bootstrap-store` or `make manual-lab-bootstrap-store-exec`; remove the selection file if you need to clear the hint"
                    .to_owned(),
            ),
        }
    }

    fn blocked(
        blocker: impl Into<String>,
        selection_path: PathBuf,
        source_manifest_path: Option<PathBuf>,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            status: ManualLabRememberSourceManifestStatus::Blocked,
            blocker: Some(blocker.into()),
            selection_path,
            source_manifest_path,
            source_manifest_digest: None,
            detail: Some(detail.into()),
            remediation,
        }
    }

    pub fn is_success(&self) -> bool {
        self.status == ManualLabRememberSourceManifestStatus::Remembered
    }

    pub fn render_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("serialize remembered source manifest report")
    }

    pub fn render_text(&self) -> String {
        let mut lines = Vec::new();
        match self.status {
            ManualLabRememberSourceManifestStatus::Remembered => {
                lines.push("manual lab source manifest remembered".to_owned());
            }
            ManualLabRememberSourceManifestStatus::Blocked => {
                let blocker = self.blocker.as_deref().unwrap_or("blocked");
                let detail = self
                    .detail
                    .as_deref()
                    .unwrap_or("remember-source-manifest could not continue");
                lines.push(format!(
                    "manual lab source manifest remember blocked by {blocker}: {detail}"
                ));
            }
        }

        lines.push(format!("selection_path={}", self.selection_path.display()));
        if let Some(path) = &self.source_manifest_path {
            lines.push(format!("source_manifest_path={}", path.display()));
        }
        if let Some(digest) = self.source_manifest_digest.as_deref() {
            lines.push(format!("source_manifest_digest={digest}"));
        }
        if let Some(detail) = self.detail.as_deref()
            && self.status == ManualLabRememberSourceManifestStatus::Remembered
        {
            lines.push(format!("detail={detail}"));
        }
        if let Some(remediation) = self.remediation.as_deref() {
            lines.push(format!("remediation: {remediation}"));
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBootstrapStatus {
    Ready,
    Executed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualLabBootstrapCandidate {
    pub path: PathBuf,
    pub admissible: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualLabBootstrapReport {
    pub status: ManualLabBootstrapStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    pub config_path: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub candidates: Vec<ManualLabBootstrapCandidate>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consume_image_command: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_state: Option<ConsumeTrustedImageState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_mode: Option<ConsumeTrustedImageValidationMode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub post_import_preflight: Option<ManualLabPreflightReport>,
}

impl ManualLabBootstrapReport {
    fn ready(
        config_path: PathBuf,
        source_manifest_path: PathBuf,
        source_manifest_digest: String,
        candidates: Vec<ManualLabBootstrapCandidate>,
        consume_image_command: String,
    ) -> Self {
        Self {
            status: ManualLabBootstrapStatus::Ready,
            blocker: None,
            config_path,
            source_manifest_path: Some(source_manifest_path),
            source_manifest_digest: Some(source_manifest_digest),
            candidates,
            consume_image_command: Some(consume_image_command),
            import_state: None,
            validation_mode: None,
            detail: Some("bootstrap-store resolved one admissible source manifest and is ready to import it".to_owned()),
            remediation: Some(
                "rerun with `--execute` or `make manual-lab-bootstrap-store-exec`, then rerun `make manual-lab-preflight`"
                    .to_owned(),
            ),
            post_import_preflight: None,
        }
    }

    fn executed(
        config_path: PathBuf,
        source_manifest_path: PathBuf,
        source_manifest_digest: String,
        candidates: Vec<ManualLabBootstrapCandidate>,
        consume_image_command: String,
        imported: ConsumedTrustedImage,
        post_import_preflight: ManualLabPreflightReport,
    ) -> Self {
        let detail = match imported.import_state {
            ConsumeTrustedImageState::Imported => {
                "bootstrap-store imported the trusted image bundle and the post-import preflight is ready"
                    .to_owned()
            }
            ConsumeTrustedImageState::AlreadyPresent => {
                "bootstrap-store verified an already-present trusted image bundle and the post-import preflight is ready"
                    .to_owned()
            }
        };
        Self {
            status: ManualLabBootstrapStatus::Executed,
            blocker: None,
            config_path,
            source_manifest_path: Some(source_manifest_path),
            source_manifest_digest: Some(source_manifest_digest),
            candidates,
            consume_image_command: Some(consume_image_command),
            import_state: Some(imported.import_state),
            validation_mode: Some(imported.validation_mode),
            detail: Some(detail),
            remediation: None,
            post_import_preflight: Some(post_import_preflight),
        }
    }

    fn blocked(blocked: ManualLabBootstrapBlocked) -> Self {
        Self {
            status: ManualLabBootstrapStatus::Blocked,
            blocker: Some(blocked.blocker),
            config_path: blocked.config_path,
            source_manifest_path: blocked.source_manifest_path,
            source_manifest_digest: blocked.source_manifest_digest,
            candidates: blocked.candidates,
            consume_image_command: blocked.consume_image_command,
            import_state: None,
            validation_mode: None,
            detail: Some(blocked.detail),
            remediation: blocked.remediation,
            post_import_preflight: blocked.post_import_preflight,
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(
            self.status,
            ManualLabBootstrapStatus::Ready | ManualLabBootstrapStatus::Executed
        )
    }

    pub fn render_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("serialize manual lab bootstrap report")
    }

    pub fn render_text(&self) -> String {
        let mut lines = Vec::new();

        match self.status {
            ManualLabBootstrapStatus::Ready => lines.push("manual lab bootstrap ready".to_owned()),
            ManualLabBootstrapStatus::Executed => lines.push("manual lab bootstrap executed".to_owned()),
            ManualLabBootstrapStatus::Blocked => {
                let blocker = self.blocker.as_deref().unwrap_or("blocked");
                let detail = self.detail.as_deref().unwrap_or("bootstrap-store could not continue");
                lines.push(format!("manual lab bootstrap blocked by {blocker}: {detail}"));
            }
        }

        lines.push(format!("config_path={}", self.config_path.display()));
        if let Some(path) = &self.source_manifest_path {
            lines.push(format!("source_manifest_path={}", path.display()));
        }
        if let Some(digest) = self.source_manifest_digest.as_deref() {
            lines.push(format!("source_manifest_digest={digest}"));
        }
        if let Some(command) = self.consume_image_command.as_deref() {
            lines.push(format!("consume_image_command={command}"));
        }
        if let Some(import_state) = self.import_state {
            let import_state = match import_state {
                ConsumeTrustedImageState::Imported => "imported",
                ConsumeTrustedImageState::AlreadyPresent => "already_present",
            };
            lines.push(format!("import_state={import_state}"));
        }
        if let Some(validation_mode) = self.validation_mode {
            let validation_mode = match validation_mode {
                ConsumeTrustedImageValidationMode::Hashed => "hashed",
                ConsumeTrustedImageValidationMode::Cached => "cached",
            };
            lines.push(format!("validation_mode={validation_mode}"));
        }
        for candidate in &self.candidates {
            let status = if candidate.admissible { "admissible" } else { "rejected" };
            lines.push(format!(
                "candidate[{status}]={} :: {}",
                candidate.path.display(),
                candidate.detail
            ));
        }
        if let Some(report) = &self.post_import_preflight {
            let status = if report.is_ready() { "ready" } else { "blocked" };
            lines.push(format!("post_import_preflight_status={status}"));
            if let Some(blocker) = report.blocker.as_deref() {
                lines.push(format!("post_import_preflight_blocker={blocker}"));
            }
        }
        if self.status != ManualLabBootstrapStatus::Blocked
            && let Some(detail) = self.detail.as_deref()
        {
            lines.push(format!("detail={detail}"));
        }
        if let Some(remediation) = self.remediation.as_deref() {
            lines.push(format!("remediation: {remediation}"));
        }

        lines.join("\n")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabEnsureArtifactsStatus {
    Ready,
    Executed,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualLabEnsureArtifactsReport {
    pub status: ManualLabEnsureArtifactsStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_path: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_manifest_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_state: Option<ConsumeTrustedImageState>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub validation_mode: Option<ConsumeTrustedImageValidationMode>,
    pub preflight: ManualLabPreflightReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap: Option<ManualLabBootstrapReport>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl ManualLabEnsureArtifactsReport {
    fn ready(preflight: ManualLabPreflightReport) -> Self {
        Self {
            status: ManualLabEnsureArtifactsStatus::Ready,
            blocker: None,
            image_store_root: preflight.image_store_root.clone(),
            manifest_dir: preflight.manifest_dir.clone(),
            source_manifest_path: None,
            source_manifest_digest: None,
            import_state: None,
            validation_mode: None,
            preflight,
            bootstrap: None,
            detail: Some(
                "manual-lab preflight already trusts the selected interop store; skipped bootstrap-store".to_owned(),
            ),
            remediation: None,
        }
    }

    fn executed(bootstrap: ManualLabBootstrapReport) -> Self {
        let preflight = bootstrap
            .post_import_preflight
            .clone()
            .expect("ensure-artifacts executed path requires post-import preflight");
        Self {
            status: ManualLabEnsureArtifactsStatus::Executed,
            blocker: None,
            image_store_root: preflight.image_store_root.clone(),
            manifest_dir: preflight.manifest_dir.clone(),
            source_manifest_path: bootstrap.source_manifest_path.clone(),
            source_manifest_digest: bootstrap.source_manifest_digest.clone(),
            import_state: bootstrap.import_state,
            validation_mode: bootstrap.validation_mode,
            preflight,
            bootstrap: Some(bootstrap),
            detail: Some(
                "ensure-artifacts provisioned or revalidated the trusted image store and post-import preflight is ready"
                    .to_owned(),
            ),
            remediation: None,
        }
    }

    fn blocked_from_preflight(preflight: ManualLabPreflightReport) -> Self {
        Self {
            status: ManualLabEnsureArtifactsStatus::Blocked,
            blocker: preflight.blocker.clone(),
            image_store_root: preflight.image_store_root.clone(),
            manifest_dir: preflight.manifest_dir.clone(),
            source_manifest_path: None,
            source_manifest_digest: None,
            import_state: None,
            validation_mode: None,
            detail: preflight.detail.clone(),
            remediation: preflight.remediation.clone(),
            preflight,
            bootstrap: None,
        }
    }

    fn blocked_from_bootstrap(preflight: ManualLabPreflightReport, bootstrap: ManualLabBootstrapReport) -> Self {
        let detail = bootstrap.detail.clone();
        let remediation = bootstrap.remediation.clone();
        Self {
            status: ManualLabEnsureArtifactsStatus::Blocked,
            blocker: bootstrap.blocker.clone(),
            image_store_root: preflight.image_store_root.clone(),
            manifest_dir: preflight.manifest_dir.clone(),
            source_manifest_path: bootstrap.source_manifest_path.clone(),
            source_manifest_digest: bootstrap.source_manifest_digest.clone(),
            import_state: bootstrap.import_state,
            validation_mode: bootstrap.validation_mode,
            detail,
            remediation,
            preflight,
            bootstrap: Some(bootstrap),
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(
            self.status,
            ManualLabEnsureArtifactsStatus::Ready | ManualLabEnsureArtifactsStatus::Executed
        )
    }

    pub fn render_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("serialize manual lab ensure-artifacts report")
    }

    pub fn render_text(&self) -> String {
        let mut lines = Vec::new();

        match self.status {
            ManualLabEnsureArtifactsStatus::Ready => lines.push("manual lab artifacts ready".to_owned()),
            ManualLabEnsureArtifactsStatus::Executed => lines.push("manual lab artifacts ensured".to_owned()),
            ManualLabEnsureArtifactsStatus::Blocked => {
                let blocker = self.blocker.as_deref().unwrap_or("blocked");
                let detail = self.detail.as_deref().unwrap_or("ensure-artifacts could not continue");
                lines.push(format!("manual lab artifacts blocked by {blocker}: {detail}"));
            }
        }

        lines.push(format!("image_store_root={}", self.image_store_root.display()));
        lines.push(format!("manifest_dir={}", self.manifest_dir.display()));
        let preflight_status = if self.preflight.is_ready() { "ready" } else { "blocked" };
        lines.push(format!("preflight_status={preflight_status}"));
        if let Some(path) = &self.source_manifest_path {
            lines.push(format!("source_manifest_path={}", path.display()));
        }
        if let Some(digest) = self.source_manifest_digest.as_deref() {
            lines.push(format!("source_manifest_digest={digest}"));
        }
        if let Some(import_state) = self.import_state {
            let import_state = match import_state {
                ConsumeTrustedImageState::Imported => "imported",
                ConsumeTrustedImageState::AlreadyPresent => "already_present",
            };
            lines.push(format!("import_state={import_state}"));
        }
        if let Some(validation_mode) = self.validation_mode {
            let validation_mode = match validation_mode {
                ConsumeTrustedImageValidationMode::Hashed => "hashed",
                ConsumeTrustedImageValidationMode::Cached => "cached",
            };
            lines.push(format!("validation_mode={validation_mode}"));
        }
        if let Some(bootstrap) = &self.bootstrap {
            let bootstrap_status = match bootstrap.status {
                ManualLabBootstrapStatus::Ready => "ready",
                ManualLabBootstrapStatus::Executed => "executed",
                ManualLabBootstrapStatus::Blocked => "blocked",
            };
            lines.push(format!("bootstrap_status={bootstrap_status}"));
        }
        if self.status != ManualLabEnsureArtifactsStatus::Blocked
            && let Some(detail) = self.detail.as_deref()
        {
            lines.push(format!("detail={detail}"));
        }
        if let Some(remediation) = self.remediation.as_deref() {
            lines.push(format!("remediation: {remediation}"));
        }

        lines.join("\n")
    }
}

struct ManualLabBootstrapBlocked {
    blocker: String,
    config_path: PathBuf,
    source_manifest_path: Option<PathBuf>,
    source_manifest_digest: Option<String>,
    candidates: Vec<ManualLabBootstrapCandidate>,
    consume_image_command: Option<String>,
    detail: String,
    remediation: Option<String>,
    post_import_preflight: Option<ManualLabPreflightReport>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabPreflightStatus {
    Ready,
    Blocked,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManualLabPreflightReport {
    pub status: ManualLabPreflightStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocker: Option<String>,
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl ManualLabPreflightReport {
    fn ready(paths: &ManualLabInteropPaths) -> Self {
        Self {
            status: ManualLabPreflightStatus::Ready,
            blocker: None,
            image_store_root: paths.image_store.clone(),
            manifest_dir: paths.manifest_dir.clone(),
            detail: None,
            remediation: None,
        }
    }

    fn blocked(
        paths: &ManualLabInteropPaths,
        blocker: Tiny11LabGateBlocker,
        detail: impl Into<String>,
        remediation: Option<String>,
    ) -> Self {
        Self {
            status: ManualLabPreflightStatus::Blocked,
            blocker: Some(tiny11_lab_gate_blocker_code(blocker).to_owned()),
            image_store_root: paths.image_store.clone(),
            manifest_dir: paths.manifest_dir.clone(),
            detail: Some(detail.into()),
            remediation,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.status == ManualLabPreflightStatus::Ready
    }

    pub fn render_json(&self) -> anyhow::Result<String> {
        serde_json::to_string_pretty(self).context("serialize manual lab preflight report")
    }

    pub fn render_text(&self) -> String {
        match (
            self.blocker.as_deref(),
            self.detail.as_deref(),
            self.remediation.as_deref(),
        ) {
            (None, _, _) => format!(
                "manual lab preflight ready\nimage_store_root={}\nmanifest_dir={}",
                self.image_store_root.display(),
                self.manifest_dir.display()
            ),
            (Some(blocker), Some(detail), Some(remediation)) => {
                format!("manual lab blocked by {blocker}: {detail}\nremediation: {remediation}")
            }
            (Some(blocker), Some(detail), None) => format!("manual lab blocked by {blocker}: {detail}"),
            _ => "manual lab blocked".to_owned(),
        }
    }
}

struct ManualLabPreflightReady {
    report: ManualLabPreflightReport,
    interop: ManualLabInteropConfig,
    chrome_binary: Option<PathBuf>,
}

enum ManualLabPreflightOutcome {
    Ready(Box<ManualLabPreflightReady>),
    Blocked(ManualLabPreflightReport),
}

struct ManualLabBootstrapPlan {
    config_path: PathBuf,
    source_manifest_path: PathBuf,
    source_manifest_digest: String,
    candidates: Vec<ManualLabBootstrapCandidate>,
    consume_image_command: String,
}

struct ManualLabBootstrapReady {
    report: ManualLabBootstrapReport,
    plan: ManualLabBootstrapPlan,
}

enum ManualLabBootstrapOutcome {
    Ready(ManualLabBootstrapReady),
    Blocked(ManualLabBootstrapReport),
}

struct ManualLabBootstrapSourceManifestResolution {
    source_manifest_path: PathBuf,
    source_manifest_digest: String,
    candidates: Vec<ManualLabBootstrapCandidate>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceManifestDocument {
    pool_name: String,
    vm_name: String,
    attestation_ref: String,
    #[serde(rename = "guest_rdp_port", default)]
    _guest_rdp_port: Option<u16>,
    base_image_path: PathBuf,
    #[serde(default)]
    boot_profile_v1: Option<ManualLabSourceBootProfileRecord>,
    source_iso: ManualLabSourceIsoRecord,
    transformation: ManualLabSourceTransformationRecord,
    base_image: ManualLabSourceBaseImageRecord,
    approval: ManualLabSourceApprovalRecord,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceBootProfileRecord {
    disk_interface: String,
    network_device_model: String,
    rtc_base: String,
    firmware_mode: String,
    #[serde(default)]
    firmware_code: Option<ManualLabSourceBootArtifactRecord>,
    #[serde(default)]
    vars_seed: Option<ManualLabSourceBootArtifactRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceBootArtifactRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceIsoRecord {
    acquisition_channel: String,
    acquisition_date: String,
    filename: String,
    size_bytes: u64,
    edition: String,
    language: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceTransformationRecord {
    timestamp: String,
    inputs: Vec<ManualLabSourceTransformationInputRecord>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceTransformationInputRecord {
    reference: String,
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceBaseImageRecord {
    sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManualLabSourceApprovalRecord {
    approved_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualLabStatusReport {
    pub state: ManualLabState,
    pub control_plane_health: Option<Value>,
    pub proxy_health: Option<Value>,
    pub frontend_health: Option<Value>,
    pub bootstrap: Option<BootstrapResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualLabTeardownReport {
    pub state: Option<ManualLabState>,
    pub removed_active_state: bool,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualLabProxyConfigOptions {
    pub control_plane_http_port: u16,
    pub proxy_http_port: u16,
    pub proxy_tcp_port: u16,
    pub frontend_http_port: u16,
    pub control_plane_service_token_file: PathBuf,
    pub proxy_backend_credentials_file: PathBuf,
}

#[derive(Debug, Clone)]
struct ManualLabInteropConfig {
    image_store: PathBuf,
    web_player_root: PathBuf,
    qemu_binary_path: PathBuf,
    kvm_path: PathBuf,
    xfreerdp_path: PathBuf,
    xfreerdp_graphics_mode: ManualLabXfreerdpGraphicsMode,
    ready_timeout_secs: u16,
    rdp_username: String,
    rdp_password: String,
    rdp_domain: Option<String>,
    rdp_security: Option<String>,
    evidence: HoneypotInteropStoreEvidence,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ManualLabXfreerdpGraphicsMode {
    Off,
    Rfx,
    Default,
    Progressive,
}

impl ManualLabXfreerdpGraphicsMode {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "disable" | "disabled" => Ok(Self::Off),
            "rfx" => Ok(Self::Rfx),
            "default" | "gfx" | "rdpgfx" | "on" | "enable" | "enabled" => Ok(Self::Default),
            "progressive" => Ok(Self::Progressive),
            other => Err(anyhow::anyhow!(
                "unsupported xfreerdp graphics mode {other:?}; expected one of off, rfx, default, progressive"
            )),
        }
    }

    fn lane_name(self) -> &'static str {
        match self {
            Self::Off => "xfreerdp-no-gfx",
            Self::Rfx => "xfreerdp-rfx",
            Self::Default => "xfreerdp-control-default",
            Self::Progressive => "xfreerdp-progressive",
        }
    }

    fn is_control_lane(self) -> bool {
        matches!(self, Self::Default)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualLabPorts {
    pub control_plane_http: u16,
    pub proxy_http: u16,
    pub proxy_tcp: u16,
    pub frontend_http: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualLabServiceProcess {
    pub pid: u32,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualLabSessionRecord {
    pub slot: usize,
    pub session_id: String,
    pub expected_guest_rdp_port: u16,
    pub xfreerdp_pid: Option<u32>,
    #[serde(default)]
    pub driver_binary: Option<PathBuf>,
    #[serde(default)]
    pub driver_args: Vec<String>,
    #[serde(default)]
    pub driver_lane: Option<String>,
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub vm_lease_id: Option<String>,
    pub stream_id: Option<String>,
    #[serde(default)]
    pub stream_probe_status: Option<String>,
    #[serde(default)]
    pub stream_probe_detail: Option<String>,
    #[serde(default)]
    pub stream_probe_http_status: Option<u16>,
    #[serde(default)]
    pub stream_probe_observed_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenEvidence {
    #[serde(default)]
    pub git_rev: String,
    #[serde(default)]
    pub bs_rows: Vec<String>,
    #[serde(default)]
    pub driver_kind: String,
    #[serde(default)]
    pub driver_lane: String,
    #[serde(default)]
    pub driver_binary: PathBuf,
    #[serde(default)]
    pub driver_version: Option<String>,
    #[serde(default)]
    pub session_count: usize,
    #[serde(default)]
    pub artifact_root: PathBuf,
    #[serde(default)]
    pub is_control_lane: bool,
    #[serde(default)]
    pub clean_state: ManualLabBlackScreenCleanStateEvidence,
    #[serde(default)]
    pub artifacts: ManualLabBlackScreenArtifactPaths,
    #[serde(default)]
    pub teardown_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub session_invocations: Vec<ManualLabSessionDriverEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenCleanStateEvidence {
    #[serde(default)]
    pub active_state_path: PathBuf,
    #[serde(default)]
    pub active_state_absent_before_launch: bool,
    #[serde(default)]
    pub run_root_absent_before_launch: bool,
    #[serde(default)]
    pub qmp_dir_absent_before_launch: bool,
    #[serde(default)]
    pub qga_dir_absent_before_launch: bool,
    #[serde(default)]
    pub recordings_dir_absent_before_launch: bool,
    #[serde(default)]
    pub control_plane_credentials_absent_before_launch: bool,
    #[serde(default)]
    pub proxy_credentials_absent_before_launch: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenArtifactPaths {
    #[serde(default)]
    pub control_plane_stdout_log: PathBuf,
    #[serde(default)]
    pub control_plane_stderr_log: PathBuf,
    #[serde(default)]
    pub proxy_stdout_log: PathBuf,
    #[serde(default)]
    pub proxy_stderr_log: PathBuf,
    #[serde(default)]
    pub frontend_stdout_log: PathBuf,
    #[serde(default)]
    pub frontend_stderr_log: PathBuf,
    #[serde(default)]
    pub chrome_stdout_log: Option<PathBuf>,
    #[serde(default)]
    pub chrome_stderr_log: Option<PathBuf>,
    #[serde(default)]
    pub xvfb_stdout_log: Option<PathBuf>,
    #[serde(default)]
    pub xvfb_stderr_log: Option<PathBuf>,
    #[serde(default)]
    pub recordings_root: PathBuf,
    #[serde(default)]
    pub player_console_log: PathBuf,
    #[serde(default)]
    pub player_websocket_log: PathBuf,
    #[serde(default)]
    pub player_http_log: PathBuf,
    #[serde(default)]
    pub stream_http_log: PathBuf,
    #[serde(default)]
    pub session_events_log: PathBuf,
    #[serde(default)]
    pub verdict_markdown: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionDriverEvidence {
    pub slot: usize,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub driver_binary: Option<PathBuf>,
    #[serde(default)]
    pub driver_args: Vec<String>,
    #[serde(default)]
    pub driver_lane: Option<String>,
    #[serde(default)]
    pub stdout_log: PathBuf,
    #[serde(default)]
    pub stderr_log: PathBuf,
    #[serde(default)]
    pub vm_lease_id: Option<String>,
    #[serde(default)]
    pub stream_id: Option<String>,
    #[serde(default)]
    pub stream_probe_status: Option<String>,
    #[serde(default)]
    pub stream_probe_detail: Option<String>,
    #[serde(default)]
    pub stream_probe_http_status: Option<u16>,
    #[serde(default)]
    pub stream_probe_observed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub playback_bootstrap_timeline: ManualLabSessionPlaybackBootstrapTimeline,
    #[serde(default)]
    pub playback_ready_correlation: ManualLabSessionPlaybackReadyCorrelation,
    #[serde(default)]
    pub gfx_filter_summary: Option<ManualLabSessionGfxFilterSummary>,
    #[serde(default)]
    pub gfx_warning_summary: Option<ManualLabSessionGfxWarningSummary>,
    #[serde(default)]
    pub black_screen_branch: ManualLabSessionBlackScreenBranch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabPlaybackBootstrapVerdict {
    Complete,
    #[default]
    Incomplete,
    Contradiction,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionPlaybackBootstrapEvent {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub seq: u64,
    #[serde(default)]
    pub ts_ns: u64,
    #[serde(default)]
    pub observed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub thread: String,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub byte_len: u64,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionPlaybackBootstrapTimeline {
    #[serde(default)]
    pub verdict: ManualLabPlaybackBootstrapVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub first_seq: Option<u64>,
    #[serde(default)]
    pub last_seq: Option<u64>,
    #[serde(default)]
    pub update_event: Option<String>,
    #[serde(default)]
    pub required_events: Vec<String>,
    #[serde(default)]
    pub missing_events: Vec<String>,
    #[serde(default)]
    pub failed_events: Vec<String>,
    #[serde(default)]
    pub events: Vec<ManualLabSessionPlaybackBootstrapEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionReadyTraceEvent {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub event: String,
    #[serde(default)]
    pub source: String,
    #[serde(default)]
    pub ts_unix_ms: u64,
    #[serde(default)]
    pub observed_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabPlaybackReadyVerdict {
    AlignedReady,
    ProbeBeforeReady,
    SourceReadyWithoutStreamReady,
    StreamReadyWithoutSourceReady,
    ProbeReadyWithoutStreamReady,
    Probe503WithoutSourceReady,
    Probe503AfterReady,
    #[default]
    IncompleteEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionPlaybackReadyCorrelation {
    #[serde(default)]
    pub verdict: ManualLabPlaybackReadyVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub producer_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub first_chunk_appended_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_connected_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub session_stream_ready_emitted_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub source_ready_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub probe_observed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub probe_http_status: Option<u16>,
    #[serde(default)]
    pub ready_trace_events: Vec<ManualLabSessionReadyTraceEvent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionGfxFilterSummary {
    #[serde(default)]
    pub server_chunk_count: u64,
    #[serde(default)]
    pub rdpegfx_pdu_count: u64,
    #[serde(default)]
    pub emitted_surface_update_count: u64,
    #[serde(default)]
    pub pending_surface_update_count: u64,
    #[serde(default)]
    pub surface_count: u64,
    #[serde(default)]
    pub cached_tile_count: u64,
    #[serde(default)]
    pub codec_context_surface_count: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabEvidenceConfidence {
    High,
    Medium,
    #[default]
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenBranchVerdict {
    AlignedReady,
    NegotiationLoss,
    ProducerLoss,
    PlayerLoss,
    DecodeCorruption,
    NoReadyTruthfulness,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionBlackScreenBranch {
    #[serde(default)]
    pub verdict: ManualLabBlackScreenBranchVerdict,
    #[serde(default)]
    pub confidence: ManualLabEvidenceConfidence,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
    #[serde(default)]
    pub teardown_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub source_ready_after_teardown: bool,
    #[serde(default)]
    pub decode_warning_delta_exceeds_baseline: bool,
    #[serde(default)]
    pub aligned_ready_baseline_session_count: usize,
    #[serde(default)]
    pub rdpegfx_pdu_count: Option<u64>,
    #[serde(default)]
    pub emitted_surface_update_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionGfxWarningSummary {
    #[serde(default)]
    pub total_warning_count: u64,
    #[serde(default)]
    pub wire_to_surface1_unknown_surface_count: u64,
    #[serde(default)]
    pub wire_to_surface2_metadata_unknown_surface_count: u64,
    #[serde(default)]
    pub wire_to_surface2_update_unknown_surface_count: u64,
    #[serde(default)]
    pub delete_encoding_context_unknown_surface_or_context_count: u64,
    #[serde(default)]
    pub surface_to_cache_unknown_surface_count: u64,
    #[serde(default)]
    pub cache_to_surface_unknown_cache_slot_count: u64,
    #[serde(default)]
    pub cache_to_surface_unknown_surface_count: u64,
    #[serde(default)]
    pub wire_to_surface1_update_failed_count: u64,
    #[serde(default)]
    pub wire_to_surface1_decode_skipped_count: u64,
    #[serde(default)]
    pub wire_to_surface2_decode_skipped_count: u64,
    #[serde(default)]
    pub surface_to_cache_capture_skipped_count: u64,
    #[serde(default)]
    pub cache_to_surface_replay_skipped_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum ManualLabStreamProbeOutcome {
    Ready {
        token: StreamTokenResponse,
        http_status: u16,
        observed_at_unix_ms: u64,
    },
    Unavailable {
        detail: String,
        http_status: u16,
        observed_at_unix_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualLabState {
    pub schema_version: u32,
    pub run_id: String,
    pub created_at_unix_secs: u64,
    pub run_root: PathBuf,
    pub manifests_dir: PathBuf,
    pub dashboard_url: String,
    pub control_plane: ManualLabServiceProcess,
    pub proxy: ManualLabServiceProcess,
    pub frontend: ManualLabServiceProcess,
    pub chrome_pid: Option<u32>,
    pub chrome_binary: Option<PathBuf>,
    pub chrome_stdout_log: Option<PathBuf>,
    pub chrome_stderr_log: Option<PathBuf>,
    pub driver_display: String,
    pub xvfb_pid: Option<u32>,
    pub xvfb_stdout_log: Option<PathBuf>,
    pub xvfb_stderr_log: Option<PathBuf>,
    pub interop_image_store: PathBuf,
    pub ports: ManualLabPorts,
    pub sessions: Vec<ManualLabSessionRecord>,
    #[serde(default)]
    pub black_screen_evidence: ManualLabBlackScreenEvidence,
}

#[derive(Debug)]
struct SpawnedProcess {
    pid: u32,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
}

#[derive(Debug)]
struct ResolvedDriverDisplay {
    value: String,
    xvfb: Option<SpawnedProcess>,
}

#[derive(Debug)]
struct ManualLabRuntimeLayout {
    run_root: PathBuf,
    logs_dir: PathBuf,
    manifests_dir: PathBuf,
    control_plane_secret_dir: PathBuf,
    proxy_webapp_root_dir: PathBuf,
    runtime_data_dir: PathBuf,
    lease_store_dir: PathBuf,
    quarantine_store_dir: PathBuf,
    qmp_dir: PathBuf,
    qga_dir: PathBuf,
    control_plane_config_path: PathBuf,
    proxy_config_dir: PathBuf,
    frontend_config_path: PathBuf,
    control_plane_service_token_path: PathBuf,
    control_plane_backend_credentials_path: PathBuf,
    proxy_backend_credentials_path: PathBuf,
    chrome_profile_dir: PathBuf,
}

pub fn active_state_path() -> PathBuf {
    repo_relative_path(MANUAL_LAB_ACTIVE_STATE_RELATIVE_PATH)
}

fn manual_lab_run_root(run_id: &str) -> PathBuf {
    repo_relative_path(MANUAL_LAB_ROOT_RELATIVE_PATH).join(run_id)
}

fn manual_lab_qemu_runtime_root(run_id: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "dgw-manual-lab-{}",
        run_id
            .strip_prefix("manual-lab-")
            .unwrap_or(run_id)
            .chars()
            .take(12)
            .collect::<String>()
    ))
}

pub fn selected_source_manifest_path() -> PathBuf {
    optional_env_path(MANUAL_LAB_SELECTED_SOURCE_MANIFEST_ENV)
        .unwrap_or_else(|| repo_relative_path(MANUAL_LAB_SELECTED_SOURCE_MANIFEST_RELATIVE_PATH))
}

fn manual_lab_manifest_path(relative_path: &str) -> PathBuf {
    repo_relative_path(relative_path)
}

pub fn honeypot_manual_lab_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_MANUAL_LAB_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ManualLabSelectedSourceManifestRecord {
    path: PathBuf,
    digest: String,
}

pub fn render_three_host_trusted_image_manifest(
    source_manifest: &Value,
    pool_name: &str,
    vm_name: &str,
    guest_rdp_port: u16,
) -> anyhow::Result<Value> {
    let mut manifest = source_manifest.clone();
    let root = manifest
        .as_object_mut()
        .context("trusted image manifest must be a JSON object")?;

    for required_key in [
        "attestation_ref",
        "base_image_path",
        "source_iso",
        "transformation",
        "base_image",
        "approval",
    ] {
        ensure!(
            root.contains_key(required_key),
            "trusted image manifest is missing required key {required_key}",
        );
    }

    root.insert("pool_name".to_owned(), json!(pool_name));
    root.insert("vm_name".to_owned(), json!(vm_name));
    root.insert("guest_rdp_port".to_owned(), json!(guest_rdp_port));

    Ok(manifest)
}

pub fn render_manual_lab_proxy_config(
    sample_json: &str,
    options: &ManualLabProxyConfigOptions,
) -> anyhow::Result<String> {
    let mut document: Value = serde_json::from_str(sample_json).context("parse proxy config sample JSON")?;
    let root = document
        .as_object_mut()
        .context("proxy config sample root must be a JSON object")?;

    root.insert(
        "ProvisionerPrivateKeyData".to_owned(),
        json!({
            "Value": PROVISIONER_PRIVATE_KEY_DATA,
        }),
    );
    root.insert(
        "Listeners".to_owned(),
        json!([
            {
                "InternalUrl": format!("tcp://127.0.0.1:{}", options.proxy_tcp_port),
                "ExternalUrl": format!("tcp://127.0.0.1:{}", options.proxy_tcp_port),
            },
            {
                "InternalUrl": format!("http://127.0.0.1:{}", options.proxy_http_port),
                "ExternalUrl": format!("http://127.0.0.1:{}", options.proxy_http_port),
            }
        ]),
    );
    root.insert(
        "__debug__".to_owned(),
        json!({
            "disable_token_validation": true,
            "honeypot_backend_credentials_file": options.proxy_backend_credentials_file.display().to_string(),
        }),
    );

    let honeypot = root
        .get_mut("Honeypot")
        .and_then(Value::as_object_mut)
        .context("proxy config sample must contain a Honeypot object")?;
    let control_plane = honeypot
        .get_mut("ControlPlane")
        .and_then(Value::as_object_mut)
        .context("proxy config sample must contain Honeypot.ControlPlane")?;
    control_plane.insert(
        "Endpoint".to_owned(),
        json!(format!("http://127.0.0.1:{}/", options.control_plane_http_port)),
    );
    control_plane.insert(
        "ServiceBearerTokenFile".to_owned(),
        json!(options.control_plane_service_token_file.display().to_string()),
    );

    let frontend = honeypot
        .get_mut("Frontend")
        .and_then(Value::as_object_mut)
        .context("proxy config sample must contain Honeypot.Frontend")?;
    frontend.insert(
        "PublicUrl".to_owned(),
        json!(format!("http://127.0.0.1:{}/", options.frontend_http_port)),
    );

    honeypot.insert(
        "KillSwitch".to_owned(),
        json!({
            "EnableSessionKill": true,
            "EnableSystemKill": true,
            "HaltNewSessionsOnSystemKill": true,
        }),
    );

    serde_json::to_string_pretty(&document).context("serialize manual lab proxy config")
}

pub fn up(options: ManualLabUpOptions) -> anyhow::Result<ManualLabState> {
    let readiness = match evaluate_manual_lab_preflight(options)? {
        ManualLabPreflightOutcome::Ready(ready) => *ready,
        ManualLabPreflightOutcome::Blocked(report) => bail!("{}", report.render_text()),
    };
    let interop = readiness.interop;
    let chrome_binary = readiness.chrome_binary;
    let session_count = manual_lab_session_count_from_env()?;

    let run_id = format!("manual-lab-{}", Uuid::new_v4().simple());
    let clean_state = build_black_screen_clean_state(&run_id);
    let layout = create_runtime_layout(&run_id)?;
    let ports = ManualLabPorts {
        control_plane_http: find_unused_port(),
        proxy_http: find_unused_port(),
        proxy_tcp: find_unused_port(),
        frontend_http: find_unused_port(),
    };
    let wildcard_token = scope_token(MANUAL_LAB_WILDCARD_SCOPE);
    let dashboard_url = format!("http://127.0.0.1:{}/?token={}", ports.frontend_http, wildcard_token);
    let mut state = ManualLabState {
        schema_version: MANUAL_LAB_SCHEMA_VERSION,
        run_id,
        created_at_unix_secs: now_unix_secs(),
        run_root: layout.run_root.clone(),
        manifests_dir: layout.manifests_dir.clone(),
        dashboard_url,
        control_plane: placeholder_process(
            layout.logs_dir.join("control-plane.stdout.log"),
            layout.logs_dir.join("control-plane.stderr.log"),
        ),
        proxy: placeholder_process(
            layout.logs_dir.join("proxy.stdout.log"),
            layout.logs_dir.join("proxy.stderr.log"),
        ),
        frontend: placeholder_process(
            layout.logs_dir.join("frontend.stdout.log"),
            layout.logs_dir.join("frontend.stderr.log"),
        ),
        chrome_pid: None,
        chrome_binary,
        chrome_stdout_log: None,
        chrome_stderr_log: None,
        driver_display: String::new(),
        xvfb_pid: None,
        xvfb_stdout_log: None,
        xvfb_stderr_log: None,
        interop_image_store: interop.image_store.clone(),
        ports,
        sessions: build_session_records(&layout.logs_dir, session_count),
        black_screen_evidence: build_black_screen_evidence(&interop, &layout.run_root, session_count),
    };
    state.black_screen_evidence.clean_state = clean_state;
    persist_active_state(&state)?;

    let result = (|| -> anyhow::Result<ManualLabState> {
        let driver_display = resolve_driver_display(&layout.logs_dir)?;
        state.driver_display = driver_display.value.clone();
        if let Some(xvfb) = driver_display.xvfb {
            state.xvfb_pid = Some(xvfb.pid);
            state.xvfb_stdout_log = Some(xvfb.stdout_log);
            state.xvfb_stderr_log = Some(xvfb.stderr_log);
        }
        persist_active_state(&state)?;

        write_three_host_manifests(&interop.evidence, &layout.manifests_dir)?;
        write_control_plane_service_token(&layout.control_plane_service_token_path)?;
        write_backend_credential_store(
            &layout.control_plane_backend_credentials_path,
            &state.sessions,
            &interop,
        )?;
        write_backend_credential_store(&layout.proxy_backend_credentials_path, &state.sessions, &interop)?;
        write_manual_lab_control_plane_config(&layout, &interop, &state.ports)?;
        write_manual_lab_proxy_config_dir(&layout, &state.ports)?;
        write_manual_lab_frontend_config(&layout, &state.ports, &wildcard_token)?;
        prepare_manual_lab_proxy_webapp_root(&layout, &interop)?;

        let control_plane = spawn_control_plane(&layout, &state.ports)?;
        state.control_plane = control_plane;
        persist_active_state(&state)?;

        let proxy = spawn_proxy(&layout, &state.ports)?;
        state.proxy = proxy;
        persist_active_state(&state)?;

        let frontend = spawn_frontend(&layout)?;
        state.frontend = frontend;
        persist_active_state(&state)?;

        let service_ready_timeout = manual_lab_service_ready_timeout(interop.ready_timeout_secs);
        eprintln!("manual lab phase=services.wait run_id={}", state.run_id);
        wait_for_services_ready(&state, service_ready_timeout)?;
        eprintln!("manual lab phase=services.ready run_id={}", state.run_id);

        let session_timeout = Duration::from_secs(u64::from(interop.ready_timeout_secs));
        for index in 0..state.sessions.len() {
            let driver_args = xfreerdp_driver_args(
                &state.sessions[index].session_id,
                state.sessions[index].expected_guest_rdp_port,
                state.ports.proxy_tcp,
                interop.rdp_security.as_deref(),
                interop.xfreerdp_graphics_mode,
            );
            state.sessions[index].driver_binary = Some(interop.xfreerdp_path.clone());
            state.sessions[index].driver_args = driver_args.clone();
            state.sessions[index].driver_lane = Some(interop.xfreerdp_graphics_mode.lane_name().to_owned());
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=session.driver.spawn run_id={} slot={} session_id={}",
                state.run_id, state.sessions[index].slot, state.sessions[index].session_id
            );
            let driver = {
                let session = &state.sessions[index];
                spawn_xfreerdp_driver(session, &interop, &state, &driver_args)?
            };
            state.sessions[index].xfreerdp_pid = Some(driver.pid);
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=session.driver.started run_id={} slot={} session_id={} pid={}",
                state.run_id, state.sessions[index].slot, state.sessions[index].session_id, driver.pid
            );

            let bootstrap_session = wait_for_bootstrap_session(
                state.ports.proxy_http,
                &state.sessions[index].session_id,
                &wildcard_token,
                state.sessions[index].xfreerdp_pid.unwrap_or_default(),
                &state.sessions[index].stdout_log,
                &state.sessions[index].stderr_log,
                session_timeout,
            )?;
            state.sessions[index].vm_lease_id = bootstrap_session.vm_lease_id.clone();
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=session.assigned run_id={} slot={} session_id={} vm_lease_id={}",
                state.run_id,
                state.sessions[index].slot,
                state.sessions[index].session_id,
                bootstrap_session.vm_lease_id.as_deref().unwrap_or("<pending>")
            );
        }

        for index in 0..state.sessions.len() {
            match probe_stream_token(
                state.ports.proxy_http,
                &state.sessions[index].session_id,
                &wildcard_token,
            )? {
                ManualLabStreamProbeOutcome::Ready {
                    token,
                    http_status,
                    observed_at_unix_ms,
                } => {
                    state.sessions[index].stream_probe_status = Some("ready".to_owned());
                    state.sessions[index].stream_probe_http_status = Some(http_status);
                    state.sessions[index].stream_probe_observed_at_unix_ms = Some(observed_at_unix_ms);
                    state.sessions[index].stream_id = Some(token.stream_id);
                    if state.sessions[index].vm_lease_id.is_none() {
                        state.sessions[index].vm_lease_id = Some(token.vm_lease_id);
                    }
                    state.sessions[index].stream_probe_detail = Some(format!(
                        "stream_id={} vm_lease_id={}",
                        state.sessions[index].stream_id.as_deref().unwrap_or("<pending>"),
                        state.sessions[index].vm_lease_id.as_deref().unwrap_or("<pending>")
                    ));
                    persist_active_state(&state)?;
                    eprintln!(
                        "manual lab phase=session.stream.ready run_id={} slot={} session_id={} stream_id={}",
                        state.run_id,
                        state.sessions[index].slot,
                        state.sessions[index].session_id,
                        state.sessions[index].stream_id.as_deref().unwrap_or("<pending>")
                    );
                }
                ManualLabStreamProbeOutcome::Unavailable {
                    detail,
                    http_status,
                    observed_at_unix_ms,
                } => {
                    state.sessions[index].stream_probe_status = Some("unavailable".to_owned());
                    state.sessions[index].stream_probe_http_status = Some(http_status);
                    state.sessions[index].stream_probe_observed_at_unix_ms = Some(observed_at_unix_ms);
                    state.sessions[index].stream_probe_detail = Some(detail.clone());
                    persist_active_state(&state)?;
                    eprintln!(
                        "manual lab phase=session.stream.unavailable run_id={} slot={} session_id={} detail={}",
                        state.run_id, state.sessions[index].slot, state.sessions[index].session_id, detail
                    );
                }
            }
        }

        wait_for_frontend_tiles(state.ports.frontend_http, state.sessions.len())?;
        eprintln!("manual lab phase=frontend.tiles.ready run_id={}", state.run_id);

        if let Some(chrome_binary) = &state.chrome_binary {
            let chrome = spawn_chrome(chrome_binary, &layout, &state.dashboard_url)?;
            state.chrome_pid = Some(chrome.pid);
            state.chrome_stdout_log = Some(chrome.stdout_log);
            state.chrome_stderr_log = Some(chrome.stderr_log);
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=chrome.started run_id={} pid={}",
                state.run_id, chrome.pid
            );
        }

        persist_active_state(&state)?;
        Ok(state.clone())
    })();

    match result {
        Ok(state) => Ok(state),
        Err(error) => {
            let teardown = teardown_internal(&state);
            if teardown.removed_active_state {
                Err(error)
            } else {
                Err(error).context(format!(
                    "manual lab cleanup did not finish cleanly; run `cargo run -p testsuite --bin honeypot-manual-lab -- down` and inspect {}",
                    state.run_root.display()
                ))
            }
        }
    }
}

pub fn preflight(options: ManualLabUpOptions) -> anyhow::Result<ManualLabPreflightReport> {
    Ok(match evaluate_manual_lab_preflight(options)? {
        ManualLabPreflightOutcome::Ready(ready) => ready.report,
        ManualLabPreflightOutcome::Blocked(report) => report,
    })
}

pub fn ensure_artifacts(mut options: ManualLabBootstrapOptions) -> anyhow::Result<ManualLabEnsureArtifactsReport> {
    let preflight = preflight(ManualLabUpOptions { open_browser: false })?;
    if preflight.is_ready() {
        return Ok(ManualLabEnsureArtifactsReport::ready(preflight));
    }

    match preflight.blocker.as_deref() {
        Some("missing_store_root") | Some("invalid_provenance") => {}
        _ => return Ok(ManualLabEnsureArtifactsReport::blocked_from_preflight(preflight)),
    }

    options.execute = true;
    let bootstrap = bootstrap_store(options)?;
    if bootstrap.status == ManualLabBootstrapStatus::Executed {
        return Ok(ManualLabEnsureArtifactsReport::executed(bootstrap));
    }

    Ok(ManualLabEnsureArtifactsReport::blocked_from_bootstrap(
        preflight, bootstrap,
    ))
}

pub fn remember_source_manifest(source_manifest_path: &Path) -> anyhow::Result<ManualLabRememberSourceManifestReport> {
    let selection_path = selected_source_manifest_path();
    let source_manifest_path = match evaluate_manual_lab_source_manifest_candidate_impl(source_manifest_path) {
        Ok(path) => path,
        Err(error) => {
            return Ok(ManualLabRememberSourceManifestReport::blocked(
                "source_manifest_invalid",
                selection_path,
                Some(source_manifest_path.to_path_buf()),
                format!("{error:#}"),
                Some(
                    "pass an admissible bundle manifest from `make manual-lab-bootstrap-store`, then rerun remember-source-manifest"
                        .to_owned(),
                ),
            ));
        }
    };
    let source_manifest_digest = manual_lab_file_sha256_hex(&source_manifest_path)?;

    if let Some(parent) = selection_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let record = ManualLabSelectedSourceManifestRecord {
        path: source_manifest_path.clone(),
        digest: source_manifest_digest.clone(),
    };
    fs::write(
        &selection_path,
        serde_json::to_vec_pretty(&record).context("serialize selected source manifest record")?,
    )
    .with_context(|| format!("write {}", selection_path.display()))?;

    Ok(ManualLabRememberSourceManifestReport::remembered(
        selection_path,
        source_manifest_path,
        source_manifest_digest,
    ))
}

pub fn bootstrap_store(options: ManualLabBootstrapOptions) -> anyhow::Result<ManualLabBootstrapReport> {
    let readiness = match evaluate_manual_lab_bootstrap(&options)? {
        ManualLabBootstrapOutcome::Ready(ready) => ready,
        ManualLabBootstrapOutcome::Blocked(report) => return Ok(report),
    };

    if !options.execute {
        return Ok(readiness.report);
    }

    let output = Command::new(&*HONEYPOT_CONTROL_PLANE_BIN_PATH)
        .arg("consume-image")
        .arg("--config")
        .arg(&readiness.plan.config_path)
        .arg("--source-manifest")
        .arg(&readiness.plan.source_manifest_path)
        .output()
        .with_context(|| format!("run {}", readiness.plan.consume_image_command))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        let failure_detail = if !stderr.is_empty() {
            stderr
        } else if !stdout.is_empty() {
            stdout
        } else {
            format!("consume-image exited with status {}", output.status)
        };
        let (blocker, remediation) = if manual_lab_bootstrap_permission_denied(&failure_detail) {
            (
                "store_root_not_writable".to_owned(),
                Some(manual_lab_store_root_permission_remediation()),
            )
        } else if manual_lab_bootstrap_import_lock_held(&failure_detail) {
            (
                "import_lock_held".to_owned(),
                Some(manual_lab_import_lock_remediation()),
            )
        } else {
            (
                "consume_image_failed".to_owned(),
                Some(
                    "fix the import error, then rerun `make manual-lab-bootstrap-store` or `make manual-lab-bootstrap-store-exec`"
                        .to_owned(),
                ),
            )
        };
        return Ok(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
            blocker,
            config_path: readiness.plan.config_path,
            source_manifest_path: Some(readiness.plan.source_manifest_path),
            source_manifest_digest: Some(readiness.plan.source_manifest_digest),
            candidates: readiness.plan.candidates,
            consume_image_command: Some(readiness.plan.consume_image_command),
            detail: failure_detail,
            remediation,
            post_import_preflight: None,
        }));
    }

    let imported: ConsumedTrustedImage = serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse consume-image json output for {}",
            readiness.plan.consume_image_command
        )
    })?;

    let post_import_preflight = preflight(ManualLabUpOptions { open_browser: false })?;
    if !post_import_preflight.is_ready() {
        let blocker = post_import_preflight.blocker.as_deref().unwrap_or("blocked");
        let detail = post_import_preflight
            .detail
            .as_deref()
            .unwrap_or("post-import preflight is still blocked");
        return Ok(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
            blocker: "post_import_preflight_still_blocked".to_owned(),
            config_path: readiness.plan.config_path,
            source_manifest_path: Some(readiness.plan.source_manifest_path),
            source_manifest_digest: Some(readiness.plan.source_manifest_digest),
            candidates: readiness.plan.candidates,
            consume_image_command: Some(readiness.plan.consume_image_command),
            detail: format!(
                "consume-image succeeded, but post-import preflight is still blocked by {blocker}: {detail}"
            ),
            remediation: post_import_preflight.remediation.clone(),
            post_import_preflight: Some(post_import_preflight),
        }));
    }

    Ok(ManualLabBootstrapReport::executed(
        readiness.plan.config_path,
        readiness.plan.source_manifest_path,
        readiness.plan.source_manifest_digest,
        readiness.plan.candidates,
        readiness.plan.consume_image_command,
        imported,
        post_import_preflight,
    ))
}

pub fn status() -> anyhow::Result<Option<ManualLabStatusReport>> {
    let state = match load_active_state()? {
        Some(state) => state,
        None => return Ok(None),
    };

    let wildcard_token = scope_token(MANUAL_LAB_WILDCARD_SCOPE);
    let control_plane_health = get_json(
        state.ports.control_plane_http,
        "/api/v1/health",
        &[authorization_header(scope_token(MANUAL_LAB_CONTROL_PLANE_SCOPE))],
    )
    .ok();
    let proxy_health = get_json(
        state.ports.proxy_http,
        "/jet/health",
        &[("Accept".to_owned(), "application/json".to_owned())],
    )
    .ok();
    let frontend_health = get_json(state.ports.frontend_http, "/health", &[]).ok();
    let bootstrap = get_json_typed::<BootstrapResponse>(
        state.ports.proxy_http,
        "/jet/honeypot/bootstrap",
        &[authorization_header(wildcard_token)],
    )
    .ok();

    Ok(Some(ManualLabStatusReport {
        state,
        control_plane_health,
        proxy_health,
        frontend_health,
        bootstrap,
    }))
}

pub fn down() -> anyhow::Result<ManualLabTeardownReport> {
    let state = match load_active_state()? {
        Some(state) => state,
        None => {
            return Ok(ManualLabTeardownReport {
                state: None,
                removed_active_state: false,
                notes: vec!["manual lab is not active".to_owned()],
            });
        }
    };

    Ok(teardown_internal(&state))
}

fn teardown_internal(state: &ManualLabState) -> ManualLabTeardownReport {
    let mut notes = Vec::new();
    let wildcard_token = scope_token(MANUAL_LAB_WILDCARD_SCOPE);
    let control_plane_token = scope_token(MANUAL_LAB_CONTROL_PLANE_SCOPE);

    for session in &state.sessions {
        if let Err(error) = post_empty(
            state.ports.proxy_http,
            &format!("/jet/session/{}/terminate", session.session_id),
            &[authorization_header(wildcard_token.clone())],
        ) {
            notes.push(format!("proxy terminate {}: {error:#}", session.session_id));
        }
    }

    for session in &state.sessions {
        if let Some(pid) = session.xfreerdp_pid
            && let Err(error) = terminate_pid(pid, MANUAL_LAB_TEARDOWN_TIMEOUT)
        {
            notes.push(format!("xfreerdp pid {pid}: {error:#}"));
        }
    }

    for session in &state.sessions {
        let Some(vm_lease_id) = &session.vm_lease_id else {
            continue;
        };

        let release = ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("manual-lab-release-{}", session.session_id),
            session_id: session.session_id.clone(),
            release_reason: "manual_lab_shutdown".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        };
        if let Err(error) = post_json(
            state.ports.control_plane_http,
            &format!("/api/v1/vm/{vm_lease_id}/release"),
            &[authorization_header(control_plane_token.clone())],
            &release,
        ) {
            notes.push(format!("control-plane release {vm_lease_id}: {error:#}"));
        }

        let recycle = RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: format!("manual-lab-recycle-{}", session.session_id),
            session_id: session.session_id.clone(),
            recycle_reason: "manual_lab_shutdown".to_owned(),
            quarantine_on_failure: true,
            force_quarantine: false,
        };
        if let Err(error) = post_json(
            state.ports.control_plane_http,
            &format!("/api/v1/vm/{vm_lease_id}/recycle"),
            &[authorization_header(control_plane_token.clone())],
            &recycle,
        ) {
            notes.push(format!("control-plane recycle {vm_lease_id}: {error:#}"));
        }
    }

    let drain_deadline = Instant::now() + MANUAL_LAB_CONTROL_PLANE_DRAIN_TIMEOUT;
    let mut observed_lease_drain = false;
    let mut last_drain_observation = None;
    while Instant::now() < drain_deadline {
        match get_json(
            state.ports.control_plane_http,
            "/api/v1/health",
            &[authorization_header(control_plane_token.clone())],
        ) {
            Ok(health) if health.get("active_lease_count").and_then(Value::as_u64) == Some(0) => {
                observed_lease_drain = true;
                break;
            }
            Ok(health) => {
                last_drain_observation = Some(format!("health={health}"));
                thread::sleep(MANUAL_LAB_HTTP_POLL_INTERVAL);
            }
            Err(error) => {
                last_drain_observation = Some(format!("{error:#}"));
                thread::sleep(MANUAL_LAB_HTTP_POLL_INTERVAL);
            }
        }
    }
    if !observed_lease_drain {
        notes.push(format!(
            "control-plane drain did not reach active_lease_count=0 within {}s: {}",
            MANUAL_LAB_CONTROL_PLANE_DRAIN_TIMEOUT.as_secs(),
            last_drain_observation.unwrap_or_else(|| "no observation recorded".to_owned())
        ));
    }

    if let Some(pid) = state.chrome_pid
        && let Err(error) = terminate_pid(pid, MANUAL_LAB_TEARDOWN_TIMEOUT)
    {
        notes.push(format!("chrome pid {pid}: {error:#}"));
    }

    for (label, pid) in [
        ("frontend", Some(state.frontend.pid)),
        ("proxy", Some(state.proxy.pid)),
        ("control-plane", Some(state.control_plane.pid)),
        ("xvfb", state.xvfb_pid),
    ] {
        if let Some(pid) = pid
            && let Err(error) = terminate_pid(pid, MANUAL_LAB_TEARDOWN_TIMEOUT)
        {
            notes.push(format!("{label} pid {pid}: {error:#}"));
        }
    }

    let teardown_started_at_unix_ms = Some(now_unix_ms());
    if let Err(error) = persist_black_screen_evidence(state, teardown_started_at_unix_ms) {
        notes.push(format!("persist black-screen evidence after teardown: {error:#}"));
    }

    let removed_active_state = match fs::remove_file(active_state_path()) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            notes.push(format!("remove active state: {error:#}"));
            false
        }
    };

    ManualLabTeardownReport {
        state: Some(state.clone()),
        removed_active_state,
        notes,
    }
}

fn create_runtime_layout(run_id: &str) -> anyhow::Result<ManualLabRuntimeLayout> {
    let run_root = manual_lab_run_root(run_id);
    let logs_dir = run_root.join("logs");
    let manifests_dir = run_root.join("manifests");
    let service_config_dir = run_root.join("config");
    let control_plane_secret_dir = run_root.join("secrets/control-plane");
    let proxy_secret_dir = run_root.join("secrets/proxy");
    let frontend_secret_dir = run_root.join("secrets/frontend");
    let proxy_webapp_root_dir = run_root.join("webapp");
    let runtime_data_dir = run_root.join("runtime/control-plane-data");
    let lease_store_dir = run_root.join("runtime/leases");
    let quarantine_store_dir = run_root.join("runtime/quarantine");
    let qemu_runtime_root = manual_lab_qemu_runtime_root(run_id);
    let qmp_dir = qemu_runtime_root.join("qmp");
    let qga_dir = qemu_runtime_root.join("qga");
    let chrome_profile_dir = run_root.join("chrome-profile");

    for dir in [
        &run_root,
        &logs_dir,
        &manifests_dir,
        &service_config_dir,
        &control_plane_secret_dir,
        &proxy_secret_dir,
        &frontend_secret_dir,
        &proxy_webapp_root_dir,
        &runtime_data_dir,
        &lease_store_dir,
        &quarantine_store_dir,
        &qmp_dir,
        &qga_dir,
        &chrome_profile_dir,
    ] {
        fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
    }

    let control_plane_config_path = service_config_dir.join("control-plane.toml");
    let proxy_config_dir = service_config_dir.join("proxy");
    fs::create_dir_all(&proxy_config_dir).with_context(|| format!("create {}", proxy_config_dir.display()))?;
    let frontend_config_path = service_config_dir.join("frontend.toml");

    Ok(ManualLabRuntimeLayout {
        run_root,
        logs_dir,
        manifests_dir,
        control_plane_secret_dir: control_plane_secret_dir.clone(),
        proxy_webapp_root_dir,
        runtime_data_dir,
        lease_store_dir,
        quarantine_store_dir,
        qmp_dir,
        qga_dir,
        control_plane_config_path,
        proxy_config_dir,
        frontend_config_path,
        control_plane_service_token_path: proxy_secret_dir.join("control-plane-service-token"),
        control_plane_backend_credentials_path: control_plane_secret_dir.join("backend-credentials.json"),
        proxy_backend_credentials_path: proxy_secret_dir.join("backend-credentials.json"),
        chrome_profile_dir,
    })
}

fn write_three_host_manifests(evidence: &HoneypotInteropStoreEvidence, output_dir: &Path) -> anyhow::Result<()> {
    let source_manifest_path = evidence
        .trusted_images
        .first()
        .map(|image| image.manifest_path.clone())
        .context("interop store does not contain a trusted image manifest")?;
    let source_manifest: Value = serde_json::from_slice(
        &fs::read(&source_manifest_path)
            .with_context(|| format!("read source manifest {}", source_manifest_path.display()))?,
    )
    .with_context(|| format!("parse source manifest {}", source_manifest_path.display()))?;

    for (index, guest_rdp_port) in [3391u16, 3392, 3393].into_iter().enumerate() {
        let vm_name = format!("manual-deck-{:02}", index + 1);
        let manifest = render_three_host_trusted_image_manifest(&source_manifest, "default", &vm_name, guest_rdp_port)?;
        let manifest_path = output_dir.join(format!("{vm_name}.json"));
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&manifest).context("serialize cloned trusted image manifest")?,
        )
        .with_context(|| format!("write {}", manifest_path.display()))?;
    }

    Ok(())
}

fn write_control_plane_service_token(path: &Path) -> anyhow::Result<()> {
    fs::write(path, format!("{}\n", scope_token(MANUAL_LAB_CONTROL_PLANE_SCOPE)))
        .with_context(|| format!("write {}", path.display()))
}

fn write_backend_credential_store(
    path: &Path,
    sessions: &[ManualLabSessionRecord],
    interop: &ManualLabInteropConfig,
) -> anyhow::Result<()> {
    let target_credential = if let Some(domain) = &interop.rdp_domain {
        json!({
            "kind": "username-password",
            "domain": domain,
            "username": interop.rdp_username,
            "password": interop.rdp_password,
        })
    } else {
        json!({
            "kind": "username-password",
            "username": interop.rdp_username,
            "password": interop.rdp_password,
        })
    };

    let mut document = serde_json::Map::new();
    for session in sessions {
        document.insert(
            honeypot_backend_credential_ref(&session.session_id),
            json!({
                "proxy_credential": {
                    "kind": "username-password",
                    "username": MANUAL_LAB_DRIVER_PROXY_USERNAME,
                    "password": MANUAL_LAB_DRIVER_PROXY_PASSWORD,
                },
                "target_credential": target_credential,
            }),
        );
    }

    fs::write(
        path,
        serde_json::to_vec_pretty(&Value::Object(document)).context("serialize backend credential store")?,
    )
    .with_context(|| format!("write {}", path.display()))
}

fn copy_directory_recursive(source_root: &Path, destination_root: &Path) -> anyhow::Result<()> {
    fs::create_dir_all(destination_root).with_context(|| format!("create {}", destination_root.display()))?;

    for entry in fs::read_dir(source_root).with_context(|| format!("read {}", source_root.display()))? {
        let entry = entry.with_context(|| format!("read {}", source_root.display()))?;
        let source_path = entry.path();
        let destination_path = destination_root.join(entry.file_name());
        let file_type = entry
            .file_type()
            .with_context(|| format!("inspect {}", source_path.display()))?;

        if file_type.is_dir() {
            copy_directory_recursive(&source_path, &destination_path)?;
        } else if file_type.is_file() {
            fs::copy(&source_path, &destination_path)
                .with_context(|| format!("copy {} -> {}", source_path.display(), destination_path.display()))?;
        }
    }

    Ok(())
}

fn prepare_manual_lab_proxy_webapp_root(
    layout: &ManualLabRuntimeLayout,
    interop: &ManualLabInteropConfig,
) -> anyhow::Result<()> {
    let player_root = layout.proxy_webapp_root_dir.join("player");
    copy_directory_recursive(&interop.web_player_root, &player_root).with_context(|| {
        format!(
            "stage manual-lab web player bundle from {} into {}",
            interop.web_player_root.display(),
            player_root.display()
        )
    })
}

fn write_manual_lab_control_plane_config(
    layout: &ManualLabRuntimeLayout,
    interop: &ManualLabInteropConfig,
    ports: &ManualLabPorts,
) -> anyhow::Result<()> {
    write_honeypot_control_plane_config(
        &layout.control_plane_config_path,
        &HoneypotControlPlaneTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{}", ports.control_plane_http))
            .service_token_validation_disabled(true)
            .backend_credentials_file_path(layout.control_plane_backend_credentials_path.clone())
            .data_dir(layout.runtime_data_dir.clone())
            .image_store(interop.image_store.clone())
            .manifest_dir(layout.manifests_dir.clone())
            .lease_store(layout.lease_store_dir.clone())
            .quarantine_store(layout.quarantine_store_dir.clone())
            .qmp_dir(layout.qmp_dir.clone())
            .qga_dir(layout.qga_dir.clone())
            .secret_dir(layout.control_plane_secret_dir.clone())
            .kvm_path(interop.kvm_path.clone())
            .enable_guest_agent(false)
            .lifecycle_driver("process")
            .stop_timeout_secs(10)
            .qemu_binary_path(interop.qemu_binary_path.clone())
            .build(),
    )
}

fn write_manual_lab_proxy_config_dir(layout: &ManualLabRuntimeLayout, ports: &ManualLabPorts) -> anyhow::Result<()> {
    let sample_path = repo_relative_path(HONEYPOT_PROXY_CONFIG_PATH);
    let sample = fs::read_to_string(&sample_path)
        .with_context(|| format!("read proxy config sample {}", sample_path.display()))?;
    let rendered = render_manual_lab_proxy_config(
        &sample,
        &ManualLabProxyConfigOptions {
            control_plane_http_port: ports.control_plane_http,
            proxy_http_port: ports.proxy_http,
            proxy_tcp_port: ports.proxy_tcp,
            frontend_http_port: ports.frontend_http,
            control_plane_service_token_file: layout.control_plane_service_token_path.clone(),
            proxy_backend_credentials_file: layout.proxy_backend_credentials_path.clone(),
        },
    )?;
    fs::write(layout.proxy_config_dir.join("gateway.json"), rendered)
        .with_context(|| format!("write {}", layout.proxy_config_dir.join("gateway.json").display()))
}

fn write_manual_lab_frontend_config(
    layout: &ManualLabRuntimeLayout,
    ports: &ManualLabPorts,
    proxy_bearer_token: &str,
) -> anyhow::Result<()> {
    write_honeypot_frontend_config(
        &layout.frontend_config_path,
        &HoneypotFrontendTestConfig::builder()
            .bind_addr(format!("127.0.0.1:{}", ports.frontend_http))
            .proxy_base_url(format!("http://127.0.0.1:{}/", ports.proxy_http))
            .proxy_bearer_token(Some(proxy_bearer_token.to_owned()))
            .operator_token_validation_disabled(true)
            .title("Observation Deck")
            .build(),
    )
}

fn spawn_control_plane(
    layout: &ManualLabRuntimeLayout,
    ports: &ManualLabPorts,
) -> anyhow::Result<ManualLabServiceProcess> {
    let process = spawn_logged_process(
        HONEYPOT_CONTROL_PLANE_BIN_PATH.as_path(),
        &[],
        &[(
            OsString::from(honeypot_control_plane::config::CONTROL_PLANE_CONFIG_ENV),
            layout.control_plane_config_path.as_os_str().to_owned(),
        )],
        layout.logs_dir.join("control-plane.stdout.log"),
        layout.logs_dir.join("control-plane.stderr.log"),
    )
    .with_context(|| format!("spawn control-plane on {}", ports.control_plane_http))?;
    Ok(ManualLabServiceProcess {
        pid: process.pid,
        stdout_log: process.stdout_log,
        stderr_log: process.stderr_log,
    })
}

fn spawn_proxy(layout: &ManualLabRuntimeLayout, ports: &ManualLabPorts) -> anyhow::Result<ManualLabServiceProcess> {
    let mut env = vec![
        (
            OsString::from("DGATEWAY_CONFIG_PATH"),
            layout.proxy_config_dir.as_os_str().to_owned(),
        ),
        (
            OsString::from(GATEWAY_WEBAPP_PATH_ENV),
            layout.proxy_webapp_root_dir.as_os_str().to_owned(),
        ),
    ];

    let xmf_library_path = repo_relative_path("target/manual-lab/xmf-official/libxmf.so");
    if xmf_library_path.is_file() {
        env.push((
            OsString::from("DGATEWAY_LIB_XMF_PATH"),
            xmf_library_path.as_os_str().to_owned(),
        ));
    }

    let process = spawn_logged_process(
        GATEWAY_BIN_PATH.as_path(),
        &[],
        &env,
        layout.logs_dir.join("proxy.stdout.log"),
        layout.logs_dir.join("proxy.stderr.log"),
    )
    .with_context(|| format!("spawn proxy on {}", ports.proxy_http))?;
    Ok(ManualLabServiceProcess {
        pid: process.pid,
        stdout_log: process.stdout_log,
        stderr_log: process.stderr_log,
    })
}

fn spawn_frontend(layout: &ManualLabRuntimeLayout) -> anyhow::Result<ManualLabServiceProcess> {
    let process = spawn_logged_process(
        HONEYPOT_FRONTEND_BIN_PATH.as_path(),
        &[],
        &[(
            OsString::from(MANUAL_LAB_FRONTEND_CONFIG_ENV),
            layout.frontend_config_path.as_os_str().to_owned(),
        )],
        layout.logs_dir.join("frontend.stdout.log"),
        layout.logs_dir.join("frontend.stderr.log"),
    )
    .context("spawn frontend")?;
    Ok(ManualLabServiceProcess {
        pid: process.pid,
        stdout_log: process.stdout_log,
        stderr_log: process.stderr_log,
    })
}

fn wait_for_services_ready(state: &ManualLabState, service_ready_timeout: Duration) -> anyhow::Result<()> {
    let control_plane_token = scope_token(MANUAL_LAB_CONTROL_PLANE_SCOPE);
    wait_for_condition(
        service_ready_timeout,
        || {
            if !process_is_running(state.control_plane.pid) {
                bail!(
                    "control-plane exited early\nstderr:\n{}",
                    read_log_tail(&state.control_plane.stderr_log)
                );
            }

            let body = get_json(
                state.ports.control_plane_http,
                "/api/v1/health",
                &[authorization_header(control_plane_token.clone())],
            )?;
            ensure!(
                body.get("service_state").and_then(Value::as_str) == Some("ready"),
                "control-plane health is not ready: {}",
                body
            );
            ensure!(
                body.get("trusted_image_count").and_then(Value::as_u64) == Some(MANUAL_LAB_HOST_COUNT as u64),
                "expected control-plane trusted_image_count={} but got {}",
                MANUAL_LAB_HOST_COUNT,
                body
            );
            Ok(())
        },
        "control-plane ready",
    )?;
    eprintln!("manual lab phase=control-plane.ready run_id={}", state.run_id);

    wait_for_condition(
        service_ready_timeout,
        || {
            if !process_is_running(state.proxy.pid) {
                bail!(
                    "proxy exited early\nstderr:\n{}",
                    read_log_tail(&state.proxy.stderr_log)
                );
            }

            let body = get_json(
                state.ports.proxy_http,
                "/jet/health",
                &[("Accept".to_owned(), "application/json".to_owned())],
            )?;
            ensure!(
                body.get("honeypot")
                    .and_then(|honeypot| honeypot.get("service_state"))
                    .and_then(Value::as_str)
                    == Some("ready"),
                "proxy honeypot health is not ready: {}",
                body
            );
            Ok(())
        },
        "proxy ready",
    )?;
    eprintln!("manual lab phase=proxy.ready run_id={}", state.run_id);

    wait_for_condition(
        service_ready_timeout,
        || {
            if !process_is_running(state.frontend.pid) {
                bail!(
                    "frontend exited early\nstderr:\n{}",
                    read_log_tail(&state.frontend.stderr_log)
                );
            }

            let body = get_json(state.ports.frontend_http, "/health", &[])?;
            ensure!(
                body.get("service_state").and_then(Value::as_str) == Some("ready"),
                "frontend health is not ready: {}",
                body
            );
            ensure!(
                body.get("proxy_bootstrap_reachable").and_then(Value::as_bool) == Some(true),
                "frontend cannot reach proxy bootstrap yet: {}",
                body
            );
            Ok(())
        },
        "frontend ready",
    )?;
    eprintln!("manual lab phase=frontend.ready run_id={}", state.run_id);
    Ok(())
}

fn spawn_xfreerdp_driver(
    session: &ManualLabSessionRecord,
    interop: &ManualLabInteropConfig,
    state: &ManualLabState,
    driver_args: &[String],
) -> anyhow::Result<SpawnedProcess> {
    spawn_logged_process_with_display(
        &interop.xfreerdp_path,
        driver_args,
        &[],
        &state.driver_display,
        session.stdout_log.clone(),
        session.stderr_log.clone(),
    )
    .with_context(|| format!("spawn xfreerdp driver for session {}", session.session_id))
}

fn xfreerdp_driver_args(
    session_id: &str,
    expected_guest_rdp_port: u16,
    proxy_tcp_port: u16,
    rdp_security: Option<&str>,
    graphics_mode: ManualLabXfreerdpGraphicsMode,
) -> Vec<String> {
    let association_token = association_token(session_id, &format!("127.0.0.1:{expected_guest_rdp_port}"));
    let mut args = vec![
        format!("/v:127.0.0.1:{proxy_tcp_port}"),
        format!("/u:{MANUAL_LAB_DRIVER_PROXY_USERNAME}"),
        format!("/p:{MANUAL_LAB_DRIVER_PROXY_PASSWORD}"),
        format!("/pcb:{association_token}"),
        "/cert:ignore".to_owned(),
        "/timeout:10000".to_owned(),
        "/log-level:ERROR".to_owned(),
    ];

    match graphics_mode {
        ManualLabXfreerdpGraphicsMode::Off => args.push("-gfx".to_owned()),
        ManualLabXfreerdpGraphicsMode::Rfx => {
            args.push("/dynamic-resolution".to_owned());
            args.push("/gfx:RFX".to_owned());
        }
        ManualLabXfreerdpGraphicsMode::Default => {
            args.push("/dynamic-resolution".to_owned());
        }
        ManualLabXfreerdpGraphicsMode::Progressive => {
            args.push("/dynamic-resolution".to_owned());
            args.push("/gfx".to_owned());
            args.push("+gfx-progressive".to_owned());
        }
    }

    if let Some(security) = rdp_security {
        args.push(format!("/sec:{security}"));
    }

    args
}

fn wait_for_bootstrap_session(
    proxy_http_port: u16,
    session_id: &str,
    wildcard_token: &str,
    driver_pid: u32,
    driver_stdout_log: &Path,
    driver_stderr_log: &Path,
    timeout: Duration,
) -> anyhow::Result<honeypot_contracts::frontend::BootstrapSession> {
    let endpoint = "/jet/honeypot/bootstrap";
    let headers = [authorization_header(wildcard_token.to_owned())];
    wait_for_condition(
        timeout,
        || {
            ensure_driver_is_live(session_id, driver_pid, driver_stdout_log, driver_stderr_log)?;
            let bootstrap: BootstrapResponse = get_json_typed(proxy_http_port, endpoint, &headers)?;
            bootstrap
                .sessions
                .into_iter()
                .find(|session| session.session_id == session_id && session.vm_lease_id.is_some())
                .with_context(|| format!("session {session_id} is not visible in bootstrap yet"))
        },
        &format!("bootstrap session {session_id}"),
    )
}

fn probe_stream_token(
    proxy_http_port: u16,
    session_id: &str,
    wildcard_token: &str,
) -> anyhow::Result<ManualLabStreamProbeOutcome> {
    let request = StreamTokenRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("manual-lab-stream-token-{session_id}"),
        session_id: session_id.to_owned(),
    };
    let body = serde_json::to_vec(&request).context("serialize manual lab stream token request")?;
    let path = format!("/jet/honeypot/session/{session_id}/stream-token");
    let (status, response_body) = send_http_request(
        proxy_http_port,
        "POST",
        &path,
        &[authorization_header(wildcard_token.to_owned())],
        Some(&body),
    )?;
    let observed_at_unix_ms = now_unix_ms();
    let http_status = parse_http_status_code(&status)
        .with_context(|| format!("parse HTTP status for POST {path} on port {proxy_http_port}: {status}"))?;

    if http_status == 200 {
        let response: StreamTokenResponse = serde_json::from_slice(&response_body)
            .with_context(|| format!("decode typed JSON response from POST {path} on port {proxy_http_port}"))?;
        response
            .ensure_supported_schema()
            .context("manual lab stream token response uses unsupported schema version")?;
        return Ok(ManualLabStreamProbeOutcome::Ready {
            token: response,
            http_status,
            observed_at_unix_ms,
        });
    }

    if http_status == 503 {
        let detail = String::from_utf8_lossy(&response_body).trim().to_owned();
        let detail = if detail.is_empty() {
            status
        } else {
            format!("{status} {detail}")
        };
        return Ok(ManualLabStreamProbeOutcome::Unavailable {
            detail,
            http_status,
            observed_at_unix_ms,
        });
    }

    anyhow::bail!("unexpected HTTP status for POST {path} on port {proxy_http_port}: {status}")
}

fn wait_for_frontend_tiles(frontend_http_port: u16, expected_tiles: usize) -> anyhow::Result<()> {
    wait_for_condition(
        MANUAL_LAB_STREAM_READY_TIMEOUT,
        || {
            let body = get_json(frontend_http_port, "/health", &[])?;
            ensure!(
                body.get("live_session_count").and_then(Value::as_u64) == Some(expected_tiles as u64),
                "frontend live_session_count has not reached {expected_tiles}: {}",
                body
            );
            Ok(())
        },
        "frontend ready tiles",
    )
}

fn spawn_chrome(
    chrome_binary: &Path,
    layout: &ManualLabRuntimeLayout,
    dashboard_url: &str,
) -> anyhow::Result<SpawnedProcess> {
    let args = [
        OsString::from("--new-window"),
        OsString::from("--no-first-run"),
        OsString::from("--no-default-browser-check"),
        OsString::from(format!("--user-data-dir={}", layout.chrome_profile_dir.display())),
        OsString::from(dashboard_url),
    ];

    spawn_logged_process(
        chrome_binary,
        &args,
        &[],
        layout.logs_dir.join("chrome.stdout.log"),
        layout.logs_dir.join("chrome.stderr.log"),
    )
}

fn build_session_records(logs_dir: &Path, session_count: usize) -> Vec<ManualLabSessionRecord> {
    [3391u16, 3392, 3393]
        .into_iter()
        .take(session_count)
        .enumerate()
        .map(|(index, guest_rdp_port)| ManualLabSessionRecord {
            slot: index + 1,
            session_id: Uuid::new_v4().to_string(),
            expected_guest_rdp_port: guest_rdp_port,
            xfreerdp_pid: None,
            driver_binary: None,
            driver_args: Vec::new(),
            driver_lane: None,
            stdout_log: logs_dir.join(format!("xfreerdp-{:02}.stdout.log", index + 1)),
            stderr_log: logs_dir.join(format!("xfreerdp-{:02}.stderr.log", index + 1)),
            vm_lease_id: None,
            stream_id: None,
            stream_probe_status: None,
            stream_probe_detail: None,
            stream_probe_http_status: None,
            stream_probe_observed_at_unix_ms: None,
        })
        .collect()
}

fn placeholder_process(stdout_log: PathBuf, stderr_log: PathBuf) -> ManualLabServiceProcess {
    ManualLabServiceProcess {
        pid: 0,
        stdout_log,
        stderr_log,
    }
}

fn persist_active_state(state: &ManualLabState) -> anyhow::Result<()> {
    let active_path = active_state_path();
    if let Some(parent) = active_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(
        &active_path,
        serde_json::to_vec_pretty(state).context("serialize manual lab active state")?,
    )
    .with_context(|| format!("write {}", active_path.display()))?;
    persist_black_screen_evidence(state, None)
}

fn load_active_state() -> anyhow::Result<Option<ManualLabState>> {
    let active_path = active_state_path();
    if !active_path.exists() {
        return Ok(None);
    }

    let state =
        serde_json::from_slice(&fs::read(&active_path).with_context(|| format!("read {}", active_path.display()))?)
            .with_context(|| format!("parse {}", active_path.display()))?;
    Ok(Some(state))
}

fn evaluate_manual_lab_preflight(options: ManualLabUpOptions) -> anyhow::Result<ManualLabPreflightOutcome> {
    let paths = resolve_manual_lab_interop_paths();

    if let Err(error) = require_honeypot_tier(HoneypotTestTier::LabE2e)
        .with_context(|| "manual lab requires the explicit lab-e2e gate before it can launch live Tiny11 hosts")
    {
        return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
            &paths,
            Tiny11LabGateBlocker::MissingRuntimeInputs,
            format!("{error:#}"),
            Some(format!(
                "set {HONEYPOT_LAB_E2E_ENV}=1 and {HONEYPOT_TIER_GATE_ENV}=<lab-e2e-gate.json> with contract_passed=true and host_smoke_passed=true"
            )),
        )));
    }

    let active_path = active_state_path();
    if active_path.exists() {
        return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
            &paths,
            Tiny11LabGateBlocker::UncleanState,
            format!(
                "manual lab is already active at {}; run `cargo run -p testsuite --bin honeypot-manual-lab -- status` or `down` first",
                active_path.display()
            ),
            Some("run `cargo run -p testsuite --bin honeypot-manual-lab -- down` to clear the active run".to_owned()),
        )));
    }

    let gate_inputs = build_manual_lab_gate_inputs(&paths);
    let evidence = match evaluate_tiny11_lab_gate(&gate_inputs) {
        Tiny11LabGateOutcome::Ready(ready) => ready.evidence,
        Tiny11LabGateOutcome::Blocked(blocked) => {
            let mut detail = blocked.detail;
            let mut remediation = blocked.remediation;

            if matches!(
                blocked.blocker,
                Tiny11LabGateBlocker::MissingStoreRoot | Tiny11LabGateBlocker::InvalidProvenance
            ) {
                let bootstrap_report = match evaluate_manual_lab_bootstrap(&ManualLabBootstrapOptions::default())? {
                    ManualLabBootstrapOutcome::Ready(ready) => ready.report,
                    ManualLabBootstrapOutcome::Blocked(report) => report,
                };
                if let Some(summary) = manual_lab_bootstrap_candidate_summary(&bootstrap_report.candidates) {
                    detail.push('\n');
                    detail.push_str(&summary);
                }
                remediation = Some(match bootstrap_report.blocker.as_deref() {
                    Some("multiple_admissible_candidates_require_explicit_source_manifest") => {
                        "run `make manual-lab-bootstrap-store` to inspect admissible source manifests, remember one with `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>`, then rerun `make manual-lab-bootstrap-store-exec` and `make manual-lab-preflight`".to_owned()
                    }
                    Some("no_admissible_candidates") => {
                        "run `make manual-lab-bootstrap-store` to inspect rejected candidates, remember one with `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>`, or rerun `make manual-lab-bootstrap-store-exec MANUAL_LAB_SOURCE_MANIFEST=<path>`, then rerun `make manual-lab-preflight`".to_owned()
                    }
                    Some("control_plane_config_invalid") | Some("control_plane_config_store_mismatch") => {
                        "fix the manual-lab control-plane bootstrap config, then rerun `make manual-lab-bootstrap-store` and `make manual-lab-preflight`".to_owned()
                    }
                    Some("remembered_source_manifest_invalid") => {
                        "rerun `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>` or `make manual-lab-bootstrap-store-exec MANUAL_LAB_SOURCE_MANIFEST=<path>`, then rerun `make manual-lab-preflight`".to_owned()
                    }
                    _ if bootstrap_report.is_success() => {
                        format!(
                            "for local manual self-test on a non-root host, run `{MANUAL_LAB_SELFTEST_HINT}`; if you want to inspect the active lane first, run `{MANUAL_LAB_SELFTEST_SHOW_PROFILE_HINT}`; for canonical /srv proof, run `{MANUAL_LAB_ENSURE_ARTIFACTS_HINT}` and then rerun `make manual-lab-preflight`"
                        )
                    }
                    _ => remediation.unwrap_or_else(|| {
                        "run `make manual-lab-bootstrap-store` to inspect local source-bundle manifests, then rerun `make manual-lab-preflight`".to_owned()
                    }),
                });
            }
            if blocked.blocker == Tiny11LabGateBlocker::MissingRuntimeInputs
                && detail.contains(GATEWAY_WEBPLAYER_PATH_ENV)
            {
                remediation = Some(format!(
                    "run `{MANUAL_LAB_ENSURE_WEBPLAYER_HINT}` to build the recording-player bundle in the containerized webplayer builder, or set {GATEWAY_WEBPLAYER_PATH_ENV}=<recording-player-dir>, then rerun `make manual-lab-preflight`"
                ));
            }

            return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
                &paths,
                blocked.blocker,
                detail,
                remediation,
            )));
        }
    };

    if options.open_browser && !interactive_browser_display_is_available() {
        return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
            &paths,
            Tiny11LabGateBlocker::MissingRuntimeInputs,
            "manual lab browser launch requires DISPLAY or WAYLAND_DISPLAY to be set",
            Some("set DISPLAY or WAYLAND_DISPLAY, or rerun with --no-browser".to_owned()),
        )));
    }

    let chrome_binary = if options.open_browser {
        match resolve_chrome_binary() {
            Ok(path) => Some(path),
            Err(error) => {
                return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
                    &paths,
                    Tiny11LabGateBlocker::MissingRuntimeInputs,
                    format!("{error:#}"),
                    Some(format!(
                        "set {MANUAL_LAB_CHROME_ENV} to a Chrome-family binary path or rerun with --no-browser"
                    )),
                )));
            }
        }
    } else {
        None
    };

    let interop = match manual_lab_interop_config_from_evidence(&paths, evidence) {
        Ok(interop) => interop,
        Err(error) => {
            return Ok(ManualLabPreflightOutcome::Blocked(ManualLabPreflightReport::blocked(
                &paths,
                Tiny11LabGateBlocker::MissingRuntimeInputs,
                format!("{error:#}"),
                Some(
                    "set the required DGW_HONEYPOT_INTEROP_* inputs and rerun `honeypot-manual-lab preflight`"
                        .to_owned(),
                ),
            )));
        }
    };

    Ok(ManualLabPreflightOutcome::Ready(Box::new(ManualLabPreflightReady {
        report: ManualLabPreflightReport::ready(&paths),
        interop,
        chrome_binary,
    })))
}

fn manual_lab_interop_config_from_evidence(
    paths: &ManualLabInteropPaths,
    evidence: HoneypotInteropStoreEvidence,
) -> anyhow::Result<ManualLabInteropConfig> {
    Ok(ManualLabInteropConfig {
        image_store: paths.image_store.clone(),
        web_player_root: paths.web_player_root.clone(),
        qemu_binary_path: paths.qemu_binary_path.clone(),
        kvm_path: paths.kvm_path.clone(),
        xfreerdp_path: paths.xfreerdp_path.clone(),
        xfreerdp_graphics_mode: xfreerdp_graphics_mode_from_env()?,
        ready_timeout_secs: optional_env_string(HONEYPOT_INTEROP_READY_TIMEOUT_SECS_ENV)
            .map(|value| value.parse::<u16>())
            .transpose()
            .context("parse DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS")?
            .unwrap_or(120),
        rdp_username: required_env_string(HONEYPOT_INTEROP_RDP_USERNAME_ENV)?,
        rdp_password: required_env_string(HONEYPOT_INTEROP_RDP_PASSWORD_ENV)?,
        rdp_domain: optional_env_string(HONEYPOT_INTEROP_RDP_DOMAIN_ENV),
        rdp_security: optional_env_string(HONEYPOT_INTEROP_RDP_SECURITY_ENV),
        evidence,
    })
}

fn manual_lab_service_ready_timeout(interop_ready_timeout_secs: u16) -> Duration {
    Duration::from_secs(u64::from(
        interop_ready_timeout_secs.max(MANUAL_LAB_SERVICE_READY_TIMEOUT_FLOOR_SECS),
    ))
}

#[derive(Debug, Clone)]
struct ManualLabInteropPaths {
    image_store: PathBuf,
    manifest_dir: PathBuf,
    web_player_root: PathBuf,
    qemu_binary_path: PathBuf,
    kvm_path: PathBuf,
    xfreerdp_path: PathBuf,
}

fn resolve_manual_lab_interop_paths() -> ManualLabInteropPaths {
    let image_store = optional_env_path(HONEYPOT_INTEROP_IMAGE_STORE_ENV)
        .unwrap_or_else(|| PathBuf::from(CANONICAL_TINY11_IMAGE_STORE_ROOT));
    let manifest_dir =
        optional_env_path(HONEYPOT_INTEROP_MANIFEST_DIR_ENV).unwrap_or_else(|| image_store.join("manifests"));
    let web_player_root = optional_env_path(GATEWAY_WEBPLAYER_PATH_ENV)
        .unwrap_or_else(|| repo_relative_path("honeypot/frontend/webplayer-workspace/dist/recording-player"));
    let qemu_binary_path = optional_env_path(HONEYPOT_INTEROP_QEMU_BINARY_ENV)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/qemu-system-x86_64"));
    let kvm_path = optional_env_path(HONEYPOT_INTEROP_KVM_PATH_ENV).unwrap_or_else(|| PathBuf::from("/dev/kvm"));
    let xfreerdp_path =
        optional_env_path(HONEYPOT_INTEROP_XFREERDP_PATH_ENV).unwrap_or_else(|| PathBuf::from("xfreerdp"));

    ManualLabInteropPaths {
        image_store,
        manifest_dir,
        web_player_root,
        qemu_binary_path,
        kvm_path,
        xfreerdp_path,
    }
}

fn manual_lab_store_root_permission_remediation() -> String {
    format!(
        "fix the configured store-root ownership for canonical /srv proof, or on a non-root host run `{MANUAL_LAB_SELFTEST_HINT}`; `{MANUAL_LAB_SELFTEST_SHOW_PROFILE_HINT}` is the read-only lane inspector"
    )
}

fn manual_lab_import_lock_remediation() -> String {
    format!(
        "wait for the in-flight `honeypot-control-plane consume-image` process to finish, or stop the reported pid if it is unexpected, then rerun `{MANUAL_LAB_SELFTEST_HINT}`; `{MANUAL_LAB_SELFTEST_SHOW_PROFILE_HINT}` is the read-only lane inspector, and canonical /srv proof remains `make manual-lab-bootstrap-store-exec` plus `make manual-lab-preflight`"
    )
}

fn manual_lab_bootstrap_permission_denied(detail: &str) -> bool {
    detail.contains("create image store") && detail.contains("Permission denied")
}

fn manual_lab_bootstrap_import_lock_held(detail: &str) -> bool {
    detail.contains("import lock ") && detail.contains("held by live pid")
}

fn build_manual_lab_gate_inputs(paths: &ManualLabInteropPaths) -> Tiny11LabGateInputs {
    Tiny11LabGateInputs {
        image_store_root: paths.image_store.clone(),
        manifest_dir: paths.manifest_dir.clone(),
        clean_state_probes: vec![
            Tiny11LabCleanStateProbe::absent("stale image import temp marker", paths.image_store.join(".importing")),
            Tiny11LabCleanStateProbe::absent(
                "stale manifest import temp marker",
                paths.manifest_dir.join(".importing"),
            ),
        ],
        runtime_inputs: vec![
            Tiny11LabRuntimeInput::non_empty_text(
                HONEYPOT_INTEROP_RDP_USERNAME_ENV,
                optional_env_string(HONEYPOT_INTEROP_RDP_USERNAME_ENV),
            ),
            Tiny11LabRuntimeInput::non_empty_text(
                HONEYPOT_INTEROP_RDP_PASSWORD_ENV,
                optional_env_string(HONEYPOT_INTEROP_RDP_PASSWORD_ENV),
            ),
            Tiny11LabRuntimeInput::existing_path(
                format!(
                    "{HONEYPOT_INTEROP_QEMU_BINARY_ENV} ({})",
                    paths.qemu_binary_path.display()
                ),
                paths.qemu_binary_path.clone(),
            ),
            Tiny11LabRuntimeInput::existing_path(
                format!("{HONEYPOT_INTEROP_KVM_PATH_ENV} ({})", paths.kvm_path.display()),
                paths.kvm_path.clone(),
            ),
            Tiny11LabRuntimeInput::existing_command(
                format!(
                    "{HONEYPOT_INTEROP_XFREERDP_PATH_ENV} ({})",
                    paths.xfreerdp_path.display()
                ),
                paths.xfreerdp_path.clone(),
            ),
            Tiny11LabRuntimeInput::existing_path(
                format!(
                    "{GATEWAY_WEBPLAYER_PATH_ENV} ({})",
                    paths.web_player_root.join("index.html").display()
                ),
                paths.web_player_root.join("index.html"),
            ),
            Tiny11LabRuntimeInput::existing_path(
                format!(
                    "{GATEWAY_WEBPLAYER_PATH_ENV} ({})",
                    paths.web_player_root.join("assets").display()
                ),
                paths.web_player_root.join("assets"),
            ),
        ],
        consume_image_config_path: Some(default_manual_lab_control_plane_config_path()),
        source_manifest_path: None,
    }
}

fn default_manual_lab_control_plane_config_path() -> PathBuf {
    optional_env_path(MANUAL_LAB_CONTROL_PLANE_CONFIG_ENV)
        .unwrap_or_else(|| manual_lab_manifest_path(MANUAL_LAB_CONTROL_PLANE_CONFIG_RELATIVE_PATH))
}

fn render_manual_lab_bootstrap_consume_command(config_path: &Path, source_manifest_path: &Path) -> String {
    format!(
        "{} consume-image --config {} --source-manifest {}",
        HONEYPOT_CONTROL_PLANE_BIN_PATH.display(),
        config_path.display(),
        source_manifest_path.display()
    )
}

fn manual_lab_file_sha256_hex(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

fn load_selected_source_manifest_record() -> anyhow::Result<Option<ManualLabSelectedSourceManifestRecord>> {
    let selection_path = selected_source_manifest_path();
    if !selection_path.exists() {
        return Ok(None);
    }

    let bytes = fs::read(&selection_path).with_context(|| format!("read {}", selection_path.display()))?;
    let record = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse selected source manifest record {}", selection_path.display()))?;
    Ok(Some(record))
}

fn discover_manual_lab_source_manifest_candidates_in_root(search_root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if !search_root.exists() {
        return Ok(Vec::new());
    }

    let mut candidates = Vec::new();
    for entry in fs::read_dir(search_root).with_context(|| format!("read {}", search_root.display()))? {
        let entry = entry.with_context(|| format!("read {}", search_root.display()))?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !name.starts_with("run-") {
            continue;
        }
        for relative_path in MANUAL_LAB_SOURCE_MANIFEST_DISCOVERY_PATHS {
            let candidate = path.join(relative_path);
            if candidate.is_file() {
                candidates.push(
                    candidate
                        .canonicalize()
                        .with_context(|| format!("canonicalize {}", candidate.display()))?,
                );
            }
        }
    }

    candidates.sort();
    candidates.dedup();
    Ok(candidates)
}

fn evaluate_manual_lab_source_manifest_candidate(candidate_path: &Path) -> ManualLabBootstrapCandidate {
    match evaluate_manual_lab_source_manifest_candidate_impl(candidate_path) {
        Ok(path) => ManualLabBootstrapCandidate {
            path,
            admissible: true,
            detail: "bundle manifest and referenced artifacts are present".to_owned(),
        },
        Err(error) => ManualLabBootstrapCandidate {
            path: candidate_path.to_path_buf(),
            admissible: false,
            detail: format!("{error:#}"),
        },
    }
}

fn evaluate_manual_lab_source_manifest_candidate_impl(candidate_path: &Path) -> anyhow::Result<PathBuf> {
    let candidate_path = candidate_path
        .canonicalize()
        .with_context(|| format!("canonicalize source manifest {}", candidate_path.display()))?;
    ensure!(candidate_path.is_file(), "source manifest is not a file");

    let manifest_bytes =
        fs::read(&candidate_path).with_context(|| format!("read source manifest {}", candidate_path.display()))?;
    let manifest: ManualLabSourceManifestDocument = serde_json::from_slice(&manifest_bytes)
        .with_context(|| format!("parse source manifest {}", candidate_path.display()))?;

    ensure!(!manifest.pool_name.trim().is_empty(), "pool_name must not be empty");
    ensure!(!manifest.vm_name.trim().is_empty(), "vm_name must not be empty");
    ensure!(
        !manifest.attestation_ref.trim().is_empty(),
        "attestation_ref must not be empty"
    );
    ensure!(
        manifest.base_image_path.is_relative(),
        "base_image_path must stay relative to the source bundle root"
    );
    ensure!(
        !manifest.source_iso.acquisition_channel.trim().is_empty(),
        "source_iso.acquisition_channel must not be empty"
    );
    ensure!(
        !manifest.source_iso.acquisition_date.trim().is_empty(),
        "source_iso.acquisition_date must not be empty"
    );
    ensure!(
        !manifest.source_iso.filename.trim().is_empty(),
        "source_iso.filename must not be empty"
    );
    ensure!(
        manifest.source_iso.size_bytes > 0,
        "source_iso.size_bytes must be greater than zero"
    );
    ensure!(
        manifest.source_iso.edition.trim() == "Windows 11 Pro x64",
        "source_iso.edition must be Windows 11 Pro x64"
    );
    ensure!(
        !manifest.source_iso.language.trim().is_empty(),
        "source_iso.language must not be empty"
    );
    ensure!(
        is_manual_lab_sha256(&manifest.source_iso.sha256),
        "source_iso.sha256 must be a lowercase or uppercase 64-character hex digest"
    );
    ensure!(
        !manifest.transformation.timestamp.trim().is_empty(),
        "transformation.timestamp must not be empty"
    );
    ensure!(
        !manifest.transformation.inputs.is_empty(),
        "transformation.inputs must not be empty"
    );
    for (index, input) in manifest.transformation.inputs.iter().enumerate() {
        ensure!(
            !input.reference.trim().is_empty(),
            "transformation.inputs[{index}].reference must not be empty"
        );
        ensure!(
            is_manual_lab_sha256(&input.sha256),
            "transformation.inputs[{index}].sha256 must be a lowercase or uppercase 64-character hex digest"
        );
    }
    ensure!(
        is_manual_lab_sha256(&manifest.base_image.sha256),
        "base_image.sha256 must be a lowercase or uppercase 64-character hex digest"
    );
    ensure!(
        !manifest.approval.approved_by.trim().is_empty(),
        "approval.approved_by must not be empty"
    );

    let bundle_root = candidate_path
        .parent()
        .context("source manifest must have a parent directory")?;
    let base_image_path = bundle_root.join(&manifest.base_image_path);
    ensure!(
        base_image_path.is_file(),
        "base_image_path {} does not exist under the source bundle root",
        base_image_path.display()
    );

    if let Some(boot_profile) = &manifest.boot_profile_v1 {
        ensure!(
            !boot_profile.disk_interface.trim().is_empty(),
            "boot_profile_v1.disk_interface must not be empty"
        );
        ensure!(
            !boot_profile.network_device_model.trim().is_empty(),
            "boot_profile_v1.network_device_model must not be empty"
        );
        ensure!(
            !boot_profile.rtc_base.trim().is_empty(),
            "boot_profile_v1.rtc_base must not be empty"
        );
        ensure!(
            !boot_profile.firmware_mode.trim().is_empty(),
            "boot_profile_v1.firmware_mode must not be empty"
        );
        if let Some(firmware_code) = &boot_profile.firmware_code {
            ensure!(
                firmware_code.path.is_relative(),
                "boot_profile_v1.firmware_code.path must stay relative to the source bundle root"
            );
            ensure!(
                is_manual_lab_sha256(&firmware_code.sha256),
                "boot_profile_v1.firmware_code.sha256 must be a lowercase or uppercase 64-character hex digest"
            );
            let firmware_code_path = bundle_root.join(&firmware_code.path);
            ensure!(
                firmware_code_path.is_file(),
                "boot_profile_v1.firmware_code.path {} does not exist under the source bundle root",
                firmware_code_path.display()
            );
        }
        if let Some(vars_seed) = &boot_profile.vars_seed {
            ensure!(
                vars_seed.path.is_relative(),
                "boot_profile_v1.vars_seed.path must stay relative to the source bundle root"
            );
            ensure!(
                is_manual_lab_sha256(&vars_seed.sha256),
                "boot_profile_v1.vars_seed.sha256 must be a lowercase or uppercase 64-character hex digest"
            );
            let vars_seed_path = bundle_root.join(&vars_seed.path);
            ensure!(
                vars_seed_path.is_file(),
                "boot_profile_v1.vars_seed.path {} does not exist under the source bundle root",
                vars_seed_path.display()
            );
        }
    }

    Ok(candidate_path)
}

fn is_manual_lab_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn resolve_manual_lab_bootstrap_candidates(
    explicit_source_manifest: Option<&Path>,
) -> anyhow::Result<Vec<ManualLabBootstrapCandidate>> {
    if let Some(path) = explicit_source_manifest {
        return Ok(vec![evaluate_manual_lab_source_manifest_candidate(path)]);
    }

    let search_root = repo_relative_path(MANUAL_LAB_TARGET_ROOT_RELATIVE_PATH);
    let mut candidates = discover_manual_lab_source_manifest_candidates_in_root(&search_root)?
        .into_iter()
        .map(|path| evaluate_manual_lab_source_manifest_candidate(&path))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(candidates)
}

fn resolve_manual_lab_bootstrap_source_manifest(
    options: &ManualLabBootstrapOptions,
    config_path: PathBuf,
) -> anyhow::Result<Result<ManualLabBootstrapSourceManifestResolution, ManualLabBootstrapReport>> {
    if let Some(path) = options.source_manifest_path.as_deref() {
        let candidates = resolve_manual_lab_bootstrap_candidates(Some(path))?;
        let admissible_candidates = candidates
            .iter()
            .filter(|candidate| candidate.admissible)
            .map(|candidate| candidate.path.clone())
            .collect::<Vec<_>>();
        return Ok(match admissible_candidates.as_slice() {
            [candidate] => Ok(ManualLabBootstrapSourceManifestResolution {
                source_manifest_path: candidate.clone(),
                source_manifest_digest: manual_lab_file_sha256_hex(candidate)?,
                candidates,
            }),
            _ => Err(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
                blocker: "explicit_source_manifest_invalid".to_owned(),
                config_path,
                source_manifest_path: options.source_manifest_path.clone(),
                source_manifest_digest: None,
                candidates,
                consume_image_command: None,
                detail: "the explicit --source-manifest path did not pass bootstrap admissibility checks".to_owned(),
                remediation: Some("fix or replace the explicit source manifest, then rerun bootstrap-store".to_owned()),
                post_import_preflight: None,
            })),
        });
    }

    if let Some(remembered) = load_selected_source_manifest_record()? {
        let remembered_candidate = evaluate_manual_lab_source_manifest_candidate(&remembered.path);
        let mut candidates = resolve_manual_lab_bootstrap_candidates(None)?;
        if candidates
            .iter()
            .all(|candidate| candidate.path != remembered_candidate.path)
        {
            candidates.push(remembered_candidate.clone());
            candidates.sort_by(|left, right| left.path.cmp(&right.path));
        }

        if !remembered_candidate.admissible {
            return Ok(Err(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
                blocker: "remembered_source_manifest_invalid".to_owned(),
                config_path,
                source_manifest_path: Some(remembered.path),
                source_manifest_digest: Some(remembered.digest),
                candidates,
                consume_image_command: None,
                detail: "the remembered source manifest hint no longer passes bootstrap admissibility checks"
                    .to_owned(),
                remediation: Some(
                    "rerun `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>` or pass `MANUAL_LAB_SOURCE_MANIFEST=<path>` explicitly to bootstrap-store"
                        .to_owned(),
                ),
                post_import_preflight: None,
            })));
        }

        let actual_digest = manual_lab_file_sha256_hex(&remembered_candidate.path)?;
        if actual_digest != remembered.digest {
            return Ok(Err(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
                blocker: "remembered_source_manifest_invalid".to_owned(),
                config_path,
                source_manifest_path: Some(remembered_candidate.path),
                source_manifest_digest: Some(actual_digest),
                candidates,
                consume_image_command: None,
                detail: "the remembered source manifest hint no longer matches the manifest digest that was selected"
                    .to_owned(),
                remediation: Some(
                    "rerun `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>` or pass `MANUAL_LAB_SOURCE_MANIFEST=<path>` explicitly to bootstrap-store"
                        .to_owned(),
                ),
                post_import_preflight: None,
            })));
        }

        return Ok(Ok(ManualLabBootstrapSourceManifestResolution {
            source_manifest_path: remembered_candidate.path,
            source_manifest_digest: actual_digest,
            candidates,
        }));
    }

    let candidates = resolve_manual_lab_bootstrap_candidates(None)?;
    let admissible_candidates = candidates
        .iter()
        .filter(|candidate| candidate.admissible)
        .map(|candidate| candidate.path.clone())
        .collect::<Vec<_>>();

    Ok(match admissible_candidates.as_slice() {
        [] => Err(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
            blocker: "no_admissible_candidates".to_owned(),
            config_path,
            source_manifest_path: None,
            source_manifest_digest: None,
            candidates,
            consume_image_command: None,
            detail: "bootstrap-store did not find an admissible local source bundle manifest".to_owned(),
            remediation: Some(
                "run `make manual-lab-bootstrap-store` to inspect candidates, remember one with `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>`, or rerun `make manual-lab-bootstrap-store-exec MANUAL_LAB_SOURCE_MANIFEST=<path>` with an explicit bundle manifest"
                    .to_owned(),
            ),
            post_import_preflight: None,
        })),
        [candidate] => Ok(ManualLabBootstrapSourceManifestResolution {
            source_manifest_path: candidate.clone(),
            source_manifest_digest: manual_lab_file_sha256_hex(candidate)?,
            candidates,
        }),
        _ => Err(ManualLabBootstrapReport::blocked(ManualLabBootstrapBlocked {
            blocker: "multiple_admissible_candidates_require_explicit_source_manifest".to_owned(),
            config_path,
            source_manifest_path: None,
            source_manifest_digest: None,
            candidates,
            consume_image_command: None,
            detail: "bootstrap-store found more than one admissible local source bundle manifest and will not guess"
                .to_owned(),
            remediation: Some(
                "remember one with `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>`, rerun `make manual-lab-bootstrap-store-exec MANUAL_LAB_SOURCE_MANIFEST=<path>`, or use `honeypot-manual-lab bootstrap-store --source-manifest <path> --execute`"
                    .to_owned(),
            ),
            post_import_preflight: None,
        })),
    })
}

fn manual_lab_bootstrap_candidate_summary(candidates: &[ManualLabBootstrapCandidate]) -> Option<String> {
    if candidates.is_empty() {
        return None;
    }

    let mut lines = Vec::with_capacity(candidates.len() + 1);
    lines.push("local source-manifest candidates:".to_owned());
    for candidate in candidates {
        let status = if candidate.admissible { "admissible" } else { "rejected" };
        lines.push(format!(
            "- [{status}] {} :: {}",
            candidate.path.display(),
            candidate.detail
        ));
    }
    Some(lines.join("\n"))
}

fn evaluate_manual_lab_bootstrap(options: &ManualLabBootstrapOptions) -> anyhow::Result<ManualLabBootstrapOutcome> {
    let paths = resolve_manual_lab_interop_paths();
    let config_path = options
        .config_path
        .clone()
        .unwrap_or_else(default_manual_lab_control_plane_config_path);
    let config = match ControlPlaneConfig::load_from_path(&config_path) {
        Ok(config) => config,
        Err(error) => {
            return Ok(ManualLabBootstrapOutcome::Blocked(ManualLabBootstrapReport::blocked(
                ManualLabBootstrapBlocked {
                    blocker: "control_plane_config_invalid".to_owned(),
                    config_path,
                    source_manifest_path: options.source_manifest_path.clone(),
                    source_manifest_digest: None,
                    candidates: Vec::new(),
                    consume_image_command: None,
                    detail: format!("{error:#}"),
                    remediation: Some(
                        "rerun with `--config <path>` or `MANUAL_LAB_CONTROL_PLANE_CONFIG=<path>` so bootstrap-store can load a control-plane config"
                            .to_owned(),
                    ),
                    post_import_preflight: None,
                },
            )));
        }
    };

    let configured_manifest_dir = config.paths.manifest_dir();
    if config.paths.image_store != paths.image_store || configured_manifest_dir != paths.manifest_dir {
        return Ok(ManualLabBootstrapOutcome::Blocked(ManualLabBootstrapReport::blocked(
            ManualLabBootstrapBlocked {
                blocker: "control_plane_config_store_mismatch".to_owned(),
                config_path,
                source_manifest_path: options.source_manifest_path.clone(),
                source_manifest_digest: None,
                candidates: Vec::new(),
                consume_image_command: None,
                detail: format!(
                    "bootstrap-store config points at image_store_root={} and manifest_dir={}, but manual-lab preflight expects {} and {}",
                    config.paths.image_store.display(),
                    configured_manifest_dir.display(),
                    paths.image_store.display(),
                    paths.manifest_dir.display()
                ),
                remediation: Some(
                    "align the control-plane config with the manual-lab DGW_HONEYPOT_INTEROP_* paths, then rerun bootstrap-store"
                        .to_owned(),
                ),
                post_import_preflight: None,
            },
        )));
    }

    let resolution = match resolve_manual_lab_bootstrap_source_manifest(options, config_path.clone())? {
        Ok(result) => result,
        Err(report) => return Ok(ManualLabBootstrapOutcome::Blocked(report)),
    };
    let source_manifest_path = resolution.source_manifest_path;
    let source_manifest_digest = resolution.source_manifest_digest;
    let candidates = resolution.candidates;

    let consume_image_command = render_manual_lab_bootstrap_consume_command(&config_path, &source_manifest_path);
    Ok(ManualLabBootstrapOutcome::Ready(ManualLabBootstrapReady {
        report: ManualLabBootstrapReport::ready(
            config_path.clone(),
            source_manifest_path.clone(),
            source_manifest_digest.clone(),
            candidates.clone(),
            consume_image_command.clone(),
        ),
        plan: ManualLabBootstrapPlan {
            config_path,
            source_manifest_path,
            source_manifest_digest,
            candidates,
            consume_image_command,
        },
    }))
}

fn tiny11_lab_gate_blocker_code(blocker: Tiny11LabGateBlocker) -> &'static str {
    match blocker {
        Tiny11LabGateBlocker::MissingStoreRoot => "missing_store_root",
        Tiny11LabGateBlocker::InvalidProvenance => "invalid_provenance",
        Tiny11LabGateBlocker::UncleanState => "unclean_state",
        Tiny11LabGateBlocker::MissingRuntimeInputs => "missing_runtime_inputs",
    }
}

fn resolve_chrome_binary() -> anyhow::Result<PathBuf> {
    if let Some(path) = optional_env_path(MANUAL_LAB_CHROME_ENV) {
        return find_command_path(&path)
            .with_context(|| format!("{MANUAL_LAB_CHROME_ENV} points at {}", path.display()));
    }

    for candidate in ["google-chrome", "chromium", "chromium-browser"] {
        if let Ok(path) = find_command_path(Path::new(candidate)) {
            return Ok(path);
        }
    }

    bail!("manual lab could not find Chrome; set {MANUAL_LAB_CHROME_ENV} to a Chrome-family binary path")
}

fn resolve_driver_display(logs_dir: &Path) -> anyhow::Result<ResolvedDriverDisplay> {
    let mut helper_errors = Vec::new();

    if let Some(xvfb_binary) =
        optional_env_path(MANUAL_LAB_XVFB_ENV).or_else(|| find_command_path(Path::new("Xvfb")).ok())
    {
        let display = select_xvfb_display();
        let xvfb = spawn_logged_process(
            &xvfb_binary,
            &[
                OsString::from(&display),
                OsString::from("-screen"),
                OsString::from("0"),
                OsString::from("1280x720x24"),
                OsString::from("-ac"),
                OsString::from("-nolisten"),
                OsString::from("tcp"),
            ],
            &[],
            logs_dir.join("xvfb.stdout.log"),
            logs_dir.join("xvfb.stderr.log"),
        )
        .with_context(|| format!("spawn Xvfb on {display}"))?;

        match wait_for_display_server("Xvfb", &display, &xvfb) {
            Ok(()) => {
                return Ok(ResolvedDriverDisplay {
                    value: display,
                    xvfb: Some(xvfb),
                });
            }
            Err(error) => helper_errors.push(format!("{error:#}")),
        }
    }

    if interactive_browser_display_is_available()
        && let Some(xephyr_binary) =
            optional_env_path(MANUAL_LAB_XEPHYR_ENV).or_else(|| find_command_path(Path::new("Xephyr")).ok())
    {
        let parent_display = std::env::var("DISPLAY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .context("manual lab requires DISPLAY to launch Xephyr")?;
        let display = select_xvfb_display();
        let xephyr = spawn_logged_process(
            &xephyr_binary,
            &[
                OsString::from(&display),
                OsString::from("-screen"),
                OsString::from("1280x720"),
                OsString::from("-ac"),
            ],
            &[(OsString::from("DISPLAY"), OsString::from(parent_display))],
            logs_dir.join("xephyr.stdout.log"),
            logs_dir.join("xephyr.stderr.log"),
        )
        .with_context(|| format!("spawn Xephyr on {display}"))?;

        match wait_for_display_server("Xephyr", &display, &xephyr) {
            Ok(()) => {
                return Ok(ResolvedDriverDisplay {
                    value: display,
                    xvfb: Some(xephyr),
                });
            }
            Err(error) => helper_errors.push(format!("{error:#}")),
        }
    }

    let display = std::env::var("DISPLAY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .context("manual lab requires Xvfb or a live DISPLAY for xfreerdp drivers")?;
    if !helper_errors.is_empty() {
        eprintln!(
            "manual lab warning: isolated helper display failed, falling back to DISPLAY={}:\n{}",
            display,
            helper_errors.join("\n")
        );
    }
    Ok(ResolvedDriverDisplay {
        value: display,
        xvfb: None,
    })
}

fn interactive_browser_display_is_available() -> bool {
    std::env::var("DISPLAY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .is_some()
        || std::env::var("WAYLAND_DISPLAY")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .is_some()
}

fn select_xvfb_display() -> String {
    for display_number in 90..=110 {
        let socket_path = PathBuf::from(format!("/tmp/.X11-unix/X{display_number}"));
        if !socket_path.exists() {
            return format!(":{display_number}");
        }
    }

    format!(":{}", 200 + (now_unix_secs() % 50))
}

fn spawn_logged_process(
    program: &Path,
    args: &[OsString],
    envs: &[(OsString, OsString)],
    stdout_log: PathBuf,
    stderr_log: PathBuf,
) -> anyhow::Result<SpawnedProcess> {
    let stdout = File::create(&stdout_log).with_context(|| format!("create {}", stdout_log.display()))?;
    let stderr = File::create(&stderr_log).with_context(|| format!("create {}", stderr_log.display()))?;
    let mut command = Command::new(program);
    command.args(args);
    command.env("RUST_BACKTRACE", "0");
    for (key, value) in envs {
        command.env(key, value);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::from(stdout));
    command.stderr(Stdio::from(stderr));
    #[cfg(unix)]
    {
        // SAFETY: `pre_exec` is installed before spawn on a freshly constructed `Command`
        // so the child can enter its own session before it starts running user-controlled work.
        unsafe {
            command.pre_exec(detach_child_process_session);
        }
    }

    let child = command
        .spawn()
        .with_context(|| format!("spawn {} with args {:?}", program.display(), args))?;

    Ok(SpawnedProcess {
        pid: child.id(),
        stdout_log,
        stderr_log,
    })
}

fn spawn_logged_process_with_display(
    program: &Path,
    args: &[String],
    envs: &[(OsString, OsString)],
    display: &str,
    stdout_log: PathBuf,
    stderr_log: PathBuf,
) -> anyhow::Result<SpawnedProcess> {
    let mut envs = envs.to_vec();
    envs.push((OsString::from("DISPLAY"), OsString::from(display)));
    let args = args.iter().map(OsString::from).collect::<Vec<_>>();
    spawn_logged_process(program, &args, &envs, stdout_log, stderr_log)
}

#[cfg(unix)]
fn detach_child_process_session() -> std::io::Result<()> {
    // SAFETY: `setsid` is async-signal-safe and is called in the child immediately before
    // `exec` to detach the helper from the launcher session.
    let result = unsafe { libc::setsid() };
    if result == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn wait_for_display_server(label: &str, display: &str, process: &SpawnedProcess) -> anyhow::Result<()> {
    wait_for_condition(
        MANUAL_LAB_DISPLAY_READY_TIMEOUT,
        || {
            ensure!(
                process_is_running(process.pid),
                "{label} exited before {display} became ready\nstdout:\n{}\nstderr:\n{}",
                read_log_tail(&process.stdout_log),
                read_log_tail(&process.stderr_log)
            );
            ensure!(
                display_socket_path(display).as_ref().is_some_and(|path| path.exists()),
                "{label} has not created its display socket for {display} yet"
            );
            Ok(())
        },
        &format!("{label} ready on {display}"),
    )
}

fn ensure_driver_is_live(
    session_id: &str,
    driver_pid: u32,
    driver_stdout_log: &Path,
    driver_stderr_log: &Path,
) -> anyhow::Result<()> {
    ensure!(
        process_is_running(driver_pid),
        "xfreerdp driver for session {session_id} exited early\nstdout:\n{}\nstderr:\n{}",
        read_log_tail(driver_stdout_log),
        read_log_tail(driver_stderr_log)
    );
    Ok(())
}

fn wait_for_condition<T, F>(timeout: Duration, mut operation: F, label: &str) -> anyhow::Result<T>
where
    F: FnMut() -> anyhow::Result<T>,
{
    let deadline = Instant::now() + timeout;
    let mut last_error = None;

    while Instant::now() < deadline {
        match operation() {
            Ok(value) => return Ok(value),
            Err(error) => {
                last_error = Some(format!("{error:#}"));
                thread::sleep(MANUAL_LAB_HTTP_POLL_INTERVAL);
            }
        }
    }

    bail!(
        "{label} did not succeed before timeout: {}",
        last_error.unwrap_or_else(|| "timed out without a concrete error".to_owned())
    )
}

fn get_json(port: u16, path: &str, headers: &[(String, String)]) -> anyhow::Result<Value> {
    let (_, body) = send_http_request(port, "GET", path, headers, None)?;
    serde_json::from_slice(&body).with_context(|| format!("decode JSON response from {path} on port {port}"))
}

fn get_json_typed<Response>(port: u16, path: &str, headers: &[(String, String)]) -> anyhow::Result<Response>
where
    Response: for<'de> Deserialize<'de>,
{
    let (_, body) = send_http_request(port, "GET", path, headers, None)?;
    serde_json::from_slice(&body).with_context(|| format!("decode typed JSON response from {path} on port {port}"))
}

fn post_empty(port: u16, path: &str, headers: &[(String, String)]) -> anyhow::Result<()> {
    let (status, _) = send_http_request(port, "POST", path, headers, Some(&[]))?;
    ensure!(
        status.contains("200") || status.contains("404"),
        "unexpected HTTP status for POST {path} on port {port}: {status}",
    );
    Ok(())
}

fn post_json<Request>(port: u16, path: &str, headers: &[(String, String)], request: &Request) -> anyhow::Result<Value>
where
    Request: Serialize,
{
    let body = serde_json::to_vec(request).context("serialize JSON request body")?;
    let (status, response_body) = send_http_request(port, "POST", path, headers, Some(&body))?;
    ensure!(
        status.contains("200") || status.contains("404"),
        "unexpected HTTP status for POST {path} on port {port}: {status}",
    );
    if status.contains("404") {
        return Ok(json!({"status": "not_found"}));
    }
    serde_json::from_slice(&response_body)
        .with_context(|| format!("decode JSON response from POST {path} on port {port}"))
}

fn send_http_request(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut stream =
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).with_context(|| format!("connect to 127.0.0.1:{port}"))?;
    stream
        .set_read_timeout(Some(MANUAL_LAB_HTTP_TIMEOUT))
        .context("set HTTP read timeout")?;
    stream
        .set_write_timeout(Some(MANUAL_LAB_HTTP_TIMEOUT))
        .context("set HTTP write timeout")?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    match body {
        Some(body) => {
            request.push_str("Content-Type: application/json\r\n");
            request.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
        }
        None => request.push_str("\r\n"),
    }
    stream
        .write_all(request.as_bytes())
        .with_context(|| format!("write HTTP request to {path} on port {port}"))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .with_context(|| format!("write HTTP request body to {path} on port {port}"))?;
    }
    let mut response = Vec::new();
    let mut header_end = None;
    let mut content_length = None;

    loop {
        let mut chunk = [0u8; 8192];
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(read_len) => {
                response.extend_from_slice(&chunk[..read_len]);
                if header_end.is_none()
                    && let Some(found_header_end) = response.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    header_end = Some(found_header_end);
                    let headers =
                        std::str::from_utf8(&response[..found_header_end]).context("decode HTTP response headers")?;
                    content_length = parse_content_length(headers)?;
                }

                if let (Some(found_header_end), Some(expected_body_len)) = (header_end, content_length)
                    && response.len() >= found_header_end + 4 + expected_body_len
                {
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if let (Some(found_header_end), Some(expected_body_len)) = (header_end, content_length)
                    && response.len() >= found_header_end + 4 + expected_body_len
                {
                    break;
                }
                return Err(error).with_context(|| format!("read HTTP response from {path} on port {port}"));
            }
            Err(error) => return Err(error).with_context(|| format!("read HTTP response from {path} on port {port}")),
        }
    }

    let header_end = header_end.context("split HTTP response headers and body")?;
    let headers = std::str::from_utf8(&response[..header_end]).context("decode HTTP response headers")?;
    let status_line = headers.lines().next().context("extract HTTP status line")?.to_owned();
    let body_start = header_end + 4;
    let body = match content_length {
        Some(expected_body_len) => response[body_start..(body_start + expected_body_len)].to_vec(),
        None => response[body_start..].to_vec(),
    };
    Ok((status_line, body))
}

fn parse_content_length(headers: &str) -> anyhow::Result<Option<usize>> {
    for line in headers.lines() {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            return value
                .trim()
                .parse::<usize>()
                .with_context(|| format!("parse content-length header value {}", value.trim()))
                .map(Some);
        }
    }

    Ok(None)
}

fn display_socket_path(display: &str) -> Option<PathBuf> {
    let display = display.strip_prefix(':')?;
    let display_number = display.split('.').next()?;
    if display_number.is_empty() {
        return None;
    }
    Some(PathBuf::from(format!("/tmp/.X11-unix/X{display_number}")))
}

fn scope_token(scope: &str) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"scope","jti":"{}","iat":{},"exp":3331553599,"nbf":{},"scope":"{}"}}"#,
        Uuid::new_v4(),
        now_unix_secs(),
        now_unix_secs(),
        scope,
    ));
    format!("{header}.{payload}.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ")
}

fn association_token(session_id: &str, target_host: &str) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"association","jti":"{}","iat":{},"exp":3331553599,"nbf":{},"jet_aid":"{}","jet_ap":"rdp","jet_cm":"fwd","dst_hst":"{}","jet_rec":"none"}}"#,
        Uuid::new_v4(),
        now_unix_secs(),
        now_unix_secs(),
        session_id,
        target_host,
    ));
    format!("{header}.{payload}.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ")
}

fn authorization_header(token: String) -> (String, String) {
    ("Authorization".to_owned(), format!("Bearer {token}"))
}

fn honeypot_backend_credential_ref(session_id: &str) -> String {
    format!("honeypot-backend-credential:{session_id}")
}

fn optional_env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn required_env_string(name: &str) -> anyhow::Result<String> {
    std::env::var(name).map_err(|_| anyhow::anyhow!("missing required environment variable {name}"))
}

fn optional_env_string(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.trim().is_empty())
}

fn optional_env_bool(name: &str) -> anyhow::Result<Option<bool>> {
    let Some(value) = optional_env_string(name) else {
        return Ok(None);
    };

    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => bail!("expected a boolean value, got {value:?}"),
    }
}

fn xfreerdp_graphics_mode_from_env() -> anyhow::Result<ManualLabXfreerdpGraphicsMode> {
    if let Some(value) = optional_env_string(HONEYPOT_INTEROP_XFREERDP_GFX_MODE_ENV) {
        return ManualLabXfreerdpGraphicsMode::parse(&value)
            .with_context(|| format!("parse {HONEYPOT_INTEROP_XFREERDP_GFX_MODE_ENV}"));
    }

    if let Some(enable_rdpgfx) = optional_env_bool(HONEYPOT_INTEROP_XFREERDP_RDPGFX_ENV)
        .with_context(|| format!("parse {HONEYPOT_INTEROP_XFREERDP_RDPGFX_ENV}"))?
    {
        return Ok(if enable_rdpgfx {
            ManualLabXfreerdpGraphicsMode::Default
        } else {
            ManualLabXfreerdpGraphicsMode::Off
        });
    }

    Ok(ManualLabXfreerdpGraphicsMode::Default)
}

fn manual_lab_session_count_from_env() -> anyhow::Result<usize> {
    let Some(value) = optional_env_string(MANUAL_LAB_SESSION_COUNT_ENV) else {
        return Ok(MANUAL_LAB_HOST_COUNT);
    };

    let session_count = value
        .parse::<usize>()
        .with_context(|| format!("parse {MANUAL_LAB_SESSION_COUNT_ENV}"))?;
    ensure!(
        (1..=MANUAL_LAB_HOST_COUNT).contains(&session_count),
        "{MANUAL_LAB_SESSION_COUNT_ENV} must be between 1 and {MANUAL_LAB_HOST_COUNT}, got {session_count}"
    );
    Ok(session_count)
}

fn parse_bs_rows_from_env() -> Vec<String> {
    optional_env_string(HONEYPOT_BS_ROWS_ENV)
        .into_iter()
        .flat_map(|value| {
            value
                .split(|ch: char| ch == ',' || ch.is_ascii_whitespace())
                .map(str::trim)
                .filter(|row| !row.is_empty())
                .map(ToOwned::to_owned)
                .collect::<Vec<_>>()
        })
        .collect()
}

fn collect_black_screen_env_snapshot() -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();
    for name in [
        HONEYPOT_LAB_E2E_ENV,
        HONEYPOT_TIER_GATE_ENV,
        "MANUAL_LAB_PROFILE",
        MANUAL_LAB_CONTROL_PLANE_CONFIG_ENV,
        MANUAL_LAB_SESSION_COUNT_ENV,
        HONEYPOT_BS_ROWS_ENV,
        MANUAL_LAB_SELECTED_SOURCE_MANIFEST_ENV,
        HONEYPOT_INTEROP_IMAGE_STORE_ENV,
        HONEYPOT_INTEROP_MANIFEST_DIR_ENV,
        HONEYPOT_INTEROP_QEMU_BINARY_ENV,
        HONEYPOT_INTEROP_KVM_PATH_ENV,
        HONEYPOT_INTEROP_RDP_DOMAIN_ENV,
        HONEYPOT_INTEROP_RDP_SECURITY_ENV,
        HONEYPOT_INTEROP_READY_TIMEOUT_SECS_ENV,
        HONEYPOT_INTEROP_XFREERDP_PATH_ENV,
        HONEYPOT_INTEROP_XFREERDP_GFX_MODE_ENV,
        HONEYPOT_INTEROP_XFREERDP_RDPGFX_ENV,
        GATEWAY_WEBPLAYER_PATH_ENV,
    ] {
        if let Some(value) = optional_env_string(name) {
            env.insert(name.to_owned(), value);
        }
    }
    env
}

fn detect_git_rev() -> String {
    Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|stdout| stdout.trim().to_owned())
        .filter(|stdout| !stdout.is_empty())
        .unwrap_or_else(|| "<unknown>".to_owned())
}

fn probe_command_version(program: &Path, version_args: &[&str]) -> Option<String> {
    for version_arg in version_args {
        let output = Command::new(program).arg(version_arg).output().ok()?;
        if !output.status.success() {
            continue;
        }
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
        if !stdout.is_empty() {
            return Some(stdout.lines().next().unwrap_or(&stdout).to_owned());
        }
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        if !stderr.is_empty() {
            return Some(stderr.lines().next().unwrap_or(&stderr).to_owned());
        }
    }
    None
}

fn build_black_screen_evidence(
    interop: &ManualLabInteropConfig,
    run_root: &Path,
    session_count: usize,
) -> ManualLabBlackScreenEvidence {
    ManualLabBlackScreenEvidence {
        git_rev: detect_git_rev(),
        bs_rows: parse_bs_rows_from_env(),
        driver_kind: "xfreerdp".to_owned(),
        driver_lane: interop.xfreerdp_graphics_mode.lane_name().to_owned(),
        driver_binary: interop.xfreerdp_path.clone(),
        driver_version: probe_command_version(&interop.xfreerdp_path, &["/version", "--version"]),
        session_count,
        artifact_root: run_root.to_path_buf(),
        is_control_lane: interop.xfreerdp_graphics_mode.is_control_lane(),
        clean_state: ManualLabBlackScreenCleanStateEvidence::default(),
        artifacts: ManualLabBlackScreenArtifactPaths::default(),
        teardown_started_at_unix_ms: None,
        env: collect_black_screen_env_snapshot(),
        session_invocations: Vec::new(),
    }
}

fn build_black_screen_clean_state(run_id: &str) -> ManualLabBlackScreenCleanStateEvidence {
    let run_root = manual_lab_run_root(run_id);
    let qemu_runtime_root = manual_lab_qemu_runtime_root(run_id);
    let qmp_dir = qemu_runtime_root.join("qmp");
    let qga_dir = qemu_runtime_root.join("qga");
    let recordings_dir = run_root.join("config/proxy/recordings");
    let control_plane_credentials = run_root.join("secrets/control-plane/backend-credentials.json");
    let proxy_credentials = run_root.join("secrets/proxy/backend-credentials.json");
    let active_state = active_state_path();

    ManualLabBlackScreenCleanStateEvidence {
        active_state_path: active_state.clone(),
        active_state_absent_before_launch: !active_state.exists(),
        run_root_absent_before_launch: !run_root.exists(),
        qmp_dir_absent_before_launch: !qmp_dir.exists(),
        qga_dir_absent_before_launch: !qga_dir.exists(),
        recordings_dir_absent_before_launch: !recordings_dir.exists(),
        control_plane_credentials_absent_before_launch: !control_plane_credentials.exists(),
        proxy_credentials_absent_before_launch: !proxy_credentials.exists(),
    }
}

fn build_black_screen_artifact_paths(state: &ManualLabState) -> ManualLabBlackScreenArtifactPaths {
    let artifacts_root = state.run_root.join("artifacts");
    ManualLabBlackScreenArtifactPaths {
        control_plane_stdout_log: state.control_plane.stdout_log.clone(),
        control_plane_stderr_log: state.control_plane.stderr_log.clone(),
        proxy_stdout_log: state.proxy.stdout_log.clone(),
        proxy_stderr_log: state.proxy.stderr_log.clone(),
        frontend_stdout_log: state.frontend.stdout_log.clone(),
        frontend_stderr_log: state.frontend.stderr_log.clone(),
        chrome_stdout_log: state.chrome_stdout_log.clone(),
        chrome_stderr_log: state.chrome_stderr_log.clone(),
        xvfb_stdout_log: state.xvfb_stdout_log.clone(),
        xvfb_stderr_log: state.xvfb_stderr_log.clone(),
        recordings_root: state.run_root.join("config/proxy/recordings"),
        player_console_log: artifacts_root.join("player-console.ndjson"),
        player_websocket_log: artifacts_root.join("player-websocket.ndjson"),
        player_http_log: artifacts_root.join("player-http.ndjson"),
        stream_http_log: artifacts_root.join("stream-http.json"),
        session_events_log: artifacts_root.join("session-events.json"),
        verdict_markdown: artifacts_root.join("black-screen-verdict.md"),
    }
}

fn parse_manual_lab_log_field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let needle = format!("{key}=");
    let start = line.find(&needle)? + needle.len();
    let remainder = &line[start..];

    if let Some(quoted) = remainder.strip_prefix('"') {
        let end = quoted.find('"')?;
        return Some(&quoted[..end]);
    }

    let end = remainder.find(|ch: char| ch.is_whitespace()).unwrap_or(remainder.len());
    let token = &remainder[..end];
    Some(token.trim_matches(|ch: char| ch == '"' || ch == ','))
}

fn parse_manual_lab_log_u64(line: &str, key: &str) -> Option<u64> {
    parse_manual_lab_log_field(line, key)?.parse::<u64>().ok()
}

fn parse_manual_lab_log_prefix_timestamp_unix_ms(line: &str) -> Option<u64> {
    let timestamp = line.split_whitespace().next()?;
    let parsed = OffsetDateTime::parse(timestamp, &Rfc3339).ok()?;
    let unix_ms = parsed.unix_timestamp_nanos().div_euclid(1_000_000);
    u64::try_from(unix_ms).ok()
}

fn parse_http_status_code(status: &str) -> Option<u16> {
    status.split_whitespace().nth(1)?.parse::<u16>().ok()
}

const MANUAL_LAB_PLAYBACK_BOOTSTRAP_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_PLAYBACK_BOOTSTRAP_REQUIRED_EVENTS: [&str; 11] = [
    "playback.bootstrap.requested",
    "playback.bootstrap.request_result",
    "handshake.connect_confirm.start",
    "handshake.connect_confirm.end",
    "leftover.client.before",
    "leftover.client.after",
    "leftover.server.before",
    "leftover.server.after",
    "interceptor.client.installed",
    "interceptor.server.installed",
    "playback.thread.start",
];
const MANUAL_LAB_PLAYBACK_BOOTSTRAP_UPDATE_EVENTS: [&str; 3] = [
    "playback.update.fastpath.first",
    "playback.update.wrapped_gfx.first",
    "playback.update.none",
];

fn build_manual_lab_playback_bootstrap_timeline(
    mut events: Vec<ManualLabSessionPlaybackBootstrapEvent>,
) -> ManualLabSessionPlaybackBootstrapTimeline {
    events.sort_by_key(|event| event.seq);

    let required_events = MANUAL_LAB_PLAYBACK_BOOTSTRAP_REQUIRED_EVENTS
        .iter()
        .map(|event| (*event).to_owned())
        .collect::<Vec<_>>();
    let mut missing_events = required_events
        .iter()
        .filter(|required| !events.iter().any(|event| event.event == **required))
        .cloned()
        .collect::<Vec<_>>();
    if !events
        .iter()
        .any(|event| MANUAL_LAB_PLAYBACK_BOOTSTRAP_UPDATE_EVENTS.contains(&event.event.as_str()))
    {
        missing_events.push("playback.update.*".to_owned());
    }

    let failed_events = events
        .iter()
        .filter(|event| {
            (MANUAL_LAB_PLAYBACK_BOOTSTRAP_REQUIRED_EVENTS.contains(&event.event.as_str())
                || MANUAL_LAB_PLAYBACK_BOOTSTRAP_UPDATE_EVENTS.contains(&event.event.as_str()))
                && event.status != "ok"
        })
        .map(|event| format!("{}:{}", event.event, event.status))
        .collect::<Vec<_>>();

    let contradiction = detect_manual_lab_playback_bootstrap_contradiction(&events);
    let detail = if let Some(detail) = contradiction.clone() {
        Some(detail)
    } else if !failed_events.is_empty() {
        Some(format!("non-ok bootstrap events: {}", failed_events.join(", ")))
    } else if !missing_events.is_empty() {
        Some(format!("missing bootstrap events: {}", missing_events.join(", ")))
    } else {
        None
    };
    let verdict = if contradiction.is_some() {
        ManualLabPlaybackBootstrapVerdict::Contradiction
    } else if !failed_events.is_empty() || !missing_events.is_empty() {
        ManualLabPlaybackBootstrapVerdict::Incomplete
    } else {
        ManualLabPlaybackBootstrapVerdict::Complete
    };
    let update_event = events
        .iter()
        .find(|event| MANUAL_LAB_PLAYBACK_BOOTSTRAP_UPDATE_EVENTS.contains(&event.event.as_str()))
        .map(|event| event.event.clone());

    ManualLabSessionPlaybackBootstrapTimeline {
        verdict,
        detail,
        first_seq: events.first().map(|event| event.seq),
        last_seq: events.last().map(|event| event.seq),
        update_event,
        required_events,
        missing_events,
        failed_events,
        events,
    }
}

fn detect_manual_lab_playback_bootstrap_contradiction(
    events: &[ManualLabSessionPlaybackBootstrapEvent],
) -> Option<String> {
    let mut last_seq = None;

    for event in events {
        if event.schema_version != MANUAL_LAB_PLAYBACK_BOOTSTRAP_SCHEMA_VERSION {
            return Some(format!(
                "unexpected bootstrap schema version {} for {}",
                event.schema_version, event.event
            ));
        }

        match last_seq {
            Some(previous_seq) if event.seq <= previous_seq => {
                return Some(format!(
                    "non-monotonic bootstrap sequence {} -> {}",
                    previous_seq, event.seq
                ));
            }
            Some(previous_seq) if event.seq != previous_seq.saturating_add(1) => {
                return Some(format!("bootstrap sequence gap {} -> {}", previous_seq, event.seq));
            }
            None if event.seq != 1 => {
                return Some(format!("bootstrap sequence started at {}", event.seq));
            }
            _ => {}
        }

        last_seq = Some(event.seq);
    }

    for (before, after) in [
        ("playback.bootstrap.requested", "playback.bootstrap.request_result"),
        ("handshake.connect_confirm.start", "handshake.connect_confirm.end"),
        ("leftover.client.before", "leftover.client.after"),
        ("leftover.server.before", "leftover.server.after"),
        ("playback.thread.start", "playback.thread.first_packet"),
        ("playback.thread.first_packet", "playback.chunk.appended.first"),
    ] {
        if let Some(detail) = detect_manual_lab_playback_bootstrap_out_of_order(events, before, after) {
            return Some(detail);
        }
    }

    let thread_start = events.iter().position(|event| event.event == "playback.thread.start");
    for update_event in MANUAL_LAB_PLAYBACK_BOOTSTRAP_UPDATE_EVENTS {
        if let (Some(start), Some(update)) = (
            thread_start,
            events.iter().position(|event| event.event == update_event),
        ) && update < start
        {
            return Some(format!("{update_event} appeared before playback.thread.start"));
        }
    }

    None
}

fn detect_manual_lab_playback_bootstrap_out_of_order(
    events: &[ManualLabSessionPlaybackBootstrapEvent],
    before: &str,
    after: &str,
) -> Option<String> {
    let before_index = events.iter().position(|event| event.event == before)?;
    let after_index = events.iter().position(|event| event.event == after)?;
    if after_index < before_index {
        return Some(format!("{after} appeared before {before}"));
    }

    None
}

fn parse_manual_lab_playback_bootstrap_trace_line(
    line: &str,
) -> Option<(String, ManualLabSessionPlaybackBootstrapEvent)> {
    if !line.contains("Playback bootstrap trace") {
        return None;
    }

    let session_id = parse_manual_lab_log_field(line, "session_id")?.to_owned();
    let error = parse_manual_lab_log_field(line, "bootstrap_error")
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned);
    let event = ManualLabSessionPlaybackBootstrapEvent {
        schema_version: parse_manual_lab_log_u64(line, "bootstrap_schema_version")
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0),
        seq: parse_manual_lab_log_u64(line, "bootstrap_seq").unwrap_or(0),
        ts_ns: parse_manual_lab_log_u64(line, "bootstrap_ts_ns").unwrap_or(0),
        observed_at_unix_ms: parse_manual_lab_log_prefix_timestamp_unix_ms(line),
        thread: parse_manual_lab_log_field(line, "bootstrap_thread")
            .unwrap_or_default()
            .to_owned(),
        event: parse_manual_lab_log_field(line, "bootstrap_event")
            .unwrap_or_default()
            .to_owned(),
        status: parse_manual_lab_log_field(line, "bootstrap_status")
            .unwrap_or_default()
            .to_owned(),
        source: parse_manual_lab_log_field(line, "bootstrap_source")
            .unwrap_or_default()
            .to_owned(),
        byte_len: parse_manual_lab_log_u64(line, "bootstrap_byte_len").unwrap_or(0),
        error,
    };

    Some((session_id, event))
}

fn parse_manual_lab_playback_bootstrap_timelines(
    proxy_stdout_log: &Path,
) -> anyhow::Result<BTreeMap<String, ManualLabSessionPlaybackBootstrapTimeline>> {
    if !proxy_stdout_log.exists() {
        return Ok(BTreeMap::new());
    }

    let log = fs::read_to_string(proxy_stdout_log).with_context(|| format!("read {}", proxy_stdout_log.display()))?;
    let mut timelines = BTreeMap::<String, Vec<ManualLabSessionPlaybackBootstrapEvent>>::new();
    for line in log.lines() {
        if let Some((session_id, event)) = parse_manual_lab_playback_bootstrap_trace_line(line) {
            timelines.entry(session_id).or_default().push(event);
        }
    }

    Ok(timelines
        .into_iter()
        .map(|(session_id, events)| (session_id, build_manual_lab_playback_bootstrap_timeline(events)))
        .collect())
}

fn parse_manual_lab_ready_trace_line(line: &str) -> Option<(String, ManualLabSessionReadyTraceEvent)> {
    if !line.contains("Ready path trace") {
        return None;
    }

    let session_id = parse_manual_lab_log_field(line, "session_id")?.to_owned();
    let event = ManualLabSessionReadyTraceEvent {
        schema_version: parse_manual_lab_log_u64(line, "ready_schema_version")
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(0),
        event: parse_manual_lab_log_field(line, "ready_event")
            .unwrap_or_default()
            .to_owned(),
        source: parse_manual_lab_log_field(line, "ready_source")
            .unwrap_or_default()
            .to_owned(),
        ts_unix_ms: parse_manual_lab_log_u64(line, "ready_ts_unix_ms").unwrap_or(0),
        observed_at_unix_ms: parse_manual_lab_log_prefix_timestamp_unix_ms(line),
    };

    Some((session_id, event))
}

fn parse_manual_lab_ready_trace_events(
    proxy_stdout_log: &Path,
) -> anyhow::Result<BTreeMap<String, Vec<ManualLabSessionReadyTraceEvent>>> {
    if !proxy_stdout_log.exists() {
        return Ok(BTreeMap::new());
    }

    let log = fs::read_to_string(proxy_stdout_log).with_context(|| format!("read {}", proxy_stdout_log.display()))?;
    let mut events = BTreeMap::<String, Vec<ManualLabSessionReadyTraceEvent>>::new();
    for line in log.lines() {
        if let Some((session_id, event)) = parse_manual_lab_ready_trace_line(line) {
            events.entry(session_id).or_default().push(event);
        }
    }

    for session_events in events.values_mut() {
        session_events.sort_by_key(|event| {
            (
                if event.ts_unix_ms == 0 {
                    event.observed_at_unix_ms.unwrap_or(0)
                } else {
                    event.ts_unix_ms
                },
                event.observed_at_unix_ms.unwrap_or(0),
            )
        });
    }

    Ok(events)
}

fn ready_trace_event_timestamp(event: &ManualLabSessionReadyTraceEvent) -> Option<u64> {
    if event.ts_unix_ms != 0 {
        Some(event.ts_unix_ms)
    } else {
        event.observed_at_unix_ms
    }
}

fn first_bootstrap_event_observed_at_unix_ms(
    timeline: &ManualLabSessionPlaybackBootstrapTimeline,
    event_name: &str,
) -> Option<u64> {
    timeline
        .events
        .iter()
        .find(|event| event.event == event_name)
        .and_then(|event| event.observed_at_unix_ms)
}

fn first_ready_trace_timestamp_unix_ms(events: &[ManualLabSessionReadyTraceEvent], event_name: &str) -> Option<u64> {
    events
        .iter()
        .find(|event| event.event == event_name)
        .and_then(ready_trace_event_timestamp)
}

fn earliest_timestamp(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

fn build_manual_lab_playback_ready_correlation(
    timeline: &ManualLabSessionPlaybackBootstrapTimeline,
    ready_trace_events: Vec<ManualLabSessionReadyTraceEvent>,
    probe_status: Option<&str>,
    probe_http_status: Option<u16>,
    probe_observed_at_unix_ms: Option<u64>,
) -> ManualLabSessionPlaybackReadyCorrelation {
    let producer_started_at_unix_ms =
        first_bootstrap_event_observed_at_unix_ms(timeline, "playback.bootstrap.request_result");
    let first_chunk_appended_at_unix_ms =
        first_bootstrap_event_observed_at_unix_ms(timeline, "playback.chunk.appended.first");
    let recording_connected_at_unix_ms =
        first_ready_trace_timestamp_unix_ms(&ready_trace_events, "recording.connected.first");
    let session_stream_ready_emitted_at_unix_ms =
        first_ready_trace_timestamp_unix_ms(&ready_trace_events, "session.stream.ready.emitted");
    let source_ready_at_unix_ms = earliest_timestamp(first_chunk_appended_at_unix_ms, recording_connected_at_unix_ms);

    let (verdict, detail) = if matches!(probe_http_status, Some(503)) && source_ready_at_unix_ms.is_none() {
        (
            ManualLabPlaybackReadyVerdict::Probe503WithoutSourceReady,
            Some("probe observed 503 before any source-ready evidence existed".to_owned()),
        )
    } else if let (Some(probe_at), Some(source_ready_at)) = (probe_observed_at_unix_ms, source_ready_at_unix_ms) {
        if probe_at < source_ready_at {
            (
                ManualLabPlaybackReadyVerdict::ProbeBeforeReady,
                Some(format!(
                    "probe observed at {probe_at} before source-ready evidence at {source_ready_at}"
                )),
            )
        } else if matches!(probe_http_status, Some(503)) {
            (
                ManualLabPlaybackReadyVerdict::Probe503AfterReady,
                Some(format!(
                    "probe observed 503 at {probe_at} after source-ready evidence at {source_ready_at}"
                )),
            )
        } else if probe_status == Some("ready") && session_stream_ready_emitted_at_unix_ms.is_some() {
            (
                ManualLabPlaybackReadyVerdict::AlignedReady,
                Some("source-ready evidence, stream-ready emission, and ready probe all aligned".to_owned()),
            )
        } else if probe_status == Some("ready") {
            (
                ManualLabPlaybackReadyVerdict::ProbeReadyWithoutStreamReady,
                Some("probe returned ready but no session.stream.ready emission was recorded".to_owned()),
            )
        } else if source_ready_at_unix_ms.is_some() && session_stream_ready_emitted_at_unix_ms.is_none() {
            (
                ManualLabPlaybackReadyVerdict::SourceReadyWithoutStreamReady,
                Some("source-ready evidence exists without a session.stream.ready emission".to_owned()),
            )
        } else {
            (
                ManualLabPlaybackReadyVerdict::IncompleteEvidence,
                Some("ready-path evidence remained incomplete after source-ready signals appeared".to_owned()),
            )
        }
    } else if source_ready_at_unix_ms.is_some() && session_stream_ready_emitted_at_unix_ms.is_none() {
        (
            ManualLabPlaybackReadyVerdict::SourceReadyWithoutStreamReady,
            Some("source-ready evidence exists without a session.stream.ready emission".to_owned()),
        )
    } else if source_ready_at_unix_ms.is_none() && session_stream_ready_emitted_at_unix_ms.is_some() {
        (
            ManualLabPlaybackReadyVerdict::StreamReadyWithoutSourceReady,
            Some("session.stream.ready was emitted without preceding source-ready evidence".to_owned()),
        )
    } else if probe_status == Some("ready") && session_stream_ready_emitted_at_unix_ms.is_none() {
        (
            ManualLabPlaybackReadyVerdict::ProbeReadyWithoutStreamReady,
            Some("probe returned ready but no session.stream.ready emission was recorded".to_owned()),
        )
    } else {
        (
            ManualLabPlaybackReadyVerdict::IncompleteEvidence,
            Some("ready-path evidence is missing one or more authoritative timestamps".to_owned()),
        )
    };

    ManualLabSessionPlaybackReadyCorrelation {
        verdict,
        detail,
        producer_started_at_unix_ms,
        first_chunk_appended_at_unix_ms,
        recording_connected_at_unix_ms,
        session_stream_ready_emitted_at_unix_ms,
        source_ready_at_unix_ms,
        probe_observed_at_unix_ms,
        probe_http_status,
        ready_trace_events,
    }
}

fn parse_manual_lab_gfx_filter_summary_line(line: &str) -> Option<(String, ManualLabSessionGfxFilterSummary)> {
    if !line.contains("GFX filter summary") {
        return None;
    }

    let session_id = parse_manual_lab_log_field(line, "session_id")?.to_owned();
    let summary = ManualLabSessionGfxFilterSummary {
        server_chunk_count: parse_manual_lab_log_u64(line, "server_chunk_count").unwrap_or(0),
        rdpegfx_pdu_count: parse_manual_lab_log_u64(line, "rdpegfx_pdu_count").unwrap_or(0),
        emitted_surface_update_count: parse_manual_lab_log_u64(line, "emitted_surface_update_count").unwrap_or(0),
        pending_surface_update_count: parse_manual_lab_log_u64(line, "pending_surface_update_count").unwrap_or(0),
        surface_count: parse_manual_lab_log_u64(line, "surface_count").unwrap_or(0),
        cached_tile_count: parse_manual_lab_log_u64(line, "cached_tile_count").unwrap_or(0),
        codec_context_surface_count: parse_manual_lab_log_u64(line, "codec_context_surface_count").unwrap_or(0),
    };

    Some((session_id, summary))
}

fn parse_manual_lab_gfx_filter_summaries(
    proxy_stdout_log: &Path,
) -> anyhow::Result<BTreeMap<String, ManualLabSessionGfxFilterSummary>> {
    if !proxy_stdout_log.exists() {
        return Ok(BTreeMap::new());
    }

    let log = fs::read_to_string(proxy_stdout_log).with_context(|| format!("read {}", proxy_stdout_log.display()))?;
    let mut summaries = BTreeMap::new();
    for line in log.lines() {
        if let Some((session_id, summary)) = parse_manual_lab_gfx_filter_summary_line(line) {
            summaries.insert(session_id, summary);
        }
    }

    Ok(summaries)
}

fn parse_manual_lab_gfx_warning_summary_line(line: &str) -> Option<(String, ManualLabSessionGfxWarningSummary)> {
    if !line.contains("GFX warning summary") {
        return None;
    }

    let session_id = parse_manual_lab_log_field(line, "session_id")?.to_owned();
    let summary = ManualLabSessionGfxWarningSummary {
        total_warning_count: parse_manual_lab_log_u64(line, "total_warning_count").unwrap_or(0),
        wire_to_surface1_unknown_surface_count: parse_manual_lab_log_u64(
            line,
            "wire_to_surface1_unknown_surface_count",
        )
        .unwrap_or(0),
        wire_to_surface2_metadata_unknown_surface_count: parse_manual_lab_log_u64(
            line,
            "wire_to_surface2_metadata_unknown_surface_count",
        )
        .unwrap_or(0),
        wire_to_surface2_update_unknown_surface_count: parse_manual_lab_log_u64(
            line,
            "wire_to_surface2_update_unknown_surface_count",
        )
        .unwrap_or(0),
        delete_encoding_context_unknown_surface_or_context_count: parse_manual_lab_log_u64(
            line,
            "delete_encoding_context_unknown_surface_or_context_count",
        )
        .unwrap_or(0),
        surface_to_cache_unknown_surface_count: parse_manual_lab_log_u64(
            line,
            "surface_to_cache_unknown_surface_count",
        )
        .unwrap_or(0),
        cache_to_surface_unknown_cache_slot_count: parse_manual_lab_log_u64(
            line,
            "cache_to_surface_unknown_cache_slot_count",
        )
        .unwrap_or(0),
        cache_to_surface_unknown_surface_count: parse_manual_lab_log_u64(
            line,
            "cache_to_surface_unknown_surface_count",
        )
        .unwrap_or(0),
        wire_to_surface1_update_failed_count: parse_manual_lab_log_u64(line, "wire_to_surface1_update_failed_count")
            .unwrap_or(0),
        wire_to_surface1_decode_skipped_count: parse_manual_lab_log_u64(line, "wire_to_surface1_decode_skipped_count")
            .unwrap_or(0),
        wire_to_surface2_decode_skipped_count: parse_manual_lab_log_u64(line, "wire_to_surface2_decode_skipped_count")
            .unwrap_or(0),
        surface_to_cache_capture_skipped_count: parse_manual_lab_log_u64(
            line,
            "surface_to_cache_capture_skipped_count",
        )
        .unwrap_or(0),
        cache_to_surface_replay_skipped_count: parse_manual_lab_log_u64(line, "cache_to_surface_replay_skipped_count")
            .unwrap_or(0),
    };

    Some((session_id, summary))
}

fn parse_manual_lab_gfx_warning_summaries(
    proxy_stdout_log: &Path,
) -> anyhow::Result<BTreeMap<String, ManualLabSessionGfxWarningSummary>> {
    if !proxy_stdout_log.exists() {
        return Ok(BTreeMap::new());
    }

    let log = fs::read_to_string(proxy_stdout_log).with_context(|| format!("read {}", proxy_stdout_log.display()))?;
    let mut summaries = BTreeMap::new();
    for line in log.lines() {
        if let Some((session_id, summary)) = parse_manual_lab_gfx_warning_summary_line(line) {
            summaries.insert(session_id, summary);
        }
    }

    Ok(summaries)
}

fn build_manual_lab_gfx_warning_baseline(
    summaries: &[ManualLabSessionGfxWarningSummary],
) -> Option<ManualLabSessionGfxWarningSummary> {
    if summaries.is_empty() {
        return None;
    }

    let mut baseline = ManualLabSessionGfxWarningSummary::default();
    for summary in summaries {
        baseline.total_warning_count = baseline.total_warning_count.max(summary.total_warning_count);
        baseline.wire_to_surface1_unknown_surface_count = baseline
            .wire_to_surface1_unknown_surface_count
            .max(summary.wire_to_surface1_unknown_surface_count);
        baseline.wire_to_surface2_metadata_unknown_surface_count = baseline
            .wire_to_surface2_metadata_unknown_surface_count
            .max(summary.wire_to_surface2_metadata_unknown_surface_count);
        baseline.wire_to_surface2_update_unknown_surface_count = baseline
            .wire_to_surface2_update_unknown_surface_count
            .max(summary.wire_to_surface2_update_unknown_surface_count);
        baseline.delete_encoding_context_unknown_surface_or_context_count = baseline
            .delete_encoding_context_unknown_surface_or_context_count
            .max(summary.delete_encoding_context_unknown_surface_or_context_count);
        baseline.surface_to_cache_unknown_surface_count = baseline
            .surface_to_cache_unknown_surface_count
            .max(summary.surface_to_cache_unknown_surface_count);
        baseline.cache_to_surface_unknown_cache_slot_count = baseline
            .cache_to_surface_unknown_cache_slot_count
            .max(summary.cache_to_surface_unknown_cache_slot_count);
        baseline.cache_to_surface_unknown_surface_count = baseline
            .cache_to_surface_unknown_surface_count
            .max(summary.cache_to_surface_unknown_surface_count);
        baseline.wire_to_surface1_update_failed_count = baseline
            .wire_to_surface1_update_failed_count
            .max(summary.wire_to_surface1_update_failed_count);
        baseline.wire_to_surface1_decode_skipped_count = baseline
            .wire_to_surface1_decode_skipped_count
            .max(summary.wire_to_surface1_decode_skipped_count);
        baseline.wire_to_surface2_decode_skipped_count = baseline
            .wire_to_surface2_decode_skipped_count
            .max(summary.wire_to_surface2_decode_skipped_count);
        baseline.surface_to_cache_capture_skipped_count = baseline
            .surface_to_cache_capture_skipped_count
            .max(summary.surface_to_cache_capture_skipped_count);
        baseline.cache_to_surface_replay_skipped_count = baseline
            .cache_to_surface_replay_skipped_count
            .max(summary.cache_to_surface_replay_skipped_count);
    }

    Some(baseline)
}

fn exceeds_decode_candidate_threshold(value: u64, baseline: u64) -> bool {
    value >= baseline.saturating_add(10) && value.saturating_mul(5) >= baseline.saturating_mul(6)
}

fn decode_warning_delta_exceeds_baseline(
    summary: Option<&ManualLabSessionGfxWarningSummary>,
    baseline: Option<&ManualLabSessionGfxWarningSummary>,
) -> bool {
    let (Some(summary), Some(baseline)) = (summary, baseline) else {
        return false;
    };

    let mut exceeded = 0;
    for (value, baseline_value) in [
        (
            summary.wire_to_surface1_update_failed_count,
            baseline.wire_to_surface1_update_failed_count,
        ),
        (
            summary.wire_to_surface1_decode_skipped_count,
            baseline.wire_to_surface1_decode_skipped_count,
        ),
        (
            summary.wire_to_surface2_decode_skipped_count,
            baseline.wire_to_surface2_decode_skipped_count,
        ),
        (
            summary.cache_to_surface_unknown_cache_slot_count,
            baseline.cache_to_surface_unknown_cache_slot_count,
        ),
        (
            summary.surface_to_cache_capture_skipped_count,
            baseline.surface_to_cache_capture_skipped_count,
        ),
    ] {
        if exceeds_decode_candidate_threshold(value, baseline_value) {
            exceeded += 1;
        }
    }

    exceeded >= 2
}

fn build_manual_lab_black_screen_branch(
    timeline: &ManualLabSessionPlaybackBootstrapTimeline,
    correlation: &ManualLabSessionPlaybackReadyCorrelation,
    gfx_filter_summary: Option<&ManualLabSessionGfxFilterSummary>,
    gfx_warning_summary: Option<&ManualLabSessionGfxWarningSummary>,
    aligned_ready_warning_baseline: Option<&ManualLabSessionGfxWarningSummary>,
    aligned_ready_baseline_session_count: usize,
    teardown_started_at_unix_ms: Option<u64>,
) -> ManualLabSessionBlackScreenBranch {
    let mut reasons = Vec::new();
    let source_ready_after_teardown = match (correlation.source_ready_at_unix_ms, teardown_started_at_unix_ms) {
        (Some(source_ready_at), Some(teardown_started_at)) => source_ready_at >= teardown_started_at,
        _ => false,
    };
    let decode_warning_delta_exceeds_baseline =
        decode_warning_delta_exceeds_baseline(gfx_warning_summary, aligned_ready_warning_baseline);
    let rdpegfx_pdu_count = gfx_filter_summary.map(|summary| summary.rdpegfx_pdu_count);
    let emitted_surface_update_count = gfx_filter_summary.map(|summary| summary.emitted_surface_update_count);
    let has_rdpegfx = rdpegfx_pdu_count.is_some_and(|count| count > 0);
    let producer_started = correlation.producer_started_at_unix_ms.is_some();
    let source_ready = correlation.source_ready_at_unix_ms.is_some();
    let stream_ready = correlation.session_stream_ready_emitted_at_unix_ms.is_some();

    let (verdict, confidence, detail) = if correlation.verdict == ManualLabPlaybackReadyVerdict::AlignedReady {
        reasons.push("source-ready evidence, stream-ready emission, and probe all aligned".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::AlignedReady,
            ManualLabEvidenceConfidence::High,
            Some("session reached a fully aligned ready path".to_owned()),
        )
    } else if !has_rdpegfx && gfx_filter_summary.is_some() {
        reasons.push("no rdpegfx PDUs were counted in the GFX filter summary".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::NegotiationLoss,
            ManualLabEvidenceConfidence::High,
            Some("graphics negotiation never produced RDPEGFX PDUs for this session".to_owned()),
        )
    } else if source_ready && !stream_ready && !source_ready_after_teardown {
        reasons.push("source-ready evidence exists without a session.stream.ready emission".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::PlayerLoss,
            ManualLabEvidenceConfidence::High,
            Some("source-ready evidence landed, but the player-ready event never followed".to_owned()),
        )
    } else if correlation.verdict == ManualLabPlaybackReadyVerdict::ProbeReadyWithoutStreamReady
        && !source_ready_after_teardown
    {
        reasons.push("the probe returned ready without a matching session.stream.ready emission".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::PlayerLoss,
            ManualLabEvidenceConfidence::Medium,
            Some("the player path advertised ready without the proxy emitting stream-ready".to_owned()),
        )
    } else if decode_warning_delta_exceeds_baseline && source_ready && !source_ready_after_teardown {
        reasons.push("warning counters exceeded the aligned-ready baseline".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::DecodeCorruption,
            ManualLabEvidenceConfidence::Medium,
            Some(
                "decode-corruption candidate: ready-path evidence exists and warning deltas spiked above baseline"
                    .to_owned(),
            ),
        )
    } else if producer_started
        && matches!(
            correlation.verdict,
            ManualLabPlaybackReadyVerdict::Probe503WithoutSourceReady
                | ManualLabPlaybackReadyVerdict::ProbeBeforeReady
                | ManualLabPlaybackReadyVerdict::IncompleteEvidence
        )
        && (!source_ready || source_ready_after_teardown)
    {
        if source_ready_after_teardown {
            reasons.push("source-ready evidence first appeared at or after teardown".to_owned());
        } else {
            reasons.push("no source-ready evidence existed when the live probe observed the session".to_owned());
        }
        (
            ManualLabBlackScreenBranchVerdict::NoReadyTruthfulness,
            ManualLabEvidenceConfidence::High,
            Some(
                "the live probe was truthful: the stream was not ready during the active observation window".to_owned(),
            ),
        )
    } else if producer_started && !source_ready && has_rdpegfx {
        reasons.push(
            "producer bootstrap started and graphics data was observed, but no source-ready evidence landed".to_owned(),
        );
        (
            ManualLabBlackScreenBranchVerdict::ProducerLoss,
            ManualLabEvidenceConfidence::Medium,
            Some("graphics negotiation succeeded, but the producer never reached a source-ready state".to_owned()),
        )
    } else if timeline.verdict == ManualLabPlaybackBootstrapVerdict::Contradiction {
        reasons.push("bootstrap timeline contains a contradiction".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::Inconclusive,
            ManualLabEvidenceConfidence::Low,
            Some("bootstrap evidence is contradictory, so the session cannot be named confidently".to_owned()),
        )
    } else {
        reasons.push("the available evidence does not satisfy a higher-confidence BS-20 branch".to_owned());
        (
            ManualLabBlackScreenBranchVerdict::Inconclusive,
            ManualLabEvidenceConfidence::Low,
            Some("the session still needs more evidence before a BS-20 branch can be named".to_owned()),
        )
    };

    if let Some(detail) = correlation.detail.as_ref() {
        reasons.push(detail.clone());
    }
    if let Some(rdpegfx_pdu_count) = rdpegfx_pdu_count {
        reasons.push(format!("rdpegfx_pdu_count={rdpegfx_pdu_count}"));
    }
    if source_ready_after_teardown {
        reasons.push("late source-ready evidence arrived only after teardown began".to_owned());
    }

    ManualLabSessionBlackScreenBranch {
        verdict,
        confidence,
        detail,
        reasons,
        teardown_started_at_unix_ms,
        source_ready_after_teardown,
        decode_warning_delta_exceeds_baseline,
        aligned_ready_baseline_session_count,
        rdpegfx_pdu_count,
        emitted_surface_update_count,
    }
}

fn persist_black_screen_evidence(
    state: &ManualLabState,
    teardown_started_at_unix_ms: Option<u64>,
) -> anyhow::Result<()> {
    let evidence_path = state.run_root.join("artifacts/black-screen-evidence.json");
    let mut evidence = state.black_screen_evidence.clone();
    if evidence.teardown_started_at_unix_ms.is_none() {
        evidence.teardown_started_at_unix_ms = teardown_started_at_unix_ms;
    }
    let playback_bootstrap_timelines = parse_manual_lab_playback_bootstrap_timelines(&state.proxy.stdout_log)?;
    let ready_trace_events = parse_manual_lab_ready_trace_events(&state.proxy.stdout_log)?;
    let gfx_filter_summaries = parse_manual_lab_gfx_filter_summaries(&state.proxy.stdout_log)?;
    let gfx_warning_summaries = parse_manual_lab_gfx_warning_summaries(&state.proxy.stdout_log)?;
    let session_evidence = state
        .sessions
        .iter()
        .map(|session| {
            let playback_bootstrap_timeline = playback_bootstrap_timelines
                .get(&session.session_id)
                .cloned()
                .unwrap_or_else(|| build_manual_lab_playback_bootstrap_timeline(Vec::new()));
            let ready_trace_events = ready_trace_events.get(&session.session_id).cloned().unwrap_or_default();
            let playback_ready_correlation = build_manual_lab_playback_ready_correlation(
                &playback_bootstrap_timeline,
                ready_trace_events,
                session.stream_probe_status.as_deref(),
                session.stream_probe_http_status,
                session.stream_probe_observed_at_unix_ms,
            );
            let gfx_filter_summary = gfx_filter_summaries.get(&session.session_id).cloned();
            let gfx_warning_summary = gfx_warning_summaries.get(&session.session_id).cloned();

            (
                session,
                playback_bootstrap_timeline,
                playback_ready_correlation,
                gfx_filter_summary,
                gfx_warning_summary,
            )
        })
        .collect::<Vec<_>>();
    let aligned_ready_warning_summaries = session_evidence
        .iter()
        .filter_map(|(_, _, correlation, _, gfx_warning_summary)| {
            (correlation.verdict == ManualLabPlaybackReadyVerdict::AlignedReady)
                .then_some(gfx_warning_summary.clone())
                .flatten()
        })
        .collect::<Vec<_>>();
    let aligned_ready_warning_baseline = build_manual_lab_gfx_warning_baseline(&aligned_ready_warning_summaries);
    let aligned_ready_baseline_session_count = aligned_ready_warning_summaries.len();
    evidence.artifacts = build_black_screen_artifact_paths(state);
    evidence.session_invocations = session_evidence
        .into_iter()
        .map(
            |(
                session,
                playback_bootstrap_timeline,
                playback_ready_correlation,
                gfx_filter_summary,
                gfx_warning_summary,
            )| {
                let black_screen_branch = build_manual_lab_black_screen_branch(
                    &playback_bootstrap_timeline,
                    &playback_ready_correlation,
                    gfx_filter_summary.as_ref(),
                    gfx_warning_summary.as_ref(),
                    aligned_ready_warning_baseline.as_ref(),
                    aligned_ready_baseline_session_count,
                    evidence.teardown_started_at_unix_ms,
                );

                ManualLabSessionDriverEvidence {
                    slot: session.slot,
                    session_id: session.session_id.clone(),
                    driver_binary: session.driver_binary.clone(),
                    driver_args: session.driver_args.clone(),
                    driver_lane: session.driver_lane.clone(),
                    stdout_log: session.stdout_log.clone(),
                    stderr_log: session.stderr_log.clone(),
                    vm_lease_id: session.vm_lease_id.clone(),
                    stream_id: session.stream_id.clone(),
                    stream_probe_status: session.stream_probe_status.clone(),
                    stream_probe_detail: session.stream_probe_detail.clone(),
                    stream_probe_http_status: session.stream_probe_http_status,
                    stream_probe_observed_at_unix_ms: session.stream_probe_observed_at_unix_ms,
                    playback_bootstrap_timeline,
                    playback_ready_correlation,
                    gfx_filter_summary,
                    gfx_warning_summary,
                    black_screen_branch,
                }
            },
        )
        .collect();
    if let Some(parent) = evidence_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(
        &evidence_path,
        serde_json::to_vec_pretty(&evidence).context("serialize manual lab black-screen evidence")?,
    )
    .with_context(|| format!("write {}", evidence_path.display()))
}

fn find_command_path(candidate: &Path) -> anyhow::Result<PathBuf> {
    if candidate.components().count() > 1 || candidate.is_absolute() {
        ensure!(candidate.is_file(), "expected command at {}", candidate.display());
        return candidate
            .canonicalize()
            .with_context(|| format!("canonicalize {}", candidate.display()));
    }

    let path_env = std::env::var_os("PATH").context("PATH is not set")?;
    for root in std::env::split_paths(&path_env) {
        let full = root.join(candidate);
        if full.is_file() {
            return full
                .canonicalize()
                .with_context(|| format!("canonicalize {}", full.display()));
        }
    }

    bail!("command {} was not found in PATH", candidate.display())
}

fn process_is_running(pid: u32) -> bool {
    if pid == 0 {
        return false;
    }

    #[cfg(unix)]
    {
        let Ok(pid) = libc::pid_t::try_from(pid) else {
            return false;
        };
        // Safety: `kill(pid, 0)` is the standard POSIX liveness probe and does not
        // deliver a signal. The pid comes from a child process id we previously recorded.
        let result = unsafe { libc::kill(pid, 0) };
        if !(result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)) {
            return false;
        }

        let stat_path = PathBuf::from(format!("/proc/{pid}/stat"));
        let Ok(stat) = fs::read_to_string(&stat_path) else {
            return true;
        };
        return parse_proc_stat_process_state(&stat) != Some('Z');
    }

    #[allow(unreachable_code)]
    false
}

fn terminate_pid(pid: u32, timeout: Duration) -> anyhow::Result<()> {
    if pid == 0 || !process_is_running(pid) {
        return Ok(());
    }

    #[cfg(unix)]
    {
        let raw_pid = pid;
        let pid = libc::pid_t::try_from(raw_pid).context("convert child pid to libc::pid_t")?;
        // Safety: the pid was captured from a spawned child process and SIGTERM is the
        // first bounded shutdown signal we use before escalating to SIGKILL.
        let signal_result = unsafe { libc::kill(pid, libc::SIGTERM) };
        if signal_result != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("send SIGTERM to pid {pid}"));
        }

        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if !process_is_running(raw_pid) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(250));
        }

        // Safety: the same child pid is still considered live after the SIGTERM grace
        // period, so SIGKILL is used as the final bounded cleanup signal.
        let signal_result = unsafe { libc::kill(pid, libc::SIGKILL) };
        if signal_result != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| format!("send SIGKILL to pid {pid}"));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if !process_is_running(raw_pid) {
                return Ok(());
            }
            thread::sleep(Duration::from_millis(250));
        }

        bail!("pid {pid} did not exit after SIGTERM/SIGKILL")
    }

    #[allow(unreachable_code)]
    Ok(())
}

fn read_log_tail(path: &Path) -> String {
    match fs::read_to_string(path) {
        Ok(contents) => {
            let mut lines = contents.lines().collect::<Vec<_>>();
            if lines.len() > 40 {
                lines.drain(..lines.len() - 40);
            }
            lines.join("\n")
        }
        Err(error) => format!("failed to read {}: {error:#}", path.display()),
    }
}

fn parse_proc_stat_process_state(stat: &str) -> Option<char> {
    stat.find('(')?;
    let close = stat.rfind(") ")?;
    stat[(close + 2)..]
        .chars()
        .next()
        .filter(|state| !state.is_whitespace())
}

fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the unix epoch")
        .as_secs()
}

fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock should be after the unix epoch")
        .as_millis()
        .try_into()
        .expect("unix timestamp in milliseconds should fit in u64")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use base64::Engine as _;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{
        ManualLabBlackScreenBranchVerdict, ManualLabEvidenceConfidence, ManualLabPlaybackBootstrapVerdict,
        ManualLabPlaybackReadyVerdict, ManualLabSessionGfxFilterSummary, ManualLabSessionGfxWarningSummary,
        ManualLabSessionPlaybackBootstrapEvent, ManualLabSessionReadyTraceEvent, ManualLabXfreerdpGraphicsMode,
        association_token, build_manual_lab_black_screen_branch, build_manual_lab_gfx_warning_baseline,
        build_manual_lab_playback_bootstrap_timeline, build_manual_lab_playback_ready_correlation,
        build_session_records, discover_manual_lab_source_manifest_candidates_in_root, display_socket_path,
        evaluate_manual_lab_source_manifest_candidate, manual_lab_manifest_path, manual_lab_service_ready_timeout,
        parse_manual_lab_gfx_filter_summary_line, parse_manual_lab_gfx_warning_summary_line,
        parse_manual_lab_playback_bootstrap_trace_line, parse_manual_lab_ready_trace_line,
        parse_proc_stat_process_state, xfreerdp_driver_args,
    };

    fn bootstrap_event(seq: u64, event: &str, status: &str) -> ManualLabSessionPlaybackBootstrapEvent {
        ManualLabSessionPlaybackBootstrapEvent {
            schema_version: 1,
            seq,
            ts_ns: seq * 100,
            observed_at_unix_ms: Some(1_700_000_000_000 + (seq * 10)),
            thread: if event.starts_with("playback.thread") || event.starts_with("playback.update") {
                "playback-thread".to_owned()
            } else {
                "proxy".to_owned()
            },
            event: event.to_owned(),
            status: status.to_owned(),
            source: "test".to_owned(),
            byte_len: 0,
            error: None,
        }
    }

    #[test]
    fn manual_lab_manifest_paths_resolve_from_repo_root() {
        for relative_path in [
            "Cargo.toml",
            "honeypot/control-plane/Cargo.toml",
            "honeypot/frontend/Cargo.toml",
            "testsuite/Cargo.toml",
        ] {
            let manifest_path = manual_lab_manifest_path(relative_path);
            assert!(
                manifest_path.is_file(),
                "missing manifest path {}",
                manifest_path.display()
            );
        }
    }

    #[test]
    fn manual_lab_service_ready_timeout_reuses_interop_ready_budget() {
        assert_eq!(manual_lab_service_ready_timeout(45), Duration::from_secs(60));
        assert_eq!(manual_lab_service_ready_timeout(120), Duration::from_secs(120));
        assert_eq!(manual_lab_service_ready_timeout(180), Duration::from_secs(180));
    }

    #[test]
    fn manual_lab_send_http_request_reads_content_length_response_without_waiting_for_eof() {
        use std::io::{Read as _, Write as _};
        use std::net::TcpListener;

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).expect("bind localhost listener");
        let port = listener.local_addr().expect("read local addr").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept manual-lab test connection");
            let mut request = Vec::new();
            let mut chunk = [0u8; 1024];
            loop {
                let read_len = stream.read(&mut chunk).expect("read manual-lab test request");
                if read_len == 0 {
                    return;
                }
                request.extend_from_slice(&chunk[..read_len]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }

            let body = br#"{"ok":true}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
                body.len()
            )
            .expect("write manual-lab test response headers");
            stream.write_all(body).expect("write manual-lab test response body");
            stream.flush().expect("flush manual-lab test response");

            loop {
                let read_len = stream.read(&mut chunk).expect("wait for manual-lab client shutdown");
                if read_len == 0 {
                    break;
                }
            }
        });

        let (status, body) =
            super::send_http_request(port, "GET", "/health", &[], None).expect("send manual lab http request");
        assert!(status.contains("200"), "{status}");
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&body).expect("parse json body"),
            json!({ "ok": true })
        );

        server.join().expect("join manual-lab test server");
    }

    #[test]
    fn manual_lab_display_socket_path_parses_x11_displays() {
        assert_eq!(
            display_socket_path(":90"),
            Some(std::path::PathBuf::from("/tmp/.X11-unix/X90"))
        );
        assert_eq!(
            display_socket_path(":91.0"),
            Some(std::path::PathBuf::from("/tmp/.X11-unix/X91"))
        );
        assert_eq!(display_socket_path("wayland-0"), None);
        assert_eq!(display_socket_path(""), None);
    }

    #[test]
    fn manual_lab_process_probe_treats_zombies_as_exited() {
        assert_eq!(
            parse_proc_stat_process_state("1234 (honeypot-control-plane) S 1 2 3 4"),
            Some('S')
        );
        assert_eq!(parse_proc_stat_process_state("5678 (xfreerdp) Z 1 2 3 4"), Some('Z'));
        assert_eq!(parse_proc_stat_process_state("malformed"), None);
    }

    #[test]
    fn manual_lab_parses_gfx_warning_summary_lines() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let line = format!(
            "2026-03-28T22:00:00.000000Z  INFO ThreadId(42) session_id={session_id} total_warning_count=9 wire_to_surface1_unknown_surface_count=1 wire_to_surface2_metadata_unknown_surface_count=2 wire_to_surface2_update_unknown_surface_count=3 delete_encoding_context_unknown_surface_or_context_count=4 surface_to_cache_unknown_surface_count=5 cache_to_surface_unknown_cache_slot_count=6 cache_to_surface_unknown_surface_count=7 wire_to_surface1_update_failed_count=8 wire_to_surface1_decode_skipped_count=9 wire_to_surface2_decode_skipped_count=10 surface_to_cache_capture_skipped_count=11 cache_to_surface_replay_skipped_count=12 GFX warning summary"
        );

        let parsed = parse_manual_lab_gfx_warning_summary_line(&line);
        assert_eq!(
            parsed,
            Some((
                session_id.to_owned(),
                ManualLabSessionGfxWarningSummary {
                    total_warning_count: 9,
                    wire_to_surface1_unknown_surface_count: 1,
                    wire_to_surface2_metadata_unknown_surface_count: 2,
                    wire_to_surface2_update_unknown_surface_count: 3,
                    delete_encoding_context_unknown_surface_or_context_count: 4,
                    surface_to_cache_unknown_surface_count: 5,
                    cache_to_surface_unknown_cache_slot_count: 6,
                    cache_to_surface_unknown_surface_count: 7,
                    wire_to_surface1_update_failed_count: 8,
                    wire_to_surface1_decode_skipped_count: 9,
                    wire_to_surface2_decode_skipped_count: 10,
                    surface_to_cache_capture_skipped_count: 11,
                    cache_to_surface_replay_skipped_count: 12,
                }
            ))
        );
    }

    #[test]
    fn manual_lab_parses_gfx_filter_summary_lines() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let line = format!(
            "2026-03-28T22:00:00.000000Z  INFO devolutions_gateway::rdp_gfx: GFX filter summary session_id={session_id} server_chunk_count=1 rdpegfx_pdu_count=1175 emitted_surface_update_count=582 pending_surface_update_count=0 surface_count=1 cached_tile_count=417 codec_context_surface_count=0"
        );

        let parsed = parse_manual_lab_gfx_filter_summary_line(&line);
        assert_eq!(
            parsed,
            Some((
                session_id.to_owned(),
                ManualLabSessionGfxFilterSummary {
                    server_chunk_count: 1,
                    rdpegfx_pdu_count: 1175,
                    emitted_surface_update_count: 582,
                    pending_surface_update_count: 0,
                    surface_count: 1,
                    cached_tile_count: 417,
                    codec_context_surface_count: 0,
                }
            ))
        );
    }

    #[test]
    fn manual_lab_parses_playback_bootstrap_trace_lines() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let line = format!(
            "2026-03-28T22:00:00.000000Z  INFO ThreadId(42) session_id={session_id} bootstrap_schema_version=1 bootstrap_seq=7 bootstrap_ts_ns=998 bootstrap_thread=proxy bootstrap_event=leftover.client.after bootstrap_status=ok bootstrap_source=client bootstrap_byte_len=512 bootstrap_error=\"\" Playback bootstrap trace"
        );

        let parsed = parse_manual_lab_playback_bootstrap_trace_line(&line);
        assert_eq!(
            parsed,
            Some((
                session_id.to_owned(),
                ManualLabSessionPlaybackBootstrapEvent {
                    schema_version: 1,
                    seq: 7,
                    ts_ns: 998,
                    observed_at_unix_ms: Some(1_774_735_200_000),
                    thread: "proxy".to_owned(),
                    event: "leftover.client.after".to_owned(),
                    status: "ok".to_owned(),
                    source: "client".to_owned(),
                    byte_len: 512,
                    error: None,
                }
            ))
        );
    }

    #[test]
    fn manual_lab_parses_ready_trace_lines() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let line = format!(
            "2026-03-28T22:00:01.000000Z  INFO ThreadId(42) session_id={session_id} ready_schema_version=1 ready_event=recording.connected.first ready_source=recording-manager ready_ts_unix_ms=1743201601000 Ready path trace"
        );

        let parsed = parse_manual_lab_ready_trace_line(&line);
        assert_eq!(
            parsed,
            Some((
                session_id.to_owned(),
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "recording.connected.first".to_owned(),
                    source: "recording-manager".to_owned(),
                    ts_unix_ms: 1_743_201_601_000,
                    observed_at_unix_ms: Some(1_774_735_201_000),
                }
            ))
        );
    }

    #[test]
    fn manual_lab_marks_complete_bootstrap_timeline() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "handshake.connect_confirm.start", "ok"),
            bootstrap_event(4, "handshake.connect_confirm.end", "ok"),
            bootstrap_event(5, "leftover.client.before", "ok"),
            bootstrap_event(6, "leftover.client.after", "ok"),
            bootstrap_event(7, "leftover.server.before", "ok"),
            bootstrap_event(8, "leftover.server.after", "ok"),
            bootstrap_event(9, "interceptor.client.installed", "ok"),
            bootstrap_event(10, "interceptor.server.installed", "ok"),
            bootstrap_event(11, "playback.thread.start", "ok"),
            bootstrap_event(12, "playback.thread.first_packet", "ok"),
            bootstrap_event(13, "playback.update.none", "ok"),
        ]);

        assert_eq!(timeline.verdict, ManualLabPlaybackBootstrapVerdict::Complete);
        assert_eq!(timeline.first_seq, Some(1));
        assert_eq!(timeline.last_seq, Some(13));
        assert_eq!(timeline.update_event.as_deref(), Some("playback.update.none"));
        assert!(timeline.missing_events.is_empty());
        assert!(timeline.failed_events.is_empty());
    }

    #[test]
    fn manual_lab_marks_incomplete_bootstrap_timeline_when_required_event_is_missing() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "handshake.connect_confirm.start", "ok"),
            bootstrap_event(4, "handshake.connect_confirm.end", "ok"),
            bootstrap_event(5, "leftover.client.before", "ok"),
            bootstrap_event(6, "leftover.client.after", "ok"),
            bootstrap_event(7, "leftover.server.before", "ok"),
            bootstrap_event(8, "interceptor.client.installed", "ok"),
            bootstrap_event(9, "interceptor.server.installed", "ok"),
            bootstrap_event(10, "playback.thread.start", "ok"),
            bootstrap_event(11, "playback.thread.first_packet", "ok"),
            bootstrap_event(12, "playback.update.none", "ok"),
        ]);

        assert_eq!(timeline.verdict, ManualLabPlaybackBootstrapVerdict::Incomplete);
        assert!(timeline.missing_events.contains(&"leftover.server.after".to_owned()));
    }

    #[test]
    fn manual_lab_marks_contradiction_for_bootstrap_sequence_gap() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(3, "playback.bootstrap.request_result", "ok"),
        ]);

        assert_eq!(timeline.verdict, ManualLabPlaybackBootstrapVerdict::Contradiction);
        assert!(
            timeline
                .detail
                .as_deref()
                .is_some_and(|detail| detail.contains("sequence gap"))
        );
    }

    #[test]
    fn manual_lab_builds_aligned_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "recording.connected.first".to_owned(),
                    source: "recording-manager".to_owned(),
                    ts_unix_ms: 1_700_000_000_040,
                    observed_at_unix_ms: Some(1_700_000_000_040),
                },
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "session.stream.ready.emitted".to_owned(),
                    source: "honeypot".to_owned(),
                    ts_unix_ms: 1_700_000_000_050,
                    observed_at_unix_ms: Some(1_700_000_000_050),
                },
            ],
            Some("ready"),
            Some(200),
            Some(1_700_000_000_060),
        );

        assert_eq!(correlation.verdict, ManualLabPlaybackReadyVerdict::AlignedReady);
        assert_eq!(correlation.producer_started_at_unix_ms, Some(1_700_000_000_020));
        assert_eq!(correlation.first_chunk_appended_at_unix_ms, Some(1_700_000_000_030));
        assert_eq!(correlation.recording_connected_at_unix_ms, Some(1_700_000_000_040));
        assert_eq!(
            correlation.session_stream_ready_emitted_at_unix_ms,
            Some(1_700_000_000_050)
        );
        assert_eq!(correlation.probe_http_status, Some(200));
        assert_eq!(correlation.ready_trace_events.len(), 2);
    }

    #[test]
    fn manual_lab_builds_probe_before_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "recording.connected.first".to_owned(),
                source: "recording-manager".to_owned(),
                ts_unix_ms: 1_700_000_000_040,
                observed_at_unix_ms: Some(1_700_000_000_040),
            }],
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_025),
        );

        assert_eq!(correlation.verdict, ManualLabPlaybackReadyVerdict::ProbeBeforeReady);
    }

    #[test]
    fn manual_lab_builds_probe_503_without_source_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![bootstrap_event(
            1,
            "playback.bootstrap.requested",
            "ok",
        )]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            Vec::new(),
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_010),
        );

        assert_eq!(
            correlation.verdict,
            ManualLabPlaybackReadyVerdict::Probe503WithoutSourceReady
        );
    }

    #[test]
    fn manual_lab_builds_source_ready_without_stream_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "recording.connected.first".to_owned(),
                source: "recording-manager".to_owned(),
                ts_unix_ms: 1_700_000_000_040,
                observed_at_unix_ms: Some(1_700_000_000_040),
            }],
            Some("unavailable"),
            Some(503),
            None,
        );

        assert_eq!(
            correlation.verdict,
            ManualLabPlaybackReadyVerdict::SourceReadyWithoutStreamReady
        );
    }

    #[test]
    fn manual_lab_builds_stream_ready_without_source_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![bootstrap_event(
            1,
            "playback.bootstrap.requested",
            "ok",
        )]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "session.stream.ready.emitted".to_owned(),
                source: "honeypot".to_owned(),
                ts_unix_ms: 1_700_000_000_050,
                observed_at_unix_ms: Some(1_700_000_000_050),
            }],
            Some("ready"),
            Some(200),
            Some(1_700_000_000_060),
        );

        assert_eq!(
            correlation.verdict,
            ManualLabPlaybackReadyVerdict::StreamReadyWithoutSourceReady
        );
    }

    #[test]
    fn manual_lab_builds_probe_ready_without_stream_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "recording.connected.first".to_owned(),
                source: "recording-manager".to_owned(),
                ts_unix_ms: 1_700_000_000_040,
                observed_at_unix_ms: Some(1_700_000_000_040),
            }],
            Some("ready"),
            Some(200),
            Some(1_700_000_000_060),
        );

        assert_eq!(
            correlation.verdict,
            ManualLabPlaybackReadyVerdict::ProbeReadyWithoutStreamReady
        );
    }

    #[test]
    fn manual_lab_builds_probe_503_after_ready_correlation() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "recording.connected.first".to_owned(),
                    source: "recording-manager".to_owned(),
                    ts_unix_ms: 1_700_000_000_040,
                    observed_at_unix_ms: Some(1_700_000_000_040),
                },
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "session.stream.ready.emitted".to_owned(),
                    source: "honeypot".to_owned(),
                    ts_unix_ms: 1_700_000_000_050,
                    observed_at_unix_ms: Some(1_700_000_000_050),
                },
            ],
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_070),
        );

        assert_eq!(correlation.verdict, ManualLabPlaybackReadyVerdict::Probe503AfterReady);
    }

    #[test]
    fn manual_lab_builds_no_ready_truthfulness_branch_for_late_source_ready() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "recording.connected.first".to_owned(),
                source: "recording-manager".to_owned(),
                ts_unix_ms: 1_700_000_000_080,
                observed_at_unix_ms: Some(1_700_000_000_080),
            }],
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_025),
        );

        let branch = build_manual_lab_black_screen_branch(
            &timeline,
            &correlation,
            Some(&ManualLabSessionGfxFilterSummary {
                rdpegfx_pdu_count: 1045,
                emitted_surface_update_count: 496,
                ..Default::default()
            }),
            Some(&ManualLabSessionGfxWarningSummary::default()),
            None,
            0,
            Some(1_700_000_000_070),
        );

        assert_eq!(branch.verdict, ManualLabBlackScreenBranchVerdict::NoReadyTruthfulness);
        assert_eq!(branch.confidence, ManualLabEvidenceConfidence::High);
        assert!(branch.source_ready_after_teardown);
    }

    #[test]
    fn manual_lab_builds_player_loss_branch_from_source_ready_without_stream_ready() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![ManualLabSessionReadyTraceEvent {
                schema_version: 1,
                event: "recording.connected.first".to_owned(),
                source: "recording-manager".to_owned(),
                ts_unix_ms: 1_700_000_000_040,
                observed_at_unix_ms: Some(1_700_000_000_040),
            }],
            Some("unavailable"),
            Some(503),
            None,
        );

        let branch = build_manual_lab_black_screen_branch(
            &timeline,
            &correlation,
            Some(&ManualLabSessionGfxFilterSummary {
                rdpegfx_pdu_count: 1175,
                emitted_surface_update_count: 582,
                ..Default::default()
            }),
            Some(&ManualLabSessionGfxWarningSummary::default()),
            None,
            0,
            None,
        );

        assert_eq!(branch.verdict, ManualLabBlackScreenBranchVerdict::PlayerLoss);
        assert_eq!(branch.confidence, ManualLabEvidenceConfidence::High);
    }

    #[test]
    fn manual_lab_builds_decode_corruption_branch_when_warning_delta_exceeds_baseline() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            vec![
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "recording.connected.first".to_owned(),
                    source: "recording-manager".to_owned(),
                    ts_unix_ms: 1_700_000_000_040,
                    observed_at_unix_ms: Some(1_700_000_000_040),
                },
                ManualLabSessionReadyTraceEvent {
                    schema_version: 1,
                    event: "session.stream.ready.emitted".to_owned(),
                    source: "honeypot".to_owned(),
                    ts_unix_ms: 1_700_000_000_050,
                    observed_at_unix_ms: Some(1_700_000_000_050),
                },
            ],
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_070),
        );
        let baseline = build_manual_lab_gfx_warning_baseline(&[ManualLabSessionGfxWarningSummary {
            wire_to_surface1_update_failed_count: 8,
            wire_to_surface1_decode_skipped_count: 9,
            wire_to_surface2_decode_skipped_count: 10,
            cache_to_surface_unknown_cache_slot_count: 6,
            surface_to_cache_capture_skipped_count: 11,
            ..Default::default()
        }])
        .expect("aligned-ready baseline");

        let branch = build_manual_lab_black_screen_branch(
            &timeline,
            &correlation,
            Some(&ManualLabSessionGfxFilterSummary {
                rdpegfx_pdu_count: 1175,
                emitted_surface_update_count: 582,
                ..Default::default()
            }),
            Some(&ManualLabSessionGfxWarningSummary {
                wire_to_surface1_update_failed_count: 24,
                wire_to_surface1_decode_skipped_count: 25,
                wire_to_surface2_decode_skipped_count: 26,
                cache_to_surface_unknown_cache_slot_count: 22,
                surface_to_cache_capture_skipped_count: 27,
                ..Default::default()
            }),
            Some(&baseline),
            2,
            None,
        );

        assert_eq!(branch.verdict, ManualLabBlackScreenBranchVerdict::DecodeCorruption);
        assert_eq!(branch.confidence, ManualLabEvidenceConfidence::Medium);
        assert!(branch.decode_warning_delta_exceeds_baseline);
    }

    #[test]
    fn manual_lab_xfreerdp_driver_can_enable_rfx_lane() {
        let args = xfreerdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            Some("tls"),
            ManualLabXfreerdpGraphicsMode::Rfx,
        );

        assert!(args.iter().any(|arg| arg == "/gfx:RFX"));
        assert!(!args.iter().any(|arg| arg == "-gfx"));
        assert!(args.iter().any(|arg| arg == "/sec:tls"));
    }

    #[test]
    fn manual_lab_xfreerdp_driver_default_matches_pre_experiment_head() {
        let args = xfreerdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            None,
            ManualLabXfreerdpGraphicsMode::Default,
        );

        assert!(args.iter().any(|arg| arg == "/dynamic-resolution"));
        assert!(!args.iter().any(|arg| arg == "/gfx"));
        assert!(!args.iter().any(|arg| arg == "/gfx:RFX"));
        assert!(!args.iter().any(|arg| arg == "-gfx"));
    }

    #[test]
    fn manual_lab_xfreerdp_driver_can_disable_gfx_entirely() {
        let args = xfreerdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            None,
            ManualLabXfreerdpGraphicsMode::Off,
        );

        assert!(args.iter().any(|arg| arg == "-gfx"));
        assert!(!args.iter().any(|arg| arg == "/gfx"));
        assert!(!args.iter().any(|arg| arg == "/gfx:RFX"));
    }

    #[test]
    fn manual_lab_xfreerdp_driver_can_enable_progressive_gfx() {
        let args = xfreerdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            None,
            ManualLabXfreerdpGraphicsMode::Progressive,
        );

        assert!(args.iter().any(|arg| arg == "/gfx"));
        assert!(args.iter().any(|arg| arg == "+gfx-progressive"));
    }

    #[test]
    fn manual_lab_xfreerdp_graphics_mode_parser_accepts_supported_values() {
        assert_eq!(
            ManualLabXfreerdpGraphicsMode::parse("off").expect("parse off"),
            ManualLabXfreerdpGraphicsMode::Off
        );
        assert_eq!(
            ManualLabXfreerdpGraphicsMode::parse("rfx").expect("parse rfx"),
            ManualLabXfreerdpGraphicsMode::Rfx
        );
        assert_eq!(
            ManualLabXfreerdpGraphicsMode::parse("enabled").expect("parse enabled"),
            ManualLabXfreerdpGraphicsMode::Default
        );
        assert_eq!(
            ManualLabXfreerdpGraphicsMode::parse("progressive").expect("parse progressive"),
            ManualLabXfreerdpGraphicsMode::Progressive
        );
    }

    #[test]
    fn manual_lab_build_session_records_respects_requested_count() {
        let logs_dir = tempdir().expect("tempdir");

        let single = build_session_records(logs_dir.path(), 1);
        let pair = build_session_records(logs_dir.path(), 2);
        let triple = build_session_records(logs_dir.path(), 3);

        assert_eq!(single.len(), 1);
        assert_eq!(pair.len(), 2);
        assert_eq!(triple.len(), 3);
        assert_eq!(single[0].slot, 1);
        assert_eq!(pair[1].slot, 2);
        assert_eq!(triple[2].slot, 3);
    }

    #[test]
    fn manual_lab_association_token_does_not_require_external_recording() {
        let token = association_token("642e76af-caa3-487b-b3ed-8abe864a7bc9", "tcp://127.0.0.1:3391");
        let (_, payload, _) = token
            .split_once('.')
            .and_then(|(head, tail)| {
                tail.rsplit_once('.')
                    .map(|(payload, signature)| (head, payload, signature))
            })
            .expect("manual-lab association token should have three segments");
        let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(payload)
            .expect("decode association token payload");
        let claims: serde_json::Value = serde_json::from_slice(&decoded).expect("parse association token payload");

        assert_eq!(claims.get("jet_rec"), Some(&json!("none")));
    }

    #[test]
    fn manual_lab_bootstrap_discovery_returns_only_sanctioned_bundle_paths() {
        let tempdir = tempdir().expect("create tempdir");
        let target_root = tempdir.path().join("target");
        fs::create_dir_all(target_root.join("run-1/artifacts/bundle")).expect("create bundle dir");
        fs::create_dir_all(target_root.join("run-2/artifacts/live-proof/source-bundle"))
            .expect("create live-proof bundle dir");
        fs::create_dir_all(target_root.join("ignored/artifacts/bundle")).expect("create ignored dir");

        let first = write_test_source_bundle(&target_root.join("run-1/artifacts/bundle"), "first");
        let second = write_test_source_bundle(&target_root.join("run-2/artifacts/live-proof/source-bundle"), "second");
        write_test_source_bundle(&target_root.join("ignored/artifacts/bundle"), "ignored");

        let discovered =
            discover_manual_lab_source_manifest_candidates_in_root(&target_root).expect("discover manifests");
        assert_eq!(discovered, vec![first, second]);
    }

    #[test]
    fn manual_lab_bootstrap_candidate_validation_rejects_missing_base_image() {
        let tempdir = tempdir().expect("create tempdir");
        let bundle_root = tempdir.path().join("bundle");
        let manifest_path = write_test_source_bundle(&bundle_root, "missing-base");
        fs::remove_file(bundle_root.join("tiny11-base.qcow2")).expect("remove base image");

        let candidate = evaluate_manual_lab_source_manifest_candidate(&manifest_path);
        assert!(!candidate.admissible, "{candidate:?}");
        assert!(candidate.detail.contains("base_image_path"), "{candidate:?}");
    }

    fn write_test_source_bundle(bundle_root: &Path, suffix: &str) -> std::path::PathBuf {
        fs::create_dir_all(bundle_root).expect("create bundle root");
        let base_image_path = bundle_root.join("tiny11-base.qcow2");
        let base_image_bytes = format!("tiny11-{suffix}-base-image").into_bytes();
        fs::write(&base_image_path, &base_image_bytes).expect("write base image");
        let base_image_sha256 = sha256_hex(&base_image_bytes);

        let manifest_path = bundle_root.join("bundle-manifest.json");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": "default",
                "vm_name": format!("tiny11-{suffix}-candidate"),
                "attestation_ref": format!("attestation://tiny11-{suffix}-candidate"),
                "base_image_path": "tiny11-base.qcow2",
                "source_iso": {
                    "acquisition_channel": "local-test",
                    "acquisition_date": "2026-03-28",
                    "filename": "windows11-pro-x64-en-us.iso",
                    "size_bytes": 1024,
                    "edition": "Windows 11 Pro x64",
                    "language": "en-US",
                    "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                "transformation": {
                    "timestamp": "2026-03-28T12:00:00Z",
                    "inputs": [
                        {
                            "reference": "tiny11-builder.ps1",
                            "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
                        }
                    ]
                },
                "base_image": {
                    "sha256": base_image_sha256
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize source manifest"),
        )
        .expect("write source manifest");

        manifest_path.canonicalize().expect("canonicalize manifest")
    }

    fn sha256_hex(data: &[u8]) -> String {
        let digest = Sha256::digest(data);
        let mut output = String::with_capacity(digest.len() * 2);
        for byte in digest {
            output.push_str(&format!("{byte:02x}"));
        }
        output
    }
}
