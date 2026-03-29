use std::collections::{BTreeMap, BTreeSet};
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
use honeypot_contracts::events::{EventEnvelope, EventPayload};
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
const HONEYPOT_BS_HYPOTHESIS_ID_ENV: &str = "DGW_HONEYPOT_BS_HYPOTHESIS_ID";
const HONEYPOT_BS_HYPOTHESIS_TEXT_ENV: &str = "DGW_HONEYPOT_BS_HYPOTHESIS_TEXT";
const HONEYPOT_BS_RETRY_CONDITION_ENV: &str = "DGW_HONEYPOT_BS_RETRY_CONDITION";
const HONEYPOT_BS_CONTROL_ARTIFACT_ROOT_ENV: &str = "DGW_HONEYPOT_BS_CONTROL_ARTIFACT_ROOT";
const HONEYPOT_INTEROP_IMAGE_STORE_ENV: &str = "DGW_HONEYPOT_INTEROP_IMAGE_STORE";
const HONEYPOT_INTEROP_MANIFEST_DIR_ENV: &str = "DGW_HONEYPOT_INTEROP_MANIFEST_DIR";
const HONEYPOT_INTEROP_QEMU_BINARY_ENV: &str = "DGW_HONEYPOT_INTEROP_QEMU_BINARY";
const HONEYPOT_INTEROP_KVM_PATH_ENV: &str = "DGW_HONEYPOT_INTEROP_KVM_PATH";
const HONEYPOT_INTEROP_RDP_USERNAME_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_USERNAME";
const HONEYPOT_INTEROP_RDP_PASSWORD_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_PASSWORD";
const HONEYPOT_INTEROP_RDP_DOMAIN_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_DOMAIN";
const HONEYPOT_INTEROP_RDP_SECURITY_ENV: &str = "DGW_HONEYPOT_INTEROP_RDP_SECURITY";
const HONEYPOT_INTEROP_READY_TIMEOUT_SECS_ENV: &str = "DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS";
const HONEYPOT_INTEROP_DRIVER_KIND_ENV: &str = "DGW_HONEYPOT_INTEROP_DRIVER_KIND";
const HONEYPOT_INTEROP_XFREERDP_PATH_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_PATH";
const HONEYPOT_INTEROP_XFREERDP_GFX_MODE_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_GFX_MODE";
const HONEYPOT_INTEROP_XFREERDP_RDPGFX_ENV: &str = "DGW_HONEYPOT_INTEROP_XFREERDP_RDPGFX";
const MANUAL_LAB_IRONRDP_RDPGFX_DRIVER_FLAG: &str = "--rdpgfx";
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

static HONEYPOT_MANUAL_IRONRDP_DRIVER_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path(manual_lab_manifest_path("testsuite/Cargo.toml"))
        .bin("honeypot-manual-irondrdp-driver")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot-manual-irondrdp-driver")
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
    driver_kind: ManualLabDriverKind,
    ironrdp_driver_path: PathBuf,
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
enum ManualLabDriverKind {
    Xfreerdp,
    IronRdpNoGfx,
    IronRdpGfx,
}

impl ManualLabDriverKind {
    fn parse(value: &str) -> anyhow::Result<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "xfreerdp" | "control" => Ok(Self::Xfreerdp),
            "ironrdp" | "ironrdp-no-gfx" | "ironrdp-no-rdpgfx" => Ok(Self::IronRdpNoGfx),
            "ironrdp-gfx" | "ironrdp-rdpgfx" => Ok(Self::IronRdpGfx),
            other => Err(anyhow::anyhow!(
                "unsupported driver kind {other:?}; expected xfreerdp, ironrdp-no-gfx, or ironrdp-gfx"
            )),
        }
    }

    fn kind_name(self) -> &'static str {
        match self {
            Self::Xfreerdp => "xfreerdp",
            Self::IronRdpNoGfx => "ironrdp",
            Self::IronRdpGfx => "ironrdp",
        }
    }

    fn env_name(self) -> &'static str {
        match self {
            Self::Xfreerdp => "xfreerdp",
            Self::IronRdpNoGfx => "ironrdp-no-gfx",
            Self::IronRdpGfx => "ironrdp-gfx",
        }
    }

    fn lane_name(self, xfreerdp_graphics_mode: ManualLabXfreerdpGraphicsMode) -> &'static str {
        match self {
            Self::Xfreerdp => xfreerdp_graphics_mode.lane_name(),
            Self::IronRdpNoGfx => "ironrdp-no-rdpgfx",
            Self::IronRdpGfx => "ironrdp-rdpgfx",
        }
    }

    fn is_control_lane(self, xfreerdp_graphics_mode: ManualLabXfreerdpGraphicsMode) -> bool {
        match self {
            Self::Xfreerdp => xfreerdp_graphics_mode.is_control_lane(),
            Self::IronRdpNoGfx => false,
            Self::IronRdpGfx => false,
        }
    }

    fn requires_display(self) -> bool {
        matches!(self, Self::Xfreerdp)
    }

    fn enforces_single_session_gate(self) -> bool {
        matches!(self, Self::IronRdpNoGfx | Self::IronRdpGfx)
    }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualLabXfreerdpLaneContract {
    pub driver_lane: String,
    pub driver_args: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualLabIronRdpLaneContract {
    pub driver_lane: String,
    pub driver_args: Vec<String>,
}

pub fn render_manual_lab_xfreerdp_lane_contract(
    association_token: &str,
    proxy_tcp_port: u16,
    guest_rdp_port: u16,
    rdp_security: Option<&str>,
    graphics_mode_name: &str,
) -> anyhow::Result<ManualLabXfreerdpLaneContract> {
    let graphics_mode = ManualLabXfreerdpGraphicsMode::parse(graphics_mode_name)
        .with_context(|| format!("parse xfreerdp graphics mode {graphics_mode_name:?}"))?;
    let driver_args = xfreerdp_driver_args(
        association_token,
        proxy_tcp_port,
        guest_rdp_port,
        rdp_security,
        graphics_mode,
    );

    Ok(ManualLabXfreerdpLaneContract {
        driver_lane: graphics_mode.lane_name().to_owned(),
        driver_args,
    })
}

pub fn render_manual_lab_ironrdp_lane_contract(
    session_id: &str,
    proxy_tcp_port: u16,
    guest_rdp_port: u16,
    rdp_security: Option<&str>,
    driver_kind_name: &str,
    rdp_domain: Option<&str>,
) -> anyhow::Result<ManualLabIronRdpLaneContract> {
    let driver_kind = ManualLabDriverKind::parse(driver_kind_name)
        .with_context(|| format!("parse IronRDP driver kind {driver_kind_name:?}"))?;
    let driver_args = match driver_kind {
        ManualLabDriverKind::IronRdpNoGfx | ManualLabDriverKind::IronRdpGfx => ironrdp_driver_args(
            session_id,
            guest_rdp_port,
            proxy_tcp_port,
            rdp_security,
            &rdp_domain.map(ToOwned::to_owned),
            matches!(driver_kind, ManualLabDriverKind::IronRdpGfx),
        ),
        ManualLabDriverKind::Xfreerdp => {
            anyhow::bail!("IronRDP lane contract only supports IronRDP driver kinds")
        }
    };

    Ok(ManualLabIronRdpLaneContract {
        driver_lane: driver_kind.lane_name(ManualLabXfreerdpGraphicsMode::Default).to_owned(),
        driver_args,
    })
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
    pub run_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub clean_state: ManualLabBlackScreenCleanStateEvidence,
    #[serde(default)]
    pub artifacts: ManualLabBlackScreenArtifactPaths,
    #[serde(default)]
    pub teardown_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    #[serde(default)]
    pub hypothesis: ManualLabBlackScreenHypothesisContext,
    #[serde(default)]
    pub session_invocations: Vec<ManualLabSessionDriverEvidence>,
    #[serde(default)]
    pub multi_session_ready_path_summary: ManualLabMultiSessionReadyPathSummary,
    #[serde(default)]
    pub run_verdict_summary: ManualLabBlackScreenRunVerdictSummary,
    #[serde(default)]
    pub do_not_retry_ledger: ManualLabBlackScreenDoNotRetryLedger,
    #[serde(default)]
    pub artifact_contract_summary: ManualLabBlackScreenArtifactContractSummary,
    #[serde(default)]
    pub control_run_comparison_summary: ManualLabBlackScreenControlRunComparisonSummary,
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
    pub player_websocket_summary: ManualLabSessionPlayerWebsocketSummary,
    #[serde(default)]
    pub player_playback_path_summary: ManualLabSessionPlayerPlaybackPathSummary,
    #[serde(default)]
    pub playback_artifact_timeline_summary: ManualLabSessionPlaybackArtifactTimelineSummary,
    #[serde(default)]
    pub recording_visibility_summary: ManualLabSessionRecordingVisibilitySummary,
    #[serde(default)]
    pub browser_visibility_summary: ManualLabSessionBrowserVisibilitySummary,
    #[serde(default)]
    pub artifact_visibility_at_browser_time: ManualLabSessionRecordingVisibilitySummary,
    #[serde(default)]
    pub browser_artifact_correlation_summary: ManualLabSessionBrowserArtifactCorrelationSummary,
    #[serde(default)]
    pub gfx_filter_summary: Option<ManualLabSessionGfxFilterSummary>,
    #[serde(default)]
    pub fastpath_warning_summary: Option<ManualLabSessionFastPathWarningSummary>,
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
pub struct ManualLabSessionPlayerWebsocketSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub open_observed: bool,
    #[serde(default)]
    pub first_message_observed: bool,
    #[serde(default)]
    pub raw_close_observed: bool,
    #[serde(default)]
    pub transformed_close_observed: bool,
    #[serde(default)]
    pub opened_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub first_message_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub closed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub capture_end_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub elapsed_ms_since_open: Option<u64>,
    #[serde(default)]
    pub raw_close_code: Option<u16>,
    #[serde(default)]
    pub raw_close_reason: Option<String>,
    #[serde(default)]
    pub transformed_close_code: Option<u16>,
    #[serde(default)]
    pub transformed_close_reason: Option<String>,
    #[serde(default)]
    pub delivery_kind: Option<String>,
    #[serde(default)]
    pub active_mode_at_close: Option<bool>,
    #[serde(default)]
    pub fallback_started_before_close: Option<bool>,
    #[serde(default)]
    pub no_close_observed_by_teardown: bool,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabPlayerPlaybackModeVerdict {
    ActiveLivePath,
    StaticFallbackDuringActive,
    MissingArtifactProbeWhileActive,
    StaticIntentFromStart,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionPlayerPlaybackPathSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabPlayerPlaybackModeVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub active_intent_observed: bool,
    #[serde(default)]
    pub active_intent_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub static_playback_started_observed: bool,
    #[serde(default)]
    pub static_playback_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_info_fetch_attempted: bool,
    #[serde(default)]
    pub recording_info_fetch_succeeded: bool,
    #[serde(default)]
    pub recording_info_fetch_failed: bool,
    #[serde(default)]
    pub recording_info_fetch_failed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_info_fetch_http_status: Option<u16>,
    #[serde(default)]
    pub missing_artifact_while_active: bool,
    #[serde(default)]
    pub telemetry_gap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabPlaybackArtifactTimelineVerdict {
    CorrelatedReadyPlayback,
    MissingRecordingArtifact,
    StreamFailedBeforeRecording,
    WebsocketAttachedWithoutReady,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionPlaybackArtifactTimelineSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabPlaybackArtifactTimelineVerdict,
    #[serde(default)]
    pub confidence: ManualLabEvidenceConfidence,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub session_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub session_assigned_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub session_stream_ready_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub session_stream_failed_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub websocket_open_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub websocket_first_message_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_first_chunk_appended_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_connected_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub recording_artifact_present: bool,
    #[serde(default)]
    pub recording_artifact_count: u64,
    #[serde(default)]
    pub recording_artifact_max_size_bytes: Option<u64>,
    #[serde(default)]
    pub recording_artifact_latest_modified_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub timeline_gaps: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabRecordingVisibilityVerdict {
    VisibleFrame,
    SparsePixels,
    AllBlack,
    MissingArtifact,
    AnalysisUnavailable,
    AnalysisFailed,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionRecordingVisibilitySummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub confidence: ManualLabEvidenceConfidence,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub analysis_backend: Option<String>,
    #[serde(default)]
    pub recording_path: Option<PathBuf>,
    #[serde(default)]
    pub probe_seek_to_ms: Option<u64>,
    #[serde(default)]
    pub video_duration_ms: Option<u64>,
    #[serde(default)]
    pub ready_state: Option<u8>,
    #[serde(default)]
    pub sample_window_ms: u64,
    #[serde(default)]
    pub sample_interval_ms: u64,
    #[serde(default)]
    pub sampled_frame_count: u64,
    #[serde(default)]
    pub first_visible_offset_ms: Option<u64>,
    #[serde(default)]
    pub first_sparse_offset_ms: Option<u64>,
    #[serde(default)]
    pub max_non_black_ratio_per_mille: Option<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBrowserPlayerMode {
    ActiveLive,
    StaticFallback,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBrowserVisibilityDataStatus {
    Ready,
    NoVideoElement,
    NoDecodableFrame,
    ReadbackError,
    InsufficientSamples,
    Transitional,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionBrowserVisibilityWindowSummary {
    #[serde(default)]
    pub window_index: u32,
    #[serde(default)]
    pub window_phase: String,
    #[serde(default)]
    pub player_mode: ManualLabBrowserPlayerMode,
    #[serde(default)]
    pub data_status: ManualLabBrowserVisibilityDataStatus,
    #[serde(default)]
    pub verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub sample_count: u64,
    #[serde(default)]
    pub valid_sample_count: u64,
    #[serde(default)]
    pub window_start_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub window_end_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub representative_current_time_ms: Option<u64>,
    #[serde(default)]
    pub video_width: Option<u32>,
    #[serde(default)]
    pub video_height: Option<u32>,
    #[serde(default)]
    pub max_non_black_ratio_per_mille: Option<u16>,
    #[serde(default)]
    pub mean_non_black_ratio_per_mille: Option<u16>,
    #[serde(default)]
    pub transition_observed: bool,
    #[serde(default)]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionBrowserVisibilitySummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub confidence: ManualLabEvidenceConfidence,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub dominant_mode: ManualLabBrowserPlayerMode,
    #[serde(default)]
    pub data_status: ManualLabBrowserVisibilityDataStatus,
    #[serde(default)]
    pub representative_current_time_ms: Option<u64>,
    #[serde(default)]
    pub valid_window_count: u64,
    #[serde(default)]
    pub transition_observed: bool,
    #[serde(default)]
    pub max_non_black_ratio_per_mille: Option<u16>,
    #[serde(default)]
    pub windows: Vec<ManualLabSessionBrowserVisibilityWindowSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBrowserArtifactCorrelationVerdict {
    BothVisible,
    BothBlack,
    BrowserBlackArtifactVisible,
    BrowserVisibleArtifactBlack,
    InconclusiveInsufficientData,
    InconclusiveAlignmentGap,
    InconclusiveTransition,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionBrowserArtifactCorrelationSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabBrowserArtifactCorrelationVerdict,
    #[serde(default)]
    pub confidence: ManualLabEvidenceConfidence,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub browser_player_mode: ManualLabBrowserPlayerMode,
    #[serde(default)]
    pub browser_verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub artifact_verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub browser_current_time_ms: Option<u64>,
    #[serde(default)]
    pub artifact_probe_seek_to_ms: Option<u64>,
    #[serde(default)]
    pub browser_data_status: ManualLabBrowserVisibilityDataStatus,
    #[serde(default)]
    pub transition_observed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabReadyPathSustainVerdict {
    SustainedActiveLive,
    MissingReadyAlignment,
    MissingActiveIntent,
    StaticFallbackObserved,
    MissingSteadyActiveWindow,
    TelemetryGap,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionReadyPathSustainSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabReadyPathSustainVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub ready_verdict: ManualLabPlaybackReadyVerdict,
    #[serde(default)]
    pub player_path_verdict: ManualLabPlayerPlaybackModeVerdict,
    #[serde(default)]
    pub dominant_mode: ManualLabBrowserPlayerMode,
    #[serde(default)]
    pub steady_window_observed: bool,
    #[serde(default)]
    pub steady_window_index: Option<u32>,
    #[serde(default)]
    pub steady_window_current_time_ms: Option<u64>,
    #[serde(default)]
    pub static_fallback_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub telemetry_gap: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabMultiSessionReadyPathVerdict {
    AllSlotsAccounted,
    MissingSlotEvidence,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabMultiSessionReadyPathSlotReason {
    UsableLivePlayback,
    MissingReadyAlignment,
    MissingActiveIntent,
    StaticFallbackObserved,
    MissingSteadyActiveWindow,
    TelemetryGap,
    MissingSlotEvidence,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabMultiSessionReadyPathSlotSummary {
    #[serde(default)]
    pub slot: usize,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub reason: ManualLabMultiSessionReadyPathSlotReason,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub ready_path_sustain_summary: ManualLabSessionReadyPathSustainSummary,
    #[serde(default)]
    pub black_screen_branch_verdict: ManualLabBlackScreenBranchVerdict,
    #[serde(default)]
    pub browser_visibility_verdict: ManualLabRecordingVisibilityVerdict,
    #[serde(default)]
    pub artifact_visibility_verdict: ManualLabRecordingVisibilityVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabMultiSessionReadyPathSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabMultiSessionReadyPathVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub expected_slot_count: usize,
    #[serde(default)]
    pub observed_session_count: usize,
    #[serde(default)]
    pub slot_summaries: Vec<ManualLabMultiSessionReadyPathSlotSummary>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenRunVerdict {
    UsablePlayback,
    ProducerReadyButCorruptionUnresolved,
    #[default]
    ContractViolationOrMissingProof,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenRunReason {
    AllSlotsUsablePlayback,
    ProducerReadyCorruptionUnresolved,
    MissingSlotEvidence,
    DuplicateSlotEvidence,
    MissingReadyAlignment,
    MissingActiveIntent,
    StaticFallbackObserved,
    MissingSteadyActiveWindow,
    TelemetryGap,
    BrowserArtifactAlignmentGap,
    BrowserArtifactInsufficientEvidence,
    BrowserArtifactBothBlack,
    BrowserArtifactContradiction,
    DecodeCorruption,
    NoReadyTruthfulness,
    ContradictorySignal,
    #[default]
    InsufficientEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenRunSlotSummary {
    #[serde(default)]
    pub slot: usize,
    #[serde(default)]
    pub session_id: String,
    #[serde(default)]
    pub ready_path_reason: ManualLabMultiSessionReadyPathSlotReason,
    #[serde(default)]
    pub browser_artifact_correlation_verdict: ManualLabBrowserArtifactCorrelationVerdict,
    #[serde(default)]
    pub black_screen_branch_verdict: ManualLabBlackScreenBranchVerdict,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenRunVerdictSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabBlackScreenRunVerdict,
    #[serde(default)]
    pub primary_reason: ManualLabBlackScreenRunReason,
    #[serde(default)]
    pub reason_codes: Vec<ManualLabBlackScreenRunReason>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub expected_slot_count: usize,
    #[serde(default)]
    pub observed_session_count: usize,
    #[serde(default)]
    pub slot_summaries: Vec<ManualLabBlackScreenRunSlotSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenHypothesisContext {
    #[serde(default)]
    pub hypothesis_id: String,
    #[serde(default)]
    pub hypothesis_text: String,
    #[serde(default)]
    pub retry_condition_text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenRetryCondition {
    NewCode,
    NewInputs,
    NewInstrumentation,
    NewSameDayControlRun,
    #[default]
    Unspecified,
}

impl ManualLabBlackScreenRetryCondition {
    fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "new_code" => Some(Self::NewCode),
            "new_inputs" => Some(Self::NewInputs),
            "new_instrumentation" => Some(Self::NewInstrumentation),
            "new_same_day_control_run" | "new_control_run_same_contract" => Some(Self::NewSameDayControlRun),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenDoNotRetryLedgerVerdict {
    NotRequired,
    EntryRecorded,
    MissingHypothesisId,
    MissingHypothesisText,
    MissingRetryCondition,
    InvalidRetryCondition,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenDoNotRetryLedgerEntry {
    #[serde(default)]
    pub hypothesis_id: String,
    #[serde(default)]
    pub hypothesis_text: String,
    #[serde(default)]
    pub bs_rows: Vec<String>,
    #[serde(default)]
    pub git_rev: String,
    #[serde(default)]
    pub failing_lane: String,
    #[serde(default)]
    pub artifact_root: PathBuf,
    #[serde(default)]
    pub run_verdict: ManualLabBlackScreenRunVerdict,
    #[serde(default)]
    pub rejection_reason_code: ManualLabBlackScreenRunReason,
    #[serde(default)]
    pub retry_condition: ManualLabBlackScreenRetryCondition,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenDoNotRetryLedger {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabBlackScreenDoNotRetryLedgerVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub entries: Vec<ManualLabBlackScreenDoNotRetryLedgerEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenArtifactContractSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub contract_id: String,
    #[serde(default)]
    pub bs_rows: Vec<String>,
    #[serde(default)]
    pub expected_slot_count: usize,
    #[serde(default)]
    pub expected_slots: Vec<usize>,
    #[serde(default)]
    pub multi_session_ready_path_schema_version: u32,
    #[serde(default)]
    pub run_verdict_schema_version: u32,
    #[serde(default)]
    pub do_not_retry_schema_version: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ManualLabBlackScreenControlRunComparisonVerdict {
    NotRequiredForControlLane,
    MeaningfulWithSameDayControl,
    MissingCurrentRunTimestamp,
    MissingControlArtifactRoot,
    MissingControlEvidence,
    InvalidControlEvidence,
    ControlRunNotControlLane,
    ControlRunMissingTimestamp,
    ControlRunMissingVerdict,
    StaleControlRun,
    ArtifactContractMismatch,
    #[default]
    Inconclusive,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabBlackScreenControlRunComparisonSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub verdict: ManualLabBlackScreenControlRunComparisonVerdict,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub control_artifact_root: Option<PathBuf>,
    #[serde(default)]
    pub control_evidence_path: Option<PathBuf>,
    #[serde(default)]
    pub control_run_started_at_unix_ms: Option<u64>,
    #[serde(default)]
    pub control_run_verdict: Option<ManualLabBlackScreenRunVerdict>,
    #[serde(default)]
    pub control_run_primary_reason: Option<ManualLabBlackScreenRunReason>,
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
pub enum ManualLabFastPathWarningEvidence {
    #[default]
    Uncertain,
    KnownNoise,
    CandidateRootCause,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ManualLabSessionFastPathWarningSummary {
    #[serde(default)]
    pub schema_version: u32,
    #[serde(default)]
    pub total_warning_count: u64,
    #[serde(default)]
    pub with_session_id_count: u64,
    #[serde(default)]
    pub without_session_id_count: u64,
    #[serde(default)]
    pub process_server_frame_error_count: u64,
    #[serde(default)]
    pub invalid_rdp_frame_prefix_count: u64,
    #[serde(default)]
    pub before_source_ready_count: u64,
    #[serde(default)]
    pub after_source_ready_count: u64,
    #[serde(default)]
    pub before_stream_ready_count: u64,
    #[serde(default)]
    pub after_stream_ready_count: u64,
    #[serde(default)]
    pub known_noise_count: u64,
    #[serde(default)]
    pub candidate_root_cause_count: u64,
    #[serde(default)]
    pub uncertain_count: u64,
    #[serde(default)]
    pub known_noise_warn_codes: Vec<String>,
    #[serde(default)]
    pub candidate_root_cause_warn_codes: Vec<String>,
    #[serde(default)]
    pub uncertain_warn_codes: Vec<String>,
    #[serde(default)]
    pub overall_evidence: ManualLabFastPathWarningEvidence,
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
    ensure!(
        !interop.driver_kind.enforces_single_session_gate() || session_count == 1,
        "{} currently supports exactly one manual-lab session; rerun with {MANUAL_LAB_SESSION_COUNT_ENV}=1",
        interop.driver_kind.lane_name(interop.xfreerdp_graphics_mode)
    );

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
    let created_at_unix_secs = now_unix_secs();
    let mut state = ManualLabState {
        schema_version: MANUAL_LAB_SCHEMA_VERSION,
        run_id,
        created_at_unix_secs,
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
        black_screen_evidence: build_black_screen_evidence(
            &interop,
            &layout.run_root,
            session_count,
            created_at_unix_secs
                .checked_mul(1000)
                .expect("manual-lab start timestamp should fit in milliseconds"),
        ),
    };
    state.black_screen_evidence.clean_state = clean_state;
    persist_active_state(&state)?;

    let result = (|| -> anyhow::Result<ManualLabState> {
        if interop.driver_kind.requires_display() {
            let driver_display = resolve_driver_display(&layout.logs_dir)?;
            state.driver_display = driver_display.value.clone();
            if let Some(xvfb) = driver_display.xvfb {
                state.xvfb_pid = Some(xvfb.pid);
                state.xvfb_stdout_log = Some(xvfb.stdout_log);
                state.xvfb_stderr_log = Some(xvfb.stderr_log);
            }
            persist_active_state(&state)?;
        }

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
            let driver_args = manual_lab_driver_args(
                &state.sessions[index].session_id,
                state.sessions[index].expected_guest_rdp_port,
                state.ports.proxy_tcp,
                &interop,
            );
            state.sessions[index].driver_binary = Some(manual_lab_driver_binary(&interop).to_path_buf());
            state.sessions[index].driver_args = driver_args.clone();
            state.sessions[index].driver_lane =
                Some(interop.driver_kind.lane_name(interop.xfreerdp_graphics_mode).to_owned());
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=session.driver.spawn run_id={} slot={} session_id={}",
                state.run_id, state.sessions[index].slot, state.sessions[index].session_id
            );
            let driver = {
                let session = &state.sessions[index];
                spawn_manual_lab_driver(session, &interop, &state, &driver_args)?
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
            notes.push(format!("driver pid {pid}: {error:#}"));
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

fn manual_lab_driver_binary(interop: &ManualLabInteropConfig) -> &Path {
    match interop.driver_kind {
        ManualLabDriverKind::Xfreerdp => &interop.xfreerdp_path,
        ManualLabDriverKind::IronRdpNoGfx | ManualLabDriverKind::IronRdpGfx => &interop.ironrdp_driver_path,
    }
}

fn spawn_manual_lab_driver(
    session: &ManualLabSessionRecord,
    interop: &ManualLabInteropConfig,
    state: &ManualLabState,
    driver_args: &[String],
) -> anyhow::Result<SpawnedProcess> {
    match interop.driver_kind {
        ManualLabDriverKind::Xfreerdp => spawn_logged_process_with_display(
            &interop.xfreerdp_path,
            driver_args,
            &[],
            &state.driver_display,
            session.stdout_log.clone(),
            session.stderr_log.clone(),
        )
        .with_context(|| format!("spawn xfreerdp driver for session {}", session.session_id)),
        ManualLabDriverKind::IronRdpNoGfx | ManualLabDriverKind::IronRdpGfx => spawn_logged_process(
            &interop.ironrdp_driver_path,
            &driver_args.iter().map(OsString::from).collect::<Vec<_>>(),
            &[],
            session.stdout_log.clone(),
            session.stderr_log.clone(),
        )
        .with_context(|| format!("spawn ironrdp driver for session {}", session.session_id)),
    }
}

fn manual_lab_driver_args(
    session_id: &str,
    expected_guest_rdp_port: u16,
    proxy_tcp_port: u16,
    interop: &ManualLabInteropConfig,
) -> Vec<String> {
    match interop.driver_kind {
        ManualLabDriverKind::Xfreerdp => xfreerdp_driver_args(
            session_id,
            expected_guest_rdp_port,
            proxy_tcp_port,
            interop.rdp_security.as_deref(),
            interop.xfreerdp_graphics_mode,
        ),
        ManualLabDriverKind::IronRdpNoGfx | ManualLabDriverKind::IronRdpGfx => ironrdp_driver_args(
            session_id,
            expected_guest_rdp_port,
            proxy_tcp_port,
            interop.rdp_security.as_deref(),
            &interop.rdp_domain,
            matches!(interop.driver_kind, ManualLabDriverKind::IronRdpGfx),
        ),
    }
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

fn ironrdp_driver_args(
    session_id: &str,
    expected_guest_rdp_port: u16,
    proxy_tcp_port: u16,
    rdp_security: Option<&str>,
    rdp_domain: &Option<String>,
    enable_rdpgfx: bool,
) -> Vec<String> {
    let association_token = association_token(session_id, &format!("127.0.0.1:{expected_guest_rdp_port}"));
    let mut args = vec![
        "--host".to_owned(),
        "127.0.0.1".to_owned(),
        "--proxy-port".to_owned(),
        proxy_tcp_port.to_string(),
        "--username".to_owned(),
        MANUAL_LAB_DRIVER_PROXY_USERNAME.to_owned(),
        "--password".to_owned(),
        MANUAL_LAB_DRIVER_PROXY_PASSWORD.to_owned(),
        "--association-token".to_owned(),
        association_token,
        "--session-id".to_owned(),
        session_id.to_owned(),
        "--lifetime-secs".to_owned(),
        "300".to_owned(),
    ];

    if enable_rdpgfx {
        args.push(MANUAL_LAB_IRONRDP_RDPGFX_DRIVER_FLAG.to_owned());
    }

    if let Some(domain) = rdp_domain {
        args.push("--domain".to_owned());
        args.push(domain.clone());
    }

    if let Some(security) = rdp_security {
        args.push("--security".to_owned());
        args.push(security.to_owned());
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
        driver_kind: manual_lab_driver_kind_from_env()?,
        ironrdp_driver_path: paths.ironrdp_driver_path.clone(),
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

fn manual_lab_driver_kind_from_env() -> anyhow::Result<ManualLabDriverKind> {
    let Some(value) = optional_env_string(HONEYPOT_INTEROP_DRIVER_KIND_ENV) else {
        return Ok(ManualLabDriverKind::Xfreerdp);
    };

    ManualLabDriverKind::parse(&value).with_context(|| format!("parse {HONEYPOT_INTEROP_DRIVER_KIND_ENV}"))
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
    driver_kind: ManualLabDriverKind,
    ironrdp_driver_path: PathBuf,
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
    let driver_kind = manual_lab_driver_kind_from_env().unwrap_or(ManualLabDriverKind::Xfreerdp);
    let ironrdp_driver_path = HONEYPOT_MANUAL_IRONRDP_DRIVER_BIN_PATH.clone();
    let xfreerdp_path =
        optional_env_path(HONEYPOT_INTEROP_XFREERDP_PATH_ENV).unwrap_or_else(|| PathBuf::from("xfreerdp"));

    ManualLabInteropPaths {
        image_store,
        manifest_dir,
        web_player_root,
        qemu_binary_path,
        kvm_path,
        driver_kind,
        ironrdp_driver_path,
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
    let driver_runtime_input = match paths.driver_kind {
        ManualLabDriverKind::Xfreerdp => Tiny11LabRuntimeInput::existing_command(
            format!(
                "{HONEYPOT_INTEROP_XFREERDP_PATH_ENV} ({})",
                paths.xfreerdp_path.display()
            ),
            paths.xfreerdp_path.clone(),
        ),
        ManualLabDriverKind::IronRdpNoGfx | ManualLabDriverKind::IronRdpGfx => Tiny11LabRuntimeInput::existing_path(
            format!(
                "{HONEYPOT_INTEROP_DRIVER_KIND_ENV}={} ({})",
                paths.driver_kind.kind_name(),
                paths.ironrdp_driver_path.display()
            ),
            paths.ironrdp_driver_path.clone(),
        ),
    };

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
            driver_runtime_input,
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

fn parse_transfer_encoding_chunked(headers: &str) -> bool {
    headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.trim().eq_ignore_ascii_case("transfer-encoding") && value.to_ascii_lowercase().contains("chunked")
        })
    })
}

fn find_crlf_offset(buffer: &[u8], start: usize) -> Option<usize> {
    buffer[start..]
        .windows(2)
        .position(|window| window == b"\r\n")
        .map(|offset| start + offset)
}

fn decode_chunked_http_body(body: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoded = Vec::new();
    let mut cursor = 0usize;

    while cursor < body.len() {
        let Some(line_end) = find_crlf_offset(body, cursor) else {
            break;
        };
        let size_line = std::str::from_utf8(&body[cursor..line_end]).context("decode HTTP chunk size line")?;
        let size_token = size_line.split(';').next().unwrap_or_default().trim();
        if size_token.is_empty() {
            break;
        }
        let chunk_size =
            usize::from_str_radix(size_token, 16).with_context(|| format!("parse HTTP chunk size {size_token}"))?;
        cursor = line_end + 2;

        if chunk_size == 0 {
            break;
        }

        if cursor + chunk_size > body.len() {
            break;
        }

        decoded.extend_from_slice(&body[cursor..cursor + chunk_size]);
        cursor += chunk_size;

        if cursor + 2 > body.len() || &body[cursor..cursor + 2] != b"\r\n" {
            break;
        }
        cursor += 2;
    }

    Ok(decoded)
}

fn send_http_request_stream_snapshot(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(String, String)],
    body: Option<&[u8]>,
    idle_timeout: Duration,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut stream =
        TcpStream::connect((Ipv4Addr::LOCALHOST, port)).with_context(|| format!("connect to 127.0.0.1:{port}"))?;
    stream
        .set_read_timeout(Some(idle_timeout))
        .context("set streaming HTTP read timeout")?;
    stream
        .set_write_timeout(Some(MANUAL_LAB_HTTP_TIMEOUT))
        .context("set streaming HTTP write timeout")?;

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
        .with_context(|| format!("write streaming HTTP request to {path} on port {port}"))?;
    if let Some(body) = body {
        stream
            .write_all(body)
            .with_context(|| format!("write streaming HTTP request body to {path} on port {port}"))?;
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
                        std::str::from_utf8(&response[..found_header_end]).context("decode streaming HTTP headers")?;
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
                if header_end.is_some() {
                    break;
                }
                return Err(error)
                    .with_context(|| format!("read streaming HTTP response headers from {path} on port {port}"));
            }
            Err(error) => {
                return Err(error).with_context(|| format!("read streaming HTTP response from {path} on port {port}"));
            }
        }
    }

    let header_end = header_end.context("split streaming HTTP response headers and body")?;
    let headers = std::str::from_utf8(&response[..header_end]).context("decode streaming HTTP response headers")?;
    let status_line = headers
        .lines()
        .next()
        .context("extract streaming HTTP status line")?
        .to_owned();
    let body_start = header_end + 4;
    let raw_body = match content_length {
        Some(expected_body_len) if response.len() >= body_start + expected_body_len => {
            response[body_start..(body_start + expected_body_len)].to_vec()
        }
        Some(_) | None => response[body_start..].to_vec(),
    };
    let body = if parse_transfer_encoding_chunked(headers) {
        decode_chunked_http_body(&raw_body)?
    } else {
        raw_body
    };

    Ok((status_line, body))
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

fn build_black_screen_hypothesis_context_from_env() -> ManualLabBlackScreenHypothesisContext {
    ManualLabBlackScreenHypothesisContext {
        hypothesis_id: optional_env_string(HONEYPOT_BS_HYPOTHESIS_ID_ENV).unwrap_or_default(),
        hypothesis_text: optional_env_string(HONEYPOT_BS_HYPOTHESIS_TEXT_ENV).unwrap_or_default(),
        retry_condition_text: optional_env_string(HONEYPOT_BS_RETRY_CONDITION_ENV).unwrap_or_default(),
    }
}

fn build_black_screen_control_artifact_root_from_env(env: &BTreeMap<String, String>) -> Option<PathBuf> {
    env.get(HONEYPOT_BS_CONTROL_ARTIFACT_ROOT_ENV)
        .map(PathBuf::from)
        .filter(|path| !path.as_os_str().is_empty())
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
        HONEYPOT_BS_HYPOTHESIS_ID_ENV,
        HONEYPOT_BS_HYPOTHESIS_TEXT_ENV,
        HONEYPOT_BS_RETRY_CONDITION_ENV,
        HONEYPOT_BS_CONTROL_ARTIFACT_ROOT_ENV,
        MANUAL_LAB_SELECTED_SOURCE_MANIFEST_ENV,
        HONEYPOT_INTEROP_DRIVER_KIND_ENV,
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
    run_started_at_unix_ms: u64,
) -> ManualLabBlackScreenEvidence {
    let mut env = collect_black_screen_env_snapshot();
    env.entry(HONEYPOT_INTEROP_DRIVER_KIND_ENV.to_owned())
        .or_insert_with(|| interop.driver_kind.env_name().to_owned());

    ManualLabBlackScreenEvidence {
        git_rev: detect_git_rev(),
        bs_rows: parse_bs_rows_from_env(),
        driver_kind: interop.driver_kind.kind_name().to_owned(),
        driver_lane: interop.driver_kind.lane_name(interop.xfreerdp_graphics_mode).to_owned(),
        driver_binary: manual_lab_driver_binary(interop).to_path_buf(),
        driver_version: probe_command_version(manual_lab_driver_binary(interop), &["--version", "/version"]),
        session_count,
        artifact_root: run_root.to_path_buf(),
        is_control_lane: interop.driver_kind.is_control_lane(interop.xfreerdp_graphics_mode),
        run_started_at_unix_ms: Some(run_started_at_unix_ms),
        clean_state: ManualLabBlackScreenCleanStateEvidence::default(),
        artifacts: ManualLabBlackScreenArtifactPaths::default(),
        teardown_started_at_unix_ms: None,
        env,
        hypothesis: build_black_screen_hypothesis_context_from_env(),
        session_invocations: Vec::new(),
        multi_session_ready_path_summary: ManualLabMultiSessionReadyPathSummary::default(),
        run_verdict_summary: ManualLabBlackScreenRunVerdictSummary::default(),
        do_not_retry_ledger: ManualLabBlackScreenDoNotRetryLedger::default(),
        artifact_contract_summary: ManualLabBlackScreenArtifactContractSummary::default(),
        control_run_comparison_summary: ManualLabBlackScreenControlRunComparisonSummary::default(),
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
const MANUAL_LAB_FASTPATH_WARNING_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_PLAYER_WEBSOCKET_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_PLAYER_PLAYBACK_PATH_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_PLAYBACK_ARTIFACT_TIMELINE_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_RECORDING_VISIBILITY_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BROWSER_VISIBILITY_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BROWSER_ARTIFACT_CORRELATION_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_READY_PATH_SUSTAIN_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_MULTI_SESSION_READY_PATH_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BLACK_SCREEN_RUN_VERDICT_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BLACK_SCREEN_DO_NOT_RETRY_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BLACK_SCREEN_ARTIFACT_CONTRACT_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BLACK_SCREEN_CONTROL_COMPARISON_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_BLACK_SCREEN_ARTIFACT_CONTRACT_ID: &str = "manual-lab-black-screen";
const MANUAL_LAB_BLACK_SCREEN_EVIDENCE_RELATIVE_PATH: &str = "artifacts/black-screen-evidence.json";
const MANUAL_LAB_RECORDING_VISIBILITY_SUMMARY_FILENAME: &str = "recording-visibility-summary.json";
const MANUAL_LAB_RECORDING_VISIBILITY_AT_BROWSER_TIME_SUMMARY_FILENAME: &str =
    "recording-visibility-at-browser-time-summary.json";
const MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_WINDOW_MS: u64 = 8_000;
const MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_INTERVAL_MS: u64 = 250;
const MANUAL_LAB_RECORDING_VISIBILITY_VIRTUAL_TIME_BUDGET_MS: u64 = 14_000;
const MANUAL_LAB_RECORDING_VISIBILITY_VISIBLE_THRESHOLD_PER_MILLE: u16 = 10;
const MANUAL_LAB_RECORDING_VISIBILITY_SPARSE_THRESHOLD_PER_MILLE: u16 = 1;

const MANUAL_LAB_RECORDING_VISIBILITY_PROBE_TEMPLATE: &str = r#"<!doctype html>
<meta charset="utf-8">
<body>
<pre id="out">starting</pre>
<video id="v" muted playsinline autoplay></video>
<canvas id="c" width="64" height="36" style="display:none"></canvas>
<script>
(async () => {
  const out = document.getElementById("out");
  const video = document.getElementById("v");
  const canvas = document.getElementById("c");
  const ctx = canvas.getContext("2d", { willReadFrequently: true });
  const src = __SOURCE_FILE_URL__;
  const maxMs = __MAX_MS__;
  const intervalMs = __INTERVAL_MS__;
  const seekToMs = __SEEK_TO_MS__;
  const visibleThreshold = __VISIBLE_THRESHOLD__;
  const sparseThreshold = __SPARSE_THRESHOLD__;
  const samples = [];
  let firstVisibleAt = null;
  let firstSparseAt = null;

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  async function waitForEvent(target, eventName, timeoutMs) {
    await Promise.race([
      new Promise((resolve) => target.addEventListener(eventName, resolve, { once: true })),
      sleep(timeoutMs),
    ]);
  }

  function sample() {
    if (video.readyState < 2) {
      return;
    }

    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const data = ctx.getImageData(0, 0, canvas.width, canvas.height).data;
    let nonBlack = 0;
    for (let i = 0; i < data.length; i += 4) {
      if (data[i] > 8 || data[i + 1] > 8 || data[i + 2] > 8) {
        nonBlack++;
      }
    }

    const ratio = nonBlack / (data.length / 4);
    samples.push({ t: video.currentTime, ratio });

    if (firstVisibleAt === null && ratio > visibleThreshold) {
      firstVisibleAt = video.currentTime;
    }

    if (firstSparseAt === null && ratio > sparseThreshold) {
      firstSparseAt = video.currentTime;
    }
  }

  video.src = src;
  video.autoplay = true;
  video.muted = true;

  try {
    await video.play();
  } catch (_error) {}

  await waitForEvent(video, "loadedmetadata", 2000);

  if (seekToMs !== null && Number.isFinite(seekToMs)) {
    const seekSeconds = Math.max(0, seekToMs / 1000);
    const clampedSeekSeconds =
      Number.isFinite(video.duration) && video.duration > 0
        ? Math.min(seekSeconds, Math.max(video.duration - 0.05, 0))
        : seekSeconds;

    try {
      video.currentTime = clampedSeekSeconds;
    } catch (_error) {}

    await sleep(500);
  }

  const handle = setInterval(sample, intervalMs);

  setTimeout(() => {
    clearInterval(handle);

    try {
      sample();
    } catch (_error) {}

    const maxRatio = samples.reduce((max, sample) => Math.max(max, sample.ratio), 0);
    out.textContent = JSON.stringify({
      readyState: video.readyState,
      duration: video.duration,
      sampled: samples.length,
      maxRatio,
      firstVisibleAt,
      firstSparseAt,
      verdict: firstVisibleAt !== null ? "visible" : (firstSparseAt !== null ? "sparse" : "black")
    });
  }, maxMs);
})();
</script>
"#;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManualLabFastPathWarningEvent {
    session_id: Option<String>,
    warn_code: String,
    observed_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
struct ManualLabPlayerWebsocketEvent {
    #[serde(default)]
    schema_version: u32,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    observed_at_unix_ms: u64,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    websocket_url: Option<String>,
    #[serde(default)]
    request_url: Option<String>,
    #[serde(default)]
    http_status: Option<u16>,
    #[serde(default)]
    opened_at_unix_ms: Option<u64>,
    #[serde(default)]
    first_message_at_unix_ms: Option<u64>,
    #[serde(default)]
    closed_at_unix_ms: Option<u64>,
    #[serde(default)]
    elapsed_ms_since_open: Option<u64>,
    #[serde(default)]
    raw_close_code: Option<u16>,
    #[serde(default)]
    raw_close_reason: Option<String>,
    #[serde(default)]
    transformed_close_code: Option<u16>,
    #[serde(default)]
    transformed_close_reason: Option<String>,
    #[serde(default)]
    delivery_kind: Option<String>,
    #[serde(default)]
    active_mode: Option<bool>,
    #[serde(default)]
    fallback_started: Option<bool>,
    #[serde(default)]
    was_clean: Option<bool>,
    #[serde(default)]
    player_mode: Option<String>,
    #[serde(default)]
    window_index: Option<u32>,
    #[serde(default)]
    window_phase: Option<String>,
    #[serde(default)]
    window_start_at_unix_ms: Option<u64>,
    #[serde(default)]
    window_end_at_unix_ms: Option<u64>,
    #[serde(default)]
    sample_count: Option<u64>,
    #[serde(default)]
    valid_sample_count: Option<u64>,
    #[serde(default)]
    sample_status: Option<String>,
    #[serde(default)]
    visibility_verdict: Option<String>,
    #[serde(default)]
    representative_current_time_ms: Option<u64>,
    #[serde(default)]
    video_width: Option<u32>,
    #[serde(default)]
    video_height: Option<u32>,
    #[serde(default)]
    max_non_black_ratio_per_mille: Option<u16>,
    #[serde(default)]
    mean_non_black_ratio_per_mille: Option<u16>,
    #[serde(default)]
    transition_observed: Option<bool>,
    #[serde(default)]
    detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManualLabRecordingArtifactSample {
    path: PathBuf,
    size_bytes: u64,
    modified_at_unix_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ManualLabRecordingVisibilityProbePayload {
    #[serde(default)]
    ready_state: Option<u8>,
    #[serde(default)]
    duration: Option<f64>,
    #[serde(default)]
    sampled: u64,
    #[serde(default)]
    max_ratio: Option<f64>,
    #[serde(default)]
    first_visible_at: Option<f64>,
    #[serde(default)]
    first_sparse_at: Option<f64>,
    #[serde(default)]
    verdict: Option<String>,
    #[serde(default)]
    timeout: bool,
    #[serde(default)]
    error: Option<String>,
}

fn render_manual_lab_recording_visibility_probe_html(
    recording_file_url: &str,
    seek_to_ms: Option<u64>,
) -> anyhow::Result<String> {
    let source_file_url =
        serde_json::to_string(recording_file_url).context("serialize recording visibility file URL")?;
    let seek_to_ms = serde_json::to_string(&seek_to_ms).context("serialize recording visibility seek offset")?;
    Ok(MANUAL_LAB_RECORDING_VISIBILITY_PROBE_TEMPLATE
        .replace("__SOURCE_FILE_URL__", &source_file_url)
        .replace(
            "__MAX_MS__",
            &MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_WINDOW_MS.to_string(),
        )
        .replace(
            "__INTERVAL_MS__",
            &MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_INTERVAL_MS.to_string(),
        )
        .replace("__SEEK_TO_MS__", &seek_to_ms)
        .replace(
            "__VISIBLE_THRESHOLD__",
            &format!(
                "{:.6}",
                f64::from(MANUAL_LAB_RECORDING_VISIBILITY_VISIBLE_THRESHOLD_PER_MILLE) / 1000.0
            ),
        )
        .replace(
            "__SPARSE_THRESHOLD__",
            &format!(
                "{:.6}",
                f64::from(MANUAL_LAB_RECORDING_VISIBILITY_SPARSE_THRESHOLD_PER_MILLE) / 1000.0
            ),
        ))
}

fn extract_manual_lab_recording_visibility_probe_json(dom: &str) -> anyhow::Result<&str> {
    let marker = r#"<pre id="out">"#;
    let start = dom
        .find(marker)
        .map(|index| index + marker.len())
        .context("find recording visibility probe output marker")?;
    let end = dom[start..]
        .find("</pre>")
        .map(|index| start + index)
        .context("find recording visibility probe closing tag")?;
    Ok(dom[start..end].trim())
}

pub fn parse_manual_lab_recording_visibility_probe_result_from_dom(dom: &str) -> anyhow::Result<Value> {
    let json = extract_manual_lab_recording_visibility_probe_json(dom)?;
    serde_json::from_str(json).context("parse recording visibility probe JSON")
}

fn parse_manual_lab_recording_visibility_probe_payload(
    dom: &str,
) -> anyhow::Result<ManualLabRecordingVisibilityProbePayload> {
    let json = extract_manual_lab_recording_visibility_probe_json(dom)?;
    serde_json::from_str(json).context("parse recording visibility probe payload")
}

fn manual_lab_local_file_url(path: &Path) -> anyhow::Result<String> {
    let absolute = path
        .canonicalize()
        .with_context(|| format!("canonicalize {}", path.display()))?;
    Ok(format!("file://{}", absolute.display()))
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn manual_lab_recording_visibility_ratio_to_per_mille(ratio: Option<f64>) -> Option<u16> {
    let ratio = ratio?;
    if !ratio.is_finite() || ratio.is_sign_negative() {
        return None;
    }

    let per_mille = (ratio * 1000.0).round().clamp(0.0, 1000.0);
    Some(per_mille as u16)
}

#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
fn manual_lab_recording_visibility_seconds_to_ms(seconds: Option<f64>) -> Option<u64> {
    let seconds = seconds?;
    if !seconds.is_finite() || seconds.is_sign_negative() {
        return None;
    }

    Some((seconds * 1000.0).round() as u64)
}

fn write_manual_lab_recording_visibility_summary_artifact(
    output_path: &Path,
    summary: &ManualLabSessionRecordingVisibilitySummary,
) -> anyhow::Result<()> {
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    fs::write(
        output_path,
        serde_json::to_vec_pretty(summary).context("serialize recording visibility summary")?,
    )
    .with_context(|| format!("write {}", output_path.display()))
}

fn run_manual_lab_recording_visibility_probe(
    chrome_binary: &Path,
    session_root: &Path,
    recording_artifact_path: &Path,
    seek_to_ms: Option<u64>,
) -> anyhow::Result<ManualLabRecordingVisibilityProbePayload> {
    let probe_page_path = session_root.join("recording-visibility-probe.html");
    let probe_dom_path = session_root.join("recording-visibility-probe.dom.html");
    let profile_dir = session_root.join("recording-visibility-chrome-profile");
    if profile_dir.exists() {
        fs::remove_dir_all(&profile_dir).with_context(|| format!("remove {}", profile_dir.display()))?;
    }
    fs::create_dir_all(&profile_dir).with_context(|| format!("create {}", profile_dir.display()))?;

    let recording_file_url = manual_lab_local_file_url(recording_artifact_path)?;
    let probe_page = render_manual_lab_recording_visibility_probe_html(&recording_file_url, seek_to_ms)?;
    fs::write(&probe_page_path, probe_page).with_context(|| format!("write {}", probe_page_path.display()))?;

    let probe_page_url = manual_lab_local_file_url(&probe_page_path)?;
    let output = Command::new(chrome_binary)
        .args([
            OsString::from("--headless=new"),
            OsString::from("--disable-gpu"),
            OsString::from("--allow-file-access-from-files"),
            OsString::from("--autoplay-policy=no-user-gesture-required"),
            OsString::from("--mute-audio"),
            OsString::from("--no-first-run"),
            OsString::from("--no-default-browser-check"),
            OsString::from(format!(
                "--virtual-time-budget={}",
                MANUAL_LAB_RECORDING_VISIBILITY_VIRTUAL_TIME_BUDGET_MS
            )),
            OsString::from(format!("--user-data-dir={}", profile_dir.display())),
            OsString::from("--dump-dom"),
            OsString::from(probe_page_url),
        ])
        .output()
        .with_context(|| format!("run {}", chrome_binary.display()))?;

    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    fs::write(&probe_dom_path, &stdout).with_context(|| format!("write {}", probe_dom_path.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
        let detail = if !stderr.is_empty() {
            stderr
        } else {
            format!("{} exited with status {}", chrome_binary.display(), output.status)
        };
        bail!("{detail}");
    }

    parse_manual_lab_recording_visibility_probe_payload(&stdout)
}

fn build_manual_lab_recording_visibility_summary(
    recordings_root: &Path,
    session_id: &str,
    chrome_binary: Option<&Path>,
    teardown_started_at_unix_ms: Option<u64>,
    probe_seek_to_ms: Option<u64>,
    summary_artifact_filename: &str,
) -> ManualLabSessionRecordingVisibilitySummary {
    let session_root = recordings_root.join(session_id);
    let recording_artifact_path = session_root.join("recording-0.webm");
    let mut summary = ManualLabSessionRecordingVisibilitySummary {
        schema_version: MANUAL_LAB_RECORDING_VISIBILITY_SCHEMA_VERSION,
        sample_window_ms: MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_WINDOW_MS,
        sample_interval_ms: MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_INTERVAL_MS,
        probe_seek_to_ms,
        recording_path: recording_artifact_path
            .is_file()
            .then_some(recording_artifact_path.clone()),
        ..Default::default()
    };

    let summary_artifact_path = session_root.join(summary_artifact_filename);
    let should_write_summary_artifact = teardown_started_at_unix_ms.is_some() && session_root.exists();

    if !recording_artifact_path.is_file() {
        summary.verdict = ManualLabRecordingVisibilityVerdict::MissingArtifact;
        summary.confidence = ManualLabEvidenceConfidence::High;
        summary.detail = Some("recording-0.webm was not present for visibility analysis".to_owned());
        if should_write_summary_artifact {
            let _ = write_manual_lab_recording_visibility_summary_artifact(&summary_artifact_path, &summary);
        }
        return summary;
    }

    if teardown_started_at_unix_ms.is_none() {
        summary.verdict = ManualLabRecordingVisibilityVerdict::AnalysisUnavailable;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some("recording visibility analysis is deferred until teardown".to_owned());
        if should_write_summary_artifact {
            let _ = write_manual_lab_recording_visibility_summary_artifact(&summary_artifact_path, &summary);
        }
        return summary;
    }

    let Some(chrome_binary) = chrome_binary else {
        summary.verdict = ManualLabRecordingVisibilityVerdict::AnalysisUnavailable;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some("no Chrome-family browser was available for recording visibility analysis".to_owned());
        if should_write_summary_artifact {
            let _ = write_manual_lab_recording_visibility_summary_artifact(&summary_artifact_path, &summary);
        }
        return summary;
    };

    summary.analysis_backend =
        probe_command_version(chrome_binary, &["--version"]).or_else(|| Some(chrome_binary.display().to_string()));

    match run_manual_lab_recording_visibility_probe(
        chrome_binary,
        &recordings_root.join(session_id),
        &recording_artifact_path,
        probe_seek_to_ms,
    ) {
        Ok(payload) => {
            summary.ready_state = payload.ready_state;
            summary.video_duration_ms = manual_lab_recording_visibility_seconds_to_ms(payload.duration);
            summary.sampled_frame_count = payload.sampled;
            summary.first_visible_offset_ms = manual_lab_recording_visibility_seconds_to_ms(payload.first_visible_at);
            summary.first_sparse_offset_ms = manual_lab_recording_visibility_seconds_to_ms(payload.first_sparse_at);
            summary.max_non_black_ratio_per_mille =
                manual_lab_recording_visibility_ratio_to_per_mille(payload.max_ratio);

            if let Some(error) = payload.error {
                summary.verdict = ManualLabRecordingVisibilityVerdict::AnalysisFailed;
                summary.confidence = ManualLabEvidenceConfidence::Low;
                summary.detail = Some(format!("recording visibility probe reported error: {error}"));
            } else {
                summary.verdict = match payload.verdict.as_deref() {
                    Some("visible") => ManualLabRecordingVisibilityVerdict::VisibleFrame,
                    Some("sparse") => ManualLabRecordingVisibilityVerdict::SparsePixels,
                    Some("black") => ManualLabRecordingVisibilityVerdict::AllBlack,
                    _ => ManualLabRecordingVisibilityVerdict::Inconclusive,
                };
                summary.confidence = if payload.sampled > 0 {
                    ManualLabEvidenceConfidence::High
                } else {
                    ManualLabEvidenceConfidence::Low
                };
                summary.detail = Some(match summary.verdict {
                    ManualLabRecordingVisibilityVerdict::VisibleFrame => format!(
                        "headless chrome found a visible non-black frame within {}ms",
                        summary.first_visible_offset_ms.unwrap_or_default()
                    ),
                    ManualLabRecordingVisibilityVerdict::SparsePixels => format!(
                        "headless chrome only found sparse non-black pixels within {}ms (max={} per-mille)",
                        summary.first_sparse_offset_ms.unwrap_or_default(),
                        summary.max_non_black_ratio_per_mille.unwrap_or_default()
                    ),
                    ManualLabRecordingVisibilityVerdict::AllBlack => format!(
                        "headless chrome kept recording-0.webm below the sparse threshold for {} sampled frames",
                        summary.sampled_frame_count
                    ),
                    ManualLabRecordingVisibilityVerdict::Inconclusive => {
                        "recording visibility probe completed without a stable verdict".to_owned()
                    }
                    ManualLabRecordingVisibilityVerdict::MissingArtifact
                    | ManualLabRecordingVisibilityVerdict::AnalysisUnavailable
                    | ManualLabRecordingVisibilityVerdict::AnalysisFailed => {
                        "recording visibility probe ended without a usable result".to_owned()
                    }
                });
            }
        }
        Err(error) => {
            summary.verdict = ManualLabRecordingVisibilityVerdict::AnalysisFailed;
            summary.confidence = ManualLabEvidenceConfidence::Low;
            summary.detail = Some(format!("{error:#}"));
        }
    }

    if should_write_summary_artifact {
        let _ = write_manual_lab_recording_visibility_summary_artifact(&summary_artifact_path, &summary);
    }
    summary
}

fn parse_manual_lab_player_websocket_events(
    recordings_root: &Path,
    session_id: &str,
) -> anyhow::Result<Vec<ManualLabPlayerWebsocketEvent>> {
    let log_path = recordings_root.join(session_id).join("player-websocket.ndjson");
    if !log_path.exists() {
        return Ok(Vec::new());
    }

    let log = fs::read_to_string(&log_path).with_context(|| format!("read {}", log_path.display()))?;
    let mut events = Vec::new();
    for (index, line) in log.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }

        let event = serde_json::from_str::<ManualLabPlayerWebsocketEvent>(line)
            .with_context(|| format!("parse {} line {}", log_path.display(), index + 1))?;
        if event.session_id == session_id {
            events.push(event);
        }
    }
    events.sort_by_key(|event| event.observed_at_unix_ms);

    Ok(events)
}

fn build_manual_lab_player_websocket_summary(
    events: &[ManualLabPlayerWebsocketEvent],
    teardown_started_at_unix_ms: Option<u64>,
) -> ManualLabSessionPlayerWebsocketSummary {
    let mut summary = ManualLabSessionPlayerWebsocketSummary {
        schema_version: MANUAL_LAB_PLAYER_WEBSOCKET_SCHEMA_VERSION,
        capture_end_at_unix_ms: teardown_started_at_unix_ms,
        ..Default::default()
    };

    for event in events {
        match event.kind.as_str() {
            "websocket_open" => {
                summary.open_observed = true;
                summary.opened_at_unix_ms = summary.opened_at_unix_ms.or(event.opened_at_unix_ms);
            }
            "websocket_first_message" => {
                summary.first_message_observed = true;
                summary.first_message_at_unix_ms = summary.first_message_at_unix_ms.or(event.first_message_at_unix_ms);
            }
            "websocket_close_raw" => {
                summary.raw_close_observed = true;
                summary.closed_at_unix_ms = summary.closed_at_unix_ms.or(event.closed_at_unix_ms);
                summary.elapsed_ms_since_open = summary.elapsed_ms_since_open.or(event.elapsed_ms_since_open);
                summary.raw_close_code = summary.raw_close_code.or(event.raw_close_code);
                summary.raw_close_reason = summary
                    .raw_close_reason
                    .clone()
                    .or_else(|| event.raw_close_reason.clone());
                summary.active_mode_at_close = summary.active_mode_at_close.or(event.active_mode);
                summary.fallback_started_before_close =
                    summary.fallback_started_before_close.or(event.fallback_started);
            }
            "websocket_close_transformed" => {
                summary.transformed_close_observed = true;
                summary.closed_at_unix_ms = summary.closed_at_unix_ms.or(event.closed_at_unix_ms);
                summary.elapsed_ms_since_open = summary.elapsed_ms_since_open.or(event.elapsed_ms_since_open);
                summary.transformed_close_code = summary.transformed_close_code.or(event.transformed_close_code);
                summary.transformed_close_reason = summary
                    .transformed_close_reason
                    .clone()
                    .or_else(|| event.transformed_close_reason.clone());
                summary.delivery_kind = summary.delivery_kind.clone().or_else(|| event.delivery_kind.clone());
                summary.active_mode_at_close = summary.active_mode_at_close.or(event.active_mode);
                summary.fallback_started_before_close =
                    summary.fallback_started_before_close.or(event.fallback_started);
            }
            _ => {}
        }
    }

    if summary.open_observed && !summary.raw_close_observed && !summary.transformed_close_observed {
        summary.no_close_observed_by_teardown = teardown_started_at_unix_ms.is_some();
    }

    summary.detail = if summary.raw_close_observed || summary.transformed_close_observed {
        let close_code = summary
            .raw_close_code
            .or(summary.transformed_close_code)
            .map(|code| code.to_string())
            .unwrap_or_else(|| "<unknown>".to_owned());
        let elapsed = summary
            .elapsed_ms_since_open
            .map(|elapsed_ms| format!("{elapsed_ms}ms"))
            .unwrap_or_else(|| "<unknown>".to_owned());
        Some(format!(
            "websocket close observed code={close_code} elapsed_since_open={elapsed}"
        ))
    } else if summary.no_close_observed_by_teardown {
        Some("no websocket close was observed before teardown".to_owned())
    } else if summary.open_observed {
        Some("websocket opened, but no close was observed during the active capture window".to_owned())
    } else if events.is_empty() {
        Some("no player websocket telemetry was captured".to_owned())
    } else {
        Some("player websocket telemetry was captured without an open or close marker".to_owned())
    };

    summary
}

fn build_manual_lab_player_playback_path_summary(
    events: &[ManualLabPlayerWebsocketEvent],
) -> ManualLabSessionPlayerPlaybackPathSummary {
    let mut summary = ManualLabSessionPlayerPlaybackPathSummary {
        schema_version: MANUAL_LAB_PLAYER_PLAYBACK_PATH_SCHEMA_VERSION,
        ..Default::default()
    };

    for event in events {
        match event.kind.as_str() {
            "player_mode_configured" => {
                if event.active_mode == Some(true) {
                    summary.active_intent_observed = true;
                    summary
                        .active_intent_at_unix_ms
                        .get_or_insert(event.observed_at_unix_ms);
                }
            }
            "websocket_open" | "websocket_first_message" => {
                if event.active_mode == Some(true) {
                    summary.active_intent_observed = true;
                    summary
                        .active_intent_at_unix_ms
                        .get_or_insert(event.observed_at_unix_ms);
                }
            }
            "static_playback_started" => {
                summary.static_playback_started_observed = true;
                summary.static_playback_started_at_unix_ms = summary
                    .static_playback_started_at_unix_ms
                    .or(Some(event.observed_at_unix_ms));
            }
            "recording_info_fetch_started" => {
                summary.recording_info_fetch_attempted = true;
                if event.active_mode == Some(true) {
                    summary.active_intent_observed = true;
                    summary
                        .active_intent_at_unix_ms
                        .get_or_insert(event.observed_at_unix_ms);
                }
            }
            "recording_info_fetch_succeeded" => {
                summary.recording_info_fetch_attempted = true;
                summary.recording_info_fetch_succeeded = true;
                if event.active_mode == Some(true) {
                    summary.active_intent_observed = true;
                    summary
                        .active_intent_at_unix_ms
                        .get_or_insert(event.observed_at_unix_ms);
                }
            }
            "recording_info_fetch_failed" => {
                summary.recording_info_fetch_attempted = true;
                summary.recording_info_fetch_failed = true;
                summary.recording_info_fetch_failed_at_unix_ms = summary
                    .recording_info_fetch_failed_at_unix_ms
                    .or(Some(event.observed_at_unix_ms));
                summary.recording_info_fetch_http_status =
                    summary.recording_info_fetch_http_status.or(event.http_status);
                if event.active_mode == Some(true) {
                    summary.active_intent_observed = true;
                    summary
                        .active_intent_at_unix_ms
                        .get_or_insert(event.observed_at_unix_ms);
                    summary.missing_artifact_while_active = true;
                }
            }
            _ => {}
        }
    }

    summary.verdict = if summary.missing_artifact_while_active {
        ManualLabPlayerPlaybackModeVerdict::MissingArtifactProbeWhileActive
    } else if summary.static_playback_started_observed && summary.active_intent_observed {
        ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive
    } else if summary.active_intent_observed {
        ManualLabPlayerPlaybackModeVerdict::ActiveLivePath
    } else if events
        .iter()
        .any(|event| event.kind == "player_mode_configured" && event.active_mode == Some(false))
    {
        ManualLabPlayerPlaybackModeVerdict::StaticIntentFromStart
    } else {
        summary.telemetry_gap = events.is_empty();
        ManualLabPlayerPlaybackModeVerdict::Inconclusive
    };

    summary.detail = Some(match summary.verdict {
        ManualLabPlayerPlaybackModeVerdict::MissingArtifactProbeWhileActive => {
            let status = summary
                .recording_info_fetch_http_status
                .map(|status| status.to_string())
                .unwrap_or_else(|| "<unknown>".to_owned());
            format!("recording.json fetch failed with status {status} while active playback was still expected")
        }
        ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive => {
            "static playback started after active playback intent was established".to_owned()
        }
        ManualLabPlayerPlaybackModeVerdict::ActiveLivePath => {
            "active playback intent held and no static fallback or missing recording fetch was observed".to_owned()
        }
        ManualLabPlayerPlaybackModeVerdict::StaticIntentFromStart => {
            "player was configured for static playback from the start".to_owned()
        }
        ManualLabPlayerPlaybackModeVerdict::Inconclusive => {
            if summary.telemetry_gap {
                "no player telemetry was captured for playback-path classification".to_owned()
            } else {
                "player telemetry did not contain enough evidence to classify playback path".to_owned()
            }
        }
    });

    summary
}

fn parse_manual_lab_browser_player_mode(value: Option<&str>) -> ManualLabBrowserPlayerMode {
    match value {
        Some("active_live") => ManualLabBrowserPlayerMode::ActiveLive,
        Some("static_fallback") => ManualLabBrowserPlayerMode::StaticFallback,
        _ => ManualLabBrowserPlayerMode::Unknown,
    }
}

fn parse_manual_lab_browser_visibility_data_status(value: Option<&str>) -> ManualLabBrowserVisibilityDataStatus {
    match value {
        Some("ready") => ManualLabBrowserVisibilityDataStatus::Ready,
        Some("no_video_element") => ManualLabBrowserVisibilityDataStatus::NoVideoElement,
        Some("no_decodable_frame") => ManualLabBrowserVisibilityDataStatus::NoDecodableFrame,
        Some("readback_error") => ManualLabBrowserVisibilityDataStatus::ReadbackError,
        Some("insufficient_samples") => ManualLabBrowserVisibilityDataStatus::InsufficientSamples,
        Some("transitional") => ManualLabBrowserVisibilityDataStatus::Transitional,
        _ => ManualLabBrowserVisibilityDataStatus::Inconclusive,
    }
}

fn parse_manual_lab_recording_visibility_verdict(value: Option<&str>) -> ManualLabRecordingVisibilityVerdict {
    match value {
        Some("visible_frame") | Some("visible") => ManualLabRecordingVisibilityVerdict::VisibleFrame,
        Some("sparse_pixels") | Some("sparse") => ManualLabRecordingVisibilityVerdict::SparsePixels,
        Some("all_black") | Some("black") => ManualLabRecordingVisibilityVerdict::AllBlack,
        _ => ManualLabRecordingVisibilityVerdict::Inconclusive,
    }
}

fn manual_lab_browser_visibility_phase_rank(phase: &str) -> u8 {
    match phase {
        "steady" => 3,
        "stabilize" => 2,
        "startup" => 1,
        _ => 0,
    }
}

fn manual_lab_evidence_confidence_rank(confidence: ManualLabEvidenceConfidence) -> u8 {
    match confidence {
        ManualLabEvidenceConfidence::High => 3,
        ManualLabEvidenceConfidence::Medium => 2,
        ManualLabEvidenceConfidence::Low => 1,
    }
}

fn manual_lab_min_evidence_confidence(
    left: ManualLabEvidenceConfidence,
    right: ManualLabEvidenceConfidence,
) -> ManualLabEvidenceConfidence {
    if manual_lab_evidence_confidence_rank(left) <= manual_lab_evidence_confidence_rank(right) {
        left
    } else {
        right
    }
}

fn manual_lab_visible_or_sparse(verdict: ManualLabRecordingVisibilityVerdict) -> bool {
    matches!(
        verdict,
        ManualLabRecordingVisibilityVerdict::VisibleFrame | ManualLabRecordingVisibilityVerdict::SparsePixels
    )
}

fn build_manual_lab_browser_visibility_summary(
    events: &[ManualLabPlayerWebsocketEvent],
) -> ManualLabSessionBrowserVisibilitySummary {
    let windows = events
        .iter()
        .filter(|event| event.kind == "browser_visibility_window")
        .map(|event| ManualLabSessionBrowserVisibilityWindowSummary {
            window_index: event.window_index.unwrap_or_default(),
            window_phase: event.window_phase.clone().unwrap_or_else(|| "unknown".to_owned()),
            player_mode: parse_manual_lab_browser_player_mode(event.player_mode.as_deref()),
            data_status: parse_manual_lab_browser_visibility_data_status(event.sample_status.as_deref()),
            verdict: parse_manual_lab_recording_visibility_verdict(event.visibility_verdict.as_deref()),
            sample_count: event.sample_count.unwrap_or_default(),
            valid_sample_count: event.valid_sample_count.unwrap_or_default(),
            window_start_at_unix_ms: event.window_start_at_unix_ms,
            window_end_at_unix_ms: event.window_end_at_unix_ms,
            representative_current_time_ms: event.representative_current_time_ms,
            video_width: event.video_width,
            video_height: event.video_height,
            max_non_black_ratio_per_mille: event.max_non_black_ratio_per_mille,
            mean_non_black_ratio_per_mille: event.mean_non_black_ratio_per_mille,
            transition_observed: event.transition_observed.unwrap_or(false),
            detail: event.detail.clone(),
        })
        .collect::<Vec<_>>();

    let valid_window_count = windows
        .iter()
        .filter(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::Ready)
        .count()
        .try_into()
        .expect("valid browser visibility window count should fit in u64");
    let transition_observed = windows.iter().any(|window| window.transition_observed);
    let max_non_black_ratio_per_mille = windows
        .iter()
        .filter_map(|window| {
            (window.data_status == ManualLabBrowserVisibilityDataStatus::Ready)
                .then_some(window.max_non_black_ratio_per_mille)
                .flatten()
        })
        .max();
    let selected_ready_window = windows
        .iter()
        .filter(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::Ready)
        .max_by_key(|window| {
            (
                manual_lab_browser_visibility_phase_rank(&window.window_phase),
                window.window_index,
            )
        });
    let dominant_mode = selected_ready_window
        .map(|window| window.player_mode)
        .or_else(|| {
            windows
                .iter()
                .filter(|window| window.player_mode != ManualLabBrowserPlayerMode::Unknown)
                .max_by_key(|window| {
                    (
                        manual_lab_browser_visibility_phase_rank(&window.window_phase),
                        window.window_index,
                    )
                })
                .map(|window| window.player_mode)
        })
        .unwrap_or_default();

    let data_status = if selected_ready_window.is_some() {
        ManualLabBrowserVisibilityDataStatus::Ready
    } else if transition_observed {
        ManualLabBrowserVisibilityDataStatus::Transitional
    } else if windows
        .iter()
        .any(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::ReadbackError)
    {
        ManualLabBrowserVisibilityDataStatus::ReadbackError
    } else if windows
        .iter()
        .any(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::NoVideoElement)
    {
        ManualLabBrowserVisibilityDataStatus::NoVideoElement
    } else if windows
        .iter()
        .any(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::NoDecodableFrame)
    {
        ManualLabBrowserVisibilityDataStatus::NoDecodableFrame
    } else if windows
        .iter()
        .any(|window| window.data_status == ManualLabBrowserVisibilityDataStatus::InsufficientSamples)
    {
        ManualLabBrowserVisibilityDataStatus::InsufficientSamples
    } else {
        ManualLabBrowserVisibilityDataStatus::Inconclusive
    };

    let verdict = selected_ready_window
        .map(|window| window.verdict)
        .unwrap_or(ManualLabRecordingVisibilityVerdict::Inconclusive);
    let representative_current_time_ms = selected_ready_window.and_then(|window| window.representative_current_time_ms);
    let confidence = if valid_window_count >= 2 && !transition_observed {
        ManualLabEvidenceConfidence::High
    } else if valid_window_count >= 1 {
        ManualLabEvidenceConfidence::Medium
    } else {
        ManualLabEvidenceConfidence::Low
    };

    let detail = Some(if let Some(window) = selected_ready_window {
        format!(
            "browser visibility selected {} window {} with {:?} at {}ms",
            window.window_phase,
            window.window_index,
            window.verdict,
            window.representative_current_time_ms.unwrap_or_default()
        )
    } else if transition_observed {
        "browser visibility windows crossed an active/static transition and were not stable enough to classify"
            .to_owned()
    } else if windows.is_empty() {
        "no browser visibility window telemetry was captured".to_owned()
    } else {
        match data_status {
            ManualLabBrowserVisibilityDataStatus::NoVideoElement => {
                "browser visibility never found a player video element".to_owned()
            }
            ManualLabBrowserVisibilityDataStatus::NoDecodableFrame => {
                "browser visibility never reached a decodable player frame".to_owned()
            }
            ManualLabBrowserVisibilityDataStatus::ReadbackError => {
                "browser visibility could not read pixels from the player video".to_owned()
            }
            ManualLabBrowserVisibilityDataStatus::InsufficientSamples => {
                "browser visibility captured too few ready samples for a stable verdict".to_owned()
            }
            ManualLabBrowserVisibilityDataStatus::Transitional => {
                "browser visibility windows were transitional".to_owned()
            }
            ManualLabBrowserVisibilityDataStatus::Ready | ManualLabBrowserVisibilityDataStatus::Inconclusive => {
                "browser visibility did not produce a stable verdict".to_owned()
            }
        }
    });

    ManualLabSessionBrowserVisibilitySummary {
        schema_version: MANUAL_LAB_BROWSER_VISIBILITY_SCHEMA_VERSION,
        verdict,
        confidence,
        detail,
        dominant_mode,
        data_status,
        representative_current_time_ms,
        valid_window_count,
        transition_observed,
        max_non_black_ratio_per_mille,
        windows,
    }
}

fn build_manual_lab_browser_artifact_correlation_summary(
    browser: &ManualLabSessionBrowserVisibilitySummary,
    artifact: &ManualLabSessionRecordingVisibilitySummary,
) -> ManualLabSessionBrowserArtifactCorrelationSummary {
    let mut summary = ManualLabSessionBrowserArtifactCorrelationSummary {
        schema_version: MANUAL_LAB_BROWSER_ARTIFACT_CORRELATION_SCHEMA_VERSION,
        browser_player_mode: browser.dominant_mode,
        browser_verdict: browser.verdict,
        artifact_verdict: artifact.verdict,
        browser_current_time_ms: browser.representative_current_time_ms,
        artifact_probe_seek_to_ms: artifact.probe_seek_to_ms,
        browser_data_status: browser.data_status,
        transition_observed: browser.transition_observed,
        ..Default::default()
    };

    if browser.transition_observed {
        summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::InconclusiveTransition;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some(
            "browser visibility crossed an active/static transition, so artifact correlation is not trustworthy"
                .to_owned(),
        );
        return summary;
    }

    if browser.data_status != ManualLabBrowserVisibilityDataStatus::Ready {
        summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::InconclusiveInsufficientData;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some(format!(
            "browser visibility did not yield a ready window: {:?}",
            browser.data_status
        ));
        return summary;
    }

    if browser.representative_current_time_ms.is_none()
        || artifact.probe_seek_to_ms.is_none()
        || browser.representative_current_time_ms != artifact.probe_seek_to_ms
    {
        summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::InconclusiveAlignmentGap;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some(
            "browser visibility did not provide a representative playback offset that matched the artifact probe"
                .to_owned(),
        );
        return summary;
    }

    if !matches!(
        artifact.verdict,
        ManualLabRecordingVisibilityVerdict::VisibleFrame
            | ManualLabRecordingVisibilityVerdict::SparsePixels
            | ManualLabRecordingVisibilityVerdict::AllBlack
    ) {
        summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::InconclusiveInsufficientData;
        summary.confidence = ManualLabEvidenceConfidence::Low;
        summary.detail = Some(format!(
            "artifact visibility at browser time was not usable for correlation: {:?}",
            artifact.verdict
        ));
        return summary;
    }

    summary.verdict = if browser.verdict == ManualLabRecordingVisibilityVerdict::AllBlack
        && artifact.verdict == ManualLabRecordingVisibilityVerdict::AllBlack
    {
        ManualLabBrowserArtifactCorrelationVerdict::BothBlack
    } else if browser.verdict == ManualLabRecordingVisibilityVerdict::AllBlack
        && manual_lab_visible_or_sparse(artifact.verdict)
    {
        ManualLabBrowserArtifactCorrelationVerdict::BrowserBlackArtifactVisible
    } else if manual_lab_visible_or_sparse(browser.verdict)
        && artifact.verdict == ManualLabRecordingVisibilityVerdict::AllBlack
    {
        ManualLabBrowserArtifactCorrelationVerdict::BrowserVisibleArtifactBlack
    } else if manual_lab_visible_or_sparse(browser.verdict) && manual_lab_visible_or_sparse(artifact.verdict) {
        ManualLabBrowserArtifactCorrelationVerdict::BothVisible
    } else {
        ManualLabBrowserArtifactCorrelationVerdict::Inconclusive
    };
    summary.confidence = manual_lab_min_evidence_confidence(browser.confidence, artifact.confidence);
    summary.detail = Some(match summary.verdict {
        ManualLabBrowserArtifactCorrelationVerdict::BothVisible => {
            "browser and artifact both showed non-black content at the aligned playback point".to_owned()
        }
        ManualLabBrowserArtifactCorrelationVerdict::BothBlack => {
            "browser and artifact were both black at the aligned playback point".to_owned()
        }
        ManualLabBrowserArtifactCorrelationVerdict::BrowserBlackArtifactVisible => {
            "browser looked black while the aligned recording artifact still had visible content".to_owned()
        }
        ManualLabBrowserArtifactCorrelationVerdict::BrowserVisibleArtifactBlack => {
            "browser showed visible content while the aligned recording artifact sampled as black".to_owned()
        }
        ManualLabBrowserArtifactCorrelationVerdict::InconclusiveInsufficientData
        | ManualLabBrowserArtifactCorrelationVerdict::InconclusiveAlignmentGap
        | ManualLabBrowserArtifactCorrelationVerdict::InconclusiveTransition
        | ManualLabBrowserArtifactCorrelationVerdict::Inconclusive => {
            "browser/artifact correlation remained inconclusive".to_owned()
        }
    });

    summary
}

pub fn build_manual_lab_ready_path_sustain_summary(
    evidence: &ManualLabSessionDriverEvidence,
) -> ManualLabSessionReadyPathSustainSummary {
    let ready = &evidence.playback_ready_correlation;
    let player = &evidence.player_playback_path_summary;
    let browser = &evidence.browser_visibility_summary;

    let steady_window = browser.windows.iter().find(|window| {
        window.window_phase == "steady"
            && window.player_mode == ManualLabBrowserPlayerMode::ActiveLive
            && window.data_status == ManualLabBrowserVisibilityDataStatus::Ready
            && !window.transition_observed
    });
    let fallback_window = browser
        .windows
        .iter()
        .find(|window| window.player_mode == ManualLabBrowserPlayerMode::StaticFallback);
    let telemetry_gap = player.telemetry_gap || browser.windows.is_empty() || browser.valid_window_count == 0;

    let mut summary = ManualLabSessionReadyPathSustainSummary {
        schema_version: MANUAL_LAB_READY_PATH_SUSTAIN_SCHEMA_VERSION,
        ready_verdict: ready.verdict,
        player_path_verdict: player.verdict,
        dominant_mode: browser.dominant_mode,
        steady_window_observed: steady_window.is_some(),
        steady_window_index: steady_window.map(|window| window.window_index),
        steady_window_current_time_ms: steady_window.and_then(|window| window.representative_current_time_ms),
        static_fallback_started_at_unix_ms: player.static_playback_started_at_unix_ms,
        telemetry_gap,
        ..Default::default()
    };

    if ready.verdict != ManualLabPlaybackReadyVerdict::AlignedReady {
        summary.verdict = ManualLabReadyPathSustainVerdict::MissingReadyAlignment;
        summary.detail = Some(format!(
            "ready-path sustain requires aligned_ready, observed {:?}",
            ready.verdict
        ));
        return summary;
    }

    if !player.active_intent_observed {
        summary.verdict = ManualLabReadyPathSustainVerdict::MissingActiveIntent;
        summary.detail = Some("active playback intent was never observed".to_owned());
        return summary;
    }

    if matches!(
        player.verdict,
        ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive
            | ManualLabPlayerPlaybackModeVerdict::StaticIntentFromStart
    ) || player.static_playback_started_observed
        || fallback_window.is_some()
    {
        summary.verdict = ManualLabReadyPathSustainVerdict::StaticFallbackObserved;
        summary.static_fallback_started_at_unix_ms = summary
            .static_fallback_started_at_unix_ms
            .or_else(|| fallback_window.and_then(|window| window.window_start_at_unix_ms));
        summary.detail = Some("static fallback was observed before the ready-path sustain proof completed".to_owned());
        return summary;
    }

    if player.verdict != ManualLabPlayerPlaybackModeVerdict::ActiveLivePath {
        summary.verdict = if telemetry_gap {
            ManualLabReadyPathSustainVerdict::TelemetryGap
        } else {
            ManualLabReadyPathSustainVerdict::Inconclusive
        };
        summary.detail = Some(format!(
            "ready-path sustain requires active_live_path, observed {:?}",
            player.verdict
        ));
        return summary;
    }

    if let Some(steady_window) = steady_window {
        summary.verdict = ManualLabReadyPathSustainVerdict::SustainedActiveLive;
        summary.detail = Some(format!(
            "ready active playback reached steady browser window {} without static fallback",
            steady_window.window_index
        ));
        return summary;
    }

    summary.verdict = if telemetry_gap {
        ManualLabReadyPathSustainVerdict::TelemetryGap
    } else {
        ManualLabReadyPathSustainVerdict::MissingSteadyActiveWindow
    };
    summary.detail =
        Some("ready active playback never reached a steady active_live browser window before teardown".to_owned());
    summary
}

fn manual_lab_multi_session_ready_path_slot_reason(
    verdict: ManualLabReadyPathSustainVerdict,
) -> ManualLabMultiSessionReadyPathSlotReason {
    match verdict {
        ManualLabReadyPathSustainVerdict::SustainedActiveLive => {
            ManualLabMultiSessionReadyPathSlotReason::UsableLivePlayback
        }
        ManualLabReadyPathSustainVerdict::MissingReadyAlignment => {
            ManualLabMultiSessionReadyPathSlotReason::MissingReadyAlignment
        }
        ManualLabReadyPathSustainVerdict::MissingActiveIntent => {
            ManualLabMultiSessionReadyPathSlotReason::MissingActiveIntent
        }
        ManualLabReadyPathSustainVerdict::StaticFallbackObserved => {
            ManualLabMultiSessionReadyPathSlotReason::StaticFallbackObserved
        }
        ManualLabReadyPathSustainVerdict::MissingSteadyActiveWindow => {
            ManualLabMultiSessionReadyPathSlotReason::MissingSteadyActiveWindow
        }
        ManualLabReadyPathSustainVerdict::TelemetryGap => ManualLabMultiSessionReadyPathSlotReason::TelemetryGap,
        ManualLabReadyPathSustainVerdict::Inconclusive => ManualLabMultiSessionReadyPathSlotReason::Inconclusive,
    }
}

pub fn build_manual_lab_multi_session_ready_path_summary(
    session_evidence: &[ManualLabSessionDriverEvidence],
    expected_slot_count: usize,
) -> ManualLabMultiSessionReadyPathSummary {
    let mut evidence_by_slot: BTreeMap<usize, Vec<&ManualLabSessionDriverEvidence>> = BTreeMap::new();
    for evidence in session_evidence {
        evidence_by_slot.entry(evidence.slot).or_default().push(evidence);
    }

    let mut summary = ManualLabMultiSessionReadyPathSummary {
        schema_version: MANUAL_LAB_MULTI_SESSION_READY_PATH_SCHEMA_VERSION,
        expected_slot_count,
        observed_session_count: session_evidence.len(),
        ..Default::default()
    };

    if expected_slot_count == 0 {
        summary.verdict = ManualLabMultiSessionReadyPathVerdict::Inconclusive;
        summary.detail = Some("multi-session ready-path summary requires at least one expected slot".to_owned());
        return summary;
    }

    let mut missing_slots = Vec::new();
    let mut duplicate_slots = Vec::new();

    for slot in 1..=expected_slot_count {
        match evidence_by_slot.get(&slot) {
            Some(entries) if entries.len() == 1 => {
                let entry = entries[0];
                let ready_path_sustain_summary = build_manual_lab_ready_path_sustain_summary(entry);
                summary.slot_summaries.push(ManualLabMultiSessionReadyPathSlotSummary {
                    slot,
                    session_id: entry.session_id.clone(),
                    reason: manual_lab_multi_session_ready_path_slot_reason(ready_path_sustain_summary.verdict),
                    detail: ready_path_sustain_summary.detail.clone(),
                    ready_path_sustain_summary,
                    black_screen_branch_verdict: entry.black_screen_branch.verdict,
                    browser_visibility_verdict: entry.browser_visibility_summary.verdict,
                    artifact_visibility_verdict: entry.artifact_visibility_at_browser_time.verdict,
                });
            }
            Some(entries) => {
                duplicate_slots.push(slot);
                summary.slot_summaries.push(ManualLabMultiSessionReadyPathSlotSummary {
                    slot,
                    reason: ManualLabMultiSessionReadyPathSlotReason::Inconclusive,
                    detail: Some(format!(
                        "expected one evidence record for slot {slot}, observed {}",
                        entries.len()
                    )),
                    ..Default::default()
                });
            }
            None => {
                missing_slots.push(slot);
                summary.slot_summaries.push(ManualLabMultiSessionReadyPathSlotSummary {
                    slot,
                    reason: ManualLabMultiSessionReadyPathSlotReason::MissingSlotEvidence,
                    detail: Some(format!(
                        "no manual-lab ready-path evidence was recorded for slot {slot}"
                    )),
                    ..Default::default()
                });
            }
        }
    }

    if !duplicate_slots.is_empty() {
        summary.verdict = ManualLabMultiSessionReadyPathVerdict::Inconclusive;
        summary.detail = Some(format!(
            "duplicate manual-lab evidence was recorded for slot(s) {}",
            duplicate_slots
                .iter()
                .map(|slot| slot.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return summary;
    }

    if !missing_slots.is_empty() {
        summary.verdict = ManualLabMultiSessionReadyPathVerdict::MissingSlotEvidence;
        summary.detail = Some(format!(
            "manual-lab ready-path evidence is missing for slot(s) {}",
            missing_slots
                .iter()
                .map(|slot| slot.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return summary;
    }

    summary.verdict = ManualLabMultiSessionReadyPathVerdict::AllSlotsAccounted;
    summary.detail = Some(format!(
        "manual-lab ready-path evidence accounted for slots 1..={expected_slot_count}"
    ));
    summary
}

fn manual_lab_push_black_screen_run_reason(
    reasons: &mut Vec<ManualLabBlackScreenRunReason>,
    reason: ManualLabBlackScreenRunReason,
) {
    if !reasons.contains(&reason) {
        reasons.push(reason);
    }
}

fn manual_lab_black_screen_run_reason_for_slot_reason(
    reason: ManualLabMultiSessionReadyPathSlotReason,
) -> Option<ManualLabBlackScreenRunReason> {
    match reason {
        ManualLabMultiSessionReadyPathSlotReason::UsableLivePlayback => None,
        ManualLabMultiSessionReadyPathSlotReason::MissingReadyAlignment => {
            Some(ManualLabBlackScreenRunReason::MissingReadyAlignment)
        }
        ManualLabMultiSessionReadyPathSlotReason::MissingActiveIntent => {
            Some(ManualLabBlackScreenRunReason::MissingActiveIntent)
        }
        ManualLabMultiSessionReadyPathSlotReason::StaticFallbackObserved => {
            Some(ManualLabBlackScreenRunReason::StaticFallbackObserved)
        }
        ManualLabMultiSessionReadyPathSlotReason::MissingSteadyActiveWindow => {
            Some(ManualLabBlackScreenRunReason::MissingSteadyActiveWindow)
        }
        ManualLabMultiSessionReadyPathSlotReason::TelemetryGap => Some(ManualLabBlackScreenRunReason::TelemetryGap),
        ManualLabMultiSessionReadyPathSlotReason::MissingSlotEvidence => {
            Some(ManualLabBlackScreenRunReason::MissingSlotEvidence)
        }
        ManualLabMultiSessionReadyPathSlotReason::Inconclusive => {
            Some(ManualLabBlackScreenRunReason::InsufficientEvidence)
        }
    }
}

fn manual_lab_black_screen_run_reason_for_browser_artifact_verdict(
    verdict: ManualLabBrowserArtifactCorrelationVerdict,
) -> Option<ManualLabBlackScreenRunReason> {
    match verdict {
        ManualLabBrowserArtifactCorrelationVerdict::BothVisible => None,
        ManualLabBrowserArtifactCorrelationVerdict::BothBlack => {
            Some(ManualLabBlackScreenRunReason::BrowserArtifactBothBlack)
        }
        ManualLabBrowserArtifactCorrelationVerdict::BrowserBlackArtifactVisible
        | ManualLabBrowserArtifactCorrelationVerdict::BrowserVisibleArtifactBlack => {
            Some(ManualLabBlackScreenRunReason::BrowserArtifactContradiction)
        }
        ManualLabBrowserArtifactCorrelationVerdict::InconclusiveAlignmentGap => {
            Some(ManualLabBlackScreenRunReason::BrowserArtifactAlignmentGap)
        }
        ManualLabBrowserArtifactCorrelationVerdict::InconclusiveInsufficientData
        | ManualLabBrowserArtifactCorrelationVerdict::InconclusiveTransition
        | ManualLabBrowserArtifactCorrelationVerdict::Inconclusive => {
            Some(ManualLabBlackScreenRunReason::BrowserArtifactInsufficientEvidence)
        }
    }
}

fn manual_lab_black_screen_run_reason_for_branch_verdict(
    verdict: ManualLabBlackScreenBranchVerdict,
) -> Option<ManualLabBlackScreenRunReason> {
    match verdict {
        ManualLabBlackScreenBranchVerdict::AlignedReady => None,
        ManualLabBlackScreenBranchVerdict::DecodeCorruption => Some(ManualLabBlackScreenRunReason::DecodeCorruption),
        ManualLabBlackScreenBranchVerdict::NoReadyTruthfulness => {
            Some(ManualLabBlackScreenRunReason::NoReadyTruthfulness)
        }
        ManualLabBlackScreenBranchVerdict::NegotiationLoss
        | ManualLabBlackScreenBranchVerdict::ProducerLoss
        | ManualLabBlackScreenBranchVerdict::PlayerLoss
        | ManualLabBlackScreenBranchVerdict::Inconclusive => Some(ManualLabBlackScreenRunReason::ContradictorySignal),
    }
}

fn build_manual_lab_black_screen_run_slot_summaries(
    evidence: &ManualLabBlackScreenEvidence,
) -> Vec<ManualLabBlackScreenRunSlotSummary> {
    let session_by_slot = evidence
        .session_invocations
        .iter()
        .map(|session| (session.slot, session))
        .collect::<BTreeMap<_, _>>();
    let multi_session_by_slot = evidence
        .multi_session_ready_path_summary
        .slot_summaries
        .iter()
        .map(|summary| (summary.slot, summary))
        .collect::<BTreeMap<_, _>>();

    (1..=evidence.session_count)
        .map(|slot| {
            let multi_session_summary = multi_session_by_slot.get(&slot).copied();
            let session = session_by_slot.get(&slot).copied();
            let session_id = multi_session_summary
                .map(|summary| summary.session_id.clone())
                .filter(|session_id| !session_id.is_empty())
                .or_else(|| session.map(|session| session.session_id.clone()))
                .unwrap_or_default();

            ManualLabBlackScreenRunSlotSummary {
                slot,
                session_id,
                ready_path_reason: multi_session_summary
                    .map(|summary| summary.reason)
                    .unwrap_or(ManualLabMultiSessionReadyPathSlotReason::MissingSlotEvidence),
                browser_artifact_correlation_verdict: session
                    .map(|session| session.browser_artifact_correlation_summary.verdict)
                    .unwrap_or(ManualLabBrowserArtifactCorrelationVerdict::Inconclusive),
                black_screen_branch_verdict: session
                    .map(|session| session.black_screen_branch.verdict)
                    .unwrap_or(ManualLabBlackScreenBranchVerdict::Inconclusive),
            }
        })
        .collect()
}

pub fn build_manual_lab_black_screen_run_verdict_summary(
    evidence: &ManualLabBlackScreenEvidence,
) -> ManualLabBlackScreenRunVerdictSummary {
    let mut summary = ManualLabBlackScreenRunVerdictSummary {
        schema_version: MANUAL_LAB_BLACK_SCREEN_RUN_VERDICT_SCHEMA_VERSION,
        expected_slot_count: evidence.session_count,
        observed_session_count: evidence.session_invocations.len(),
        slot_summaries: build_manual_lab_black_screen_run_slot_summaries(evidence),
        ..Default::default()
    };

    if summary.expected_slot_count == 0 {
        summary.primary_reason = ManualLabBlackScreenRunReason::InsufficientEvidence;
        summary.reason_codes = vec![ManualLabBlackScreenRunReason::InsufficientEvidence];
        summary.detail = Some("run verdict requires at least one expected session slot".to_owned());
        return summary;
    }

    let duplicate_slots = evidence
        .session_invocations
        .iter()
        .fold(BTreeMap::<usize, usize>::new(), |mut counts, session| {
            *counts.entry(session.slot).or_default() += 1;
            counts
        })
        .into_iter()
        .filter_map(|(slot, count)| (count > 1).then_some(slot))
        .collect::<Vec<_>>();

    if !duplicate_slots.is_empty() {
        summary.primary_reason = ManualLabBlackScreenRunReason::DuplicateSlotEvidence;
        summary.reason_codes = vec![ManualLabBlackScreenRunReason::DuplicateSlotEvidence];
        summary.detail = Some(format!(
            "run verdict failed closed because duplicate evidence was recorded for slot(s) {}",
            duplicate_slots
                .iter()
                .map(|slot| slot.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return summary;
    }

    if evidence.multi_session_ready_path_summary.expected_slot_count != evidence.session_count {
        summary.primary_reason = ManualLabBlackScreenRunReason::ContradictorySignal;
        summary.reason_codes = vec![ManualLabBlackScreenRunReason::ContradictorySignal];
        summary.detail = Some(format!(
            "run verdict failed closed because multi-session evidence expected {} slot(s) while the run expected {}",
            evidence.multi_session_ready_path_summary.expected_slot_count, evidence.session_count
        ));
        return summary;
    }

    let mut red_reasons = Vec::new();
    let mut amber_reasons = Vec::new();
    let mut missing_slots = Vec::new();

    for slot_summary in &summary.slot_summaries {
        if slot_summary.ready_path_reason == ManualLabMultiSessionReadyPathSlotReason::MissingSlotEvidence {
            missing_slots.push(slot_summary.slot);
        }

        if let Some(reason) = manual_lab_black_screen_run_reason_for_slot_reason(slot_summary.ready_path_reason) {
            manual_lab_push_black_screen_run_reason(&mut red_reasons, reason);
        }

        if let Some(reason) = manual_lab_black_screen_run_reason_for_browser_artifact_verdict(
            slot_summary.browser_artifact_correlation_verdict,
        ) {
            match reason {
                ManualLabBlackScreenRunReason::BrowserArtifactBothBlack
                | ManualLabBlackScreenRunReason::BrowserArtifactContradiction => {
                    manual_lab_push_black_screen_run_reason(&mut amber_reasons, reason);
                }
                _ => manual_lab_push_black_screen_run_reason(&mut red_reasons, reason),
            }
        }

        if let Some(reason) =
            manual_lab_black_screen_run_reason_for_branch_verdict(slot_summary.black_screen_branch_verdict)
        {
            match reason {
                ManualLabBlackScreenRunReason::DecodeCorruption => {
                    manual_lab_push_black_screen_run_reason(&mut amber_reasons, reason);
                }
                _ => manual_lab_push_black_screen_run_reason(&mut red_reasons, reason),
            }
        }
    }

    if !missing_slots.is_empty() {
        summary.primary_reason = ManualLabBlackScreenRunReason::MissingSlotEvidence;
        summary.reason_codes = vec![ManualLabBlackScreenRunReason::MissingSlotEvidence];
        summary.detail = Some(format!(
            "run verdict failed closed because evidence is missing for slot(s) {}",
            missing_slots
                .iter()
                .map(|slot| slot.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        return summary;
    }

    if !red_reasons.is_empty() {
        summary.primary_reason = red_reasons[0];
        summary.reason_codes = red_reasons;
        summary.detail = Some(format!("run verdict failed closed due to {:?}", summary.primary_reason));
        return summary;
    }

    if !amber_reasons.is_empty() {
        summary.verdict = ManualLabBlackScreenRunVerdict::ProducerReadyButCorruptionUnresolved;
        summary.primary_reason = ManualLabBlackScreenRunReason::ProducerReadyCorruptionUnresolved;
        summary
            .reason_codes
            .push(ManualLabBlackScreenRunReason::ProducerReadyCorruptionUnresolved);
        for reason in amber_reasons {
            manual_lab_push_black_screen_run_reason(&mut summary.reason_codes, reason);
        }
        summary.detail = Some(
            "all expected slots were accounted for, but ready playback still showed unresolved corruption signals"
                .to_owned(),
        );
        return summary;
    }

    summary.verdict = ManualLabBlackScreenRunVerdict::UsablePlayback;
    summary.primary_reason = ManualLabBlackScreenRunReason::AllSlotsUsablePlayback;
    summary.reason_codes = vec![ManualLabBlackScreenRunReason::AllSlotsUsablePlayback];
    summary.detail =
        Some("all expected slots reached usable live playback without unresolved corruption signals".to_owned());
    summary
}

pub fn build_manual_lab_black_screen_artifact_contract_summary(
    evidence: &ManualLabBlackScreenEvidence,
) -> ManualLabBlackScreenArtifactContractSummary {
    ManualLabBlackScreenArtifactContractSummary {
        schema_version: MANUAL_LAB_BLACK_SCREEN_ARTIFACT_CONTRACT_SCHEMA_VERSION,
        contract_id: MANUAL_LAB_BLACK_SCREEN_ARTIFACT_CONTRACT_ID.to_owned(),
        bs_rows: evidence.bs_rows.clone(),
        expected_slot_count: evidence.session_count,
        expected_slots: (1..=evidence.session_count).collect(),
        multi_session_ready_path_schema_version: MANUAL_LAB_MULTI_SESSION_READY_PATH_SCHEMA_VERSION,
        run_verdict_schema_version: MANUAL_LAB_BLACK_SCREEN_RUN_VERDICT_SCHEMA_VERSION,
        do_not_retry_schema_version: MANUAL_LAB_BLACK_SCREEN_DO_NOT_RETRY_SCHEMA_VERSION,
    }
}

fn manual_lab_black_screen_evidence_path(artifact_root: &Path) -> PathBuf {
    artifact_root.join(MANUAL_LAB_BLACK_SCREEN_EVIDENCE_RELATIVE_PATH)
}

fn parse_unix_ms_utc_date(unix_ms: u64) -> Option<time::Date> {
    let unix_secs = i64::try_from(unix_ms / 1000).ok()?;
    OffsetDateTime::from_unix_timestamp(unix_secs)
        .ok()
        .map(|timestamp| timestamp.date())
}

fn is_same_utc_day(lhs_unix_ms: u64, rhs_unix_ms: u64) -> bool {
    parse_unix_ms_utc_date(lhs_unix_ms) == parse_unix_ms_utc_date(rhs_unix_ms)
}

fn load_manual_lab_black_screen_evidence(
    control_artifact_root: &Path,
) -> anyhow::Result<(PathBuf, ManualLabBlackScreenEvidence)> {
    let evidence_path = manual_lab_black_screen_evidence_path(control_artifact_root);
    let bytes = fs::read(&evidence_path).with_context(|| format!("read {}", evidence_path.display()))?;
    let evidence = serde_json::from_slice(&bytes).with_context(|| format!("parse {}", evidence_path.display()))?;
    Ok((evidence_path, evidence))
}

pub fn build_manual_lab_black_screen_control_run_comparison_summary(
    evidence: &ManualLabBlackScreenEvidence,
) -> ManualLabBlackScreenControlRunComparisonSummary {
    let mut summary = ManualLabBlackScreenControlRunComparisonSummary {
        schema_version: MANUAL_LAB_BLACK_SCREEN_CONTROL_COMPARISON_SCHEMA_VERSION,
        ..Default::default()
    };

    if evidence.is_control_lane {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::NotRequiredForControlLane;
        summary.detail =
            Some("control lane is the comparison baseline, so a sibling control run is not required".to_owned());
        return summary;
    }

    let Some(current_run_started_at_unix_ms) = evidence.run_started_at_unix_ms else {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::MissingCurrentRunTimestamp;
        summary.detail = Some("variant run is missing a current run_started_at_unix_ms timestamp".to_owned());
        return summary;
    };

    let Some(control_artifact_root) = build_black_screen_control_artifact_root_from_env(&evidence.env) else {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::MissingControlArtifactRoot;
        summary.detail = Some(format!(
            "variant run is missing {} for same-day control comparison",
            HONEYPOT_BS_CONTROL_ARTIFACT_ROOT_ENV
        ));
        return summary;
    };
    summary.control_artifact_root = Some(control_artifact_root.clone());

    let (control_evidence_path, control_evidence) = match load_manual_lab_black_screen_evidence(&control_artifact_root)
    {
        Ok(loaded) => loaded,
        Err(error) => {
            let control_evidence_path = manual_lab_black_screen_evidence_path(&control_artifact_root);
            summary.control_evidence_path = Some(control_evidence_path.clone());
            if !control_evidence_path.is_file() {
                summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::MissingControlEvidence;
                summary.detail = Some(format!(
                    "variant run could not find sibling control evidence at {}",
                    control_evidence_path.display()
                ));
                return summary;
            }
            summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::InvalidControlEvidence;
            summary.detail = Some(format!(
                "variant run could not load sibling control evidence from {}: {error:#}",
                control_evidence_path.display()
            ));
            return summary;
        }
    };
    summary.control_evidence_path = Some(control_evidence_path);
    summary.control_run_started_at_unix_ms = control_evidence.run_started_at_unix_ms;
    summary.control_run_verdict = Some(control_evidence.run_verdict_summary.verdict);
    summary.control_run_primary_reason = Some(control_evidence.run_verdict_summary.primary_reason);

    if !control_evidence.is_control_lane {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::ControlRunNotControlLane;
        summary.detail = Some("sibling control evidence is not marked as a control lane run".to_owned());
        return summary;
    }

    let Some(control_run_started_at_unix_ms) = control_evidence.run_started_at_unix_ms else {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::ControlRunMissingTimestamp;
        summary.detail = Some("sibling control evidence is missing a run_started_at_unix_ms timestamp".to_owned());
        return summary;
    };

    if control_evidence.run_verdict_summary.schema_version != MANUAL_LAB_BLACK_SCREEN_RUN_VERDICT_SCHEMA_VERSION
        || control_evidence.run_verdict_summary.reason_codes.is_empty()
    {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::ControlRunMissingVerdict;
        summary.detail = Some("sibling control evidence is missing a current run verdict summary".to_owned());
        return summary;
    }

    if !is_same_utc_day(current_run_started_at_unix_ms, control_run_started_at_unix_ms) {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::StaleControlRun;
        summary.detail = Some(format!(
            "variant run timestamp {} and control run timestamp {} were not recorded on the same UTC day",
            current_run_started_at_unix_ms, control_run_started_at_unix_ms
        ));
        return summary;
    }

    let expected_contract = build_manual_lab_black_screen_artifact_contract_summary(evidence);
    if control_evidence.artifact_contract_summary != expected_contract {
        summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::ArtifactContractMismatch;
        summary.detail = Some("sibling control evidence did not persist the same artifact contract summary".to_owned());
        return summary;
    }

    summary.verdict = ManualLabBlackScreenControlRunComparisonVerdict::MeaningfulWithSameDayControl;
    summary.detail = Some(format!(
        "variant lane {} is backed by same-day control evidence from {} with verdict {:?}",
        evidence.driver_lane,
        control_artifact_root.display(),
        control_evidence.run_verdict_summary.verdict
    ));
    summary
}

pub fn build_manual_lab_black_screen_do_not_retry_ledger(
    evidence: &ManualLabBlackScreenEvidence,
) -> ManualLabBlackScreenDoNotRetryLedger {
    let mut ledger = ManualLabBlackScreenDoNotRetryLedger {
        schema_version: MANUAL_LAB_BLACK_SCREEN_DO_NOT_RETRY_SCHEMA_VERSION,
        ..Default::default()
    };

    if evidence.run_verdict_summary.verdict == ManualLabBlackScreenRunVerdict::UsablePlayback {
        ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::NotRequired;
        ledger.detail =
            Some("run reached usable playback, so no disproven-hypothesis ledger entry was required".to_owned());
        return ledger;
    }

    if evidence.hypothesis.hypothesis_id.trim().is_empty() {
        ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::MissingHypothesisId;
        ledger.detail =
            Some("non-green run is missing DGW_HONEYPOT_BS_HYPOTHESIS_ID for the do-not-retry ledger".to_owned());
        return ledger;
    }

    if evidence.hypothesis.hypothesis_text.trim().is_empty() {
        ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::MissingHypothesisText;
        ledger.detail =
            Some("non-green run is missing DGW_HONEYPOT_BS_HYPOTHESIS_TEXT for the do-not-retry ledger".to_owned());
        return ledger;
    }

    if evidence.hypothesis.retry_condition_text.trim().is_empty() {
        ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::MissingRetryCondition;
        ledger.detail =
            Some("non-green run is missing DGW_HONEYPOT_BS_RETRY_CONDITION for the do-not-retry ledger".to_owned());
        return ledger;
    }

    let Some(retry_condition) = ManualLabBlackScreenRetryCondition::parse(&evidence.hypothesis.retry_condition_text)
    else {
        ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::InvalidRetryCondition;
        ledger.detail = Some(format!(
            "non-green run provided unsupported retry condition {:?}",
            evidence.hypothesis.retry_condition_text
        ));
        return ledger;
    };

    ledger.verdict = ManualLabBlackScreenDoNotRetryLedgerVerdict::EntryRecorded;
    ledger.entries.push(ManualLabBlackScreenDoNotRetryLedgerEntry {
        hypothesis_id: evidence.hypothesis.hypothesis_id.clone(),
        hypothesis_text: evidence.hypothesis.hypothesis_text.clone(),
        bs_rows: evidence.bs_rows.clone(),
        git_rev: evidence.git_rev.clone(),
        failing_lane: evidence.driver_lane.clone(),
        artifact_root: evidence.artifact_root.clone(),
        run_verdict: evidence.run_verdict_summary.verdict,
        rejection_reason_code: evidence.run_verdict_summary.primary_reason,
        retry_condition,
    });
    ledger.detail = Some(format!(
        "recorded do-not-retry ledger entry for hypothesis {} from lane {}",
        evidence.hypothesis.hypothesis_id, evidence.driver_lane
    ));
    ledger
}

fn event_payload_timestamp_unix_ms(event: &EventEnvelope) -> Option<u64> {
    let payload_time = match &event.payload {
        EventPayload::SessionStarted { started_at, .. } => Some(started_at.as_str()),
        EventPayload::SessionAssigned { assigned_at, .. } => Some(assigned_at.as_str()),
        EventPayload::SessionStreamReady { ready_at, .. } => Some(ready_at.as_str()),
        EventPayload::SessionEnded { ended_at, .. } => Some(ended_at.as_str()),
        EventPayload::SessionKilled { killed_at, .. } => Some(killed_at.as_str()),
        EventPayload::SessionRecycleRequested { requested_at, .. } => Some(requested_at.as_str()),
        EventPayload::HostRecycled { completed_at, .. } => Some(completed_at.as_str()),
        EventPayload::SessionStreamFailed { failed_at, .. } => Some(failed_at.as_str()),
        EventPayload::ProxyStatusDegraded { degraded_at, .. } => Some(degraded_at.as_str()),
    };

    payload_time
        .and_then(parse_rfc3339_timestamp_unix_ms)
        .or_else(|| parse_rfc3339_timestamp_unix_ms(&event.emitted_at))
}

fn build_manual_lab_playback_artifact_timeline_summary(
    session_events: &[EventEnvelope],
    playback_ready_correlation: &ManualLabSessionPlaybackReadyCorrelation,
    player_websocket_summary: &ManualLabSessionPlayerWebsocketSummary,
    recordings_root: &Path,
    session_id: &str,
) -> ManualLabSessionPlaybackArtifactTimelineSummary {
    let session_started_at_unix_ms = session_events.iter().find_map(|event| match event.payload {
        EventPayload::SessionStarted { .. } => event_payload_timestamp_unix_ms(event),
        _ => None,
    });
    let session_assigned_at_unix_ms = session_events.iter().find_map(|event| match event.payload {
        EventPayload::SessionAssigned { .. } => event_payload_timestamp_unix_ms(event),
        _ => None,
    });
    let session_stream_ready_at_unix_ms = session_events.iter().find_map(|event| match event.payload {
        EventPayload::SessionStreamReady { .. } => event_payload_timestamp_unix_ms(event),
        _ => None,
    });
    let session_stream_failed_at_unix_ms = session_events.iter().find_map(|event| match event.payload {
        EventPayload::SessionStreamFailed { .. } => event_payload_timestamp_unix_ms(event),
        _ => None,
    });
    let websocket_open_at_unix_ms = player_websocket_summary.opened_at_unix_ms;
    let websocket_first_message_at_unix_ms = player_websocket_summary.first_message_at_unix_ms;
    let recording_first_chunk_appended_at_unix_ms = playback_ready_correlation.first_chunk_appended_at_unix_ms;
    let recording_connected_at_unix_ms = playback_ready_correlation.recording_connected_at_unix_ms;
    let recording_artifacts =
        collect_manual_lab_recording_artifact_samples(recordings_root, session_id).unwrap_or_default();
    let recording_artifact_present = !recording_artifacts.is_empty();
    let recording_artifact_count = recording_artifacts
        .len()
        .try_into()
        .expect("recording artifact count should fit in u64");
    let recording_artifact_max_size_bytes = recording_artifacts.iter().map(|sample| sample.size_bytes).max();
    let recording_artifact_latest_modified_at_unix_ms = recording_artifacts
        .iter()
        .filter_map(|sample| sample.modified_at_unix_ms)
        .max();

    let mut timeline_gaps = Vec::new();
    if session_started_at_unix_ms.is_none() {
        timeline_gaps.push("missing session.started".to_owned());
    }
    if session_assigned_at_unix_ms.is_none() {
        timeline_gaps.push("missing session.assigned".to_owned());
    }
    if session_stream_ready_at_unix_ms.is_none() && session_stream_failed_at_unix_ms.is_none() {
        timeline_gaps.push("missing session.stream.ready and session.stream.failed".to_owned());
    }
    if session_stream_ready_at_unix_ms.is_some() && websocket_open_at_unix_ms.is_none() {
        timeline_gaps.push("missing websocket_open for ready session".to_owned());
    }
    if !recording_artifact_present {
        timeline_gaps.push("missing recording-*.webm artifact".to_owned());
    }
    if recording_first_chunk_appended_at_unix_ms.is_none() {
        timeline_gaps.push("missing playback.chunk.appended.first".to_owned());
    }

    let (verdict, confidence, detail) = if session_stream_failed_at_unix_ms.is_some()
        && recording_first_chunk_appended_at_unix_ms.is_none()
        && !recording_artifact_present
    {
        (
            ManualLabPlaybackArtifactTimelineVerdict::StreamFailedBeforeRecording,
            ManualLabEvidenceConfidence::High,
            Some("session.stream.failed landed before any recording artifact or first-chunk signal".to_owned()),
        )
    } else if session_stream_ready_at_unix_ms.is_some()
        && websocket_open_at_unix_ms.is_some()
        && recording_first_chunk_appended_at_unix_ms.is_some()
        && recording_artifact_present
    {
        (
            ManualLabPlaybackArtifactTimelineVerdict::CorrelatedReadyPlayback,
            if session_started_at_unix_ms.is_some() && session_assigned_at_unix_ms.is_some() {
                ManualLabEvidenceConfidence::High
            } else {
                ManualLabEvidenceConfidence::Medium
            },
            Some(
                "session lifecycle, websocket attach, and recording artifact signals aligned on one ready path"
                    .to_owned(),
            ),
        )
    } else if websocket_open_at_unix_ms.is_some() && session_stream_ready_at_unix_ms.is_none() {
        (
            ManualLabPlaybackArtifactTimelineVerdict::WebsocketAttachedWithoutReady,
            ManualLabEvidenceConfidence::Medium,
            Some("websocket attached without a correlated session.stream.ready event".to_owned()),
        )
    } else if session_stream_ready_at_unix_ms.is_some()
        && (!recording_artifact_present || recording_first_chunk_appended_at_unix_ms.is_none())
    {
        (
            ManualLabPlaybackArtifactTimelineVerdict::MissingRecordingArtifact,
            ManualLabEvidenceConfidence::Medium,
            Some("session.stream.ready was emitted without a correlated recording artifact growth signal".to_owned()),
        )
    } else {
        (
            ManualLabPlaybackArtifactTimelineVerdict::Inconclusive,
            ManualLabEvidenceConfidence::Low,
            Some(
                "the available session, websocket, and recording signals did not satisfy a tighter BS-31 verdict"
                    .to_owned(),
            ),
        )
    };

    ManualLabSessionPlaybackArtifactTimelineSummary {
        schema_version: MANUAL_LAB_PLAYBACK_ARTIFACT_TIMELINE_SCHEMA_VERSION,
        verdict,
        confidence,
        detail,
        session_started_at_unix_ms,
        session_assigned_at_unix_ms,
        session_stream_ready_at_unix_ms,
        session_stream_failed_at_unix_ms,
        websocket_open_at_unix_ms,
        websocket_first_message_at_unix_ms,
        recording_first_chunk_appended_at_unix_ms,
        recording_connected_at_unix_ms,
        recording_artifact_present,
        recording_artifact_count,
        recording_artifact_max_size_bytes,
        recording_artifact_latest_modified_at_unix_ms,
        timeline_gaps,
    }
}

fn write_manual_lab_player_websocket_artifact(
    output_path: &Path,
    events: &[ManualLabPlayerWebsocketEvent],
) -> anyhow::Result<()> {
    if events.is_empty() {
        return Ok(());
    }

    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }

    let mut ordered_events = events.to_vec();
    ordered_events.sort_by_key(|event| event.observed_at_unix_ms);

    let mut body = String::new();
    for event in &ordered_events {
        body.push_str(&serde_json::to_string(event).context("serialize aggregated player websocket event")?);
        body.push('\n');
    }

    fs::write(output_path, body).with_context(|| format!("write {}", output_path.display()))
}

fn parse_manual_lab_fastpath_warning_line(line: &str) -> Option<ManualLabFastPathWarningEvent> {
    if !line.contains("Passive FastPath observer") {
        return None;
    }

    let warn_code = parse_manual_lab_log_field(line, "warn_code")
        .map(ToOwned::to_owned)
        .or_else(|| {
            if line.contains("failed to process server frame") {
                Some("fastpath_process_server_frame_error".to_owned())
            } else if line.contains("dropped an invalid RDP frame prefix") {
                Some("fastpath_invalid_rdp_frame_prefix".to_owned())
            } else {
                None
            }
        })?;
    let session_id = parse_manual_lab_log_field(line, "session_id")
        .map(str::trim)
        .filter(|value| !value.is_empty() && *value != "none" && *value != "unbound")
        .map(ToOwned::to_owned);

    Some(ManualLabFastPathWarningEvent {
        session_id,
        warn_code,
        observed_at_unix_ms: parse_manual_lab_log_prefix_timestamp_unix_ms(line),
    })
}

fn parse_manual_lab_fastpath_warning_events(
    proxy_stdout_log: &Path,
) -> anyhow::Result<Vec<ManualLabFastPathWarningEvent>> {
    if !proxy_stdout_log.exists() {
        return Ok(Vec::new());
    }

    let log = fs::read_to_string(proxy_stdout_log).with_context(|| format!("read {}", proxy_stdout_log.display()))?;
    Ok(log.lines().filter_map(parse_manual_lab_fastpath_warning_line).collect())
}

fn build_manual_lab_fastpath_warning_summary(
    events: &[ManualLabFastPathWarningEvent],
    unattributed_warning_count: u64,
    correlation: &ManualLabSessionPlaybackReadyCorrelation,
    aligned_ready_baseline_warn_codes: &BTreeSet<String>,
) -> ManualLabSessionFastPathWarningSummary {
    let mut summary = ManualLabSessionFastPathWarningSummary {
        schema_version: MANUAL_LAB_FASTPATH_WARNING_SCHEMA_VERSION,
        with_session_id_count: events
            .iter()
            .filter(|event| event.session_id.is_some())
            .count()
            .try_into()
            .expect("with-session fastpath warning count should fit in u64"),
        without_session_id_count: unattributed_warning_count,
        ..Default::default()
    };

    let mut known_noise_warn_codes = BTreeSet::new();
    let mut candidate_root_cause_warn_codes = BTreeSet::new();
    let mut uncertain_warn_codes = BTreeSet::new();

    for event in events {
        summary.total_warning_count = summary.total_warning_count.saturating_add(1);

        match event.warn_code.as_str() {
            "fastpath_process_server_frame_error" => {
                summary.process_server_frame_error_count = summary.process_server_frame_error_count.saturating_add(1);
            }
            "fastpath_invalid_rdp_frame_prefix" => {
                summary.invalid_rdp_frame_prefix_count = summary.invalid_rdp_frame_prefix_count.saturating_add(1);
            }
            _ => {}
        }

        if let Some(observed_at_unix_ms) = event.observed_at_unix_ms {
            if let Some(source_ready_at_unix_ms) = correlation.source_ready_at_unix_ms {
                if observed_at_unix_ms < source_ready_at_unix_ms {
                    summary.before_source_ready_count = summary.before_source_ready_count.saturating_add(1);
                } else {
                    summary.after_source_ready_count = summary.after_source_ready_count.saturating_add(1);
                }
            } else {
                summary.before_source_ready_count = summary.before_source_ready_count.saturating_add(1);
            }

            if let Some(stream_ready_at_unix_ms) = correlation.session_stream_ready_emitted_at_unix_ms {
                if observed_at_unix_ms < stream_ready_at_unix_ms {
                    summary.before_stream_ready_count = summary.before_stream_ready_count.saturating_add(1);
                } else {
                    summary.after_stream_ready_count = summary.after_stream_ready_count.saturating_add(1);
                }
            } else {
                summary.before_stream_ready_count = summary.before_stream_ready_count.saturating_add(1);
            }
        }

        let is_known_noise = aligned_ready_baseline_warn_codes.contains(&event.warn_code);
        let is_candidate_root_cause = !is_known_noise
            && correlation.verdict != ManualLabPlaybackReadyVerdict::AlignedReady
            && event.observed_at_unix_ms.is_some();

        if is_known_noise {
            summary.known_noise_count = summary.known_noise_count.saturating_add(1);
            known_noise_warn_codes.insert(event.warn_code.clone());
        } else if is_candidate_root_cause {
            summary.candidate_root_cause_count = summary.candidate_root_cause_count.saturating_add(1);
            candidate_root_cause_warn_codes.insert(event.warn_code.clone());
        } else {
            summary.uncertain_count = summary.uncertain_count.saturating_add(1);
            uncertain_warn_codes.insert(event.warn_code.clone());
        }
    }

    summary.total_warning_count = summary.total_warning_count.saturating_add(unattributed_warning_count);
    if unattributed_warning_count > 0 {
        summary.uncertain_count = summary.uncertain_count.saturating_add(unattributed_warning_count);
        uncertain_warn_codes.insert("unattributed_fastpath_warning".to_owned());
    }

    summary.known_noise_warn_codes = known_noise_warn_codes.into_iter().collect();
    summary.candidate_root_cause_warn_codes = candidate_root_cause_warn_codes.into_iter().collect();
    summary.uncertain_warn_codes = uncertain_warn_codes.into_iter().collect();
    summary.overall_evidence = if summary.candidate_root_cause_count > 0 {
        ManualLabFastPathWarningEvidence::CandidateRootCause
    } else if summary.total_warning_count > 0 && summary.uncertain_count == 0 {
        ManualLabFastPathWarningEvidence::KnownNoise
    } else {
        ManualLabFastPathWarningEvidence::Uncertain
    };

    summary
}

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

fn parse_rfc3339_timestamp_unix_ms(value: &str) -> Option<u64> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339).ok()?;
    let unix_ms = parsed.unix_timestamp_nanos().div_euclid(1_000_000);
    u64::try_from(unix_ms).ok()
}

fn parse_manual_lab_session_events_sse_body(body: &[u8]) -> anyhow::Result<Vec<EventEnvelope>> {
    let text = String::from_utf8(body.to_vec()).context("decode honeypot SSE body as UTF-8")?;
    let mut events = Vec::new();
    let mut data_lines = Vec::<String>::new();

    for line in text.lines() {
        if line.is_empty() {
            if !data_lines.is_empty() {
                let payload = data_lines.join("\n");
                if let Ok(event) = serde_json::from_str::<EventEnvelope>(&payload) {
                    events.push(event);
                }
                data_lines.clear();
            }
            continue;
        }

        if line.starts_with(':') {
            continue;
        }

        if let Some(data_line) = line.strip_prefix("data:") {
            data_lines.push(data_line.trim_start().to_owned());
        }
    }

    if !data_lines.is_empty() {
        let payload = data_lines.join("\n");
        if let Ok(event) = serde_json::from_str::<EventEnvelope>(&payload) {
            events.push(event);
        }
    }

    Ok(events)
}

fn write_manual_lab_session_events_artifact(path: &Path, events: &[EventEnvelope]) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    fs::write(
        path,
        serde_json::to_vec_pretty(events).context("serialize manual lab session events")?,
    )
    .with_context(|| format!("write {}", path.display()))
}

fn refresh_manual_lab_session_events_artifact(state: &ManualLabState, session_events_log: &Path) -> anyhow::Result<()> {
    if !process_is_running(state.proxy.pid) {
        return Ok(());
    }

    let headers = [
        authorization_header(scope_token(MANUAL_LAB_WILDCARD_SCOPE)),
        ("Accept".to_owned(), "text/event-stream".to_owned()),
        ("Cache-Control".to_owned(), "no-cache".to_owned()),
    ];
    let (status, body) = send_http_request_stream_snapshot(
        state.ports.proxy_http,
        "GET",
        "/jet/honeypot/events?cursor=0",
        &headers,
        None,
        Duration::from_secs(2),
    )?;
    ensure!(
        status.contains("200"),
        "unexpected HTTP status for GET /jet/honeypot/events on port {}: {status}",
        state.ports.proxy_http,
    );
    let events = parse_manual_lab_session_events_sse_body(&body)?;
    write_manual_lab_session_events_artifact(session_events_log, &events)
}

fn parse_manual_lab_session_event_log(
    session_events_log: &Path,
) -> anyhow::Result<BTreeMap<String, Vec<EventEnvelope>>> {
    if !session_events_log.exists() {
        return Ok(BTreeMap::new());
    }

    let events = serde_json::from_slice::<Vec<EventEnvelope>>(
        &fs::read(session_events_log).with_context(|| format!("read {}", session_events_log.display()))?,
    )
    .with_context(|| format!("decode {}", session_events_log.display()))?;

    let mut grouped = BTreeMap::<String, Vec<EventEnvelope>>::new();
    for event in events {
        let Some(session_id) = event.session_id.clone() else {
            continue;
        };
        grouped.entry(session_id).or_default().push(event);
    }

    for session_events in grouped.values_mut() {
        session_events.sort_by_key(|event| (event.session_seq, event.global_cursor.parse::<u64>().unwrap_or(0)));
    }

    Ok(grouped)
}

fn collect_manual_lab_recording_artifact_samples(
    recordings_root: &Path,
    session_id: &str,
) -> anyhow::Result<Vec<ManualLabRecordingArtifactSample>> {
    let session_root = recordings_root.join(session_id);
    if !session_root.exists() {
        return Ok(Vec::new());
    }

    let mut samples = Vec::new();
    for entry in fs::read_dir(&session_root).with_context(|| format!("read {}", session_root.display()))? {
        let entry = entry.with_context(|| format!("read {}", session_root.display()))?;
        let path = entry.path();
        if !entry
            .file_type()
            .with_context(|| format!("inspect {}", path.display()))?
            .is_file()
        {
            continue;
        }

        let Some(file_name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if !(file_name.starts_with("recording-") && file_name.ends_with(".webm")) {
            continue;
        }

        let metadata = entry
            .metadata()
            .with_context(|| format!("read metadata for {}", path.display()))?;
        let modified_at_unix_ms = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .and_then(|duration| u64::try_from(duration.as_millis()).ok());
        samples.push(ManualLabRecordingArtifactSample {
            path,
            size_bytes: metadata.len(),
            modified_at_unix_ms,
        });
    }

    samples.sort_by_key(|sample| (sample.modified_at_unix_ms.unwrap_or(0), sample.size_bytes));
    Ok(samples)
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
    let evidence_path = manual_lab_black_screen_evidence_path(&state.run_root);
    let mut evidence = state.black_screen_evidence.clone();
    if evidence.teardown_started_at_unix_ms.is_none() {
        evidence.teardown_started_at_unix_ms = teardown_started_at_unix_ms;
    }
    let artifacts = build_black_screen_artifact_paths(state);
    let _ = refresh_manual_lab_session_events_artifact(state, &artifacts.session_events_log);
    evidence.artifacts = artifacts;
    let playback_bootstrap_timelines = parse_manual_lab_playback_bootstrap_timelines(&state.proxy.stdout_log)?;
    let ready_trace_events = parse_manual_lab_ready_trace_events(&state.proxy.stdout_log)?;
    let session_events = parse_manual_lab_session_event_log(&evidence.artifacts.session_events_log)?;
    let gfx_filter_summaries = parse_manual_lab_gfx_filter_summaries(&state.proxy.stdout_log)?;
    let fastpath_warning_events = parse_manual_lab_fastpath_warning_events(&state.proxy.stdout_log)?;
    let gfx_warning_summaries = parse_manual_lab_gfx_warning_summaries(&state.proxy.stdout_log)?;
    let recording_visibility_chrome = state.chrome_binary.clone().or_else(|| resolve_chrome_binary().ok());
    let unattributed_fastpath_warning_count = fastpath_warning_events
        .iter()
        .filter(|event| event.session_id.is_none())
        .count()
        .try_into()
        .expect("unattributed fastpath warning count should fit in u64");
    let session_evidence = state
        .sessions
        .iter()
        .map(|session| -> anyhow::Result<_> {
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
            let fastpath_warnings = fastpath_warning_events
                .iter()
                .filter(|event| event.session_id.as_deref() == Some(session.session_id.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            let gfx_warning_summary = gfx_warning_summaries.get(&session.session_id).cloned();
            let player_websocket_events =
                parse_manual_lab_player_websocket_events(&evidence.artifacts.recordings_root, &session.session_id)?;
            let session_events = session_events.get(&session.session_id).cloned().unwrap_or_default();

            Ok((
                session,
                session_events,
                playback_bootstrap_timeline,
                playback_ready_correlation,
                player_websocket_events,
                gfx_filter_summary,
                fastpath_warnings,
                gfx_warning_summary,
            ))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;
    let aligned_ready_fastpath_warn_codes = session_evidence
        .iter()
        .filter(|(_, _, _, correlation, _, _, _, _)| correlation.verdict == ManualLabPlaybackReadyVerdict::AlignedReady)
        .flat_map(|(_, _, _, _, _, _, fastpath_warnings, _)| {
            fastpath_warnings.iter().map(|event| event.warn_code.clone())
        })
        .collect::<BTreeSet<_>>();
    let aligned_ready_warning_summaries = session_evidence
        .iter()
        .filter_map(|(_, _, _, correlation, _, _, _, gfx_warning_summary)| {
            (correlation.verdict == ManualLabPlaybackReadyVerdict::AlignedReady)
                .then_some(gfx_warning_summary.clone())
                .flatten()
        })
        .collect::<Vec<_>>();
    let aligned_ready_warning_baseline = build_manual_lab_gfx_warning_baseline(&aligned_ready_warning_summaries);
    let aligned_ready_baseline_session_count = aligned_ready_warning_summaries.len();
    let aggregated_player_websocket_events = session_evidence
        .iter()
        .flat_map(|(_, _, _, _, player_websocket_events, _, _, _)| player_websocket_events.clone())
        .collect::<Vec<_>>();
    write_manual_lab_player_websocket_artifact(
        &evidence.artifacts.player_websocket_log,
        &aggregated_player_websocket_events,
    )?;
    evidence.session_invocations = session_evidence
        .into_iter()
        .map(
            |(
                session,
                session_events,
                playback_bootstrap_timeline,
                playback_ready_correlation,
                player_websocket_events,
                gfx_filter_summary,
                fastpath_warnings,
                gfx_warning_summary,
            )| {
                let player_websocket_summary = build_manual_lab_player_websocket_summary(
                    &player_websocket_events,
                    evidence.teardown_started_at_unix_ms,
                );
                let player_playback_path_summary =
                    build_manual_lab_player_playback_path_summary(&player_websocket_events);
                let playback_artifact_timeline_summary = build_manual_lab_playback_artifact_timeline_summary(
                    &session_events,
                    &playback_ready_correlation,
                    &player_websocket_summary,
                    &evidence.artifacts.recordings_root,
                    &session.session_id,
                );
                let recording_visibility_summary = build_manual_lab_recording_visibility_summary(
                    &evidence.artifacts.recordings_root,
                    &session.session_id,
                    recording_visibility_chrome.as_deref(),
                    evidence.teardown_started_at_unix_ms,
                    None,
                    MANUAL_LAB_RECORDING_VISIBILITY_SUMMARY_FILENAME,
                );
                let browser_visibility_summary = build_manual_lab_browser_visibility_summary(&player_websocket_events);
                let artifact_visibility_at_browser_time = if let Some(representative_current_time_ms) =
                    browser_visibility_summary.representative_current_time_ms
                {
                    build_manual_lab_recording_visibility_summary(
                        &evidence.artifacts.recordings_root,
                        &session.session_id,
                        recording_visibility_chrome.as_deref(),
                        evidence.teardown_started_at_unix_ms,
                        Some(representative_current_time_ms),
                        MANUAL_LAB_RECORDING_VISIBILITY_AT_BROWSER_TIME_SUMMARY_FILENAME,
                    )
                } else {
                    ManualLabSessionRecordingVisibilitySummary {
                        schema_version: MANUAL_LAB_RECORDING_VISIBILITY_SCHEMA_VERSION,
                        verdict: ManualLabRecordingVisibilityVerdict::AnalysisUnavailable,
                        confidence: ManualLabEvidenceConfidence::Low,
                        detail: Some(
                            "browser visibility did not produce a representative playback time for artifact alignment"
                                .to_owned(),
                        ),
                        analysis_backend: recording_visibility_summary.analysis_backend.clone(),
                        recording_path: recording_visibility_summary.recording_path.clone(),
                        sample_window_ms: MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_WINDOW_MS,
                        sample_interval_ms: MANUAL_LAB_RECORDING_VISIBILITY_SAMPLE_INTERVAL_MS,
                        ..Default::default()
                    }
                };
                let browser_artifact_correlation_summary = build_manual_lab_browser_artifact_correlation_summary(
                    &browser_visibility_summary,
                    &artifact_visibility_at_browser_time,
                );
                let fastpath_warning_summary = build_manual_lab_fastpath_warning_summary(
                    &fastpath_warnings,
                    unattributed_fastpath_warning_count,
                    &playback_ready_correlation,
                    &aligned_ready_fastpath_warn_codes,
                );
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
                    player_websocket_summary,
                    player_playback_path_summary,
                    playback_artifact_timeline_summary,
                    recording_visibility_summary,
                    browser_visibility_summary,
                    artifact_visibility_at_browser_time,
                    browser_artifact_correlation_summary,
                    gfx_filter_summary,
                    fastpath_warning_summary: Some(fastpath_warning_summary),
                    gfx_warning_summary,
                    black_screen_branch,
                }
            },
        )
        .collect();
    evidence.multi_session_ready_path_summary =
        build_manual_lab_multi_session_ready_path_summary(&evidence.session_invocations, evidence.session_count);
    evidence.run_verdict_summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);
    evidence.do_not_retry_ledger = build_manual_lab_black_screen_do_not_retry_ledger(&evidence);
    evidence.artifact_contract_summary = build_manual_lab_black_screen_artifact_contract_summary(&evidence);
    evidence.control_run_comparison_summary = build_manual_lab_black_screen_control_run_comparison_summary(&evidence);
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
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;
    use std::time::Duration;

    use base64::Engine as _;
    use honeypot_contracts::events::{EventEnvelope, EventPayload, SessionState, StreamState};
    use honeypot_contracts::stream::StreamTransport;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tempfile::tempdir;

    use super::{
        ManualLabBlackScreenBranchVerdict, ManualLabBrowserArtifactCorrelationVerdict, ManualLabBrowserPlayerMode,
        ManualLabBrowserVisibilityDataStatus, ManualLabDriverKind, ManualLabEvidenceConfidence,
        ManualLabFastPathWarningEvent, ManualLabFastPathWarningEvidence, ManualLabPlaybackArtifactTimelineVerdict,
        ManualLabPlaybackBootstrapVerdict, ManualLabPlaybackReadyVerdict, ManualLabPlayerPlaybackModeVerdict,
        ManualLabPlayerWebsocketEvent, ManualLabRecordingVisibilityVerdict, ManualLabSessionBrowserVisibilitySummary,
        ManualLabSessionGfxFilterSummary, ManualLabSessionGfxWarningSummary, ManualLabSessionPlaybackBootstrapEvent,
        ManualLabSessionPlayerPlaybackPathSummary, ManualLabSessionPlayerWebsocketSummary,
        ManualLabSessionReadyTraceEvent, ManualLabSessionRecordingVisibilitySummary, ManualLabXfreerdpGraphicsMode,
        association_token, build_manual_lab_black_screen_branch, build_manual_lab_browser_artifact_correlation_summary,
        build_manual_lab_browser_visibility_summary, build_manual_lab_fastpath_warning_summary,
        build_manual_lab_gfx_warning_baseline, build_manual_lab_playback_artifact_timeline_summary,
        build_manual_lab_playback_bootstrap_timeline, build_manual_lab_playback_ready_correlation,
        build_manual_lab_player_playback_path_summary, build_manual_lab_player_websocket_summary,
        build_session_records, discover_manual_lab_source_manifest_candidates_in_root, display_socket_path,
        evaluate_manual_lab_source_manifest_candidate, ironrdp_driver_args, manual_lab_manifest_path,
        manual_lab_service_ready_timeout, parse_manual_lab_fastpath_warning_line,
        parse_manual_lab_gfx_filter_summary_line, parse_manual_lab_gfx_warning_summary_line,
        parse_manual_lab_playback_bootstrap_trace_line, parse_manual_lab_player_websocket_events,
        parse_manual_lab_ready_trace_line, parse_proc_stat_process_state, xfreerdp_driver_args,
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

    fn player_websocket_event(session_id: &str, kind: &str, observed_at_unix_ms: u64) -> ManualLabPlayerWebsocketEvent {
        ManualLabPlayerWebsocketEvent {
            schema_version: 1,
            session_id: session_id.to_owned(),
            observed_at_unix_ms,
            kind: kind.to_owned(),
            ..Default::default()
        }
    }

    fn session_event(session_id: &str, session_seq: u64, emitted_at: &str, payload: EventPayload) -> EventEnvelope {
        EventEnvelope {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            event_id: format!("honeypot-event-{session_seq}"),
            correlation_id: format!("honeypot-correlation-{session_seq}"),
            emitted_at: emitted_at.to_owned(),
            session_id: Some(session_id.to_owned()),
            vm_lease_id: Some("lease-00000001".to_owned()),
            stream_id: Some("stream-00000001".to_owned()),
            global_cursor: session_seq.to_string(),
            session_seq,
            payload,
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
    fn manual_lab_parses_fastpath_warning_lines() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let line = format!(
            "2026-03-28T22:00:02.000000Z  WARN ThreadId(42) session_id={session_id} warn_code=fastpath_process_server_frame_error warn_category=fastpath warn_phase=frame_process error=\"oops\" Passive FastPath observer failed to process server frame"
        );

        let parsed = parse_manual_lab_fastpath_warning_line(&line);
        assert_eq!(
            parsed,
            Some(ManualLabFastPathWarningEvent {
                session_id: Some(session_id.to_owned()),
                warn_code: "fastpath_process_server_frame_error".to_owned(),
                observed_at_unix_ms: Some(1_774_735_202_000),
            })
        );
    }

    #[test]
    fn manual_lab_parses_player_websocket_events_from_recording_dir() {
        let temp = tempdir().expect("tempdir");
        let session_id = "11111111-2222-3333-4444-555555555555";
        let session_dir = temp.path().join(session_id);
        fs::create_dir_all(&session_dir).expect("create session dir");
        let log_path = session_dir.join("player-websocket.ndjson");
        fs::write(
            &log_path,
            concat!(
                "{\"schemaVersion\":1,\"sessionId\":\"11111111-2222-3333-4444-555555555555\",\"observedAtUnixMs\":10,\"kind\":\"websocket_open\",\"openedAtUnixMs\":10}\n",
                "{\"schemaVersion\":1,\"sessionId\":\"11111111-2222-3333-4444-555555555555\",\"observedAtUnixMs\":20,\"kind\":\"websocket_close_raw\",\"closedAtUnixMs\":25,\"elapsedMsSinceOpen\":15,\"rawCloseCode\":4001,\"rawCloseReason\":\"streaming ended\",\"activeMode\":true,\"fallbackStarted\":false}\n"
            ),
        )
        .expect("write websocket log");

        let events =
            parse_manual_lab_player_websocket_events(temp.path(), session_id).expect("parse player websocket events");

        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, "websocket_open");
        assert_eq!(events[1].raw_close_code, Some(4001));
        assert_eq!(events[1].elapsed_ms_since_open, Some(15));
    }

    #[test]
    fn manual_lab_parses_browser_visibility_window_events_from_recording_dir() {
        let temp = tempdir().expect("tempdir");
        let session_id = "11111111-2222-3333-4444-555555555555";
        let session_dir = temp.path().join(session_id);
        fs::create_dir_all(&session_dir).expect("create session dir");
        let log_path = session_dir.join("player-websocket.ndjson");
        fs::write(
            &log_path,
            concat!(
                "{\"schemaVersion\":1,\"sessionId\":\"11111111-2222-3333-4444-555555555555\",\"observedAtUnixMs\":10,\"kind\":\"browser_visibility_window\",\"playerMode\":\"active_live\",\"windowIndex\":2,\"windowPhase\":\"steady\",\"sampleCount\":6,\"validSampleCount\":4,\"sampleStatus\":\"ready\",\"visibilityVerdict\":\"visible_frame\",\"representativeCurrentTimeMs\":4510,\"maxNonBlackRatioPerMille\":27,\"meanNonBlackRatioPerMille\":11,\"transitionObserved\":false}\n"
            ),
        )
        .expect("write websocket log");

        let events =
            parse_manual_lab_player_websocket_events(temp.path(), session_id).expect("parse player websocket events");

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "browser_visibility_window");
        assert_eq!(events[0].player_mode.as_deref(), Some("active_live"));
        assert_eq!(events[0].window_phase.as_deref(), Some("steady"));
        assert_eq!(events[0].representative_current_time_ms, Some(4510));
        assert_eq!(events[0].max_non_black_ratio_per_mille, Some(27));
    }

    #[test]
    fn manual_lab_builds_player_websocket_summary_with_raw_and_transformed_close() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut open = player_websocket_event(session_id, "websocket_open", 100);
        open.opened_at_unix_ms = Some(100);
        let mut raw_close = player_websocket_event(session_id, "websocket_close_raw", 160);
        raw_close.closed_at_unix_ms = Some(160);
        raw_close.elapsed_ms_since_open = Some(60);
        raw_close.raw_close_code = Some(4001);
        raw_close.raw_close_reason = Some("streaming ended".to_owned());
        raw_close.active_mode = Some(true);
        raw_close.fallback_started = Some(false);
        let mut transformed_close = player_websocket_event(session_id, "websocket_close_transformed", 165);
        transformed_close.closed_at_unix_ms = Some(165);
        transformed_close.elapsed_ms_since_open = Some(65);
        transformed_close.transformed_close_code = Some(1000);
        transformed_close.delivery_kind = Some("onclose".to_owned());
        transformed_close.active_mode = Some(false);
        transformed_close.fallback_started = Some(true);

        let summary = build_manual_lab_player_websocket_summary(&[open, raw_close, transformed_close], Some(200));

        assert_eq!(
            summary,
            ManualLabSessionPlayerWebsocketSummary {
                schema_version: 1,
                open_observed: true,
                first_message_observed: false,
                raw_close_observed: true,
                transformed_close_observed: true,
                opened_at_unix_ms: Some(100),
                first_message_at_unix_ms: None,
                closed_at_unix_ms: Some(160),
                capture_end_at_unix_ms: Some(200),
                elapsed_ms_since_open: Some(60),
                raw_close_code: Some(4001),
                raw_close_reason: Some("streaming ended".to_owned()),
                transformed_close_code: Some(1000),
                transformed_close_reason: None,
                delivery_kind: Some("onclose".to_owned()),
                active_mode_at_close: Some(true),
                fallback_started_before_close: Some(false),
                no_close_observed_by_teardown: false,
                detail: Some("websocket close observed code=4001 elapsed_since_open=60ms".to_owned()),
            }
        );
    }

    #[test]
    fn manual_lab_builds_player_websocket_summary_when_no_close_is_observed() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut open = player_websocket_event(session_id, "websocket_open", 100);
        open.opened_at_unix_ms = Some(100);
        let mut first_message = player_websocket_event(session_id, "websocket_first_message", 120);
        first_message.first_message_at_unix_ms = Some(120);
        first_message.elapsed_ms_since_open = Some(20);

        let summary = build_manual_lab_player_websocket_summary(&[open, first_message], Some(200));

        assert_eq!(summary.open_observed, true);
        assert_eq!(summary.first_message_observed, true);
        assert_eq!(summary.raw_close_observed, false);
        assert_eq!(summary.transformed_close_observed, false);
        assert_eq!(summary.no_close_observed_by_teardown, true);
        assert_eq!(summary.capture_end_at_unix_ms, Some(200));
        assert_eq!(
            summary.detail.as_deref(),
            Some("no websocket close was observed before teardown")
        );
    }

    #[test]
    fn manual_lab_builds_player_playback_path_summary_for_active_live_path() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut configured = player_websocket_event(session_id, "player_mode_configured", 100);
        configured.active_mode = Some(true);
        configured.fallback_started = Some(false);
        let mut open = player_websocket_event(session_id, "websocket_open", 105);
        open.active_mode = Some(true);
        open.fallback_started = Some(false);
        open.opened_at_unix_ms = Some(105);
        let mut fetch_started = player_websocket_event(session_id, "recording_info_fetch_started", 110);
        fetch_started.active_mode = Some(true);
        fetch_started.fallback_started = Some(false);
        fetch_started.request_url = Some("http://gateway/jet/jrec/pull/session/recording.json".to_owned());
        let mut fetch_succeeded = player_websocket_event(session_id, "recording_info_fetch_succeeded", 120);
        fetch_succeeded.active_mode = Some(true);
        fetch_succeeded.fallback_started = Some(false);
        fetch_succeeded.http_status = Some(200);

        let summary =
            build_manual_lab_player_playback_path_summary(&[configured, open, fetch_started, fetch_succeeded]);

        assert_eq!(
            summary,
            ManualLabSessionPlayerPlaybackPathSummary {
                schema_version: 1,
                verdict: ManualLabPlayerPlaybackModeVerdict::ActiveLivePath,
                detail: Some(
                    "active playback intent held and no static fallback or missing recording fetch was observed"
                        .to_owned(),
                ),
                active_intent_observed: true,
                active_intent_at_unix_ms: Some(100),
                static_playback_started_observed: false,
                static_playback_started_at_unix_ms: None,
                recording_info_fetch_attempted: true,
                recording_info_fetch_succeeded: true,
                recording_info_fetch_failed: false,
                recording_info_fetch_failed_at_unix_ms: None,
                recording_info_fetch_http_status: None,
                missing_artifact_while_active: false,
                telemetry_gap: false,
            }
        );
    }

    #[test]
    fn manual_lab_builds_player_playback_path_summary_for_static_fallback_during_active() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut configured = player_websocket_event(session_id, "player_mode_configured", 100);
        configured.active_mode = Some(true);
        configured.fallback_started = Some(false);
        let mut fallback = player_websocket_event(session_id, "static_playback_started", 150);
        fallback.active_mode = Some(false);
        fallback.fallback_started = Some(true);

        let summary = build_manual_lab_player_playback_path_summary(&[configured, fallback]);

        assert_eq!(
            summary,
            ManualLabSessionPlayerPlaybackPathSummary {
                schema_version: 1,
                verdict: ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive,
                detail: Some("static playback started after active playback intent was established".to_owned()),
                active_intent_observed: true,
                active_intent_at_unix_ms: Some(100),
                static_playback_started_observed: true,
                static_playback_started_at_unix_ms: Some(150),
                recording_info_fetch_attempted: false,
                recording_info_fetch_succeeded: false,
                recording_info_fetch_failed: false,
                recording_info_fetch_failed_at_unix_ms: None,
                recording_info_fetch_http_status: None,
                missing_artifact_while_active: false,
                telemetry_gap: false,
            }
        );
    }

    #[test]
    fn manual_lab_builds_player_playback_path_summary_for_missing_artifact_while_active() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut configured = player_websocket_event(session_id, "player_mode_configured", 100);
        configured.active_mode = Some(true);
        configured.fallback_started = Some(false);
        let mut fetch_failed = player_websocket_event(session_id, "recording_info_fetch_failed", 140);
        fetch_failed.active_mode = Some(true);
        fetch_failed.fallback_started = Some(false);
        fetch_failed.http_status = Some(404);
        fetch_failed.request_url = Some("http://gateway/jet/jrec/pull/session/recording.json".to_owned());

        let summary = build_manual_lab_player_playback_path_summary(&[configured, fetch_failed]);

        assert_eq!(
            summary,
            ManualLabSessionPlayerPlaybackPathSummary {
                schema_version: 1,
                verdict: ManualLabPlayerPlaybackModeVerdict::MissingArtifactProbeWhileActive,
                detail: Some(
                    "recording.json fetch failed with status 404 while active playback was still expected".to_owned(),
                ),
                active_intent_observed: true,
                active_intent_at_unix_ms: Some(100),
                static_playback_started_observed: false,
                static_playback_started_at_unix_ms: None,
                recording_info_fetch_attempted: true,
                recording_info_fetch_succeeded: false,
                recording_info_fetch_failed: true,
                recording_info_fetch_failed_at_unix_ms: Some(140),
                recording_info_fetch_http_status: Some(404),
                missing_artifact_while_active: true,
                telemetry_gap: false,
            }
        );
    }

    #[test]
    fn manual_lab_builds_browser_visibility_summary_preferring_steady_ready_window() {
        let session_id = "11111111-2222-3333-4444-555555555555";

        let mut startup = player_websocket_event(session_id, "browser_visibility_window", 100);
        startup.player_mode = Some("active_live".to_owned());
        startup.window_index = Some(0);
        startup.window_phase = Some("startup".to_owned());
        startup.sample_count = Some(5);
        startup.valid_sample_count = Some(3);
        startup.sample_status = Some("ready".to_owned());
        startup.visibility_verdict = Some("all_black".to_owned());
        startup.representative_current_time_ms = Some(450);
        startup.max_non_black_ratio_per_mille = Some(0);
        startup.mean_non_black_ratio_per_mille = Some(0);

        let mut steady = player_websocket_event(session_id, "browser_visibility_window", 300);
        steady.player_mode = Some("active_live".to_owned());
        steady.window_index = Some(2);
        steady.window_phase = Some("steady".to_owned());
        steady.sample_count = Some(8);
        steady.valid_sample_count = Some(6);
        steady.sample_status = Some("ready".to_owned());
        steady.visibility_verdict = Some("visible_frame".to_owned());
        steady.representative_current_time_ms = Some(4_520);
        steady.max_non_black_ratio_per_mille = Some(28);
        steady.mean_non_black_ratio_per_mille = Some(12);

        let summary = build_manual_lab_browser_visibility_summary(&[startup, steady]);

        assert_eq!(
            summary,
            ManualLabSessionBrowserVisibilitySummary {
                schema_version: 1,
                verdict: ManualLabRecordingVisibilityVerdict::VisibleFrame,
                confidence: ManualLabEvidenceConfidence::High,
                detail: Some("browser visibility selected steady window 2 with VisibleFrame at 4520ms".to_owned()),
                dominant_mode: ManualLabBrowserPlayerMode::ActiveLive,
                data_status: ManualLabBrowserVisibilityDataStatus::Ready,
                representative_current_time_ms: Some(4_520),
                valid_window_count: 2,
                transition_observed: false,
                max_non_black_ratio_per_mille: Some(28),
                windows: vec![
                    super::ManualLabSessionBrowserVisibilityWindowSummary {
                        window_index: 0,
                        window_phase: "startup".to_owned(),
                        player_mode: ManualLabBrowserPlayerMode::ActiveLive,
                        data_status: ManualLabBrowserVisibilityDataStatus::Ready,
                        verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
                        sample_count: 5,
                        valid_sample_count: 3,
                        window_start_at_unix_ms: None,
                        window_end_at_unix_ms: None,
                        representative_current_time_ms: Some(450),
                        video_width: None,
                        video_height: None,
                        max_non_black_ratio_per_mille: Some(0),
                        mean_non_black_ratio_per_mille: Some(0),
                        transition_observed: false,
                        detail: None,
                    },
                    super::ManualLabSessionBrowserVisibilityWindowSummary {
                        window_index: 2,
                        window_phase: "steady".to_owned(),
                        player_mode: ManualLabBrowserPlayerMode::ActiveLive,
                        data_status: ManualLabBrowserVisibilityDataStatus::Ready,
                        verdict: ManualLabRecordingVisibilityVerdict::VisibleFrame,
                        sample_count: 8,
                        valid_sample_count: 6,
                        window_start_at_unix_ms: None,
                        window_end_at_unix_ms: None,
                        representative_current_time_ms: Some(4_520),
                        video_width: None,
                        video_height: None,
                        max_non_black_ratio_per_mille: Some(28),
                        mean_non_black_ratio_per_mille: Some(12),
                        transition_observed: false,
                        detail: None,
                    },
                ],
            }
        );
    }

    #[test]
    fn manual_lab_browser_visibility_summary_keeps_transitional_windows_inconclusive() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let mut transition = player_websocket_event(session_id, "browser_visibility_window", 200);
        transition.player_mode = Some("static_fallback".to_owned());
        transition.window_index = Some(1);
        transition.window_phase = Some("stabilize".to_owned());
        transition.sample_count = Some(6);
        transition.valid_sample_count = Some(1);
        transition.sample_status = Some("transitional".to_owned());
        transition.visibility_verdict = Some("inconclusive".to_owned());
        transition.transition_observed = Some(true);

        let summary = build_manual_lab_browser_visibility_summary(&[transition]);

        assert_eq!(summary.verdict, ManualLabRecordingVisibilityVerdict::Inconclusive);
        assert_eq!(summary.data_status, ManualLabBrowserVisibilityDataStatus::Transitional);
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::Low);
        assert_eq!(summary.transition_observed, true);
    }

    #[test]
    fn manual_lab_builds_browser_artifact_correlation_for_browser_black_artifact_visible() {
        let browser = ManualLabSessionBrowserVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
            confidence: ManualLabEvidenceConfidence::High,
            detail: None,
            dominant_mode: ManualLabBrowserPlayerMode::ActiveLive,
            data_status: ManualLabBrowserVisibilityDataStatus::Ready,
            representative_current_time_ms: Some(4_500),
            valid_window_count: 2,
            transition_observed: false,
            max_non_black_ratio_per_mille: Some(0),
            windows: Vec::new(),
        };
        let artifact = ManualLabSessionRecordingVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::VisibleFrame,
            confidence: ManualLabEvidenceConfidence::High,
            detail: None,
            analysis_backend: None,
            recording_path: None,
            probe_seek_to_ms: Some(4_500),
            video_duration_ms: None,
            ready_state: None,
            sample_window_ms: 8_000,
            sample_interval_ms: 250,
            sampled_frame_count: 12,
            first_visible_offset_ms: Some(0),
            first_sparse_offset_ms: Some(0),
            max_non_black_ratio_per_mille: Some(25),
        };

        let summary = build_manual_lab_browser_artifact_correlation_summary(&browser, &artifact);

        assert_eq!(
            summary.verdict,
            ManualLabBrowserArtifactCorrelationVerdict::BrowserBlackArtifactVisible
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::High);
        assert_eq!(summary.browser_current_time_ms, Some(4_500));
        assert_eq!(summary.artifact_probe_seek_to_ms, Some(4_500));
    }

    #[test]
    fn manual_lab_builds_browser_artifact_correlation_for_both_black() {
        let browser = ManualLabSessionBrowserVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
            confidence: ManualLabEvidenceConfidence::Medium,
            detail: None,
            dominant_mode: ManualLabBrowserPlayerMode::ActiveLive,
            data_status: ManualLabBrowserVisibilityDataStatus::Ready,
            representative_current_time_ms: Some(900),
            valid_window_count: 1,
            transition_observed: false,
            max_non_black_ratio_per_mille: Some(0),
            windows: Vec::new(),
        };
        let artifact = ManualLabSessionRecordingVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
            confidence: ManualLabEvidenceConfidence::High,
            detail: None,
            analysis_backend: None,
            recording_path: None,
            probe_seek_to_ms: Some(900),
            video_duration_ms: None,
            ready_state: None,
            sample_window_ms: 8_000,
            sample_interval_ms: 250,
            sampled_frame_count: 12,
            first_visible_offset_ms: None,
            first_sparse_offset_ms: None,
            max_non_black_ratio_per_mille: Some(0),
        };

        let summary = build_manual_lab_browser_artifact_correlation_summary(&browser, &artifact);

        assert_eq!(summary.verdict, ManualLabBrowserArtifactCorrelationVerdict::BothBlack);
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::Medium);
    }

    #[test]
    fn manual_lab_browser_artifact_correlation_stays_inconclusive_for_transitions() {
        let browser = ManualLabSessionBrowserVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::Inconclusive,
            confidence: ManualLabEvidenceConfidence::Low,
            detail: None,
            dominant_mode: ManualLabBrowserPlayerMode::Unknown,
            data_status: ManualLabBrowserVisibilityDataStatus::Transitional,
            representative_current_time_ms: None,
            valid_window_count: 0,
            transition_observed: true,
            max_non_black_ratio_per_mille: None,
            windows: Vec::new(),
        };
        let artifact = ManualLabSessionRecordingVisibilitySummary::default();

        let summary = build_manual_lab_browser_artifact_correlation_summary(&browser, &artifact);

        assert_eq!(
            summary.verdict,
            ManualLabBrowserArtifactCorrelationVerdict::InconclusiveTransition
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::Low);
    }

    #[test]
    fn manual_lab_builds_correlated_ready_playback_artifact_timeline_summary() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
            bootstrap_event(3, "playback.chunk.appended.first", "ok"),
        ]);
        let ready = build_manual_lab_playback_ready_correlation(
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
        let player = ManualLabSessionPlayerWebsocketSummary {
            schema_version: 1,
            open_observed: true,
            first_message_observed: true,
            opened_at_unix_ms: Some(1_700_000_000_060),
            first_message_at_unix_ms: Some(1_700_000_000_065),
            ..Default::default()
        };
        let events = vec![
            session_event(
                session_id,
                1,
                "2026-03-29T01:00:00Z",
                EventPayload::SessionStarted {
                    attacker_addr: "127.0.0.1:40000".to_owned(),
                    listener_id: "gateway".to_owned(),
                    started_at: "2026-03-29T01:00:00Z".to_owned(),
                    session_state: SessionState::Connected,
                },
            ),
            session_event(
                session_id,
                2,
                "2026-03-29T01:00:01Z",
                EventPayload::SessionAssigned {
                    assigned_at: "2026-03-29T01:00:01Z".to_owned(),
                    vm_name: "manual-deck-01".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3391".to_owned(),
                    attestation_ref: "attestation:test".to_owned(),
                },
            ),
            session_event(
                session_id,
                3,
                "2026-03-29T01:00:02Z",
                EventPayload::SessionStreamReady {
                    ready_at: "2026-03-29T01:00:02Z".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: "/jet/honeypot/session/test/stream".to_owned(),
                    token_expires_at: "2026-03-29T01:05:02Z".to_owned(),
                    stream_state: StreamState::Ready,
                },
            ),
        ];
        let temp = tempdir().expect("tempdir");
        let session_root = temp.path().join(session_id);
        fs::create_dir_all(&session_root).expect("create session recording root");
        fs::write(session_root.join("recording-0.webm"), vec![0u8; 64]).expect("write recording");

        let summary =
            build_manual_lab_playback_artifact_timeline_summary(&events, &ready, &player, temp.path(), session_id);

        assert_eq!(
            summary.verdict,
            ManualLabPlaybackArtifactTimelineVerdict::CorrelatedReadyPlayback
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::High);
        assert!(summary.recording_artifact_present);
        assert_eq!(summary.recording_artifact_count, 1);
        assert!(summary.timeline_gaps.is_empty());
    }

    #[test]
    fn manual_lab_builds_missing_recording_artifact_timeline_summary() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![
            bootstrap_event(1, "playback.bootstrap.requested", "ok"),
            bootstrap_event(2, "playback.bootstrap.request_result", "ok"),
        ]);
        let ready = build_manual_lab_playback_ready_correlation(
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
        let player = ManualLabSessionPlayerWebsocketSummary {
            schema_version: 1,
            open_observed: true,
            opened_at_unix_ms: Some(1_700_000_000_060),
            ..Default::default()
        };
        let events = vec![
            session_event(
                session_id,
                1,
                "2026-03-29T01:00:00Z",
                EventPayload::SessionStarted {
                    attacker_addr: "127.0.0.1:40000".to_owned(),
                    listener_id: "gateway".to_owned(),
                    started_at: "2026-03-29T01:00:00Z".to_owned(),
                    session_state: SessionState::Connected,
                },
            ),
            session_event(
                session_id,
                2,
                "2026-03-29T01:00:01Z",
                EventPayload::SessionAssigned {
                    assigned_at: "2026-03-29T01:00:01Z".to_owned(),
                    vm_name: "manual-deck-01".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3391".to_owned(),
                    attestation_ref: "attestation:test".to_owned(),
                },
            ),
            session_event(
                session_id,
                3,
                "2026-03-29T01:00:02Z",
                EventPayload::SessionStreamReady {
                    ready_at: "2026-03-29T01:00:02Z".to_owned(),
                    transport: StreamTransport::Websocket,
                    stream_endpoint: "/jet/honeypot/session/test/stream".to_owned(),
                    token_expires_at: "2026-03-29T01:05:02Z".to_owned(),
                    stream_state: StreamState::Ready,
                },
            ),
        ];
        let temp = tempdir().expect("tempdir");

        let summary =
            build_manual_lab_playback_artifact_timeline_summary(&events, &ready, &player, temp.path(), session_id);

        assert_eq!(
            summary.verdict,
            ManualLabPlaybackArtifactTimelineVerdict::MissingRecordingArtifact
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::Medium);
        assert!(!summary.recording_artifact_present);
        assert!(
            summary
                .timeline_gaps
                .iter()
                .any(|gap| gap == "missing recording-*.webm artifact")
        );
    }

    #[test]
    fn manual_lab_builds_stream_failed_before_recording_timeline_summary() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![bootstrap_event(
            1,
            "playback.bootstrap.requested",
            "ok",
        )]);
        let ready = build_manual_lab_playback_ready_correlation(
            &timeline,
            Vec::new(),
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_060),
        );
        let events = vec![
            session_event(
                session_id,
                1,
                "2026-03-29T01:00:00Z",
                EventPayload::SessionStarted {
                    attacker_addr: "127.0.0.1:40000".to_owned(),
                    listener_id: "gateway".to_owned(),
                    started_at: "2026-03-29T01:00:00Z".to_owned(),
                    session_state: SessionState::Connected,
                },
            ),
            session_event(
                session_id,
                2,
                "2026-03-29T01:00:01Z",
                EventPayload::SessionAssigned {
                    assigned_at: "2026-03-29T01:00:01Z".to_owned(),
                    vm_name: "manual-deck-01".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3391".to_owned(),
                    attestation_ref: "attestation:test".to_owned(),
                },
            ),
            session_event(
                session_id,
                3,
                "2026-03-29T01:00:02Z",
                EventPayload::SessionStreamFailed {
                    failed_at: "2026-03-29T01:00:02Z".to_owned(),
                    failure_code: honeypot_contracts::error::ErrorCode::StreamUnavailable,
                    retryable: true,
                    stream_state: StreamState::Failed,
                },
            ),
        ];
        let temp = tempdir().expect("tempdir");

        let summary = build_manual_lab_playback_artifact_timeline_summary(
            &events,
            &ready,
            &ManualLabSessionPlayerWebsocketSummary::default(),
            temp.path(),
            session_id,
        );

        assert_eq!(
            summary.verdict,
            ManualLabPlaybackArtifactTimelineVerdict::StreamFailedBeforeRecording
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::High);
    }

    #[test]
    fn manual_lab_builds_websocket_attached_without_ready_timeline_summary() {
        let session_id = "11111111-2222-3333-4444-555555555555";
        let timeline = build_manual_lab_playback_bootstrap_timeline(vec![bootstrap_event(
            1,
            "playback.bootstrap.requested",
            "ok",
        )]);
        let ready = build_manual_lab_playback_ready_correlation(
            &timeline,
            Vec::new(),
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_060),
        );
        let events = vec![
            session_event(
                session_id,
                1,
                "2026-03-29T01:00:00Z",
                EventPayload::SessionStarted {
                    attacker_addr: "127.0.0.1:40000".to_owned(),
                    listener_id: "gateway".to_owned(),
                    started_at: "2026-03-29T01:00:00Z".to_owned(),
                    session_state: SessionState::Connected,
                },
            ),
            session_event(
                session_id,
                2,
                "2026-03-29T01:00:01Z",
                EventPayload::SessionAssigned {
                    assigned_at: "2026-03-29T01:00:01Z".to_owned(),
                    vm_name: "manual-deck-01".to_owned(),
                    guest_rdp_addr: "127.0.0.1:3391".to_owned(),
                    attestation_ref: "attestation:test".to_owned(),
                },
            ),
        ];
        let player = ManualLabSessionPlayerWebsocketSummary {
            schema_version: 1,
            open_observed: true,
            opened_at_unix_ms: Some(1_700_000_000_060),
            ..Default::default()
        };
        let temp = tempdir().expect("tempdir");

        let summary =
            build_manual_lab_playback_artifact_timeline_summary(&events, &ready, &player, temp.path(), session_id);

        assert_eq!(
            summary.verdict,
            ManualLabPlaybackArtifactTimelineVerdict::WebsocketAttachedWithoutReady
        );
        assert_eq!(summary.confidence, ManualLabEvidenceConfidence::Medium);
    }

    #[test]
    fn manual_lab_parses_legacy_fastpath_warning_lines() {
        let line = "2026-03-28T22:00:03.000000Z  WARN ThreadId(42) buffer_len=9 prefix_hex=0300000902f08068 error=invalid-length Passive FastPath observer dropped an invalid RDP frame prefix";

        let parsed = parse_manual_lab_fastpath_warning_line(line);
        assert_eq!(
            parsed,
            Some(ManualLabFastPathWarningEvent {
                session_id: None,
                warn_code: "fastpath_invalid_rdp_frame_prefix".to_owned(),
                observed_at_unix_ms: Some(1_774_735_203_000),
            })
        );
    }

    #[test]
    fn manual_lab_classifies_fastpath_known_noise_from_aligned_ready_baseline() {
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
        let summary = build_manual_lab_fastpath_warning_summary(
            &[ManualLabFastPathWarningEvent {
                session_id: Some("session-a".to_owned()),
                warn_code: "fastpath_process_server_frame_error".to_owned(),
                observed_at_unix_ms: Some(1_700_000_000_030),
            }],
            0,
            &correlation,
            &BTreeSet::from(["fastpath_process_server_frame_error".to_owned()]),
        );

        assert_eq!(summary.total_warning_count, 1);
        assert_eq!(summary.known_noise_count, 1);
        assert_eq!(summary.candidate_root_cause_count, 0);
        assert_eq!(summary.uncertain_count, 0);
        assert_eq!(summary.overall_evidence, ManualLabFastPathWarningEvidence::KnownNoise);
    }

    #[test]
    fn manual_lab_classifies_novel_pre_ready_fastpath_warning_as_candidate_root_cause() {
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
        let summary = build_manual_lab_fastpath_warning_summary(
            &[ManualLabFastPathWarningEvent {
                session_id: Some("session-b".to_owned()),
                warn_code: "fastpath_unseen_warning".to_owned(),
                observed_at_unix_ms: Some(1_700_000_000_005),
            }],
            0,
            &correlation,
            &BTreeSet::new(),
        );

        assert_eq!(summary.known_noise_count, 0);
        assert_eq!(summary.candidate_root_cause_count, 1);
        assert_eq!(
            summary.overall_evidence,
            ManualLabFastPathWarningEvidence::CandidateRootCause
        );
    }

    #[test]
    fn manual_lab_emits_zero_fastpath_warning_summary_when_no_events_exist() {
        let timeline = build_manual_lab_playback_bootstrap_timeline(Vec::new());
        let correlation = build_manual_lab_playback_ready_correlation(
            &timeline,
            Vec::new(),
            Some("unavailable"),
            Some(503),
            Some(1_700_000_000_010),
        );
        let summary = build_manual_lab_fastpath_warning_summary(&[], 0, &correlation, &BTreeSet::new());

        assert_eq!(summary.schema_version, 1);
        assert_eq!(summary.total_warning_count, 0);
        assert_eq!(summary.with_session_id_count, 0);
        assert_eq!(summary.without_session_id_count, 0);
        assert_eq!(summary.overall_evidence, ManualLabFastPathWarningEvidence::Uncertain);
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
    fn manual_lab_driver_kind_parser_accepts_supported_values() {
        assert_eq!(
            ManualLabDriverKind::parse("xfreerdp").expect("parse xfreerdp"),
            ManualLabDriverKind::Xfreerdp
        );
        assert_eq!(
            ManualLabDriverKind::parse("ironrdp").expect("parse ironrdp"),
            ManualLabDriverKind::IronRdpNoGfx
        );
        assert_eq!(
            ManualLabDriverKind::parse("ironrdp-no-rdpgfx").expect("parse ironrdp-no-rdpgfx"),
            ManualLabDriverKind::IronRdpNoGfx
        );
        assert_eq!(
            ManualLabDriverKind::parse("ironrdp-gfx").expect("parse ironrdp-gfx"),
            ManualLabDriverKind::IronRdpGfx
        );
    }

    #[test]
    fn manual_lab_irondrdp_driver_args_include_association_token() {
        let args = ironrdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            Some("nla"),
            &Some("LAB".to_owned()),
            false,
        );

        assert!(args.windows(2).any(|window| window == ["--host", "127.0.0.1"]));
        assert!(args.windows(2).any(|window| window == ["--proxy-port", "3389"]));
        assert!(args.windows(2).any(|window| window == ["--security", "nla"]));
        assert!(args.windows(2).any(|window| window == ["--domain", "LAB"]));
        assert!(args.windows(2).any(|window| window[0] == "--association-token"));
        assert!(
            args.windows(2)
                .any(|window| window == ["--session-id", "642e76af-caa3-487b-b3ed-8abe864a7bc9"])
        );
    }

    #[test]
    fn manual_lab_irondrdp_gfx_driver_args_include_rdpgfx_flag() {
        let args = ironrdp_driver_args(
            "642e76af-caa3-487b-b3ed-8abe864a7bc9",
            3391,
            3389,
            Some("nla"),
            &Some("LAB".to_owned()),
            true,
        );

        assert!(args.iter().any(|arg| arg == MANUAL_LAB_IRONRDP_RDPGFX_DRIVER_FLAG));
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
