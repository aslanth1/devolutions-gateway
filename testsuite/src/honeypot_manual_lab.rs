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
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use uuid::Uuid;

use crate::honeypot_control_plane::{
    CANONICAL_TINY11_IMAGE_STORE_ROOT, HoneypotControlPlaneTestConfig, HoneypotInteropStoreEvidence,
    Tiny11LabCleanStateProbe, Tiny11LabGateBlocker, Tiny11LabGateInputs, Tiny11LabGateOutcome, Tiny11LabRuntimeInput,
    evaluate_tiny11_lab_gate, find_unused_port, write_honeypot_control_plane_config,
};
use crate::honeypot_frontend::{HoneypotFrontendTestConfig, write_honeypot_frontend_config};
use crate::honeypot_release::{HONEYPOT_PROXY_CONFIG_PATH, repo_relative_path};
use crate::honeypot_tiers::{HoneypotTestTier, require_honeypot_tier};

const MANUAL_LAB_SCHEMA_VERSION: u32 = 1;
const MANUAL_LAB_HOST_COUNT: usize = 3;
const MANUAL_LAB_ROOT_RELATIVE_PATH: &str = "target/manual-lab";
const MANUAL_LAB_ACTIVE_STATE_RELATIVE_PATH: &str = "target/manual-lab/active.json";
const MANUAL_LAB_DRIVER_PROXY_USERNAME: &str = "operator";
const MANUAL_LAB_DRIVER_PROXY_PASSWORD: &str = "attacker-password";
const MANUAL_LAB_CONTROL_PLANE_SCOPE: &str = "gateway.honeypot.control-plane";
const MANUAL_LAB_WILDCARD_SCOPE: &str = "*";
const MANUAL_LAB_CHROME_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_CHROME";
const MANUAL_LAB_XVFB_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_XVFB";
const MANUAL_LAB_XEPHYR_ENV: &str = "DGW_HONEYPOT_MANUAL_LAB_XEPHYR";
const MANUAL_LAB_FRONTEND_CONFIG_ENV: &str = "HONEYPOT_FRONTEND_CONFIG_PATH";
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
    qemu_binary_path: PathBuf,
    kvm_path: PathBuf,
    xfreerdp_path: PathBuf,
    ready_timeout_secs: u16,
    rdp_username: String,
    rdp_password: String,
    rdp_domain: Option<String>,
    rdp_security: Option<String>,
    evidence: HoneypotInteropStoreEvidence,
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
    pub stdout_log: PathBuf,
    pub stderr_log: PathBuf,
    pub vm_lease_id: Option<String>,
    pub stream_id: Option<String>,
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

fn manual_lab_manifest_path(relative_path: &str) -> PathBuf {
    repo_relative_path(relative_path)
}

pub fn honeypot_manual_lab_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_MANUAL_LAB_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
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
    require_honeypot_tier(HoneypotTestTier::LabE2e)
        .with_context(|| "manual lab requires the explicit lab-e2e gate before it can launch live Tiny11 hosts")?;

    let active_path = active_state_path();
    ensure!(
        !active_path.exists(),
        "manual lab is already active at {}; run `cargo run -p testsuite --bin honeypot-manual-lab -- status` or `down` first",
        active_path.display()
    );

    let interop = load_manual_lab_interop_config()?;
    let chrome_binary = if options.open_browser {
        Some(resolve_chrome_binary()?)
    } else {
        None
    };
    if options.open_browser {
        ensure!(
            interactive_browser_display_is_available(),
            "manual lab browser launch requires DISPLAY or WAYLAND_DISPLAY to be set",
        );
    }

    let run_id = format!("manual-lab-{}", Uuid::new_v4().simple());
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
        sessions: build_session_records(&layout.logs_dir),
    };
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
            eprintln!(
                "manual lab phase=session.driver.spawn run_id={} slot={} session_id={}",
                state.run_id, state.sessions[index].slot, state.sessions[index].session_id
            );
            let driver = {
                let session = &state.sessions[index];
                spawn_xfreerdp_driver(session, &interop, &state)?
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
            let token = wait_for_stream_token(
                state.ports.proxy_http,
                &state.sessions[index].session_id,
                &wildcard_token,
            )?;
            state.sessions[index].stream_id = Some(token.stream_id);
            if state.sessions[index].vm_lease_id.is_none() {
                state.sessions[index].vm_lease_id = Some(token.vm_lease_id);
            }
            persist_active_state(&state)?;
            eprintln!(
                "manual lab phase=session.stream.ready run_id={} slot={} session_id={} stream_id={}",
                state.run_id,
                state.sessions[index].slot,
                state.sessions[index].session_id,
                state.sessions[index].stream_id.as_deref().unwrap_or("<pending>")
            );
        }

        wait_for_frontend_tiles(state.ports.frontend_http, MANUAL_LAB_HOST_COUNT)?;
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
    let run_root = repo_relative_path(MANUAL_LAB_ROOT_RELATIVE_PATH).join(run_id);
    let logs_dir = run_root.join("logs");
    let manifests_dir = run_root.join("manifests");
    let service_config_dir = run_root.join("config");
    let control_plane_secret_dir = run_root.join("secrets/control-plane");
    let proxy_secret_dir = run_root.join("secrets/proxy");
    let frontend_secret_dir = run_root.join("secrets/frontend");
    let runtime_data_dir = run_root.join("runtime/control-plane-data");
    let lease_store_dir = run_root.join("runtime/leases");
    let quarantine_store_dir = run_root.join("runtime/quarantine");
    let qemu_runtime_root = std::env::temp_dir().join(format!(
        "dgw-manual-lab-{}",
        run_id
            .strip_prefix("manual-lab-")
            .unwrap_or(run_id)
            .chars()
            .take(12)
            .collect::<String>()
    ));
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
    let process = spawn_logged_process(
        GATEWAY_BIN_PATH.as_path(),
        &[],
        &[(
            OsString::from("DGATEWAY_CONFIG_PATH"),
            layout.proxy_config_dir.as_os_str().to_owned(),
        )],
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
) -> anyhow::Result<SpawnedProcess> {
    let association_token = association_token(
        &session.session_id,
        &format!("127.0.0.1:{}", session.expected_guest_rdp_port),
    );
    let mut args = vec![
        format!("/v:127.0.0.1:{}", state.ports.proxy_tcp),
        format!("/u:{MANUAL_LAB_DRIVER_PROXY_USERNAME}"),
        format!("/p:{MANUAL_LAB_DRIVER_PROXY_PASSWORD}"),
        format!("/pcb:{association_token}"),
        "/cert:ignore".to_owned(),
        "/timeout:10000".to_owned(),
        "/log-level:ERROR".to_owned(),
        "/dynamic-resolution".to_owned(),
    ];
    if let Some(security) = &interop.rdp_security {
        args.push(format!("/sec:{security}"));
    }

    spawn_logged_process_with_display(
        &interop.xfreerdp_path,
        &args,
        &[],
        &state.driver_display,
        session.stdout_log.clone(),
        session.stderr_log.clone(),
    )
    .with_context(|| format!("spawn xfreerdp driver for session {}", session.session_id))
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

fn wait_for_stream_token(
    proxy_http_port: u16,
    session_id: &str,
    wildcard_token: &str,
) -> anyhow::Result<StreamTokenResponse> {
    wait_for_condition(
        MANUAL_LAB_STREAM_READY_TIMEOUT,
        || {
            let request = StreamTokenRequest {
                schema_version: honeypot_contracts::SCHEMA_VERSION,
                request_id: format!("manual-lab-stream-token-{session_id}"),
                session_id: session_id.to_owned(),
            };
            let response: StreamTokenResponse = post_json_typed(
                proxy_http_port,
                &format!("/jet/honeypot/session/{session_id}/stream-token"),
                &[authorization_header(wildcard_token.to_owned())],
                &request,
            )?;
            response
                .ensure_supported_schema()
                .context("manual lab stream token response uses unsupported schema version")?;
            Ok(response)
        },
        &format!("stream token for session {session_id}"),
    )
}

fn wait_for_frontend_tiles(frontend_http_port: u16, expected_tiles: usize) -> anyhow::Result<()> {
    wait_for_condition(
        MANUAL_LAB_STREAM_READY_TIMEOUT,
        || {
            let body = get_json(frontend_http_port, "/health", &[])?;
            ensure!(
                body.get("ready_tile_count").and_then(Value::as_u64) == Some(expected_tiles as u64),
                "frontend ready_tile_count has not reached {expected_tiles}: {}",
                body
            );
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

fn build_session_records(logs_dir: &Path) -> Vec<ManualLabSessionRecord> {
    [3391u16, 3392, 3393]
        .into_iter()
        .enumerate()
        .map(|(index, guest_rdp_port)| ManualLabSessionRecord {
            slot: index + 1,
            session_id: Uuid::new_v4().to_string(),
            expected_guest_rdp_port: guest_rdp_port,
            xfreerdp_pid: None,
            stdout_log: logs_dir.join(format!("xfreerdp-{:02}.stdout.log", index + 1)),
            stderr_log: logs_dir.join(format!("xfreerdp-{:02}.stderr.log", index + 1)),
            vm_lease_id: None,
            stream_id: None,
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
    .with_context(|| format!("write {}", active_path.display()))
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

fn load_manual_lab_interop_config() -> anyhow::Result<ManualLabInteropConfig> {
    let paths = resolve_manual_lab_interop_paths();
    let evidence = match evaluate_tiny11_lab_gate(&build_manual_lab_gate_inputs(&paths)) {
        Tiny11LabGateOutcome::Ready(ready) => ready.evidence,
        Tiny11LabGateOutcome::Blocked(blocked) => {
            bail!(
                "{}",
                tiny11_lab_gate_error_message(blocked.blocker, &blocked.detail, blocked.remediation.as_deref())
            );
        }
    };

    Ok(ManualLabInteropConfig {
        image_store: paths.image_store.clone(),
        qemu_binary_path: paths.qemu_binary_path,
        kvm_path: paths.kvm_path,
        xfreerdp_path: paths.xfreerdp_path,
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
    qemu_binary_path: PathBuf,
    kvm_path: PathBuf,
    xfreerdp_path: PathBuf,
}

fn resolve_manual_lab_interop_paths() -> ManualLabInteropPaths {
    let image_store = optional_env_path(HONEYPOT_INTEROP_IMAGE_STORE_ENV)
        .unwrap_or_else(|| PathBuf::from(CANONICAL_TINY11_IMAGE_STORE_ROOT));
    let manifest_dir =
        optional_env_path(HONEYPOT_INTEROP_MANIFEST_DIR_ENV).unwrap_or_else(|| image_store.join("manifests"));
    let qemu_binary_path = optional_env_path(HONEYPOT_INTEROP_QEMU_BINARY_ENV)
        .unwrap_or_else(|| PathBuf::from("/usr/bin/qemu-system-x86_64"));
    let kvm_path = optional_env_path(HONEYPOT_INTEROP_KVM_PATH_ENV).unwrap_or_else(|| PathBuf::from("/dev/kvm"));
    let xfreerdp_path =
        optional_env_path(HONEYPOT_INTEROP_XFREERDP_PATH_ENV).unwrap_or_else(|| PathBuf::from("xfreerdp"));

    ManualLabInteropPaths {
        image_store,
        manifest_dir,
        qemu_binary_path,
        kvm_path,
        xfreerdp_path,
    }
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
        ],
        consume_image_config_path: Some(PathBuf::from("honeypot/docker/config/control-plane/config.toml")),
        source_manifest_path: None,
    }
}

fn tiny11_lab_gate_error_message(blocker: Tiny11LabGateBlocker, detail: &str, remediation: Option<&str>) -> String {
    let blocker = match blocker {
        Tiny11LabGateBlocker::MissingStoreRoot => "missing_store_root",
        Tiny11LabGateBlocker::InvalidProvenance => "invalid_provenance",
        Tiny11LabGateBlocker::UncleanState => "unclean_state",
        Tiny11LabGateBlocker::MissingRuntimeInputs => "missing_runtime_inputs",
    };

    match remediation {
        Some(remediation) => format!("Tiny11 lab gate blocked by {blocker}: {detail}\nremediation: {remediation}"),
        None => format!("Tiny11 lab gate blocked by {blocker}: {detail}"),
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

fn post_json_typed<Request, Response>(
    port: u16,
    path: &str,
    headers: &[(String, String)],
    request: &Request,
) -> anyhow::Result<Response>
where
    Request: Serialize,
    Response: for<'de> Deserialize<'de>,
{
    let body = serde_json::to_vec(request).context("serialize JSON request body")?;
    let (status, response_body) = send_http_request(port, "POST", path, headers, Some(&body))?;
    ensure!(
        status.contains("200"),
        "unexpected HTTP status for POST {path} on port {port}: {status}",
    );
    serde_json::from_slice(&response_body)
        .with_context(|| format!("decode typed JSON response from POST {path} on port {port}"))
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use base64::Engine as _;
    use serde_json::json;

    use super::{
        association_token, display_socket_path, manual_lab_manifest_path, manual_lab_service_ready_timeout,
        parse_proc_stat_process_state,
    };

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
}
