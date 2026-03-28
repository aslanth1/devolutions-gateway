use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Component, Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use honeypot_contracts::control_plane::HealthResponse;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use typed_builder::TypedBuilder;
use uuid::Uuid;

use crate::ports::allocate_test_port;

static HONEYPOT_CONTROL_PLANE_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("../honeypot/control-plane/Cargo.toml")
        .bin("honeypot-control-plane")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot control-plane")
        .path()
        .to_path_buf()
});

static FAKE_QEMU_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("Cargo.toml")
        .bin("fake-qemu")
        .current_release()
        .current_target()
        .run()
        .expect("build fake qemu test helper")
        .path()
        .to_path_buf()
});

static HONEYPOT_MANUAL_HEADED_WRITER_BIN_PATH: LazyLock<PathBuf> = LazyLock::new(|| {
    escargot::CargoBuild::new()
        .manifest_path("Cargo.toml")
        .bin("honeypot-manual-headed-writer")
        .current_release()
        .current_target()
        .run()
        .expect("build honeypot manual-headed writer")
        .path()
        .to_path_buf()
});

#[derive(Debug, Clone, TypedBuilder)]
pub struct HoneypotControlPlaneTestConfig {
    #[builder(setter(into))]
    pub bind_addr: String,
    #[builder(default = true)]
    pub service_token_validation_disabled: bool,
    #[builder(default, setter(into, strip_option))]
    pub proxy_verifier_public_key_pem: Option<String>,
    #[builder(default, setter(into, strip_option))]
    pub proxy_verifier_public_key_pem_file: Option<PathBuf>,
    #[builder(default, setter(into, strip_option))]
    pub backend_credentials_file_path: Option<PathBuf>,
    #[builder(setter(into))]
    pub data_dir: PathBuf,
    #[builder(setter(into))]
    pub image_store: PathBuf,
    #[builder(setter(into))]
    pub manifest_dir: PathBuf,
    #[builder(setter(into))]
    pub lease_store: PathBuf,
    #[builder(setter(into))]
    pub quarantine_store: PathBuf,
    #[builder(setter(into))]
    pub qmp_dir: PathBuf,
    #[builder(default, setter(into, strip_option))]
    pub qga_dir: Option<PathBuf>,
    #[builder(setter(into))]
    pub secret_dir: PathBuf,
    #[builder(setter(into))]
    pub kvm_path: PathBuf,
    #[builder(default = false)]
    pub enable_guest_agent: bool,
    #[builder(default = "simulated".to_owned(), setter(into))]
    pub lifecycle_driver: String,
    #[builder(default = 1)]
    pub stop_timeout_secs: u64,
    #[builder(default = 8)]
    pub qemu_max_vcpu_count: u8,
    #[builder(default = 16 * 1024)]
    pub qemu_max_memory_mib: u32,
    #[builder(default = 64 * 1024)]
    pub qemu_max_overlay_size_mib: u64,
    #[builder(default = 15)]
    pub max_stop_timeout_secs: u64,
    #[builder(setter(into))]
    pub qemu_binary_path: PathBuf,
    #[builder(default = "q35".to_owned(), setter(into))]
    pub qemu_machine_type: String,
    #[builder(default = "host".to_owned(), setter(into))]
    pub qemu_cpu_model: String,
    #[builder(default = 4)]
    pub qemu_vcpu_count: u8,
    #[builder(default = 8192)]
    pub qemu_memory_mib: u32,
    #[builder(default = "net0".to_owned(), setter(into))]
    pub qemu_netdev_id: String,
}

pub fn honeypot_control_plane_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_CONTROL_PLANE_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn honeypot_control_plane_tokio_cmd() -> tokio::process::Command {
    let mut cmd = tokio::process::Command::new(&*HONEYPOT_CONTROL_PLANE_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd.kill_on_drop(true);
    cmd.stdout(Stdio::null());
    cmd
}

pub fn fake_qemu_bin_path() -> PathBuf {
    FAKE_QEMU_BIN_PATH.clone()
}

pub fn honeypot_manual_headed_writer_assert_cmd() -> assert_cmd::Command {
    let mut cmd = assert_cmd::Command::new(&*HONEYPOT_MANUAL_HEADED_WRITER_BIN_PATH);
    cmd.env("RUST_BACKTRACE", "0");
    cmd
}

pub fn write_honeypot_control_plane_config(path: &Path, config: &HoneypotControlPlaneTestConfig) -> anyhow::Result<()> {
    let backend_credentials_file_path = config
        .backend_credentials_file_path
        .clone()
        .unwrap_or_else(|| config.secret_dir.join("backend-credentials.json"));
    let mut document = format!(
        "[http]\n\
         bind_addr = \"{}\"\n\n\
         [auth]\n\
         service_token_validation_disabled = {}\n\n\
         [backend_credentials]\n\
         adapter = \"file\"\n\
         file_path = \"{}\"\n\n\
         [runtime]\n\
         enable_guest_agent = {}\n\n\
         lifecycle_driver = \"{}\"\n\
         stop_timeout_secs = {}\n\n\
         [runtime.limits]\n\
         max_vcpu_count = {}\n\
         max_memory_mib = {}\n\
         max_overlay_size_mib = {}\n\
         max_stop_timeout_secs = {}\n\n\
         [runtime.qemu]\n\
         binary_path = \"{}\"\n\
         machine_type = \"{}\"\n\
         cpu_model = \"{}\"\n\
         vcpu_count = {}\n\
         memory_mib = {}\n\
         network.netdev_id = \"{}\"\n\n\
         [paths]\n\
         data_dir = \"{}\"\n\
         image_store = \"{}\"\n\
         manifest_dir = \"{}\"\n\
         lease_store = \"{}\"\n\
         quarantine_store = \"{}\"\n\
         qmp_dir = \"{}\"\n\
         secret_dir = \"{}\"\n\
         kvm_path = \"{}\"\n",
        config.bind_addr,
        config.service_token_validation_disabled,
        backend_credentials_file_path.display(),
        config.enable_guest_agent,
        config.lifecycle_driver,
        config.stop_timeout_secs,
        config.qemu_max_vcpu_count,
        config.qemu_max_memory_mib,
        config.qemu_max_overlay_size_mib,
        config.max_stop_timeout_secs,
        config.qemu_binary_path.display(),
        config.qemu_machine_type,
        config.qemu_cpu_model,
        config.qemu_vcpu_count,
        config.qemu_memory_mib,
        config.qemu_netdev_id,
        config.data_dir.display(),
        config.image_store.display(),
        config.manifest_dir.display(),
        config.lease_store.display(),
        config.quarantine_store.display(),
        config.qmp_dir.display(),
        config.secret_dir.display(),
        config.kvm_path.display(),
    );

    if let Some(qga_dir) = &config.qga_dir {
        document.push_str(&format!("qga_dir = \"{}\"\n", qga_dir.display()));
    }

    if let Some(proxy_verifier_public_key_pem) = &config.proxy_verifier_public_key_pem {
        document.push_str(&format!(
            "\nauth.proxy_verifier_public_key_pem = '''\n{}\n'''\n",
            proxy_verifier_public_key_pem
        ));
    }
    if let Some(proxy_verifier_public_key_pem_file) = &config.proxy_verifier_public_key_pem_file {
        document.push_str(&format!(
            "\nauth.proxy_verifier_public_key_pem_file = \"{}\"\n",
            proxy_verifier_public_key_pem_file.display()
        ));
    }

    fs::write(path, document).with_context(|| format!("write control-plane config at {}", path.display()))
}

pub async fn read_health_response(port: u16) -> anyhow::Result<HealthResponse> {
    read_health_response_with_bearer_token(port, None).await
}

pub async fn read_health_response_with_bearer_token(
    port: u16,
    bearer_token: Option<&str>,
) -> anyhow::Result<HealthResponse> {
    let (_, response) = get_json_response_with_bearer_token(port, "/api/v1/health", bearer_token).await?;
    Ok(response)
}

pub async fn get_json_response<Response>(port: u16, path: &str) -> anyhow::Result<(String, Response)>
where
    Response: DeserializeOwned,
{
    get_json_response_with_bearer_token(port, path, None).await
}

pub async fn get_json_response_with_bearer_token<Response>(
    port: u16,
    path: &str,
    bearer_token: Option<&str>,
) -> anyhow::Result<(String, Response)>
where
    Response: DeserializeOwned,
{
    let (status_line, body) = send_http_request(port, "GET", path, bearer_token, None).await?;
    let response = serde_json::from_slice(&body).context("parse json response body")?;
    Ok((status_line, response))
}

pub async fn post_json_response<Request, Response>(
    port: u16,
    path: &str,
    request: &Request,
) -> anyhow::Result<(String, Response)>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    post_json_response_with_bearer_token(port, path, None, request).await
}

pub async fn post_json_response_with_bearer_token<Request, Response>(
    port: u16,
    path: &str,
    bearer_token: Option<&str>,
    request: &Request,
) -> anyhow::Result<(String, Response)>
where
    Request: Serialize,
    Response: DeserializeOwned,
{
    let body = serde_json::to_vec(request).context("serialize json request body")?;
    let (status_line, body) = send_http_request(port, "POST", path, bearer_token, Some(&body)).await?;
    let response = serde_json::from_slice(&body).context("parse json response body")?;
    Ok((status_line, response))
}

pub async fn send_http_request(
    port: u16,
    method: &str,
    path: &str,
    bearer_token: Option<&str>,
    body: Option<&[u8]>,
) -> anyhow::Result<(String, Vec<u8>)> {
    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connect to honeypot control-plane endpoint on port {port}"))?;

    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");

    if let Some(bearer_token) = bearer_token {
        request.push_str(&format!("Authorization: Bearer {bearer_token}\r\n"));
    }

    match body {
        Some(body) => {
            request.push_str(&format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n\r\n",
                body.len()
            ));
        }
        None => request.push_str("\r\n"),
    }

    stream
        .write_all(request.as_bytes())
        .await
        .context("write control-plane request headers")?;

    if let Some(body) = body {
        stream
            .write_all(body)
            .await
            .context("write control-plane request body")?;
    }

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .context("read control-plane response")?;

    let response = String::from_utf8(response).context("decode control-plane response as utf-8")?;
    let (headers, body) = response
        .split_once("\r\n\r\n")
        .context("split control-plane response headers and body")?;
    let status_line = headers
        .lines()
        .next()
        .context("read control-plane status line")?
        .to_owned();

    Ok((status_line, body.as_bytes().to_vec()))
}

pub fn find_unused_port() -> u16 {
    allocate_test_port()
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotInteropTrustedImage {
    pub manifest_path: PathBuf,
    pub pool_name: String,
    pub vm_name: String,
    pub attestation_ref: String,
    pub base_image_path: PathBuf,
    pub base_image_sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HoneypotInteropStoreEvidence {
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
    pub trusted_images: Vec<HoneypotInteropTrustedImage>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropManifestDocument {
    pool_name: String,
    vm_name: String,
    attestation_ref: String,
    base_image_path: PathBuf,
    source_iso: HoneypotInteropSourceIsoRecord,
    transformation: HoneypotInteropTransformationRecord,
    base_image: HoneypotInteropBaseImageRecord,
    approval: HoneypotInteropApprovalRecord,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropSourceIsoRecord {
    acquisition_channel: String,
    acquisition_date: String,
    filename: String,
    size_bytes: u64,
    edition: String,
    language: String,
    sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropTransformationRecord {
    timestamp: String,
    inputs: Vec<HoneypotInteropTransformationInputRecord>,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropTransformationInputRecord {
    reference: String,
    sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropBaseImageRecord {
    sha256: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Deserialize)]
struct HoneypotInteropApprovalRecord {
    approved_by: String,
}

#[cfg(unix)]
pub fn load_honeypot_interop_store_evidence(
    image_store_root: &Path,
    manifest_dir: &Path,
) -> anyhow::Result<HoneypotInteropStoreEvidence> {
    const REQUIRED_WINDOWS_EDITION: &str = "Windows 11 Pro x64";

    let image_store_root = image_store_root
        .canonicalize()
        .with_context(|| format!("canonicalize image store root {}", image_store_root.display()))?;
    let manifest_dir = manifest_dir
        .canonicalize()
        .with_context(|| format!("canonicalize manifest dir {}", manifest_dir.display()))?;

    anyhow::ensure!(
        image_store_root.is_dir(),
        "interop image store root must be a directory: {}",
        image_store_root.display()
    );
    anyhow::ensure!(
        manifest_dir.is_dir(),
        "interop manifest dir must be a directory: {}",
        manifest_dir.display()
    );

    let mut manifest_paths = fs::read_dir(&manifest_dir)
        .with_context(|| format!("read interop manifest dir {}", manifest_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("collect interop manifests from {}", manifest_dir.display()))?;
    manifest_paths.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
    manifest_paths.sort();

    anyhow::ensure!(
        !manifest_paths.is_empty(),
        "interop manifest dir {} does not contain any .json manifests",
        manifest_dir.display()
    );

    let mut trusted_images = Vec::with_capacity(manifest_paths.len());

    for manifest_path in manifest_paths {
        let manifest_bytes =
            fs::read(&manifest_path).with_context(|| format!("read interop manifest {}", manifest_path.display()))?;
        let manifest: HoneypotInteropManifestDocument = serde_json::from_slice(&manifest_bytes)
            .with_context(|| format!("parse interop manifest {}", manifest_path.display()))?;

        ensure_non_empty_manifest_field(&manifest_path, "pool_name", &manifest.pool_name)?;
        ensure_non_empty_manifest_field(&manifest_path, "vm_name", &manifest.vm_name)?;
        ensure_non_empty_manifest_field(&manifest_path, "attestation_ref", &manifest.attestation_ref)?;
        ensure_non_empty_manifest_field(
            &manifest_path,
            "source_iso.acquisition_channel",
            &manifest.source_iso.acquisition_channel,
        )?;
        ensure_non_empty_manifest_field(
            &manifest_path,
            "source_iso.acquisition_date",
            &manifest.source_iso.acquisition_date,
        )?;
        ensure_non_empty_manifest_field(&manifest_path, "source_iso.filename", &manifest.source_iso.filename)?;
        anyhow::ensure!(
            manifest.source_iso.size_bytes > 0,
            "source_iso.size_bytes must be greater than zero in {}",
            manifest_path.display()
        );
        anyhow::ensure!(
            manifest.source_iso.edition.trim() == REQUIRED_WINDOWS_EDITION,
            "source_iso.edition must be {REQUIRED_WINDOWS_EDITION} in {}",
            manifest_path.display()
        );
        ensure_non_empty_manifest_field(&manifest_path, "source_iso.language", &manifest.source_iso.language)?;
        validate_sha256_field(&manifest_path, "source_iso.sha256", &manifest.source_iso.sha256)?;
        ensure_non_empty_manifest_field(
            &manifest_path,
            "transformation.timestamp",
            &manifest.transformation.timestamp,
        )?;
        anyhow::ensure!(
            !manifest.transformation.inputs.is_empty(),
            "transformation.inputs must not be empty in {}",
            manifest_path.display()
        );
        for (index, input) in manifest.transformation.inputs.iter().enumerate() {
            ensure_non_empty_manifest_field(
                &manifest_path,
                &format!("transformation.inputs[{index}].reference"),
                &input.reference,
            )?;
            validate_sha256_field(
                &manifest_path,
                &format!("transformation.inputs[{index}].sha256"),
                &input.sha256,
            )?;
        }
        validate_sha256_field(&manifest_path, "base_image.sha256", &manifest.base_image.sha256)?;
        ensure_non_empty_manifest_field(&manifest_path, "approval.approved_by", &manifest.approval.approved_by)?;
        anyhow::ensure!(
            manifest.base_image_path.is_relative(),
            "base_image_path must stay relative to the configured interop image store in {}",
            manifest_path.display()
        );

        let base_image_path = image_store_root.join(&manifest.base_image_path);
        let base_image_path = base_image_path
            .canonicalize()
            .with_context(|| format!("canonicalize interop base image {}", base_image_path.display()))?;
        anyhow::ensure!(
            base_image_path.starts_with(&image_store_root),
            "interop base image {} escapes the configured image store root {}",
            base_image_path.display(),
            image_store_root.display()
        );
        anyhow::ensure!(
            base_image_path.is_file(),
            "interop base image must be a file: {}",
            base_image_path.display()
        );

        trusted_images.push(HoneypotInteropTrustedImage {
            manifest_path,
            pool_name: manifest.pool_name,
            vm_name: manifest.vm_name,
            attestation_ref: manifest.attestation_ref,
            base_image_path,
            base_image_sha256: manifest.base_image.sha256.to_ascii_lowercase(),
        });
    }

    Ok(HoneypotInteropStoreEvidence {
        image_store_root,
        manifest_dir,
        trusted_images,
    })
}

#[cfg(unix)]
pub fn validate_honeypot_interop_lease_binding(
    evidence: &HoneypotInteropStoreEvidence,
    attestation_ref: &str,
    base_image_path: &Path,
) -> anyhow::Result<()> {
    let base_image_path = base_image_path
        .canonicalize()
        .with_context(|| format!("canonicalize interop lease base image {}", base_image_path.display()))?;
    anyhow::ensure!(
        base_image_path.starts_with(&evidence.image_store_root),
        "lease base image {} is outside the configured interop image store root {}",
        base_image_path.display(),
        evidence.image_store_root.display()
    );
    anyhow::ensure!(
        evidence
            .trusted_images
            .iter()
            .any(|trusted_image| trusted_image.attestation_ref == attestation_ref
                && trusted_image.base_image_path == base_image_path),
        "lease attestation_ref {attestation_ref} and base image {} are not bound to a validated interop manifest in {}",
        base_image_path.display(),
        evidence.manifest_dir.display()
    );

    Ok(())
}

#[cfg(unix)]
pub const CANONICAL_TINY11_IMAGE_STORE_ROOT: &str = "/srv/honeypot/images";
#[cfg(unix)]
const GENERIC_CONSUME_IMAGE_REMEDIATION: &str = "populate the canonical Tiny11 interop store with `honeypot-control-plane consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>`";

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tiny11LabGateBlocker {
    MissingStoreRoot,
    InvalidProvenance,
    UncleanState,
    MissingRuntimeInputs,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Tiny11LabGateBlocked {
    pub blocker: Tiny11LabGateBlocker,
    pub detail: String,
    pub remediation: Option<String>,
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Tiny11LabGateReady {
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
    pub evidence: HoneypotInteropStoreEvidence,
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub enum Tiny11LabGateOutcome {
    Ready(Tiny11LabGateReady),
    Blocked(Tiny11LabGateBlocked),
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Tiny11LabCleanStateProbe {
    pub label: String,
    pub path: PathBuf,
}

#[cfg(unix)]
impl Tiny11LabCleanStateProbe {
    pub fn absent(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            path: path.into(),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub enum Tiny11LabRuntimeInputCheck {
    NonEmptyText(Option<String>),
    ExistingPath(PathBuf),
    ExistingCommand(PathBuf),
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Tiny11LabRuntimeInput {
    pub label: String,
    pub check: Tiny11LabRuntimeInputCheck,
}

#[cfg(unix)]
impl Tiny11LabRuntimeInput {
    pub fn non_empty_text(label: impl Into<String>, value: Option<String>) -> Self {
        Self {
            label: label.into(),
            check: Tiny11LabRuntimeInputCheck::NonEmptyText(value),
        }
    }

    pub fn existing_path(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            check: Tiny11LabRuntimeInputCheck::ExistingPath(path.into()),
        }
    }

    pub fn existing_command(label: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        Self {
            label: label.into(),
            check: Tiny11LabRuntimeInputCheck::ExistingCommand(path.into()),
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub struct Tiny11LabGateInputs {
    pub image_store_root: PathBuf,
    pub manifest_dir: PathBuf,
    pub clean_state_probes: Vec<Tiny11LabCleanStateProbe>,
    pub runtime_inputs: Vec<Tiny11LabRuntimeInput>,
    pub consume_image_config_path: Option<PathBuf>,
    pub source_manifest_path: Option<PathBuf>,
}

#[cfg(unix)]
pub fn evaluate_tiny11_lab_gate(inputs: &Tiny11LabGateInputs) -> Tiny11LabGateOutcome {
    if !inputs.image_store_root.is_dir() {
        return Tiny11LabGateOutcome::Blocked(Tiny11LabGateBlocked {
            blocker: Tiny11LabGateBlocker::MissingStoreRoot,
            detail: format!(
                "canonical Tiny11 interop image store root {} is absent or not a directory",
                inputs.image_store_root.display()
            ),
            remediation: Some(render_consume_image_remediation(
                inputs.consume_image_config_path.as_deref(),
                inputs.source_manifest_path.as_deref(),
            )),
            image_store_root: inputs.image_store_root.clone(),
            manifest_dir: inputs.manifest_dir.clone(),
        });
    }

    let evidence = match load_honeypot_interop_store_evidence(&inputs.image_store_root, &inputs.manifest_dir) {
        Ok(evidence) => evidence,
        Err(error) => {
            return Tiny11LabGateOutcome::Blocked(Tiny11LabGateBlocked {
                blocker: Tiny11LabGateBlocker::InvalidProvenance,
                detail: format!(
                    "canonical Tiny11 interop store at {} failed provenance validation: {error:#}",
                    inputs.image_store_root.display()
                ),
                remediation: Some(render_consume_image_remediation(
                    inputs.consume_image_config_path.as_deref(),
                    inputs.source_manifest_path.as_deref(),
                )),
                image_store_root: inputs.image_store_root.clone(),
                manifest_dir: inputs.manifest_dir.clone(),
            });
        }
    };

    let stale_paths = inputs
        .clean_state_probes
        .iter()
        .filter(|probe| probe.path.exists())
        .map(|probe| format!("{} ({})", probe.label, probe.path.display()))
        .collect::<Vec<_>>();
    if !stale_paths.is_empty() {
        return Tiny11LabGateOutcome::Blocked(Tiny11LabGateBlocked {
            blocker: Tiny11LabGateBlocker::UncleanState,
            detail: format!(
                "canonical Tiny11 interop store at {} is not in the expected clean state: {}",
                evidence.image_store_root.display(),
                stale_paths.join(", ")
            ),
            remediation: None,
            image_store_root: evidence.image_store_root.clone(),
            manifest_dir: evidence.manifest_dir,
        });
    }

    let missing_runtime_inputs = inputs
        .runtime_inputs
        .iter()
        .filter(|input| !tiny11_lab_runtime_input_is_ready(input))
        .map(|input| input.label.clone())
        .collect::<Vec<_>>();
    if !missing_runtime_inputs.is_empty() {
        return Tiny11LabGateOutcome::Blocked(Tiny11LabGateBlocked {
            blocker: Tiny11LabGateBlocker::MissingRuntimeInputs,
            detail: format!(
                "missing required Tiny11 lab runtime inputs: {}",
                missing_runtime_inputs.join(", ")
            ),
            remediation: None,
            image_store_root: evidence.image_store_root.clone(),
            manifest_dir: evidence.manifest_dir,
        });
    }

    Tiny11LabGateOutcome::Ready(Tiny11LabGateReady {
        image_store_root: evidence.image_store_root.clone(),
        manifest_dir: evidence.manifest_dir.clone(),
        evidence,
    })
}

#[cfg(unix)]
fn render_consume_image_remediation(config_path: Option<&Path>, source_manifest_path: Option<&Path>) -> String {
    let Some(source_manifest_path) = source_manifest_path else {
        return GENERIC_CONSUME_IMAGE_REMEDIATION.to_owned();
    };
    if !source_manifest_path.is_file() {
        return GENERIC_CONSUME_IMAGE_REMEDIATION.to_owned();
    }

    let config_display = config_path
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| "<control-plane.toml>".to_owned());
    format!(
        "populate the canonical Tiny11 interop store with `honeypot-control-plane consume-image --config {} --source-manifest {}`",
        config_display,
        source_manifest_path.display()
    )
}

#[cfg(unix)]
fn tiny11_lab_runtime_input_is_ready(input: &Tiny11LabRuntimeInput) -> bool {
    match &input.check {
        Tiny11LabRuntimeInputCheck::NonEmptyText(value) => value.as_ref().is_some_and(|value| !value.trim().is_empty()),
        Tiny11LabRuntimeInputCheck::ExistingPath(path) => path.exists(),
        Tiny11LabRuntimeInputCheck::ExistingCommand(path) => {
            if path.components().count() == 1 && matches!(path.components().next(), Some(Component::Normal(_))) {
                std::env::var_os("PATH").is_some_and(|paths| {
                    std::env::split_paths(&paths).any(|search_root| search_root.join(path).is_file())
                })
            } else {
                path.is_file()
            }
        }
    }
}

#[cfg(unix)]
pub const ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE: &str = "gold_image_acceptance";
#[cfg(unix)]
pub const ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY: &str = "gold_image_repeatability";
#[cfg(unix)]
pub const ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP: &str = "external_client_interop";
#[cfg(unix)]
pub const ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL: &str = "digest_mismatch_negative_control";
#[cfg(unix)]
pub const ROW706_EVIDENCE_SCHEMA_VERSION: u32 = 2;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Row706AnchorStatus {
    Passed,
    Skipped,
    Failed,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Row706RunStatus {
    Running,
    Complete,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row706AnchorResult {
    pub schema_version: u32,
    pub run_id: String,
    pub anchor_id: String,
    pub executed: bool,
    pub status: Row706AnchorStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_image_path: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_store_root: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row706RunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub created_at_unix_secs: u64,
    pub status: Row706RunStatus,
    pub expected_anchor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_unix_secs: Option<u64>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row706EvidenceEnvelope {
    pub anchor_results: Vec<Row706AnchorResult>,
    pub attestation_ref: String,
    pub base_image_path: PathBuf,
    pub image_store_root: PathBuf,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row706AttemptOutcomeKind {
    Verified,
    BlockedPrereq,
    FailedRuntime,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row706AttemptOutcome {
    pub run_id: String,
    pub kind: Row706AttemptOutcomeKind,
    pub detail: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Row706AttemptDisposition {
    ReadyForVerification,
    BlockedPrereq { detail: String },
}

#[cfg(unix)]
impl Row706AttemptOutcome {
    fn verified(run_id: &str) -> Self {
        Self {
            run_id: run_id.to_owned(),
            kind: Row706AttemptOutcomeKind::Verified,
            detail: None,
        }
    }

    fn blocked_prereq(run_id: &str, detail: impl Into<String>) -> Self {
        Self {
            run_id: run_id.to_owned(),
            kind: Row706AttemptOutcomeKind::BlockedPrereq,
            detail: Some(detail.into()),
        }
    }

    fn failed_runtime(run_id: &str, detail: impl Into<String>) -> Self {
        Self {
            run_id: run_id.to_owned(),
            kind: Row706AttemptOutcomeKind::FailedRuntime,
            detail: Some(detail.into()),
        }
    }
}

#[cfg(unix)]
pub fn attempt_row706_evidence_run<F>(root: &Path, run_id: &str, execute: F) -> Row706AttemptOutcome
where
    F: FnOnce(&Path, &str) -> anyhow::Result<Row706AttemptDisposition>,
{
    if let Err(error) = row706_begin_run(root, run_id) {
        return Row706AttemptOutcome::failed_runtime(run_id, format!("{error:#}"));
    }

    let disposition = match execute(root, run_id) {
        Ok(disposition) => disposition,
        Err(error) => return Row706AttemptOutcome::failed_runtime(run_id, format!("{error:#}")),
    };

    match disposition {
        Row706AttemptDisposition::BlockedPrereq { detail } => Row706AttemptOutcome::blocked_prereq(run_id, detail),
        Row706AttemptDisposition::ReadyForVerification => match row706_complete_run(root, run_id) {
            Ok(true) => match verify_row706_evidence_envelope(root, run_id) {
                Ok(_) => Row706AttemptOutcome::verified(run_id),
                Err(error) => Row706AttemptOutcome::failed_runtime(run_id, format!("{error:#}")),
            },
            Ok(false) => Row706AttemptOutcome::failed_runtime(
                run_id,
                format!("row706 run {run_id} did not emit all required anchors"),
            ),
            Err(error) => Row706AttemptOutcome::failed_runtime(run_id, format!("{error:#}")),
        },
    }
}

#[cfg(unix)]
pub fn row706_default_evidence_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("testsuite crate should live under the repo root")
        .join("target/row706")
}

#[cfg(unix)]
pub fn row706_runs_root(root: &Path) -> PathBuf {
    root.join("runs")
}

#[cfg(unix)]
pub fn row706_run_dir(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    validate_row706_run_id(run_id)?;
    Ok(row706_runs_root(root).join(run_id))
}

#[cfg(unix)]
pub fn row706_begin_run(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    let run_dir = row706_run_dir(root, run_id)?;
    let runs_root = row706_runs_root(root);
    fs::create_dir_all(&runs_root).with_context(|| format!("create row706 runs root {}", runs_root.display()))?;

    if run_dir.exists() {
        let metadata = fs::symlink_metadata(&run_dir)
            .with_context(|| format!("read row706 run dir metadata {}", run_dir.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "row706 run dir must be a real directory: {}",
            run_dir.display()
        );
    } else {
        fs::create_dir(&run_dir).with_context(|| format!("create row706 run dir {}", run_dir.display()))?;
    }
    ensure_row706_run_dir_within_root(&runs_root, &run_dir)?;

    let manifest = Row706RunManifest {
        schema_version: ROW706_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        created_at_unix_secs: unix_timestamp_secs()?,
        status: Row706RunStatus::Running,
        expected_anchor_ids: expected_row706_anchor_ids()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        completed_at_unix_secs: None,
    };
    let manifest_path = row706_run_manifest_path(&run_dir);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .with_context(|| format!("create row706 run manifest {}", manifest_path.display()))?;
    let bytes = serde_json::to_vec_pretty(&manifest).context("serialize row706 run manifest")?;
    file.write_all(&bytes)
        .with_context(|| format!("write row706 run manifest {}", manifest_path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync row706 run manifest {}", manifest_path.display()))?;

    Ok(run_dir)
}

#[cfg(unix)]
pub fn row706_complete_run(root: &Path, run_id: &str) -> anyhow::Result<bool> {
    let run_dir = row706_run_dir(root, run_id)?;
    let mut manifest = read_row706_run_manifest(&run_dir)?;
    anyhow::ensure!(
        manifest.run_id == run_id,
        "row706 manifest run_id {} does not match requested run {}",
        manifest.run_id,
        run_id
    );

    if manifest.status == Row706RunStatus::Complete {
        return Ok(true);
    }

    if expected_row706_anchor_ids()
        .into_iter()
        .any(|anchor_id| !row706_anchor_result_path(&run_dir, anchor_id).is_file())
    {
        return Ok(false);
    }

    manifest.status = Row706RunStatus::Complete;
    manifest.completed_at_unix_secs = Some(unix_timestamp_secs()?);
    write_row706_run_manifest(&run_dir, &manifest)?;

    Ok(true)
}

#[cfg(unix)]
pub fn write_row706_anchor_result(root: &Path, run_id: &str, result: &Row706AnchorResult) -> anyhow::Result<()> {
    validate_row706_anchor_result_shape(result)?;
    anyhow::ensure!(
        result.run_id == run_id,
        "row706 anchor {} run_id {} does not match requested run {}",
        result.anchor_id,
        result.run_id,
        run_id
    );

    let run_dir = row706_run_dir(root, run_id)?;
    let manifest = read_row706_run_manifest(&run_dir)?;
    anyhow::ensure!(
        manifest.status == Row706RunStatus::Running,
        "row706 run {} must be running before writing anchor {}",
        run_id,
        result.anchor_id
    );
    anyhow::ensure!(
        manifest
            .expected_anchor_ids
            .iter()
            .any(|anchor_id| anchor_id == &result.anchor_id),
        "row706 anchor {} is not declared in manifest {}",
        result.anchor_id,
        row706_run_manifest_path(&run_dir).display()
    );

    let result_path = row706_anchor_result_path(&run_dir, &result.anchor_id);
    anyhow::ensure!(
        !result_path.exists(),
        "row706 anchor {} already exists in {}",
        result.anchor_id,
        result_path.display()
    );

    let tmp_path = result_path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(result).context("serialize row706 anchor result")?;
    fs::write(&tmp_path, bytes).with_context(|| format!("write row706 temp fragment {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &result_path).with_context(|| {
        format!(
            "publish row706 anchor result {} via {}",
            result_path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

#[cfg(unix)]
pub fn verify_row706_evidence_envelope(root: &Path, run_id: &str) -> anyhow::Result<Row706EvidenceEnvelope> {
    let run_dir = row706_run_dir(root, run_id)?;
    let manifest = read_row706_run_manifest(&run_dir)?;
    anyhow::ensure!(
        manifest.run_id == run_id,
        "row706 manifest run_id {} does not match requested run {}",
        manifest.run_id,
        run_id
    );
    anyhow::ensure!(
        manifest.status == Row706RunStatus::Complete,
        "row706 run {} must be complete before verification",
        run_id
    );

    let results = read_row706_anchor_results(&run_dir, &manifest)?;
    let mut by_anchor_id = BTreeMap::new();
    for result in results {
        by_anchor_id.insert(result.anchor_id.clone(), result);
    }

    let positive_anchor_results = [
        by_anchor_id
            .get(ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE)
            .expect("gold image acceptance anchor should exist"),
        by_anchor_id
            .get(ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY)
            .expect("gold image repeatability anchor should exist"),
        by_anchor_id
            .get(ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP)
            .expect("external client interop anchor should exist"),
    ];

    let first_positive_anchor = positive_anchor_results[0];
    anyhow::ensure!(
        first_positive_anchor.executed && first_positive_anchor.status == Row706AnchorStatus::Passed,
        "row706 positive anchor {} must be executed and passed",
        first_positive_anchor.anchor_id
    );
    let attestation_ref = first_positive_anchor.attestation_ref.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "row706 positive anchor {} is missing attestation_ref",
            first_positive_anchor.anchor_id
        )
    })?;
    let base_image_path = first_positive_anchor.base_image_path.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "row706 positive anchor {} is missing base_image_path",
            first_positive_anchor.anchor_id
        )
    })?;
    let image_store_root = first_positive_anchor.image_store_root.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "row706 positive anchor {} is missing image_store_root",
            first_positive_anchor.anchor_id
        )
    })?;

    for result in positive_anchor_results {
        anyhow::ensure!(
            result.executed && result.status == Row706AnchorStatus::Passed,
            "row706 positive anchor {} must be executed and passed",
            result.anchor_id
        );
        anyhow::ensure!(
            result.attestation_ref.as_deref() == Some(attestation_ref.as_str()),
            "row706 positive anchor {} does not match attestation_ref {}",
            result.anchor_id,
            attestation_ref
        );
        anyhow::ensure!(
            result.base_image_path.as_deref() == Some(base_image_path.as_path()),
            "row706 positive anchor {} does not match base_image_path {}",
            result.anchor_id,
            base_image_path.display()
        );
        anyhow::ensure!(
            result.image_store_root.as_deref() == Some(image_store_root.as_path()),
            "row706 positive anchor {} does not match image_store_root {}",
            result.anchor_id,
            image_store_root.display()
        );
    }

    let negative_control = by_anchor_id
        .get(ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL)
        .expect("digest mismatch negative control anchor should exist");
    anyhow::ensure!(
        negative_control.executed && negative_control.status == Row706AnchorStatus::Passed,
        "row706 negative control anchor {} must be executed and passed",
        negative_control.anchor_id
    );

    Ok(Row706EvidenceEnvelope {
        anchor_results: by_anchor_id.into_values().collect(),
        attestation_ref,
        base_image_path,
        image_store_root,
    })
}

#[cfg(unix)]
fn read_row706_anchor_results(run_dir: &Path, manifest: &Row706RunManifest) -> anyhow::Result<Vec<Row706AnchorResult>> {
    let mut json_paths = fs::read_dir(run_dir)
        .with_context(|| format!("read row706 run dir {}", run_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("collect row706 run entries from {}", run_dir.display()))?;
    json_paths.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
    json_paths.sort();

    let expected_json_names: BTreeMap<_, _> = expected_row706_anchor_ids()
        .into_iter()
        .map(|anchor_id| (format!("{anchor_id}.json"), anchor_id))
        .collect();
    for json_path in &json_paths {
        let file_name = json_path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .ok_or_else(|| anyhow::anyhow!("row706 run dir contains a non-utf8 json path {}", json_path.display()))?;
        anyhow::ensure!(
            file_name == "manifest.json" || expected_json_names.contains_key(file_name),
            "row706 run {} contains unexpected json file {}",
            manifest.run_id,
            json_path.display()
        );
    }

    let mut results = Vec::with_capacity(manifest.expected_anchor_ids.len());
    for anchor_id in &manifest.expected_anchor_ids {
        let result_path = row706_anchor_result_path(run_dir, anchor_id);
        let bytes =
            fs::read(&result_path).with_context(|| format!("read row706 fragment {}", result_path.display()))?;
        let result: Row706AnchorResult = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse row706 fragment {}", result_path.display()))?;
        validate_row706_anchor_result_shape(&result)?;
        anyhow::ensure!(
            result.run_id == manifest.run_id,
            "row706 anchor {} does not match run_id {}",
            result.anchor_id,
            manifest.run_id
        );
        results.push(result);
    }

    Ok(results)
}

#[cfg(unix)]
fn read_row706_run_manifest(run_dir: &Path) -> anyhow::Result<Row706RunManifest> {
    let manifest_path = row706_run_manifest_path(run_dir);
    let bytes =
        fs::read(&manifest_path).with_context(|| format!("read row706 run manifest {}", manifest_path.display()))?;
    let manifest: Row706RunManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse row706 run manifest {}", manifest_path.display()))?;
    validate_row706_run_manifest_shape(run_dir, &manifest)?;

    Ok(manifest)
}

#[cfg(unix)]
fn write_row706_run_manifest(run_dir: &Path, manifest: &Row706RunManifest) -> anyhow::Result<()> {
    validate_row706_run_manifest_shape(run_dir, manifest)?;
    let manifest_path = row706_run_manifest_path(run_dir);
    let tmp_path = manifest_path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(manifest).context("serialize row706 run manifest")?;
    fs::write(&tmp_path, bytes).with_context(|| format!("write row706 temp manifest {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &manifest_path).with_context(|| {
        format!(
            "publish row706 run manifest {} via {}",
            manifest_path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

#[cfg(unix)]
fn expected_row706_anchor_ids() -> [&'static str; 4] {
    [
        ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE,
        ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY,
        ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP,
        ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL,
    ]
}

#[cfg(unix)]
fn row706_run_manifest_path(run_dir: &Path) -> PathBuf {
    run_dir.join("manifest.json")
}

#[cfg(unix)]
fn row706_anchor_result_path(run_dir: &Path, anchor_id: &str) -> PathBuf {
    run_dir.join(format!("{anchor_id}.json"))
}

#[cfg(unix)]
fn validate_row706_anchor_result_shape(result: &Row706AnchorResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.schema_version == ROW706_EVIDENCE_SCHEMA_VERSION,
        "row706 anchor {} must use schema version {}",
        result.anchor_id,
        ROW706_EVIDENCE_SCHEMA_VERSION
    );
    validate_row706_run_id(&result.run_id)?;
    anyhow::ensure!(
        expected_row706_anchor_ids().contains(&result.anchor_id.as_str()),
        "row706 anchor id {} is not recognized",
        result.anchor_id
    );
    match result.status {
        Row706AnchorStatus::Skipped => anyhow::ensure!(
            !result.executed,
            "row706 skipped anchor {} must set executed=false",
            result.anchor_id
        ),
        Row706AnchorStatus::Passed | Row706AnchorStatus::Failed => anyhow::ensure!(
            result.executed,
            "row706 executed anchor {} must set executed=true when status is {:?}",
            result.anchor_id,
            result.status
        ),
    }

    Ok(())
}

#[cfg(unix)]
fn validate_row706_run_manifest_shape(run_dir: &Path, manifest: &Row706RunManifest) -> anyhow::Result<()> {
    anyhow::ensure!(
        manifest.schema_version == ROW706_EVIDENCE_SCHEMA_VERSION,
        "row706 manifest in {} must use schema version {}",
        row706_run_manifest_path(run_dir).display(),
        ROW706_EVIDENCE_SCHEMA_VERSION
    );
    validate_row706_run_id(&manifest.run_id)?;
    anyhow::ensure!(
        manifest.expected_anchor_ids.len() == expected_row706_anchor_ids().len(),
        "row706 manifest {} must declare all expected anchors",
        row706_run_manifest_path(run_dir).display()
    );
    for anchor_id in expected_row706_anchor_ids() {
        anyhow::ensure!(
            manifest
                .expected_anchor_ids
                .iter()
                .any(|declared_anchor| declared_anchor == anchor_id),
            "row706 manifest {} is missing expected anchor {}",
            row706_run_manifest_path(run_dir).display(),
            anchor_id
        );
    }
    if manifest.status == Row706RunStatus::Complete {
        anyhow::ensure!(
            manifest.completed_at_unix_secs.is_some(),
            "row706 manifest {} must record completed_at_unix_secs when complete",
            row706_run_manifest_path(run_dir).display()
        );
    }

    Ok(())
}

#[cfg(unix)]
fn validate_row706_run_id(run_id: &str) -> anyhow::Result<()> {
    let parsed = Uuid::parse_str(run_id).with_context(|| format!("row706 run_id {run_id} must be a valid UUID"))?;
    anyhow::ensure!(
        parsed.get_version_num() == 4,
        "row706 run_id {run_id} must be a UUID v4"
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_row706_run_dir_within_root(runs_root: &Path, run_dir: &Path) -> anyhow::Result<()> {
    let canonical_runs_root = runs_root
        .canonicalize()
        .with_context(|| format!("canonicalize row706 runs root {}", runs_root.display()))?;
    let canonical_run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("canonicalize row706 run dir {}", run_dir.display()))?;
    anyhow::ensure!(
        canonical_run_dir.starts_with(&canonical_runs_root),
        "row706 run dir {} escapes runs root {}",
        canonical_run_dir.display(),
        canonical_runs_root.display()
    );
    Ok(())
}

#[cfg(unix)]
fn unix_timestamp_secs() -> anyhow::Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs())
}

#[cfg(unix)]
fn ensure_non_empty_manifest_field(manifest_path: &Path, field_name: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        !value.trim().is_empty(),
        "{field_name} must not be empty in {}",
        manifest_path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn validate_sha256_field(manifest_path: &Path, field_name: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{field_name} must be a 64-character lowercase or uppercase hex SHA-256 in {}",
        manifest_path.display()
    );
    Ok(())
}

#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_PREREQ_GATE: &str = "manual_prereq_gate";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_IDENTITY_BINDING: &str = "manual_identity_binding";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN: &str = "manual_stack_startup_shutdown";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_TINY11_RDP_READY: &str = "manual_tiny11_rdp_ready";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION: &str = "manual_headed_qemu_chrome_observation";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION: &str = "manual_bounded_interaction";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE: &str = "manual_video_evidence";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE: &str = "manual_redaction_hygiene";
#[cfg(unix)]
pub const MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE: &str = "manual_artifact_storage";
#[cfg(unix)]
pub const MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION: u32 = 1;
#[cfg(unix)]
const MANUAL_HEADED_INTERACTION_MAX_DURATION_SECS: u64 = 3600;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualHeadedAnchorStatus {
    Passed,
    BlockedPrereq,
    Failed,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManualHeadedRunStatus {
    Running,
    Complete,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualHeadedAnchorResult {
    pub schema_version: u32,
    pub run_id: String,
    pub row706_run_id: String,
    pub anchor_id: String,
    pub executed: bool,
    pub status: ManualHeadedAnchorStatus,
    pub producer: String,
    pub captured_at_unix_secs: u64,
    pub source_artifact_relpath: PathBuf,
    pub source_artifact_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vm_lease_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManualHeadedRunManifest {
    pub schema_version: u32,
    pub run_id: String,
    pub created_at_unix_secs: u64,
    pub status: ManualHeadedRunStatus,
    pub expected_anchor_ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completed_at_unix_secs: Option<u64>,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManualHeadedEvidenceEnvelope {
    pub row706_run_id: String,
    pub anchor_results: Vec<ManualHeadedAnchorResult>,
}

#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ManualHeadedTimeWindow {
    start_unix_secs: u64,
    end_unix_secs: u64,
}

#[cfg(unix)]
impl ManualHeadedTimeWindow {
    fn duration_secs(self) -> u64 {
        self.end_unix_secs - self.start_unix_secs
    }

    fn contains(self, other: Self) -> bool {
        self.start_unix_secs <= other.start_unix_secs && self.end_unix_secs >= other.end_unix_secs
    }
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ManualHeadedTiny11RdpReadyArtifact {
    session_id: Option<String>,
    vm_lease_id: String,
    row706_run_id: String,
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy)]
struct ManualHeadedAnchorSpec {
    id: &'static str,
    runtime_required: bool,
    requires_session_id: bool,
    requires_vm_lease_id: bool,
}

#[cfg(unix)]
const MANUAL_HEADED_ANCHOR_SPECS: [ManualHeadedAnchorSpec; 9] = [
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_PREREQ_GATE,
        runtime_required: false,
        requires_session_id: false,
        requires_vm_lease_id: false,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_IDENTITY_BINDING,
        runtime_required: false,
        requires_session_id: false,
        requires_vm_lease_id: false,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
        runtime_required: true,
        requires_session_id: false,
        requires_vm_lease_id: false,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        runtime_required: true,
        requires_session_id: false,
        requires_vm_lease_id: true,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
        runtime_required: true,
        requires_session_id: true,
        requires_vm_lease_id: true,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        runtime_required: true,
        requires_session_id: true,
        requires_vm_lease_id: true,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
        runtime_required: true,
        requires_session_id: true,
        requires_vm_lease_id: true,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE,
        runtime_required: false,
        requires_session_id: false,
        requires_vm_lease_id: false,
    },
    ManualHeadedAnchorSpec {
        id: MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE,
        runtime_required: false,
        requires_session_id: false,
        requires_vm_lease_id: false,
    },
];

#[cfg(unix)]
pub fn manual_headed_profile_dir(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    Ok(ensure_row706_run_dir_exists(root, run_id)?.join("manual_headed"))
}

#[cfg(unix)]
pub fn manual_headed_artifacts_root(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    Ok(manual_headed_profile_dir(root, run_id)?.join("artifacts"))
}

#[cfg(unix)]
pub fn resolve_manual_headed_anchor_artifact_path(
    root: &Path,
    run_id: &str,
    relpath: &Path,
) -> anyhow::Result<PathBuf> {
    manual_headed_anchor_artifact_path(root, run_id, relpath)
}

#[cfg(unix)]
pub fn manual_headed_anchor_runtime_required(anchor_id: &str) -> anyhow::Result<bool> {
    Ok(manual_headed_anchor_spec(anchor_id)
        .ok_or_else(|| anyhow::anyhow!("manual-headed anchor id {} is not recognized", anchor_id))?
        .runtime_required)
}

#[cfg(unix)]
pub fn validate_manual_headed_anchor_artifact(
    anchor_id: &str,
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
    row706_envelope: Option<&Row706EvidenceEnvelope>,
    row706_run_id: Option<&str>,
) -> anyhow::Result<()> {
    match anchor_id {
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN => {
            validate_manual_headed_stack_startup_shutdown_artifact(artifact_path)
        }
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY => {
            let _ = validate_manual_headed_tiny11_rdp_ready_artifact(
                artifact_path,
                session_id,
                vm_lease_id,
                row706_envelope,
                row706_run_id,
            )?;
            Ok(())
        }
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION => {
            validate_manual_headed_qemu_chrome_observation_artifact(artifact_path, session_id, vm_lease_id)
        }
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION => {
            validate_manual_headed_bounded_interaction_artifact(artifact_path, session_id, vm_lease_id)
        }
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE => {
            validate_manual_headed_video_evidence_artifact(artifact_path, session_id, vm_lease_id)
        }
        _ => {
            let _ = (session_id, vm_lease_id, row706_envelope, row706_run_id);
            Ok(())
        }
    }
}

#[cfg(unix)]
pub fn manual_headed_begin_run(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    let profile_dir = manual_headed_profile_dir(root, run_id)?;
    let artifacts_root = profile_dir.join("artifacts");
    if profile_dir.exists() {
        let metadata = fs::symlink_metadata(&profile_dir)
            .with_context(|| format!("read manual-headed profile metadata {}", profile_dir.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "manual-headed profile dir must be a real directory: {}",
            profile_dir.display()
        );
    } else {
        fs::create_dir_all(&profile_dir)
            .with_context(|| format!("create manual-headed profile dir {}", profile_dir.display()))?;
    }
    fs::create_dir_all(&artifacts_root)
        .with_context(|| format!("create manual-headed artifacts root {}", artifacts_root.display()))?;
    ensure_manual_headed_dir_within_run(root, run_id, &profile_dir)?;

    let manifest = ManualHeadedRunManifest {
        schema_version: MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
        run_id: run_id.to_owned(),
        created_at_unix_secs: unix_timestamp_secs()?,
        status: ManualHeadedRunStatus::Running,
        expected_anchor_ids: manual_headed_expected_anchor_ids()
            .into_iter()
            .map(ToOwned::to_owned)
            .collect(),
        completed_at_unix_secs: None,
    };
    let manifest_path = manual_headed_run_manifest_path(&profile_dir);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&manifest_path)
        .with_context(|| format!("create manual-headed run manifest {}", manifest_path.display()))?;
    let bytes = serde_json::to_vec_pretty(&manifest).context("serialize manual-headed run manifest")?;
    file.write_all(&bytes)
        .with_context(|| format!("write manual-headed run manifest {}", manifest_path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync manual-headed run manifest {}", manifest_path.display()))?;

    Ok(profile_dir)
}

#[cfg(unix)]
pub fn manual_headed_complete_run(root: &Path, run_id: &str) -> anyhow::Result<bool> {
    let profile_dir = manual_headed_profile_dir(root, run_id)?;
    let mut manifest = read_manual_headed_run_manifest(&profile_dir)?;
    anyhow::ensure!(
        manifest.run_id == run_id,
        "manual-headed manifest run_id {} does not match requested run {}",
        manifest.run_id,
        run_id
    );

    if manifest.status == ManualHeadedRunStatus::Complete {
        return Ok(true);
    }

    if manual_headed_expected_anchor_ids()
        .into_iter()
        .any(|anchor_id| !manual_headed_anchor_result_path(&profile_dir, anchor_id).is_file())
    {
        return Ok(false);
    }

    manifest.status = ManualHeadedRunStatus::Complete;
    manifest.completed_at_unix_secs = Some(unix_timestamp_secs()?);
    write_manual_headed_run_manifest(&profile_dir, &manifest)?;

    Ok(true)
}

#[cfg(unix)]
pub fn write_manual_headed_anchor_result(
    root: &Path,
    run_id: &str,
    result: &ManualHeadedAnchorResult,
) -> anyhow::Result<()> {
    validate_manual_headed_anchor_result_shape(result)?;
    anyhow::ensure!(
        result.run_id == run_id,
        "manual-headed anchor {} run_id {} does not match requested run {}",
        result.anchor_id,
        result.run_id,
        run_id
    );
    anyhow::ensure!(
        result.row706_run_id == run_id,
        "manual-headed anchor {} must bind to row706 run {}",
        result.anchor_id,
        run_id
    );

    let profile_dir = manual_headed_profile_dir(root, run_id)?;
    let manifest = read_manual_headed_run_manifest(&profile_dir)?;
    anyhow::ensure!(
        manifest.status == ManualHeadedRunStatus::Running,
        "manual-headed run {} must be running before writing anchor {}",
        run_id,
        result.anchor_id
    );
    anyhow::ensure!(
        manifest
            .expected_anchor_ids
            .iter()
            .any(|anchor_id| anchor_id == &result.anchor_id),
        "manual-headed anchor {} is not declared in manifest {}",
        result.anchor_id,
        manual_headed_run_manifest_path(&profile_dir).display()
    );

    let artifact_path = manual_headed_anchor_artifact_path(root, run_id, &result.source_artifact_relpath)?;
    anyhow::ensure!(
        artifact_path.is_file(),
        "manual-headed anchor {} source artifact {} does not exist",
        result.anchor_id,
        artifact_path.display()
    );
    let actual_sha256 = sha256_file_hex(&artifact_path)?;
    anyhow::ensure!(
        actual_sha256.eq_ignore_ascii_case(&result.source_artifact_sha256),
        "manual-headed anchor {} source artifact digest mismatch for {}",
        result.anchor_id,
        artifact_path.display()
    );

    let result_path = manual_headed_anchor_result_path(&profile_dir, &result.anchor_id);
    anyhow::ensure!(
        !result_path.exists(),
        "manual-headed anchor {} already exists in {}",
        result.anchor_id,
        result_path.display()
    );
    let tmp_path = result_path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(result).context("serialize manual-headed anchor result")?;
    fs::write(&tmp_path, bytes).with_context(|| format!("write manual-headed temp fragment {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &result_path).with_context(|| {
        format!(
            "publish manual-headed anchor result {} via {}",
            result_path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

#[cfg(unix)]
pub fn verify_manual_headed_evidence_envelope(
    root: &Path,
    run_id: &str,
) -> anyhow::Result<ManualHeadedEvidenceEnvelope> {
    let profile_dir = manual_headed_profile_dir(root, run_id)?;
    let manifest = read_manual_headed_run_manifest(&profile_dir)?;
    anyhow::ensure!(
        manifest.run_id == run_id,
        "manual-headed manifest run_id {} does not match requested run {}",
        manifest.run_id,
        run_id
    );
    anyhow::ensure!(
        manifest.status == ManualHeadedRunStatus::Complete,
        "manual-headed run {} must be complete before verification",
        run_id
    );

    let results = read_manual_headed_anchor_results(root, run_id, &profile_dir, &manifest)?;
    let by_anchor_id: BTreeMap<_, _> = results
        .iter()
        .map(|result| (result.anchor_id.as_str(), result))
        .collect();

    for spec in MANUAL_HEADED_ANCHOR_SPECS {
        let result = by_anchor_id
            .get(spec.id)
            .copied()
            .ok_or_else(|| anyhow::anyhow!("manual-headed anchor {} is missing", spec.id))?;
        anyhow::ensure!(
            result.executed && result.status == ManualHeadedAnchorStatus::Passed,
            "manual-headed anchor {} must be executed and passed",
            spec.id
        );
        if spec.runtime_required {
            verify_row706_evidence_envelope(root, &result.row706_run_id).with_context(|| {
                format!(
                    "manual-headed runtime anchor {} requires a verified row706 run {}",
                    spec.id, result.row706_run_id
                )
            })?;
        }
    }

    let rdp_ready = by_anchor_id
        .get(MANUAL_HEADED_ANCHOR_TINY11_RDP_READY)
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manual-headed anchor {} is missing",
                MANUAL_HEADED_ANCHOR_TINY11_RDP_READY
            )
        })?;
    let rdp_ready_row706 = verify_row706_evidence_envelope(root, &rdp_ready.row706_run_id).with_context(|| {
        format!(
            "manual-headed Tiny11 RDP-ready anchor {} requires a verified row706 run {}",
            MANUAL_HEADED_ANCHOR_TINY11_RDP_READY, rdp_ready.row706_run_id
        )
    })?;
    let rdp_ready_path = manual_headed_anchor_artifact_path(root, run_id, &rdp_ready.source_artifact_relpath)?;
    let rdp_ready_artifact = validate_manual_headed_tiny11_rdp_ready_artifact(
        &rdp_ready_path,
        rdp_ready.session_id.as_deref(),
        rdp_ready.vm_lease_id.as_deref(),
        Some(&rdp_ready_row706),
        Some(&rdp_ready.row706_run_id),
    )?;
    let headed_observation = by_anchor_id
        .get(MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION)
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manual-headed anchor {} is missing",
                MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
            )
        })?;
    anyhow::ensure!(
        headed_observation.vm_lease_id == rdp_ready.vm_lease_id,
        "manual-headed anchors {} and {} must bind to the same vm_lease_id",
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
    );
    if let Some(rdp_ready_session_id) = rdp_ready_artifact.session_id.as_deref() {
        anyhow::ensure!(
            headed_observation.session_id.as_deref() == Some(rdp_ready_session_id),
            "manual-headed anchors {} and {} must bind to the same session_id when Tiny11 RDP-ready evidence records one",
            MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
            MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
        );
    }
    anyhow::ensure!(
        rdp_ready_artifact.vm_lease_id == headed_observation.vm_lease_id.as_deref().unwrap_or_default(),
        "manual-headed anchors {} and {} must bind to the same vm_lease_id inside the Tiny11 RDP-ready artifact",
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
    );
    anyhow::ensure!(
        rdp_ready_artifact.row706_run_id == rdp_ready.row706_run_id,
        "manual-headed anchor {} must keep artifact provenance.row706_run_id aligned with row706_run_id {}",
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        rdp_ready.row706_run_id
    );
    let bounded_interaction = by_anchor_id
        .get(MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION)
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manual-headed anchor {} is missing",
                MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION
            )
        })?;
    let video_evidence = by_anchor_id
        .get(MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE)
        .copied()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "manual-headed anchor {} is missing",
                MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE
            )
        })?;
    anyhow::ensure!(
        bounded_interaction.session_id == headed_observation.session_id,
        "manual-headed anchors {} and {} must bind to the same session_id",
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
    );
    anyhow::ensure!(
        bounded_interaction.vm_lease_id == headed_observation.vm_lease_id,
        "manual-headed anchors {} and {} must bind to the same vm_lease_id",
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION
    );
    anyhow::ensure!(
        bounded_interaction.session_id == video_evidence.session_id,
        "manual-headed anchors {} and {} must bind to the same session_id",
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE
    );
    anyhow::ensure!(
        bounded_interaction.vm_lease_id == video_evidence.vm_lease_id,
        "manual-headed anchors {} and {} must bind to the same vm_lease_id",
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE
    );

    let bounded_interaction_path =
        manual_headed_anchor_artifact_path(root, run_id, &bounded_interaction.source_artifact_relpath)?;
    let bounded_interaction_window = read_manual_headed_bounded_interaction_window(&bounded_interaction_path)?;
    let video_evidence_path =
        manual_headed_anchor_artifact_path(root, run_id, &video_evidence.source_artifact_relpath)?;
    let video_window = read_manual_headed_video_evidence_window(&video_evidence_path)?;
    anyhow::ensure!(
        video_window.contains(bounded_interaction_window),
        "manual-headed interaction window must stay within the recorded video timestamp_window"
    );

    Ok(ManualHeadedEvidenceEnvelope {
        row706_run_id: run_id.to_owned(),
        anchor_results: results,
    })
}

#[cfg(unix)]
fn read_manual_headed_anchor_results(
    root: &Path,
    run_id: &str,
    profile_dir: &Path,
    manifest: &ManualHeadedRunManifest,
) -> anyhow::Result<Vec<ManualHeadedAnchorResult>> {
    let mut json_paths = fs::read_dir(profile_dir)
        .with_context(|| format!("read manual-headed run dir {}", profile_dir.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("collect manual-headed run entries from {}", profile_dir.display()))?;
    json_paths.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
    json_paths.sort();

    let expected_json_names: BTreeMap<_, _> = manual_headed_expected_anchor_ids()
        .into_iter()
        .map(|anchor_id| (format!("{anchor_id}.json"), anchor_id))
        .collect();
    for json_path in &json_paths {
        let file_name = json_path
            .file_name()
            .and_then(|file_name| file_name.to_str())
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "manual-headed run dir contains a non-utf8 json path {}",
                    json_path.display()
                )
            })?;
        anyhow::ensure!(
            file_name == "manifest.json" || expected_json_names.contains_key(file_name),
            "manual-headed run {} contains unexpected json file {}",
            manifest.run_id,
            json_path.display()
        );
    }

    let mut results = Vec::with_capacity(manifest.expected_anchor_ids.len());
    for anchor_id in &manifest.expected_anchor_ids {
        let result_path = manual_headed_anchor_result_path(profile_dir, anchor_id);
        let bytes =
            fs::read(&result_path).with_context(|| format!("read manual-headed fragment {}", result_path.display()))?;
        let result: ManualHeadedAnchorResult = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse manual-headed fragment {}", result_path.display()))?;
        validate_manual_headed_anchor_result_shape(&result)?;
        anyhow::ensure!(
            result.run_id == manifest.run_id,
            "manual-headed anchor {} does not match run_id {}",
            result.anchor_id,
            manifest.run_id
        );
        anyhow::ensure!(
            result.row706_run_id == run_id,
            "manual-headed anchor {} must bind to row706 run {}",
            result.anchor_id,
            run_id
        );

        let artifact_path = manual_headed_anchor_artifact_path(root, run_id, &result.source_artifact_relpath)?;
        anyhow::ensure!(
            artifact_path.is_file(),
            "manual-headed anchor {} source artifact {} does not exist",
            result.anchor_id,
            artifact_path.display()
        );
        let metadata = fs::symlink_metadata(&artifact_path)
            .with_context(|| format!("read manual-headed artifact metadata {}", artifact_path.display()))?;
        anyhow::ensure!(
            !metadata.file_type().is_symlink(),
            "manual-headed anchor {} source artifact must not be a symlink: {}",
            result.anchor_id,
            artifact_path.display()
        );
        let actual_sha256 = sha256_file_hex(&artifact_path)?;
        anyhow::ensure!(
            actual_sha256.eq_ignore_ascii_case(&result.source_artifact_sha256),
            "manual-headed anchor {} source artifact digest mismatch for {}",
            result.anchor_id,
            artifact_path.display()
        );
        let row706_envelope = if result.anchor_id == MANUAL_HEADED_ANCHOR_TINY11_RDP_READY {
            Some(
                verify_row706_evidence_envelope(root, &result.row706_run_id).with_context(|| {
                    format!(
                        "manual-headed Tiny11 RDP-ready anchor {} requires a verified row706 run {}",
                        result.anchor_id, result.row706_run_id
                    )
                })?,
            )
        } else {
            None
        };
        validate_manual_headed_anchor_artifact(
            &result.anchor_id,
            &artifact_path,
            result.session_id.as_deref(),
            result.vm_lease_id.as_deref(),
            row706_envelope.as_ref(),
            Some(&result.row706_run_id),
        )
        .with_context(|| {
            format!(
                "validate manual-headed artifact semantics for anchor {}",
                result.anchor_id
            )
        })?;
        results.push(result);
    }

    Ok(results)
}

#[cfg(unix)]
fn validate_manual_headed_stack_startup_shutdown_artifact(artifact_path: &Path) -> anyhow::Result<()> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "stack startup or shutdown artifact {} must be a json object",
            artifact_path.display()
        )
    })?;

    let startup_captured_at_unix_secs = object
        .get("startup_captured_at_unix_secs")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide startup_captured_at_unix_secs > 0",
                artifact_path.display()
            )
        })?;
    let teardown_captured_at_unix_secs = object
        .get("teardown_captured_at_unix_secs")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide teardown_captured_at_unix_secs >= startup_captured_at_unix_secs",
                artifact_path.display()
            )
        })?;
    anyhow::ensure!(
        startup_captured_at_unix_secs > 0 && teardown_captured_at_unix_secs >= startup_captured_at_unix_secs,
        "stack startup or shutdown artifact {} must provide ordered startup and teardown timestamps",
        artifact_path.display()
    );

    let services = object.get("services").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "stack startup or shutdown artifact {} must provide services for control-plane, proxy, and frontend",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        services.len() == 3,
        "stack startup or shutdown artifact {} must provide exactly three services",
        artifact_path.display()
    );
    for service_id in ["control-plane", "proxy", "frontend"] {
        let service = services.get(service_id).and_then(Value::as_object).ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide services.{service_id}",
                artifact_path.display()
            )
        })?;
        let evidence_kind = service.get("evidence_kind").and_then(Value::as_str).ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide services.{service_id}.evidence_kind",
                artifact_path.display()
            )
        })?;
        anyhow::ensure!(
            matches!(evidence_kind, "health" | "bootstrap"),
            "stack startup or shutdown artifact {} must use evidence_kind health or bootstrap for service {}",
            artifact_path.display(),
            service_id
        );
        let startup_status = service.get("startup_status").and_then(Value::as_str).ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide services.{service_id}.startup_status",
                artifact_path.display()
            )
        })?;
        anyhow::ensure!(
            matches!(startup_status, "healthy" | "ready" | "reachable"),
            "stack startup or shutdown artifact {} must use startup_status healthy, ready, or reachable for service {}",
            artifact_path.display(),
            service_id
        );
    }

    let teardown_disposition = object
        .get("teardown_disposition")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "stack startup or shutdown artifact {} must provide teardown_disposition",
                artifact_path.display()
            )
        })?;
    match teardown_disposition {
        "clean_shutdown" => Ok(()),
        "explicit_failure" => {
            validate_manual_headed_nonempty_json_string(object.get("failure_code"), "failure_code", artifact_path)?;
            validate_manual_headed_nonempty_json_string(object.get("failure_reason"), "failure_reason", artifact_path)?;
            Ok(())
        }
        _ => anyhow::bail!(
            "stack startup or shutdown artifact {} must use teardown_disposition clean_shutdown or explicit_failure",
            artifact_path.display()
        ),
    }
}

#[cfg(unix)]
fn validate_manual_headed_tiny11_rdp_ready_artifact(
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
    row706_envelope: Option<&Row706EvidenceEnvelope>,
    row706_run_id: Option<&str>,
) -> anyhow::Result<ManualHeadedTiny11RdpReadyArtifact> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "Tiny11 RDP-ready artifact {} must be a json object",
            artifact_path.display()
        )
    })?;

    let probe = object.get("probe").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "Tiny11 RDP-ready artifact {} must provide probe",
            artifact_path.display()
        )
    })?;
    validate_manual_headed_nonempty_json_string(probe.get("method"), "probe.method", artifact_path)?;
    validate_manual_headed_nonempty_json_string(probe.get("endpoint"), "probe.endpoint", artifact_path)?;
    anyhow::ensure!(
        probe
            .get("captured_at_unix_secs")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "Tiny11 RDP-ready artifact {} must provide probe.captured_at_unix_secs > 0",
        artifact_path.display()
    );
    anyhow::ensure!(
        probe.get("ready").and_then(Value::as_bool) == Some(true),
        "Tiny11 RDP-ready artifact {} must provide probe.ready = true",
        artifact_path.display()
    );
    validate_manual_headed_nonempty_json_string(probe.get("evidence_ref"), "probe.evidence_ref", artifact_path)?;

    let identity = object.get("identity").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "Tiny11 RDP-ready artifact {} must provide identity",
            artifact_path.display()
        )
    })?;
    let actual_vm_lease_id = identity
        .get("vm_lease_id")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact {} must provide identity.vm_lease_id", artifact_path.display()))?;
    anyhow::ensure!(
        !actual_vm_lease_id.trim().is_empty(),
        "artifact {} must provide a non-empty identity.vm_lease_id",
        artifact_path.display()
    );
    if let Some(expected_vm_lease_id) = vm_lease_id {
        anyhow::ensure!(
            actual_vm_lease_id == expected_vm_lease_id,
            "artifact {} identity.vm_lease_id {} does not match requested {}",
            artifact_path.display(),
            actual_vm_lease_id,
            expected_vm_lease_id
        );
    }
    let actual_session_id =
        read_manual_headed_optional_json_string(identity.get("session_id"), "identity.session_id", artifact_path)?;
    if let Some(expected_session_id) = session_id {
        anyhow::ensure!(
            actual_session_id.as_deref() == Some(expected_session_id),
            "artifact {} identity.session_id {:?} does not match requested {}",
            artifact_path.display(),
            actual_session_id,
            expected_session_id
        );
    }

    let provenance = object.get("provenance").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "Tiny11 RDP-ready artifact {} must provide provenance",
            artifact_path.display()
        )
    })?;
    let actual_row706_run_id = provenance.get("row706_run_id").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "artifact {} must provide provenance.row706_run_id",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        !actual_row706_run_id.trim().is_empty(),
        "artifact {} must provide a non-empty provenance.row706_run_id",
        artifact_path.display()
    );
    if let Some(expected_row706_run_id) = row706_run_id {
        anyhow::ensure!(
            actual_row706_run_id == expected_row706_run_id,
            "artifact {} provenance.row706_run_id {} does not match requested {}",
            artifact_path.display(),
            actual_row706_run_id,
            expected_row706_run_id
        );
    }
    let actual_attestation_ref = provenance
        .get("attestation_ref")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "artifact {} must provide provenance.attestation_ref",
                artifact_path.display()
            )
        })?;
    anyhow::ensure!(
        !actual_attestation_ref.trim().is_empty(),
        "artifact {} must provide a non-empty provenance.attestation_ref",
        artifact_path.display()
    );
    let actual_interop_store_root = provenance
        .get("interop_store_root")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "artifact {} must provide provenance.interop_store_root",
                artifact_path.display()
            )
        })?;
    anyhow::ensure!(
        !actual_interop_store_root.trim().is_empty(),
        "artifact {} must provide a non-empty provenance.interop_store_root",
        artifact_path.display()
    );
    if let Some(row706_envelope) = row706_envelope {
        anyhow::ensure!(
            actual_attestation_ref == row706_envelope.attestation_ref,
            "artifact {} provenance.attestation_ref {} does not match verified row706 attestation_ref {}",
            artifact_path.display(),
            actual_attestation_ref,
            row706_envelope.attestation_ref
        );
        anyhow::ensure!(
            actual_interop_store_root == row706_envelope.image_store_root.to_string_lossy(),
            "artifact {} provenance.interop_store_root {} does not match verified row706 image_store_root {}",
            artifact_path.display(),
            actual_interop_store_root,
            row706_envelope.image_store_root.display()
        );
    }

    let key_source = object.get("key_source").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "Tiny11 RDP-ready artifact {} must provide key_source",
            artifact_path.display()
        )
    })?;
    let key_source_class = key_source
        .get("class")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact {} must provide key_source.class", artifact_path.display()))?;
    anyhow::ensure!(
        matches!(
            key_source_class,
            "repo_allowlisted_windows_license" | "non_git_secret_alias"
        ),
        "Tiny11 RDP-ready artifact {} must use key_source.class repo_allowlisted_windows_license or non_git_secret_alias",
        artifact_path.display()
    );
    let key_source_alias = key_source
        .get("alias")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("artifact {} must provide key_source.alias", artifact_path.display()))?;
    anyhow::ensure!(
        !key_source_alias.trim().is_empty(),
        "artifact {} must provide a non-empty key_source.alias",
        artifact_path.display()
    );
    anyhow::ensure!(
        !manual_headed_value_looks_like_windows_product_key(key_source_alias),
        "Tiny11 RDP-ready artifact {} key_source.alias must not contain raw Windows product key material",
        artifact_path.display()
    );
    anyhow::ensure!(
        !manual_headed_value_looks_like_absolute_or_host_path(key_source_alias),
        "Tiny11 RDP-ready artifact {} key_source.alias must not expose an absolute or host-specific path",
        artifact_path.display()
    );
    if key_source_class == "repo_allowlisted_windows_license" {
        anyhow::ensure!(
            key_source_alias == "WINDOWS11-LICENSE.md",
            "Tiny11 RDP-ready artifact {} must use key_source.alias WINDOWS11-LICENSE.md for repo_allowlisted_windows_license",
            artifact_path.display()
        );
    }

    Ok(ManualHeadedTiny11RdpReadyArtifact {
        session_id: actual_session_id,
        vm_lease_id: actual_vm_lease_id.to_owned(),
        row706_run_id: actual_row706_run_id.to_owned(),
    })
}

#[cfg(unix)]
fn validate_manual_headed_qemu_chrome_observation_artifact(
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
) -> anyhow::Result<()> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "headed QEMU plus Chrome observation artifact {} must be a json object",
            artifact_path.display()
        )
    })?;

    let qemu_display_mode = object.get("qemu_display_mode").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "headed QEMU plus Chrome observation artifact {} must provide qemu_display_mode",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        qemu_display_mode == "headed",
        "headed QEMU plus Chrome observation artifact {} must use qemu_display_mode headed",
        artifact_path.display()
    );
    validate_manual_headed_nonempty_json_string(
        object.get("qemu_launch_reference"),
        "qemu_launch_reference",
        artifact_path,
    )?;

    let browser_family = object.get("browser_family").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "headed QEMU plus Chrome observation artifact {} must provide browser_family",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        browser_family == "chrome",
        "headed QEMU plus Chrome observation artifact {} must use browser_family chrome",
        artifact_path.display()
    );
    validate_manual_headed_nonempty_json_string(
        object.get("frontend_access_path"),
        "frontend_access_path",
        artifact_path,
    )?;

    let correlation_snapshot = object
        .get("correlation_snapshot")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "headed QEMU plus Chrome observation artifact {} must provide correlation_snapshot",
                artifact_path.display()
            )
        })?;
    let observed_surface = correlation_snapshot
        .get("observed_surface")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "headed QEMU plus Chrome observation artifact {} must provide correlation_snapshot.observed_surface",
                artifact_path.display()
            )
        })?;
    anyhow::ensure!(
        matches!(observed_surface, "tile" | "session"),
        "headed QEMU plus Chrome observation artifact {} must use observed_surface tile or session",
        artifact_path.display()
    );
    validate_manual_headed_optional_matching_json_string(
        correlation_snapshot.get("observed_session_id"),
        "correlation_snapshot.observed_session_id",
        session_id,
        artifact_path,
    )?;
    validate_manual_headed_optional_matching_json_string(
        correlation_snapshot.get("observed_vm_lease_id"),
        "correlation_snapshot.observed_vm_lease_id",
        vm_lease_id,
        artifact_path,
    )?;

    Ok(())
}

#[cfg(unix)]
fn validate_manual_headed_bounded_interaction_artifact(
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
) -> anyhow::Result<()> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "bounded interaction artifact {} must be a json object",
            artifact_path.display()
        )
    })?;

    let interaction_window = read_manual_headed_time_window(
        object.get("interaction_window"),
        "bounded interaction artifact",
        "interaction_window",
        artifact_path,
    )?;
    anyhow::ensure!(
        interaction_window.duration_secs() <= MANUAL_HEADED_INTERACTION_MAX_DURATION_SECS,
        "bounded interaction artifact {} must keep interaction_window within {} seconds",
        artifact_path.display(),
        MANUAL_HEADED_INTERACTION_MAX_DURATION_SECS
    );
    validate_manual_headed_optional_matching_json_string(
        object.get("session_id"),
        "session_id",
        session_id,
        artifact_path,
    )?;
    validate_manual_headed_optional_matching_json_string(
        object.get("vm_lease_id"),
        "vm_lease_id",
        vm_lease_id,
        artifact_path,
    )?;

    let modalities = object.get("modalities").and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "bounded interaction artifact {} must provide modalities.mouse, modalities.keyboard, and modalities.browsing",
            artifact_path.display()
        )
    })?;
    for modality in ["mouse", "keyboard", "browsing"] {
        let modality_object = modalities.get(modality).and_then(Value::as_object).ok_or_else(|| {
            anyhow::anyhow!(
                "bounded interaction artifact {} must provide modalities.{modality}",
                artifact_path.display()
            )
        })?;
        anyhow::ensure!(
            modality_object
                .get("event_count")
                .and_then(Value::as_u64)
                .is_some_and(|value| value > 0),
            "bounded interaction artifact {} must provide modalities.{modality}.event_count > 0",
            artifact_path.display()
        );
        let evidence_refs = modality_object
            .get("evidence_refs")
            .and_then(Value::as_array)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "bounded interaction artifact {} must provide modalities.{modality}.evidence_refs",
                    artifact_path.display()
                )
            })?;
        anyhow::ensure!(
            !evidence_refs.is_empty()
                && evidence_refs
                    .iter()
                    .all(|value| value.as_str().is_some_and(|value| !value.trim().is_empty())),
            "bounded interaction artifact {} must provide at least one non-empty modalities.{modality}.evidence_refs entry",
            artifact_path.display()
        );
    }

    Ok(())
}

#[cfg(unix)]
fn validate_manual_headed_video_evidence_artifact(
    artifact_path: &Path,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
) -> anyhow::Result<()> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must be a json object",
            artifact_path.display()
        )
    })?;

    let video_sha256 = object.get("video_sha256").and_then(Value::as_str).ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must provide video_sha256",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        manual_headed_value_is_sha256_hex(video_sha256),
        "video evidence artifact {} must provide a 64-character hex video_sha256",
        artifact_path.display()
    );
    anyhow::ensure!(
        object
            .get("duration_floor_secs")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "video evidence artifact {} must provide duration_floor_secs > 0",
        artifact_path.display()
    );
    let _ = read_manual_headed_time_window(
        object.get("timestamp_window"),
        "video evidence artifact",
        "timestamp_window",
        artifact_path,
    )?;
    validate_manual_headed_nonempty_json_string(object.get("storage_uri"), "storage_uri", artifact_path)?;
    validate_manual_headed_retention_window(object.get("retention_window"), artifact_path)?;
    validate_manual_headed_optional_matching_json_string(
        object.get("session_id"),
        "session_id",
        session_id,
        artifact_path,
    )?;
    validate_manual_headed_optional_matching_json_string(
        object.get("vm_lease_id"),
        "vm_lease_id",
        vm_lease_id,
        artifact_path,
    )?;

    Ok(())
}

#[cfg(unix)]
fn read_manual_headed_video_evidence_window(artifact_path: &Path) -> anyhow::Result<ManualHeadedTimeWindow> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must be a json object",
            artifact_path.display()
        )
    })?;
    read_manual_headed_time_window(
        object.get("timestamp_window"),
        "video evidence artifact",
        "timestamp_window",
        artifact_path,
    )
}

#[cfg(unix)]
fn read_manual_headed_bounded_interaction_window(artifact_path: &Path) -> anyhow::Result<ManualHeadedTimeWindow> {
    let document = read_json_document(artifact_path)?;
    let object = document.as_object().ok_or_else(|| {
        anyhow::anyhow!(
            "bounded interaction artifact {} must be a json object",
            artifact_path.display()
        )
    })?;
    read_manual_headed_time_window(
        object.get("interaction_window"),
        "bounded interaction artifact",
        "interaction_window",
        artifact_path,
    )
}

#[cfg(unix)]
fn read_manual_headed_time_window(
    value: Option<&Value>,
    artifact_kind: &str,
    field: &str,
    artifact_path: &Path,
) -> anyhow::Result<ManualHeadedTimeWindow> {
    let window = value.and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "{artifact_kind} {} must provide {field}.start_unix_secs and {field}.end_unix_secs",
            artifact_path.display()
        )
    })?;
    let start = window.get("start_unix_secs").and_then(Value::as_u64).ok_or_else(|| {
        anyhow::anyhow!(
            "{artifact_kind} {} must provide {field}.start_unix_secs",
            artifact_path.display()
        )
    })?;
    let end = window.get("end_unix_secs").and_then(Value::as_u64).ok_or_else(|| {
        anyhow::anyhow!(
            "{artifact_kind} {} must provide {field}.end_unix_secs",
            artifact_path.display()
        )
    })?;
    anyhow::ensure!(
        start > 0 && end > start,
        "{artifact_kind} {} must provide an ordered {field} range",
        artifact_path.display()
    );
    Ok(ManualHeadedTimeWindow {
        start_unix_secs: start,
        end_unix_secs: end,
    })
}

#[cfg(unix)]
fn validate_manual_headed_retention_window(value: Option<&Value>, artifact_path: &Path) -> anyhow::Result<()> {
    let retention_window = value.and_then(Value::as_object).ok_or_else(|| {
        anyhow::anyhow!(
            "video evidence artifact {} must provide retention_window.policy and retention_window.expires_at_unix_secs",
            artifact_path.display()
        )
    })?;
    validate_manual_headed_nonempty_json_string(
        retention_window.get("policy"),
        "retention_window.policy",
        artifact_path,
    )?;
    anyhow::ensure!(
        retention_window
            .get("expires_at_unix_secs")
            .and_then(Value::as_u64)
            .is_some_and(|value| value > 0),
        "video evidence artifact {} must provide retention_window.expires_at_unix_secs > 0",
        artifact_path.display()
    );
    Ok(())
}

#[cfg(unix)]
fn read_json_document(path: &Path) -> anyhow::Result<Value> {
    let bytes = fs::read(path).with_context(|| format!("read json artifact {}", path.display()))?;
    serde_json::from_slice(&bytes).with_context(|| format!("parse json artifact {}", path.display()))
}

#[cfg(unix)]
fn read_manual_headed_optional_json_string(
    value: Option<&Value>,
    field: &str,
    artifact_path: &Path,
) -> anyhow::Result<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            anyhow::ensure!(
                !value.trim().is_empty(),
                "artifact {} must provide a non-empty {} when present",
                artifact_path.display(),
                field
            );
            Ok(Some(value.clone()))
        }
        _ => Err(anyhow::anyhow!(
            "artifact {} must provide {} as a string when present",
            artifact_path.display(),
            field
        )),
    }
}

#[cfg(unix)]
fn validate_manual_headed_nonempty_json_string(
    value: Option<&Value>,
    field: &str,
    artifact_path: &Path,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        value
            .and_then(Value::as_str)
            .is_some_and(|value| !value.trim().is_empty()),
        "artifact {} must provide a non-empty {}",
        artifact_path.display(),
        field
    );
    Ok(())
}

#[cfg(unix)]
fn validate_manual_headed_optional_matching_json_string(
    value: Option<&Value>,
    field: &str,
    expected: Option<&str>,
    artifact_path: &Path,
) -> anyhow::Result<()> {
    if let Some(expected) = expected {
        let actual = value
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("artifact {} must provide {}", artifact_path.display(), field))?;
        anyhow::ensure!(
            actual == expected,
            "artifact {} {} {} does not match requested {}",
            artifact_path.display(),
            field,
            actual,
            expected
        );
    }
    Ok(())
}

#[cfg(unix)]
fn manual_headed_value_looks_like_windows_product_key(value: &str) -> bool {
    let candidate = value.trim();
    let groups: Vec<_> = candidate.split('-').collect();
    groups.len() == 5
        && groups
            .iter()
            .all(|group| group.len() == 5 && group.chars().all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit()))
}

#[cfg(unix)]
fn manual_headed_value_looks_like_absolute_or_host_path(value: &str) -> bool {
    let value = value.trim();
    value.starts_with('/')
        || value.starts_with("~/")
        || value.starts_with(".\\")
        || value.starts_with("..\\")
        || value.starts_with("../")
        || value.contains('\\')
        || value.as_bytes().get(1).is_some_and(|byte| *byte == b':')
}

#[cfg(unix)]
fn manual_headed_value_is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[cfg(unix)]
fn read_manual_headed_run_manifest(profile_dir: &Path) -> anyhow::Result<ManualHeadedRunManifest> {
    let manifest_path = manual_headed_run_manifest_path(profile_dir);
    let bytes = fs::read(&manifest_path)
        .with_context(|| format!("read manual-headed run manifest {}", manifest_path.display()))?;
    let manifest: ManualHeadedRunManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("parse manual-headed run manifest {}", manifest_path.display()))?;
    validate_manual_headed_run_manifest_shape(profile_dir, &manifest)?;

    Ok(manifest)
}

#[cfg(unix)]
fn write_manual_headed_run_manifest(profile_dir: &Path, manifest: &ManualHeadedRunManifest) -> anyhow::Result<()> {
    validate_manual_headed_run_manifest_shape(profile_dir, manifest)?;
    let manifest_path = manual_headed_run_manifest_path(profile_dir);
    let tmp_path = manifest_path.with_extension(format!("tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(manifest).context("serialize manual-headed run manifest")?;
    fs::write(&tmp_path, bytes).with_context(|| format!("write manual-headed temp manifest {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &manifest_path).with_context(|| {
        format!(
            "publish manual-headed run manifest {} via {}",
            manifest_path.display(),
            tmp_path.display()
        )
    })?;

    Ok(())
}

#[cfg(unix)]
fn manual_headed_anchor_spec(anchor_id: &str) -> Option<ManualHeadedAnchorSpec> {
    MANUAL_HEADED_ANCHOR_SPECS
        .iter()
        .find(|spec| spec.id == anchor_id)
        .copied()
}

#[cfg(unix)]
fn manual_headed_expected_anchor_ids() -> [&'static str; 9] {
    [
        MANUAL_HEADED_ANCHOR_PREREQ_GATE,
        MANUAL_HEADED_ANCHOR_IDENTITY_BINDING,
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
        MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE,
        MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE,
    ]
}

#[cfg(unix)]
fn manual_headed_run_manifest_path(profile_dir: &Path) -> PathBuf {
    profile_dir.join("manifest.json")
}

#[cfg(unix)]
fn manual_headed_anchor_result_path(profile_dir: &Path, anchor_id: &str) -> PathBuf {
    profile_dir.join(format!("{anchor_id}.json"))
}

#[cfg(unix)]
fn manual_headed_anchor_artifact_path(root: &Path, run_id: &str, relpath: &Path) -> anyhow::Result<PathBuf> {
    validate_manual_headed_relpath(relpath)?;
    let artifacts_root = manual_headed_artifacts_root(root, run_id)?;
    let artifact_path = artifacts_root.join(relpath);
    let canonical_artifacts_root = artifacts_root
        .canonicalize()
        .with_context(|| format!("canonicalize manual-headed artifacts root {}", artifacts_root.display()))?;
    let parent = artifact_path.parent().ok_or_else(|| {
        anyhow::anyhow!(
            "manual-headed artifact path must have a parent: {}",
            artifact_path.display()
        )
    })?;
    fs::create_dir_all(parent).with_context(|| format!("create manual-headed artifact parent {}", parent.display()))?;
    let canonical_parent = parent
        .canonicalize()
        .with_context(|| format!("canonicalize manual-headed artifact parent {}", parent.display()))?;
    anyhow::ensure!(
        canonical_parent.starts_with(&canonical_artifacts_root),
        "manual-headed artifact parent {} escapes artifacts root {}",
        canonical_parent.display(),
        canonical_artifacts_root.display()
    );
    Ok(artifact_path)
}

#[cfg(unix)]
fn validate_manual_headed_anchor_result_shape(result: &ManualHeadedAnchorResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.schema_version == MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
        "manual-headed anchor {} must use schema version {}",
        result.anchor_id,
        MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION
    );
    validate_row706_run_id(&result.run_id)?;
    validate_row706_run_id(&result.row706_run_id)?;
    let spec = manual_headed_anchor_spec(&result.anchor_id)
        .ok_or_else(|| anyhow::anyhow!("manual-headed anchor id {} is not recognized", result.anchor_id))?;
    anyhow::ensure!(
        !result.producer.trim().is_empty(),
        "manual-headed anchor {} producer must not be empty",
        result.anchor_id
    );
    anyhow::ensure!(
        result.captured_at_unix_secs > 0,
        "manual-headed anchor {} must record captured_at_unix_secs",
        result.anchor_id
    );
    validate_sha256_field(
        Path::new("manual-headed"),
        &format!("{}.source_artifact_sha256", result.anchor_id),
        &result.source_artifact_sha256,
    )?;
    validate_manual_headed_relpath(&result.source_artifact_relpath)?;

    match result.status {
        ManualHeadedAnchorStatus::BlockedPrereq => anyhow::ensure!(
            !result.executed,
            "manual-headed blocked-prereq anchor {} must set executed=false",
            result.anchor_id
        ),
        ManualHeadedAnchorStatus::Passed | ManualHeadedAnchorStatus::Failed => anyhow::ensure!(
            result.executed,
            "manual-headed executed anchor {} must set executed=true when status is {:?}",
            result.anchor_id,
            result.status
        ),
    }

    if spec.requires_session_id {
        anyhow::ensure!(
            result
                .session_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "manual-headed anchor {} requires session_id",
            result.anchor_id
        );
    }
    if spec.requires_vm_lease_id {
        anyhow::ensure!(
            result
                .vm_lease_id
                .as_deref()
                .is_some_and(|value| !value.trim().is_empty()),
            "manual-headed anchor {} requires vm_lease_id",
            result.anchor_id
        );
    }

    Ok(())
}

#[cfg(unix)]
fn validate_manual_headed_run_manifest_shape(
    profile_dir: &Path,
    manifest: &ManualHeadedRunManifest,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        manifest.schema_version == MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
        "manual-headed manifest in {} must use schema version {}",
        manual_headed_run_manifest_path(profile_dir).display(),
        MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION
    );
    validate_row706_run_id(&manifest.run_id)?;
    anyhow::ensure!(
        manifest.expected_anchor_ids.len() == manual_headed_expected_anchor_ids().len(),
        "manual-headed manifest {} must declare all expected anchors",
        manual_headed_run_manifest_path(profile_dir).display()
    );
    for anchor_id in manual_headed_expected_anchor_ids() {
        anyhow::ensure!(
            manifest
                .expected_anchor_ids
                .iter()
                .any(|declared_anchor| declared_anchor == anchor_id),
            "manual-headed manifest {} is missing expected anchor {}",
            manual_headed_run_manifest_path(profile_dir).display(),
            anchor_id
        );
    }
    if manifest.status == ManualHeadedRunStatus::Complete {
        anyhow::ensure!(
            manifest.completed_at_unix_secs.is_some(),
            "manual-headed manifest {} must record completed_at_unix_secs when complete",
            manual_headed_run_manifest_path(profile_dir).display()
        );
    }

    Ok(())
}

#[cfg(unix)]
fn validate_manual_headed_relpath(relpath: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(
        !relpath.as_os_str().is_empty(),
        "manual-headed artifact relpath must not be empty"
    );
    anyhow::ensure!(
        relpath.is_relative(),
        "manual-headed artifact relpath must stay relative: {}",
        relpath.display()
    );
    anyhow::ensure!(
        relpath
            .components()
            .all(|component| matches!(component, Component::Normal(_))),
        "manual-headed artifact relpath must not escape or use special components: {}",
        relpath.display()
    );
    Ok(())
}

#[cfg(unix)]
fn ensure_row706_run_dir_exists(root: &Path, run_id: &str) -> anyhow::Result<PathBuf> {
    let run_dir = row706_run_dir(root, run_id)?;
    let runs_root = row706_runs_root(root);
    fs::create_dir_all(&runs_root).with_context(|| format!("create row706 runs root {}", runs_root.display()))?;
    if run_dir.exists() {
        let metadata = fs::symlink_metadata(&run_dir)
            .with_context(|| format!("read row706 run dir metadata {}", run_dir.display()))?;
        anyhow::ensure!(
            metadata.file_type().is_dir() && !metadata.file_type().is_symlink(),
            "row706 run dir must be a real directory: {}",
            run_dir.display()
        );
    } else {
        fs::create_dir(&run_dir).with_context(|| format!("create row706 run dir {}", run_dir.display()))?;
    }
    ensure_row706_run_dir_within_root(&runs_root, &run_dir)?;
    Ok(run_dir)
}

#[cfg(unix)]
fn ensure_manual_headed_dir_within_run(root: &Path, run_id: &str, profile_dir: &Path) -> anyhow::Result<()> {
    let run_dir = ensure_row706_run_dir_exists(root, run_id)?;
    let canonical_run_dir = run_dir
        .canonicalize()
        .with_context(|| format!("canonicalize row706 run dir {}", run_dir.display()))?;
    let canonical_profile_dir = profile_dir
        .canonicalize()
        .with_context(|| format!("canonicalize manual-headed profile dir {}", profile_dir.display()))?;
    anyhow::ensure!(
        canonical_profile_dir.starts_with(&canonical_run_dir),
        "manual-headed profile dir {} escapes row706 run dir {}",
        canonical_profile_dir.display(),
        canonical_run_dir.display()
    );
    Ok(())
}

#[cfg(unix)]
fn sha256_file_hex(path: &Path) -> anyhow::Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read sha256 input {}", path.display()))?;
    Ok(format!("{:x}", Sha256::digest(&bytes)))
}
