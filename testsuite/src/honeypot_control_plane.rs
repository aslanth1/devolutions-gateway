use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::LazyLock;

use anyhow::Context as _;
use honeypot_contracts::control_plane::HealthResponse;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use typed_builder::TypedBuilder;

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
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind localhost ephemeral port")
        .local_addr()
        .expect("read ephemeral port")
        .port()
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
pub const ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE: &str = "gold_image_acceptance";
#[cfg(unix)]
pub const ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY: &str = "gold_image_repeatability";
#[cfg(unix)]
pub const ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP: &str = "external_client_interop";
#[cfg(unix)]
pub const ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL: &str = "digest_mismatch_negative_control";
#[cfg(unix)]
pub const ROW706_EVIDENCE_SCHEMA_VERSION: u32 = 1;

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Row706AnchorStatus {
    Passed,
    Skipped,
    Failed,
}

#[cfg(unix)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row706AnchorResult {
    pub schema_version: u32,
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row706EvidenceEnvelope {
    pub anchor_results: Vec<Row706AnchorResult>,
    pub attestation_ref: String,
    pub base_image_path: PathBuf,
    pub image_store_root: PathBuf,
}

#[cfg(unix)]
pub fn row706_default_evidence_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("testsuite crate should live under the repo root")
        .join("target/row706")
}

#[cfg(unix)]
pub fn write_row706_anchor_result(root: &Path, result: &Row706AnchorResult) -> anyhow::Result<()> {
    validate_row706_anchor_result_shape(result)?;
    fs::create_dir_all(root).with_context(|| format!("create row706 evidence dir {}", root.display()))?;

    let result_path = row706_anchor_result_path(root, &result.anchor_id);
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
pub fn read_row706_anchor_results(root: &Path) -> anyhow::Result<Vec<Row706AnchorResult>> {
    anyhow::ensure!(
        root.is_dir(),
        "row706 evidence dir must exist and be a directory: {}",
        root.display()
    );

    let mut result_paths = fs::read_dir(root)
        .with_context(|| format!("read row706 evidence dir {}", root.display()))?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("collect row706 fragments from {}", root.display()))?;
    result_paths.retain(|path| path.extension().is_some_and(|extension| extension == "json"));
    result_paths.sort();

    anyhow::ensure!(
        !result_paths.is_empty(),
        "row706 evidence dir {} does not contain any .json fragments",
        root.display()
    );

    let mut results = Vec::with_capacity(result_paths.len());
    let mut seen_anchor_ids = BTreeMap::new();

    for result_path in result_paths {
        let bytes =
            fs::read(&result_path).with_context(|| format!("read row706 fragment {}", result_path.display()))?;
        let result: Row706AnchorResult = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse row706 fragment {}", result_path.display()))?;
        validate_row706_anchor_result_shape(&result)?;
        if let Some(previous_path) = seen_anchor_ids.insert(result.anchor_id.clone(), result_path.clone()) {
            anyhow::bail!(
                "row706 anchor {} is duplicated in {} and {}",
                result.anchor_id,
                previous_path.display(),
                result_path.display()
            );
        }
        results.push(result);
    }

    Ok(results)
}

#[cfg(unix)]
pub fn verify_row706_evidence_envelope(root: &Path) -> anyhow::Result<Row706EvidenceEnvelope> {
    let results = read_row706_anchor_results(root)?;
    let mut by_anchor_id = BTreeMap::new();
    for result in results {
        by_anchor_id.insert(result.anchor_id.clone(), result);
    }

    for anchor_id in expected_row706_anchor_ids() {
        anyhow::ensure!(
            by_anchor_id.contains_key(anchor_id),
            "row706 evidence is missing required anchor fragment {anchor_id}"
        );
    }
    anyhow::ensure!(
        by_anchor_id.len() == expected_row706_anchor_ids().len(),
        "row706 evidence contains unexpected anchors in {}",
        root.display()
    );

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
fn expected_row706_anchor_ids() -> [&'static str; 4] {
    [
        ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE,
        ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY,
        ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP,
        ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL,
    ]
}

#[cfg(unix)]
fn row706_anchor_result_path(root: &Path, anchor_id: &str) -> PathBuf {
    root.join(format!("{anchor_id}.json"))
}

#[cfg(unix)]
fn validate_row706_anchor_result_shape(result: &Row706AnchorResult) -> anyhow::Result<()> {
    anyhow::ensure!(
        result.schema_version == ROW706_EVIDENCE_SCHEMA_VERSION,
        "row706 anchor {} must use schema version {}",
        result.anchor_id,
        ROW706_EVIDENCE_SCHEMA_VERSION
    );
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
