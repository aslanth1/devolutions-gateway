use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::PathConfig;

const DEFAULT_GUEST_RDP_PORT: u16 = 3389;
const REQUIRED_WINDOWS_EDITION: &str = "Windows 11 Pro x64";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedImage {
    pub(crate) vm_name: String,
    pub(crate) attestation_ref: String,
    pub(crate) guest_rdp_port: u16,
    pub(crate) base_image_path: PathBuf,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedImageManifestDocument {
    vm_name: String,
    attestation_ref: String,
    #[serde(default)]
    guest_rdp_port: Option<u16>,
    base_image_path: PathBuf,
    source_iso: SourceIsoRecord,
    transformation: TransformationRecord,
    base_image: BaseImageRecord,
    approval: ApprovalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceIsoRecord {
    acquisition_channel: String,
    acquisition_date: String,
    filename: String,
    size_bytes: u64,
    edition: String,
    language: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformationRecord {
    timestamp: String,
    inputs: Vec<TransformationInputRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformationInputRecord {
    reference: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseImageRecord {
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    approved_by: String,
}

pub(crate) fn trusted_images(paths: &PathConfig) -> anyhow::Result<Vec<TrustedImage>> {
    let mut manifests = json_files(&paths.manifest_dir())?;
    manifests.sort();

    manifests
        .into_iter()
        .enumerate()
        .map(|(index, manifest_path)| {
            let manifest = read_trusted_image_manifest(&manifest_path)?;
            validate_manifest(&manifest, &manifest_path)?;

            let base_image_path = resolve_base_image_path(paths, &manifest.base_image_path)?;
            validate_image_store_path(&paths.image_store, &base_image_path).with_context(|| {
                format!(
                    "validate trusted image store contract for {}",
                    base_image_path.display()
                )
            })?;

            let actual_base_image_sha256 = sha256_file(&base_image_path)
                .with_context(|| format!("hash trusted base image {}", base_image_path.display()))?;
            let expected_base_image_sha256 = normalize_sha256("base_image.sha256", &manifest.base_image.sha256)?;
            anyhow::ensure!(
                actual_base_image_sha256 == expected_base_image_sha256,
                "base_image.sha256 mismatch for {}: expected {}, got {}",
                base_image_path.display(),
                expected_base_image_sha256,
                actual_base_image_sha256,
            );

            Ok(TrustedImage {
                vm_name: manifest.vm_name,
                attestation_ref: manifest.attestation_ref,
                guest_rdp_port: manifest
                    .guest_rdp_port
                    .unwrap_or_else(|| DEFAULT_GUEST_RDP_PORT.saturating_add(u16::try_from(index).unwrap_or(0))),
                base_image_path,
            })
        })
        .collect()
}

pub(crate) fn validate_trusted_image_identity(
    paths: &PathConfig,
    vm_name: &str,
    attestation_ref: &str,
    base_image_path: &Path,
) -> anyhow::Result<()> {
    let trusted_images = trusted_images(paths)?;
    anyhow::ensure!(
        trusted_images.iter().any(|trusted_image| {
            trusted_image.vm_name == vm_name
                && trusted_image.attestation_ref == attestation_ref
                && trusted_image.base_image_path == base_image_path
        }),
        "trusted image identity for vm_name {vm_name}, attestation_ref {attestation_ref}, and base image {} is no longer valid",
        base_image_path.display(),
    );
    Ok(())
}

fn read_trusted_image_manifest(path: &Path) -> anyhow::Result<TrustedImageManifestDocument> {
    let data = fs::read_to_string(path).with_context(|| format!("read trusted image manifest {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("parse trusted image manifest {}", path.display()))
}

fn validate_manifest(manifest: &TrustedImageManifestDocument, manifest_path: &Path) -> anyhow::Result<()> {
    ensure_non_empty("vm_name", &manifest.vm_name)?;
    ensure_non_empty("attestation_ref", &manifest.attestation_ref)?;
    if let Some(guest_rdp_port) = manifest.guest_rdp_port {
        anyhow::ensure!(guest_rdp_port > 0, "guest_rdp_port must be greater than zero");
    }
    anyhow::ensure!(
        !manifest.base_image_path.as_os_str().is_empty(),
        "base_image_path must not be empty in {}",
        manifest_path.display(),
    );

    ensure_non_empty(
        "source_iso.acquisition_channel",
        &manifest.source_iso.acquisition_channel,
    )?;
    ensure_non_empty("source_iso.acquisition_date", &manifest.source_iso.acquisition_date)?;
    ensure_non_empty("source_iso.filename", &manifest.source_iso.filename)?;
    anyhow::ensure!(
        manifest.source_iso.size_bytes > 0,
        "source_iso.size_bytes must be greater than zero in {}",
        manifest_path.display(),
    );
    anyhow::ensure!(
        manifest.source_iso.edition.trim() == REQUIRED_WINDOWS_EDITION,
        "source_iso.edition must be {REQUIRED_WINDOWS_EDITION} in {}",
        manifest_path.display(),
    );
    ensure_non_empty("source_iso.language", &manifest.source_iso.language)?;
    let _ = normalize_sha256("source_iso.sha256", &manifest.source_iso.sha256)?;

    ensure_non_empty("transformation.timestamp", &manifest.transformation.timestamp)?;
    anyhow::ensure!(
        !manifest.transformation.inputs.is_empty(),
        "transformation.inputs must not be empty in {}",
        manifest_path.display(),
    );
    for (index, input) in manifest.transformation.inputs.iter().enumerate() {
        ensure_non_empty(&format!("transformation.inputs[{index}].reference"), &input.reference)?;
        let _ = normalize_sha256(&format!("transformation.inputs[{index}].sha256"), &input.sha256)?;
    }

    let _ = normalize_sha256("base_image.sha256", &manifest.base_image.sha256)?;
    ensure_non_empty("approval.approved_by", &manifest.approval.approved_by)?;

    Ok(())
}

fn resolve_base_image_path(paths: &PathConfig, configured_path: &Path) -> anyhow::Result<PathBuf> {
    let resolved_path = if configured_path.is_absolute() {
        configured_path.to_path_buf()
    } else {
        paths.image_store.join(configured_path)
    };

    Ok(resolved_path)
}

fn validate_image_store_path(image_store: &Path, path: &Path) -> anyhow::Result<()> {
    let image_store = image_store
        .canonicalize()
        .with_context(|| format!("canonicalize image store {}", image_store.display()))?;
    let path = path
        .canonicalize()
        .with_context(|| format!("canonicalize trusted base image {}", path.display()))?;

    anyhow::ensure!(
        path.starts_with(&image_store),
        "trusted base image {} escapes image store {}",
        path.display(),
        image_store.display(),
    );

    Ok(())
}

fn normalize_sha256(label: &str, digest: &str) -> anyhow::Result<String> {
    let digest = digest.trim().to_ascii_lowercase();
    anyhow::ensure!(!digest.is_empty(), "{label} must not be empty");
    anyhow::ensure!(digest.len() == 64, "{label} must be a 64-character SHA-256 hex digest");
    anyhow::ensure!(
        digest.bytes().all(|byte| byte.is_ascii_hexdigit()),
        "{label} must contain only hexadecimal characters",
    );
    Ok(digest)
}

fn ensure_non_empty(label: &str, value: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!value.trim().is_empty(), "{label} must not be empty");
    Ok(())
}

fn sha256_file(path: &Path) -> anyhow::Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("open trusted base image {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .with_context(|| format!("read trusted base image {}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn json_files(root: &Path) -> anyhow::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();
    let entries = fs::read_dir(root).with_context(|| format!("read directory {}", root.display()))?;

    for entry in entries {
        let entry = entry.with_context(|| format!("read entry in {}", root.display()))?;
        let path = entry.path();
        if is_json_file(&path) {
            paths.push(path);
        }
    }

    Ok(paths)
}

fn is_json_file(path: &Path) -> bool {
    path.is_file() && path.extension().and_then(|ext| ext.to_str()) == Some("json")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use serde_json::json;

    use super::trusted_images;
    use crate::config::PathConfig;

    #[test]
    fn trusted_images_reject_incomplete_attestation_manifests() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let manifest_path = paths.manifest_dir().join("image-0.json");
        fs::write(&manifest_path, "{}").expect("write incomplete manifest");

        let error = trusted_images(&paths).expect_err("incomplete manifest should fail");
        assert!(format!("{error:#}").contains("vm_name"), "{error:#}");
    }

    #[test]
    fn trusted_images_reject_base_image_digest_mismatch() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let manifest_path = paths.manifest_dir().join("image-0.json");
        let base_image_path = paths.image_store.join("image-0.qcow2");

        fs::write(&base_image_path, b"fake-base-image").expect("write base image");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "vm_name": "honeypot-image-0",
                "attestation_ref": "attestation://image-0",
                "guest_rdp_port": 3389,
                "base_image_path": "image-0.qcow2",
                "source_iso": {
                    "acquisition_channel": "msdn",
                    "acquisition_date": "2026-03-25",
                    "filename": "windows11-pro-x64.iso",
                    "size_bytes": 1024,
                    "edition": "Windows 11 Pro x64",
                    "language": "en-US",
                    "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
                },
                "transformation": {
                    "timestamp": "2026-03-25T12:00:00Z",
                    "inputs": [{
                        "reference": "tiny11-builder.ps1",
                        "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
                    }]
                },
                "base_image": {
                    "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize manifest"),
        )
        .expect("write manifest");

        let error = trusted_images(&paths).expect_err("digest mismatch should fail");
        assert!(format!("{error:#}").contains("base_image.sha256 mismatch"), "{error:#}");
    }

    fn test_paths(root: &Path) -> PathConfig {
        let image_store = root.join("images");
        let manifest_dir = image_store.join("manifests");
        let lease_store = root.join("leases");
        let quarantine_store = root.join("quarantine");
        let qmp_dir = root.join("qmp");
        let secret_dir = root.join("secrets");
        let data_dir = root.join("data");
        let kvm_path = root.join("kvm");

        fs::create_dir_all(&manifest_dir).expect("create manifest dir");
        fs::create_dir_all(&lease_store).expect("create lease dir");
        fs::create_dir_all(&quarantine_store).expect("create quarantine dir");
        fs::create_dir_all(&qmp_dir).expect("create qmp dir");
        fs::create_dir_all(&secret_dir).expect("create secret dir");
        fs::create_dir_all(&data_dir).expect("create data dir");
        fs::write(&kvm_path, []).expect("create fake kvm path");

        PathConfig {
            data_dir,
            image_store,
            manifest_dir: Some(manifest_dir),
            lease_store,
            quarantine_store,
            qmp_dir,
            qga_dir: None,
            secret_dir,
            kvm_path,
        }
    }
}
