use std::collections::HashSet;
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{PathConfig, QemuDiskInterface, QemuFirmwareMode, QemuNetworkDeviceModel, QemuRtcBase};

const DEFAULT_GUEST_RDP_PORT: u16 = 3389;
const REQUIRED_WINDOWS_EDITION: &str = "Windows 11 Pro x64";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedImage {
    pub(crate) pool_name: String,
    pub(crate) vm_name: String,
    pub(crate) attestation_ref: String,
    pub(crate) guest_rdp_port: u16,
    pub(crate) base_image_path: PathBuf,
    pub(crate) boot_profile_v1: Option<TrustedBootProfileV1>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedBootProfileV1 {
    pub(crate) disk_interface: QemuDiskInterface,
    pub(crate) network_device_model: QemuNetworkDeviceModel,
    pub(crate) rtc_base: QemuRtcBase,
    pub(crate) firmware_mode: QemuFirmwareMode,
    pub(crate) firmware_code_path: Option<PathBuf>,
    pub(crate) vars_seed_path: Option<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumeTrustedImageState {
    Imported,
    AlreadyPresent,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsumedTrustedImage {
    pub import_state: ConsumeTrustedImageState,
    pub pool_name: String,
    pub vm_name: String,
    pub attestation_ref: String,
    pub manifest_path: PathBuf,
    pub base_image_path: PathBuf,
    pub base_image_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustedImageManifestDocument {
    pool_name: String,
    vm_name: String,
    attestation_ref: String,
    #[serde(default)]
    guest_rdp_port: Option<u16>,
    base_image_path: PathBuf,
    #[serde(default)]
    boot_profile_v1: Option<BootProfileV1Record>,
    source_iso: SourceIsoRecord,
    transformation: TransformationRecord,
    base_image: BaseImageRecord,
    approval: ApprovalRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootProfileV1Record {
    disk_interface: QemuDiskInterface,
    network_device_model: QemuNetworkDeviceModel,
    rtc_base: QemuRtcBase,
    firmware_mode: QemuFirmwareMode,
    #[serde(default)]
    firmware_code: Option<BootArtifactRecord>,
    #[serde(default)]
    vars_seed: Option<BootArtifactRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BootArtifactRecord {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformationRecord {
    timestamp: String,
    inputs: Vec<TransformationInputRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformationInputRecord {
    reference: String,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaseImageRecord {
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalRecord {
    approved_by: String,
}

pub fn consume_trusted_image(paths: &PathConfig, source_manifest_path: &Path) -> anyhow::Result<ConsumedTrustedImage> {
    fs::create_dir_all(&paths.image_store)
        .with_context(|| format!("create image store {}", paths.image_store.display()))?;
    let manifest_dir = paths.manifest_dir();
    fs::create_dir_all(&manifest_dir).with_context(|| format!("create manifest dir {}", manifest_dir.display()))?;

    let source_manifest_path = source_manifest_path
        .canonicalize()
        .with_context(|| format!("canonicalize source manifest {}", source_manifest_path.display()))?;
    validate_regular_file("source manifest", &source_manifest_path)?;
    validate_non_symlink_file("source manifest", &source_manifest_path)?;

    let manifest = read_trusted_image_manifest(&source_manifest_path)?;
    validate_manifest(&manifest, &source_manifest_path)?;

    let source_bundle_root = source_manifest_path
        .parent()
        .context("source manifest must have a parent directory")?
        .canonicalize()
        .with_context(|| format!("canonicalize source bundle root {}", source_manifest_path.display()))?;
    let source_base_image_path = resolve_source_bundle_base_image_path(&source_bundle_root, &manifest.base_image_path)?;
    validate_non_symlink_file("source base image", &source_base_image_path)?;
    let expected_base_image_sha256 = normalize_sha256("base_image.sha256", &manifest.base_image.sha256)?;
    let imported_boot_profile_v1 = manifest
        .boot_profile_v1
        .as_ref()
        .map(|profile| import_boot_profile_v1(paths, &source_bundle_root, profile))
        .transpose()?;

    let final_image_file_name = format!("sha256-{}.qcow2", expected_base_image_sha256);
    let final_base_image_path = paths.image_store.join(&final_image_file_name);
    let final_manifest_path = manifest_dir.join(format!(
        "{}-{}.json",
        sanitize_file_component(&manifest.vm_name),
        &expected_base_image_sha256[..12]
    ));
    let imported_manifest = TrustedImageManifestDocument {
        base_image_path: PathBuf::from(&final_image_file_name),
        boot_profile_v1: imported_boot_profile_v1,
        ..manifest
    };

    let _import_lock = ImportLock::acquire(&manifest_dir, &final_manifest_path)?;
    validate_existing_trusted_identity(
        paths,
        &imported_manifest,
        &final_base_image_path,
        &final_manifest_path,
        &expected_base_image_sha256,
    )?;

    let final_image_exists = final_base_image_path.exists();
    let final_manifest_exists = final_manifest_path.exists();
    if final_image_exists || final_manifest_exists {
        anyhow::ensure!(
            final_image_exists && final_manifest_exists,
            "existing imported artifact is incomplete for vm_name {}",
            imported_manifest.vm_name,
        );
        let existing_manifest = read_trusted_image_manifest(&final_manifest_path)?;
        anyhow::ensure!(
            existing_manifest == imported_manifest,
            "existing imported manifest {} does not match the requested trusted artifact",
            final_manifest_path.display(),
        );
        let actual_digest = sha256_file(&final_base_image_path)?;
        anyhow::ensure!(
            actual_digest == expected_base_image_sha256,
            "existing imported base image digest mismatch for {}: expected {}, got {}",
            final_base_image_path.display(),
            expected_base_image_sha256,
            actual_digest,
        );

        return Ok(ConsumedTrustedImage {
            import_state: ConsumeTrustedImageState::AlreadyPresent,
            pool_name: imported_manifest.pool_name,
            vm_name: imported_manifest.vm_name,
            attestation_ref: imported_manifest.attestation_ref,
            manifest_path: final_manifest_path,
            base_image_path: final_base_image_path,
            base_image_sha256: expected_base_image_sha256,
        });
    }

    let temp_image_path = final_base_image_path.with_extension("qcow2.importing");
    let temp_manifest_path = final_manifest_path.with_extension("json.importing");
    let temp_image_guard = TempPathGuard::new(&temp_image_path);
    let temp_manifest_guard = TempPathGuard::new(&temp_manifest_path);

    copy_file_atomically(&source_base_image_path, &temp_image_path)?;
    let copied_digest = sha256_file(&temp_image_path)?;
    anyhow::ensure!(
        copied_digest == expected_base_image_sha256,
        "base_image.sha256 mismatch for imported artifact {}: expected {}, got {}",
        temp_image_path.display(),
        expected_base_image_sha256,
        copied_digest,
    );

    write_json_atomically(&temp_manifest_path, &imported_manifest)?;

    fs::rename(&temp_image_path, &final_base_image_path).with_context(|| {
        format!(
            "rename imported base image {} to {}",
            temp_image_path.display(),
            final_base_image_path.display(),
        )
    })?;
    sync_parent_dir(&final_base_image_path)?;
    temp_image_guard.disarm();

    fs::rename(&temp_manifest_path, &final_manifest_path).with_context(|| {
        format!(
            "rename imported manifest {} to {}",
            temp_manifest_path.display(),
            final_manifest_path.display(),
        )
    })?;
    sync_parent_dir(&final_manifest_path)?;
    temp_manifest_guard.disarm();

    if let Err(error) = trusted_images(paths) {
        let _ = fs::remove_file(&final_manifest_path);
        let _ = fs::remove_file(&final_base_image_path);
        return Err(error).with_context(|| {
            format!(
                "validate imported trusted image {} and {}",
                final_manifest_path.display(),
                final_base_image_path.display(),
            )
        });
    }

    Ok(ConsumedTrustedImage {
        import_state: ConsumeTrustedImageState::Imported,
        pool_name: imported_manifest.pool_name,
        vm_name: imported_manifest.vm_name,
        attestation_ref: imported_manifest.attestation_ref,
        manifest_path: final_manifest_path,
        base_image_path: final_base_image_path,
        base_image_sha256: expected_base_image_sha256,
    })
}

pub(crate) fn trusted_images(paths: &PathConfig) -> anyhow::Result<Vec<TrustedImage>> {
    let mut manifests = json_files(&paths.manifest_dir())?;
    manifests.sort();

    let trusted_images = manifests
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
                pool_name: manifest.pool_name,
                vm_name: manifest.vm_name,
                attestation_ref: manifest.attestation_ref,
                guest_rdp_port: manifest
                    .guest_rdp_port
                    .unwrap_or_else(|| DEFAULT_GUEST_RDP_PORT.saturating_add(u16::try_from(index).unwrap_or(0))),
                base_image_path,
                boot_profile_v1: manifest
                    .boot_profile_v1
                    .as_ref()
                    .map(|profile| load_trusted_boot_profile_v1(paths, profile))
                    .transpose()?,
            })
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    validate_unique_vm_names(&trusted_images)?;

    Ok(trusted_images)
}

pub(crate) fn validate_trusted_image_identity(
    paths: &PathConfig,
    pool_name: &str,
    vm_name: &str,
    attestation_ref: &str,
    base_image_path: &Path,
) -> anyhow::Result<()> {
    let trusted_images = trusted_images(paths)?;
    anyhow::ensure!(
        trusted_images.iter().any(|trusted_image| {
            trusted_image.pool_name == pool_name
                && trusted_image.vm_name == vm_name
                && trusted_image.attestation_ref == attestation_ref
                && trusted_image.base_image_path == base_image_path
        }),
        "trusted image identity for pool_name {pool_name}, vm_name {vm_name}, attestation_ref {attestation_ref}, and base image {} is no longer valid",
        base_image_path.display(),
    );
    Ok(())
}

fn read_trusted_image_manifest(path: &Path) -> anyhow::Result<TrustedImageManifestDocument> {
    let data = fs::read_to_string(path).with_context(|| format!("read trusted image manifest {}", path.display()))?;
    serde_json::from_str(&data).with_context(|| format!("parse trusted image manifest {}", path.display()))
}

fn validate_manifest(manifest: &TrustedImageManifestDocument, manifest_path: &Path) -> anyhow::Result<()> {
    ensure_non_empty("pool_name", &manifest.pool_name)?;
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
    if let Some(boot_profile_v1) = &manifest.boot_profile_v1 {
        validate_boot_profile_v1(boot_profile_v1, manifest_path)?;
    }
    ensure_non_empty("approval.approved_by", &manifest.approval.approved_by)?;

    Ok(())
}

fn validate_unique_vm_names(trusted_images: &[TrustedImage]) -> anyhow::Result<()> {
    let mut vm_names = HashSet::new();

    for trusted_image in trusted_images {
        anyhow::ensure!(
            vm_names.insert(trusted_image.vm_name.clone()),
            "trusted vm_name {} must be unique across all pools",
            trusted_image.vm_name,
        );
    }

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

fn resolve_source_bundle_base_image_path(source_bundle_root: &Path, configured_path: &Path) -> anyhow::Result<PathBuf> {
    resolve_source_bundle_file_path(
        source_bundle_root,
        "base_image_path",
        "source base image",
        configured_path,
    )
}

fn resolve_source_bundle_file_path(
    source_bundle_root: &Path,
    path_label: &str,
    file_label: &str,
    configured_path: &Path,
) -> anyhow::Result<PathBuf> {
    validate_bundle_relative_path(path_label, configured_path)?;

    let resolved_path = source_bundle_root.join(configured_path);
    validate_non_symlink_file(file_label, &resolved_path)?;
    let canonical_path = resolved_path
        .canonicalize()
        .with_context(|| format!("canonicalize {file_label} {}", resolved_path.display()))?;

    anyhow::ensure!(
        canonical_path.starts_with(source_bundle_root),
        "{file_label} {} escapes source bundle {}",
        canonical_path.display(),
        source_bundle_root.display(),
    );

    Ok(canonical_path)
}

fn import_boot_profile_v1(
    paths: &PathConfig,
    source_bundle_root: &Path,
    profile: &BootProfileV1Record,
) -> anyhow::Result<BootProfileV1Record> {
    let firmware_code = profile
        .firmware_code
        .as_ref()
        .map(|artifact| import_boot_artifact(paths, source_bundle_root, "boot_profile_v1.firmware_code", artifact))
        .transpose()?;
    let vars_seed = profile
        .vars_seed
        .as_ref()
        .map(|artifact| import_boot_artifact(paths, source_bundle_root, "boot_profile_v1.vars_seed", artifact))
        .transpose()?;

    Ok(BootProfileV1Record {
        disk_interface: profile.disk_interface,
        network_device_model: profile.network_device_model,
        rtc_base: profile.rtc_base,
        firmware_mode: profile.firmware_mode,
        firmware_code,
        vars_seed,
    })
}

fn import_boot_artifact(
    paths: &PathConfig,
    source_bundle_root: &Path,
    label: &str,
    artifact: &BootArtifactRecord,
) -> anyhow::Result<BootArtifactRecord> {
    let source_path =
        resolve_source_bundle_file_path(source_bundle_root, &format!("{label}.path"), label, &artifact.path)?;
    let expected_sha256 = normalize_sha256(&format!("{label}.sha256"), &artifact.sha256)?;
    let final_file_name =
        trusted_artifact_file_name(&expected_sha256, source_path.extension().and_then(|ext| ext.to_str()));
    let final_path = paths.image_store.join(&final_file_name);

    if final_path.exists() {
        let actual_digest = sha256_file(&final_path)?;
        anyhow::ensure!(
            actual_digest == expected_sha256,
            "existing imported artifact {} does not match the requested digest {}",
            final_path.display(),
            expected_sha256,
        );
    } else {
        copy_file_atomically(&source_path, &final_path)?;
        let actual_digest = sha256_file(&final_path)?;
        anyhow::ensure!(
            actual_digest == expected_sha256,
            "{label}.sha256 mismatch for imported artifact {}: expected {}, got {}",
            final_path.display(),
            expected_sha256,
            actual_digest,
        );
    }

    Ok(BootArtifactRecord {
        path: PathBuf::from(final_file_name),
        sha256: expected_sha256,
    })
}

fn load_trusted_boot_profile_v1(
    paths: &PathConfig,
    profile: &BootProfileV1Record,
) -> anyhow::Result<TrustedBootProfileV1> {
    let firmware_code_path = profile
        .firmware_code
        .as_ref()
        .map(|artifact| load_trusted_boot_artifact(&paths.image_store, "boot_profile_v1.firmware_code", artifact))
        .transpose()?;
    let vars_seed_path = profile
        .vars_seed
        .as_ref()
        .map(|artifact| load_trusted_boot_artifact(&paths.image_store, "boot_profile_v1.vars_seed", artifact))
        .transpose()?;

    Ok(TrustedBootProfileV1 {
        disk_interface: profile.disk_interface,
        network_device_model: profile.network_device_model,
        rtc_base: profile.rtc_base,
        firmware_mode: profile.firmware_mode,
        firmware_code_path,
        vars_seed_path,
    })
}

fn load_trusted_boot_artifact(
    image_store: &Path,
    label: &str,
    artifact: &BootArtifactRecord,
) -> anyhow::Result<PathBuf> {
    let artifact_path = resolve_trusted_image_store_path(image_store, label, &artifact.path)?;
    validate_image_store_path(image_store, &artifact_path)
        .with_context(|| format!("validate trusted image store contract for {}", artifact_path.display()))?;

    let actual_digest = sha256_file(&artifact_path)
        .with_context(|| format!("hash trusted boot artifact {}", artifact_path.display()))?;
    let expected_digest = normalize_sha256(&format!("{label}.sha256"), &artifact.sha256)?;
    anyhow::ensure!(
        actual_digest == expected_digest,
        "{label}.sha256 mismatch for {}: expected {}, got {}",
        artifact_path.display(),
        expected_digest,
        actual_digest,
    );

    Ok(artifact_path)
}

fn validate_boot_profile_v1(profile: &BootProfileV1Record, manifest_path: &Path) -> anyhow::Result<()> {
    match profile.firmware_mode {
        QemuFirmwareMode::None => {
            anyhow::ensure!(
                profile.firmware_code.is_none(),
                "boot_profile_v1.firmware_code must be absent when firmware_mode is none in {}",
                manifest_path.display(),
            );
            anyhow::ensure!(
                profile.vars_seed.is_none(),
                "boot_profile_v1.vars_seed must be absent when firmware_mode is none in {}",
                manifest_path.display(),
            );
        }
        QemuFirmwareMode::UefiPflash => {
            let firmware_code = profile.firmware_code.as_ref().with_context(|| {
                format!(
                    "boot_profile_v1.firmware_code must be present when firmware_mode is uefi_pflash in {}",
                    manifest_path.display()
                )
            })?;
            let vars_seed = profile.vars_seed.as_ref().with_context(|| {
                format!(
                    "boot_profile_v1.vars_seed must be present when firmware_mode is uefi_pflash in {}",
                    manifest_path.display()
                )
            })?;
            validate_boot_artifact("boot_profile_v1.firmware_code", firmware_code)?;
            validate_boot_artifact("boot_profile_v1.vars_seed", vars_seed)?;
        }
    }

    if matches!(profile.firmware_mode, QemuFirmwareMode::None) {
        return Ok(());
    }

    Ok(())
}

fn validate_boot_artifact(label: &str, artifact: &BootArtifactRecord) -> anyhow::Result<()> {
    validate_bundle_relative_path(&format!("{label}.path"), &artifact.path)?;
    let _ = normalize_sha256(&format!("{label}.sha256"), &artifact.sha256)?;
    Ok(())
}

fn resolve_trusted_image_store_path(
    image_store: &Path,
    label: &str,
    configured_path: &Path,
) -> anyhow::Result<PathBuf> {
    validate_bundle_relative_path(label, configured_path)?;
    Ok(image_store.join(configured_path))
}

fn trusted_artifact_file_name(digest: &str, extension: Option<&str>) -> String {
    let extension = extension.filter(|value| !value.is_empty()).unwrap_or("bin");
    format!("artifact-sha256-{}.{}", digest, sanitize_file_component(extension))
}

fn validate_bundle_relative_path(label: &str, path: &Path) -> anyhow::Result<()> {
    anyhow::ensure!(!path.as_os_str().is_empty(), "{label} must not be empty");
    anyhow::ensure!(!path.is_absolute(), "{label} must be a relative bundle path");
    anyhow::ensure!(
        path.components()
            .all(|component| matches!(component, std::path::Component::Normal(_))),
        "{label} must not contain traversal or special path components",
    );
    Ok(())
}

fn validate_regular_file(label: &str, path: &Path) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read metadata for {} {}", label, path.display()))?;
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{label} {} must be a regular file",
        path.display()
    );
    Ok(())
}

fn validate_non_symlink_file(label: &str, path: &Path) -> anyhow::Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("read metadata for {} {}", label, path.display()))?;
    anyhow::ensure!(
        !metadata.file_type().is_symlink(),
        "{label} {} must not be a symlink",
        path.display()
    );
    anyhow::ensure!(
        metadata.file_type().is_file(),
        "{label} {} must be a regular file",
        path.display()
    );
    Ok(())
}

fn validate_existing_trusted_identity(
    paths: &PathConfig,
    manifest: &TrustedImageManifestDocument,
    final_base_image_path: &Path,
    final_manifest_path: &Path,
    expected_base_image_sha256: &str,
) -> anyhow::Result<()> {
    let trusted_images = trusted_images(paths)?;

    if let Some(existing_trusted_image) = trusted_images
        .iter()
        .find(|trusted_image| trusted_image.vm_name == manifest.vm_name)
    {
        let existing_identity_matches = existing_trusted_image.pool_name == manifest.pool_name
            && existing_trusted_image.attestation_ref == manifest.attestation_ref
            && existing_trusted_image.base_image_path == final_base_image_path;
        anyhow::ensure!(
            existing_identity_matches,
            "trusted vm_name {} already exists with a different identity",
            manifest.vm_name,
        );
    }

    anyhow::ensure!(
        !final_manifest_path.exists()
            || !final_base_image_path.exists()
            || sha256_file(final_base_image_path)? == expected_base_image_sha256,
        "existing imported base image {} does not match the requested digest {}",
        final_base_image_path.display(),
        expected_base_image_sha256,
    );

    Ok(())
}

fn copy_file_atomically(source_path: &Path, destination_path: &Path) -> anyhow::Result<()> {
    let mut source_file =
        fs::File::open(source_path).with_context(|| format!("open source base image {}", source_path.display()))?;
    let mut destination_file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination_path)
        .with_context(|| format!("create staging image {}", destination_path.display()))?;
    let mut buffer = [0u8; 8192];

    loop {
        let read = source_file
            .read(&mut buffer)
            .with_context(|| format!("read source base image {}", source_path.display()))?;
        if read == 0 {
            break;
        }

        destination_file
            .write_all(&buffer[..read])
            .with_context(|| format!("write staging image {}", destination_path.display()))?;
    }

    destination_file
        .sync_all()
        .with_context(|| format!("sync staging image {}", destination_path.display()))?;
    sync_parent_dir(destination_path)
}

fn write_json_atomically<T>(path: &Path, value: &T) -> anyhow::Result<()>
where
    T: Serialize,
{
    let bytes = serde_json::to_vec_pretty(value).context("serialize imported trusted manifest")?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("create staging manifest {}", path.display()))?;
    file.write_all(&bytes)
        .with_context(|| format!("write staging manifest {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync staging manifest {}", path.display()))?;
    sync_parent_dir(path)
}

fn sanitize_file_component(value: &str) -> String {
    let sanitized = value
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    if sanitized.is_empty() {
        "trusted-image".to_owned()
    } else {
        sanitized
    }
}

fn sync_parent_dir(path: &Path) -> anyhow::Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("resolve parent directory for {}", path.display()))?;
    #[cfg(unix)]
    {
        let directory = fs::File::open(parent).with_context(|| format!("open directory {}", parent.display()))?;
        directory
            .sync_all()
            .with_context(|| format!("sync directory {}", parent.display()))?;
    }

    #[cfg(not(unix))]
    let _ = parent;

    Ok(())
}

struct TempPathGuard {
    path: PathBuf,
    armed: std::sync::atomic::AtomicBool,
}

impl TempPathGuard {
    fn new(path: &Path) -> Self {
        Self {
            path: path.to_path_buf(),
            armed: std::sync::atomic::AtomicBool::new(true),
        }
    }

    fn disarm(&self) {
        self.armed.store(false, std::sync::atomic::Ordering::Release);
    }
}

impl Drop for TempPathGuard {
    fn drop(&mut self) {
        if self.armed.load(std::sync::atomic::Ordering::Acquire) {
            let _ = fs::remove_file(&self.path);
        }
    }
}

struct ImportLock {
    path: PathBuf,
}

impl ImportLock {
    fn acquire(manifest_dir: &Path, final_manifest_path: &Path) -> anyhow::Result<Self> {
        let file_name = final_manifest_path
            .file_name()
            .and_then(|value| value.to_str())
            .context("resolve imported manifest file name")?;
        let path = manifest_dir.join(format!(".{file_name}.lock"));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .with_context(|| format!("create import lock {}", path.display()))?;
        writeln!(file, "pid={}", std::process::id())
            .with_context(|| format!("write import lock {}", path.display()))?;
        file.sync_all()
            .with_context(|| format!("sync import lock {}", path.display()))?;
        Ok(Self { path })
    }
}

impl Drop for ImportLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
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
    use std::path::{Path, PathBuf};

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    use super::{ConsumeTrustedImageState, consume_trusted_image, trusted_images};
    use crate::config::{PathConfig, QemuDiskInterface, QemuFirmwareMode, QemuNetworkDeviceModel, QemuRtcBase};

    #[test]
    fn trusted_images_reject_incomplete_attestation_manifests() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let manifest_path = paths.manifest_dir().join("image-0.json");
        fs::write(&manifest_path, "{}").expect("write incomplete manifest");

        let error = trusted_images(&paths).expect_err("incomplete manifest should fail");
        assert!(
            format!("{error:#}").contains("missing field `pool_name`") || format!("{error:#}").contains("vm_name"),
            "{error:#}"
        );
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
                "pool_name": "default",
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

    #[test]
    fn trusted_images_reject_duplicate_vm_names_across_pools() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let first_manifest_path = paths.manifest_dir().join("image-0.json");
        let second_manifest_path = paths.manifest_dir().join("image-1.json");
        let first_base_image_path = paths.image_store.join("image-0.qcow2");
        let second_base_image_path = paths.image_store.join("image-1.qcow2");
        let first_base_image = b"fake-base-image-0";
        let second_base_image = b"fake-base-image-1";
        let first_digest = format!("{:x}", Sha256::digest(first_base_image));
        let second_digest = format!("{:x}", Sha256::digest(second_base_image));

        fs::write(&first_base_image_path, first_base_image).expect("write first base image");
        fs::write(&second_base_image_path, second_base_image).expect("write second base image");

        fs::write(
            &first_manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": "default",
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
                    "sha256": first_digest
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize first manifest"),
        )
        .expect("write first manifest");

        fs::write(
            &second_manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": "canary",
                "vm_name": "honeypot-image-0",
                "attestation_ref": "attestation://image-1",
                "guest_rdp_port": 3390,
                "base_image_path": "image-1.qcow2",
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
                    "sha256": second_digest
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize second manifest"),
        )
        .expect("write second manifest");

        let error = trusted_images(&paths).expect_err("duplicate vm_name should fail");
        assert!(format!("{error:#}").contains("must be unique"), "{error:#}");
    }

    #[test]
    fn consume_trusted_image_imports_a_bundle_into_the_trusted_store() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(tempdir.path(), "honeypot-import-0", "default", "image-0");

        let imported = consume_trusted_image(&paths, &bundle.manifest_path).expect("import trusted image bundle");

        assert_eq!(imported.import_state, ConsumeTrustedImageState::Imported);
        assert!(imported.base_image_path.starts_with(&paths.image_store));
        assert!(imported.manifest_path.starts_with(paths.manifest_dir()));
        assert!(imported.base_image_path.is_file());
        assert!(imported.manifest_path.is_file());

        let trusted_images = trusted_images(&paths).expect("load imported trusted images");
        assert_eq!(trusted_images.len(), 1);
        assert_eq!(trusted_images[0].vm_name, "honeypot-import-0");
        assert_eq!(trusted_images[0].pool_name, "default");
        assert_eq!(trusted_images[0].attestation_ref, "attestation://image-0");
        assert_eq!(trusted_images[0].base_image_path, imported.base_image_path);
    }

    #[test]
    fn consume_trusted_image_imports_boot_profile_artifacts_into_the_trusted_store() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle_with_boot_profile(
            tempdir.path(),
            "honeypot-import-boot-profile",
            "default",
            "image-boot-profile",
            b"base-image-boot-profile",
            b"fake firmware code",
            b"fake vars seed",
        );

        let imported = consume_trusted_image(&paths, &bundle.manifest_path).expect("import trusted image bundle");
        let trusted_images = trusted_images(&paths).expect("load imported trusted images");
        let trusted_image = trusted_images
            .into_iter()
            .find(|trusted_image| trusted_image.vm_name == "honeypot-import-boot-profile")
            .expect("find imported trusted image");
        let boot_profile = trusted_image
            .boot_profile_v1
            .expect("imported trusted image should include boot_profile_v1");

        assert_eq!(trusted_image.base_image_path, imported.base_image_path);
        assert_eq!(boot_profile.disk_interface, QemuDiskInterface::AhciIde);
        assert_eq!(boot_profile.network_device_model, QemuNetworkDeviceModel::E1000);
        assert_eq!(boot_profile.rtc_base, QemuRtcBase::Localtime);
        assert_eq!(boot_profile.firmware_mode, QemuFirmwareMode::UefiPflash);
        let firmware_code_path = boot_profile
            .firmware_code_path
            .expect("boot profile should include firmware code");
        let vars_seed_path = boot_profile
            .vars_seed_path
            .expect("boot profile should include vars seed");
        assert!(firmware_code_path.starts_with(&paths.image_store));
        assert!(vars_seed_path.starts_with(&paths.image_store));
        assert_eq!(
            fs::read(&firmware_code_path).expect("read imported firmware code"),
            b"fake firmware code"
        );
        assert_eq!(
            fs::read(&vars_seed_path).expect("read imported vars seed"),
            b"fake vars seed"
        );
    }

    #[test]
    fn consume_trusted_image_is_idempotent_for_the_same_bundle() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(tempdir.path(), "honeypot-import-0", "default", "image-0");

        let first = consume_trusted_image(&paths, &bundle.manifest_path).expect("first import should succeed");
        let second = consume_trusted_image(&paths, &bundle.manifest_path).expect("second import should succeed");

        assert_eq!(first.import_state, ConsumeTrustedImageState::Imported);
        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(first.base_image_path, second.base_image_path);
        assert_eq!(first.manifest_path, second.manifest_path);
    }

    #[test]
    fn consume_trusted_image_rejects_bundle_path_escape() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let source_root = tempdir.path().join("source-bundle");
        let escape_image_path = tempdir.path().join("escape.qcow2");
        let manifest_path = source_root.join("image-escape.json");
        let base_image_contents = b"escape-base-image";

        fs::create_dir_all(&source_root).expect("create source root");
        fs::write(&escape_image_path, base_image_contents).expect("write escape image");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": "default",
                "vm_name": "honeypot-import-escape",
                "attestation_ref": "attestation://image-escape",
                "guest_rdp_port": 3389,
                "base_image_path": "../escape.qcow2",
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
                    "sha256": format!("{:x}", Sha256::digest(base_image_contents))
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize escape manifest"),
        )
        .expect("write escape manifest");

        let error = consume_trusted_image(&paths, &manifest_path).expect_err("path escape should fail");
        assert!(
            format!("{error:#}").contains("relative bundle path")
                || format!("{error:#}").contains("traversal")
                || format!("{error:#}").contains("escapes source bundle"),
            "{error:#}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn consume_trusted_image_rejects_symlinked_source_base_image() {
        use std::os::unix::fs::symlink;

        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let source_root = tempdir.path().join("source-bundle");
        let outside_root = tempdir.path().join("outside");
        let manifest_path = source_root.join("image-symlink.json");
        let outside_image_path = outside_root.join("real-image.qcow2");
        let linked_image_path = source_root.join("linked-image.qcow2");
        let base_image_contents = b"symlink-base-image";

        fs::create_dir_all(&source_root).expect("create source root");
        fs::create_dir_all(&outside_root).expect("create outside root");
        fs::write(&outside_image_path, base_image_contents).expect("write outside image");
        symlink(&outside_image_path, &linked_image_path).expect("create source image symlink");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": "default",
                "vm_name": "honeypot-import-symlink",
                "attestation_ref": "attestation://image-symlink",
                "guest_rdp_port": 3389,
                "base_image_path": "linked-image.qcow2",
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
                    "sha256": format!("{:x}", Sha256::digest(base_image_contents))
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize symlink manifest"),
        )
        .expect("write symlink manifest");

        let error = consume_trusted_image(&paths, &manifest_path).expect_err("symlink source should fail");
        assert!(format!("{error:#}").contains("must not be a symlink"), "{error:#}");
    }

    #[test]
    fn consume_trusted_image_rejects_duplicate_vm_name_with_different_identity() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let first_bundle = create_source_bundle(tempdir.path(), "honeypot-import-0", "default", "image-0");
        let second_bundle = create_source_bundle_with_contents(
            tempdir.path(),
            "honeypot-import-0",
            "default",
            "image-1",
            b"other-base-image",
        );

        consume_trusted_image(&paths, &first_bundle.manifest_path).expect("first import should succeed");
        let error =
            consume_trusted_image(&paths, &second_bundle.manifest_path).expect_err("duplicate vm_name should fail");
        assert!(
            format!("{error:#}").contains("already exists with a different identity"),
            "{error:#}"
        );
    }

    struct SourceBundle {
        manifest_path: PathBuf,
    }

    fn create_source_bundle(root: &Path, vm_name: &str, pool_name: &str, suffix: &str) -> SourceBundle {
        create_source_bundle_with_contents(
            root,
            vm_name,
            pool_name,
            suffix,
            format!("base-image-{suffix}").as_bytes(),
        )
    }

    fn create_source_bundle_with_boot_profile(
        root: &Path,
        vm_name: &str,
        pool_name: &str,
        suffix: &str,
        base_image_contents: &[u8],
        firmware_code_contents: &[u8],
        vars_seed_contents: &[u8],
    ) -> SourceBundle {
        let source_root = root.join(format!("source-bundle-{suffix}"));
        let manifest_path = source_root.join(format!("{suffix}.json"));
        let base_image_path = source_root.join(format!("{suffix}.qcow2"));
        let firmware_code_path = source_root.join(format!("{suffix}-OVMF_CODE.fd"));
        let vars_seed_path = source_root.join(format!("{suffix}-OVMF_VARS.seed.fd"));

        fs::create_dir_all(&source_root).expect("create source bundle root");
        fs::write(&base_image_path, base_image_contents).expect("write source base image");
        fs::write(&firmware_code_path, firmware_code_contents).expect("write source firmware code");
        fs::write(&vars_seed_path, vars_seed_contents).expect("write source vars seed");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": pool_name,
                "vm_name": vm_name,
                "attestation_ref": format!("attestation://{suffix}"),
                "guest_rdp_port": 3389,
                "base_image_path": base_image_path.file_name().and_then(|value| value.to_str()).expect("source base image name"),
                "boot_profile_v1": {
                    "disk_interface": "ahci_ide",
                    "network_device_model": "e1000",
                    "rtc_base": "localtime",
                    "firmware_mode": "uefi_pflash",
                    "firmware_code": {
                        "path": firmware_code_path.file_name().and_then(|value| value.to_str()).expect("firmware code name"),
                        "sha256": format!("{:x}", Sha256::digest(firmware_code_contents))
                    },
                    "vars_seed": {
                        "path": vars_seed_path.file_name().and_then(|value| value.to_str()).expect("vars seed name"),
                        "sha256": format!("{:x}", Sha256::digest(vars_seed_contents))
                    }
                },
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
                    "sha256": format!("{:x}", Sha256::digest(base_image_contents))
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize source manifest"),
        )
        .expect("write source manifest");

        SourceBundle { manifest_path }
    }

    fn create_source_bundle_with_contents(
        root: &Path,
        vm_name: &str,
        pool_name: &str,
        suffix: &str,
        base_image_contents: &[u8],
    ) -> SourceBundle {
        let source_root = root.join(format!("source-bundle-{suffix}"));
        let manifest_path = source_root.join(format!("{suffix}.json"));
        let base_image_path = source_root.join(format!("{suffix}.qcow2"));

        fs::create_dir_all(&source_root).expect("create source bundle root");
        fs::write(&base_image_path, base_image_contents).expect("write source base image");
        fs::write(
            &manifest_path,
            serde_json::to_vec_pretty(&json!({
                "pool_name": pool_name,
                "vm_name": vm_name,
                "attestation_ref": format!("attestation://{suffix}"),
                "guest_rdp_port": 3389,
                "base_image_path": base_image_path.file_name().and_then(|value| value.to_str()).expect("source base image name"),
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
                    "sha256": format!("{:x}", Sha256::digest(base_image_contents))
                },
                "approval": {
                    "approved_by": "operator@example.test"
                }
            }))
            .expect("serialize source manifest"),
        )
        .expect("write source manifest");

        SourceBundle { manifest_path }
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
