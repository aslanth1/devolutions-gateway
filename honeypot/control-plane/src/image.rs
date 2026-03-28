use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::config::{PathConfig, QemuDiskInterface, QemuFirmwareMode, QemuNetworkDeviceModel, QemuRtcBase};

const DEFAULT_GUEST_RDP_PORT: u16 = 3389;
const REQUIRED_WINDOWS_EDITION: &str = "Windows 11 Pro x64";
const TRUSTED_DIGEST_STAMP_SCHEMA_VERSION: u32 = 1;

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

#[derive(Debug)]
pub(crate) struct TrustedImageCatalog {
    paths: PathConfig,
    state: TrustedImageCatalogState,
}

#[derive(Debug, Clone)]
enum TrustedImageCatalogState {
    Ready(CachedTrustedImageCatalog),
    Invalid(InvalidTrustedImageCatalog),
}

#[derive(Debug, Clone)]
struct CachedTrustedImageCatalog {
    trusted_images: Vec<TrustedImage>,
    store_stamp: TrustedImageStoreStamp,
}

#[derive(Debug, Clone)]
struct InvalidTrustedImageCatalog {
    reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct TrustedImageStoreStamp {
    manifests: Vec<ManifestStamp>,
    tracked_files: Vec<FileStamp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ManifestStamp {
    path: PathBuf,
    sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    path: PathBuf,
    len: u64,
    modified_millis: u128,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(unix)]
    ctime_secs: i64,
    #[cfg(unix)]
    ctime_nsecs: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TrustedImageCatalogInspection {
    pub(crate) trusted_image_count: usize,
    pub(crate) invalid_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumeTrustedImageState {
    Imported,
    AlreadyPresent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsumeTrustedImageValidationMode {
    Hashed,
    Cached,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConsumedTrustedImage {
    pub import_state: ConsumeTrustedImageState,
    pub validation_mode: ConsumeTrustedImageValidationMode,
    pub pool_name: String,
    pub vm_name: String,
    pub attestation_ref: String,
    pub manifest_path: PathBuf,
    pub base_image_path: PathBuf,
    pub base_image_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TrustedDigestStamp {
    schema_version: u32,
    sha256: String,
    file_stamp: FileStamp,
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

    if let Some(existing_import) = existing_imported_trusted_image(
        &imported_manifest,
        &final_base_image_path,
        &final_manifest_path,
        &expected_base_image_sha256,
    )? {
        return Ok(existing_import);
    }
    validate_existing_trusted_identity(paths, &imported_manifest, &final_base_image_path, &final_manifest_path)?;

    let _import_lock = ImportLock::acquire(&manifest_dir, &final_manifest_path)?;
    if let Some(existing_import) = existing_imported_trusted_image(
        &imported_manifest,
        &final_base_image_path,
        &final_manifest_path,
        &expected_base_image_sha256,
    )? {
        return Ok(existing_import);
    }
    validate_existing_trusted_identity(paths, &imported_manifest, &final_base_image_path, &final_manifest_path)?;

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
        validation_mode: ConsumeTrustedImageValidationMode::Hashed,
        pool_name: imported_manifest.pool_name,
        vm_name: imported_manifest.vm_name,
        attestation_ref: imported_manifest.attestation_ref,
        manifest_path: final_manifest_path,
        base_image_path: final_base_image_path,
        base_image_sha256: expected_base_image_sha256,
    })
}

fn existing_imported_trusted_image(
    manifest: &TrustedImageManifestDocument,
    final_base_image_path: &Path,
    final_manifest_path: &Path,
    expected_base_image_sha256: &str,
) -> anyhow::Result<Option<ConsumedTrustedImage>> {
    let final_image_exists = final_base_image_path.exists();
    let final_manifest_exists = final_manifest_path.exists();
    if !final_image_exists && !final_manifest_exists {
        return Ok(None);
    }

    anyhow::ensure!(
        final_image_exists && final_manifest_exists,
        "existing imported artifact is incomplete for vm_name {}",
        manifest.vm_name,
    );
    let existing_manifest = read_trusted_image_manifest(final_manifest_path)?;
    anyhow::ensure!(
        existing_manifest == *manifest,
        "existing imported manifest {} does not match the requested trusted artifact",
        final_manifest_path.display(),
    );
    let validation_mode =
        validate_base_image_digest_with_stamp(final_base_image_path, expected_base_image_sha256, "base_image")?;

    Ok(Some(ConsumedTrustedImage {
        import_state: ConsumeTrustedImageState::AlreadyPresent,
        validation_mode,
        pool_name: manifest.pool_name.clone(),
        vm_name: manifest.vm_name.clone(),
        attestation_ref: manifest.attestation_ref.clone(),
        manifest_path: final_manifest_path.to_path_buf(),
        base_image_path: final_base_image_path.to_path_buf(),
        base_image_sha256: expected_base_image_sha256.to_owned(),
    }))
}

pub(crate) fn trusted_images(paths: &PathConfig) -> anyhow::Result<Vec<TrustedImage>> {
    let mut manifests = json_files(&paths.manifest_dir())?;
    manifests.sort();

    let mut base_image_sha256_cache = HashMap::new();
    let mut trusted_images = Vec::with_capacity(manifests.len());

    for (index, manifest_path) in manifests.into_iter().enumerate() {
        let manifest = read_trusted_image_manifest(&manifest_path)?;
        validate_manifest(&manifest, &manifest_path)?;

        let base_image_path = resolve_base_image_path(paths, &manifest.base_image_path)?;
        validate_image_store_path(&paths.image_store, &base_image_path).with_context(|| {
            format!(
                "validate trusted image store contract for {}",
                base_image_path.display()
            )
        })?;

        let expected_base_image_sha256 = normalize_sha256("base_image.sha256", &manifest.base_image.sha256)?;
        cached_verified_sha256_file(
            &mut base_image_sha256_cache,
            &base_image_path,
            &expected_base_image_sha256,
            "base_image",
        )?;

        trusted_images.push(TrustedImage {
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
        });
    }

    validate_unique_vm_names(&trusted_images)?;

    Ok(trusted_images)
}

impl TrustedImageCatalog {
    pub(crate) fn load(paths: PathConfig) -> anyhow::Result<Self> {
        let trusted_images = trusted_images(&paths)?;
        let store_stamp = TrustedImageStoreStamp::capture(&paths, &trusted_images)?;

        Ok(Self {
            paths,
            state: TrustedImageCatalogState::Ready(CachedTrustedImageCatalog {
                trusted_images,
                store_stamp,
            }),
        })
    }

    pub(crate) fn inspect(&mut self) -> TrustedImageCatalogInspection {
        match self.ensure_current() {
            Ok(trusted_images) => TrustedImageCatalogInspection {
                trusted_image_count: trusted_images.len(),
                invalid_reason: None,
            },
            Err(error) => {
                let invalid_reason = match &self.state {
                    TrustedImageCatalogState::Ready(_) => Some(error.to_string()),
                    TrustedImageCatalogState::Invalid(invalid) => Some(invalid.reason.clone()),
                };

                TrustedImageCatalogInspection {
                    trusted_image_count: self.trusted_image_count(),
                    invalid_reason,
                }
            }
        }
    }

    pub(crate) fn trusted_images(&mut self) -> anyhow::Result<Vec<TrustedImage>> {
        self.ensure_current().cloned()
    }

    fn trusted_image_count(&self) -> usize {
        match &self.state {
            TrustedImageCatalogState::Ready(catalog) => catalog.trusted_images.len(),
            TrustedImageCatalogState::Invalid(_) => 0,
        }
    }

    fn ensure_current(&mut self) -> anyhow::Result<&Vec<TrustedImage>> {
        let cached_catalog = match &self.state {
            TrustedImageCatalogState::Ready(catalog) => catalog.clone(),
            TrustedImageCatalogState::Invalid(invalid) => anyhow::bail!(invalid.reason.clone()),
        };

        let current_stamp = match TrustedImageStoreStamp::capture(&self.paths, &cached_catalog.trusted_images) {
            Ok(stamp) => stamp,
            Err(error) => {
                let reason = format!("trusted_catalog_invalid:{error:#}");
                self.state = TrustedImageCatalogState::Invalid(InvalidTrustedImageCatalog { reason: reason.clone() });
                anyhow::bail!(reason);
            }
        };

        if current_stamp != cached_catalog.store_stamp {
            let reason =
                "trusted_catalog_invalid:trusted image store drift detected; restart the control-plane to revalidate"
                    .to_owned();
            self.state = TrustedImageCatalogState::Invalid(InvalidTrustedImageCatalog { reason: reason.clone() });
            anyhow::bail!(reason);
        }

        match &self.state {
            TrustedImageCatalogState::Ready(catalog) => Ok(&catalog.trusted_images),
            TrustedImageCatalogState::Invalid(invalid) => anyhow::bail!(invalid.reason.clone()),
        }
    }
}

pub(crate) fn validate_trusted_image_identity(
    paths: &PathConfig,
    pool_name: &str,
    vm_name: &str,
    attestation_ref: &str,
    base_image_path: &Path,
) -> anyhow::Result<()> {
    let trusted_images = trusted_images(paths)?;
    validate_trusted_image_identity_in_catalog(&trusted_images, pool_name, vm_name, attestation_ref, base_image_path)
}

pub(crate) fn validate_trusted_image_identity_in_catalog(
    trusted_images: &[TrustedImage],
    pool_name: &str,
    vm_name: &str,
    attestation_ref: &str,
    base_image_path: &Path,
) -> anyhow::Result<()> {
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

impl TrustedImageStoreStamp {
    fn capture(paths: &PathConfig, trusted_images: &[TrustedImage]) -> anyhow::Result<Self> {
        let mut manifests = json_files(&paths.manifest_dir())?;
        manifests.sort();
        let manifests = manifests
            .into_iter()
            .map(ManifestStamp::capture)
            .collect::<anyhow::Result<Vec<_>>>()?;

        let mut tracked_paths = trusted_images
            .iter()
            .flat_map(|trusted_image| {
                let mut paths = vec![trusted_image.base_image_path.clone()];
                if let Some(boot_profile_v1) = &trusted_image.boot_profile_v1 {
                    if let Some(path) = &boot_profile_v1.firmware_code_path {
                        paths.push(path.clone());
                    }
                    if let Some(path) = &boot_profile_v1.vars_seed_path {
                        paths.push(path.clone());
                    }
                }
                paths
            })
            .collect::<Vec<_>>();
        tracked_paths.sort();
        tracked_paths.dedup();
        let tracked_files = tracked_paths
            .into_iter()
            .map(FileStamp::capture)
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self {
            manifests,
            tracked_files,
        })
    }
}

impl ManifestStamp {
    fn capture(path: PathBuf) -> anyhow::Result<Self> {
        let sha256 = sha256_file(&path).with_context(|| format!("hash trusted manifest {}", path.display()))?;

        Ok(Self { path, sha256 })
    }
}

impl FileStamp {
    fn capture(path: PathBuf) -> anyhow::Result<Self> {
        let metadata = fs::metadata(&path).with_context(|| format!("read metadata for {}", path.display()))?;
        let modified_millis = metadata
            .modified()
            .ok()
            .and_then(|modified| modified.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |duration| duration.as_millis());

        Ok(Self {
            path,
            len: metadata.len(),
            modified_millis,
            #[cfg(unix)]
            dev: std::os::unix::fs::MetadataExt::dev(&metadata),
            #[cfg(unix)]
            ino: std::os::unix::fs::MetadataExt::ino(&metadata),
            #[cfg(unix)]
            ctime_secs: std::os::unix::fs::MetadataExt::ctime(&metadata),
            #[cfg(unix)]
            ctime_nsecs: std::os::unix::fs::MetadataExt::ctime_nsec(&metadata),
        })
    }
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
        !final_manifest_path.exists() || final_base_image_path.exists(),
        "existing imported artifact is incomplete for vm_name {}",
        manifest.vm_name,
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
        let path = import_lock_path(manifest_dir, final_manifest_path)?;
        loop {
            match fs::OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(mut file) => {
                    writeln!(file, "pid={}", std::process::id())
                        .with_context(|| format!("write import lock {}", path.display()))?;
                    file.sync_all()
                        .with_context(|| format!("sync import lock {}", path.display()))?;
                    return Ok(Self { path });
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    #[cfg(unix)]
                    match inspect_import_lock(&path)? {
                        None => continue,
                        Some(ImportLockInspection::DeadPid(pid)) => match fs::remove_file(&path) {
                            Ok(()) => continue,
                            Err(remove_error) if remove_error.kind() == std::io::ErrorKind::NotFound => {
                                continue;
                            }
                            Err(remove_error) => {
                                return Err(remove_error).with_context(|| {
                                    format!("remove stale import lock {} from dead pid {pid}", path.display(),)
                                });
                            }
                        },
                        Some(ImportLockInspection::LivePid(pid)) => {
                            anyhow::bail!("import lock {} is held by live pid {pid}", path.display());
                        }
                    }

                    #[cfg(not(unix))]
                    {
                        return Err(error).with_context(|| format!("create import lock {}", path.display()));
                    }
                }
                Err(error) => {
                    return Err(error).with_context(|| format!("create import lock {}", path.display()));
                }
            }
        }
    }
}

impl Drop for ImportLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn import_lock_path(manifest_dir: &Path, final_manifest_path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = final_manifest_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("resolve imported manifest file name")?;
    Ok(manifest_dir.join(format!(".{file_name}.lock")))
}

#[cfg(unix)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ImportLockInspection {
    LivePid(i32),
    DeadPid(i32),
}

#[cfg(unix)]
fn inspect_import_lock(path: &Path) -> anyhow::Result<Option<ImportLockInspection>> {
    let contents = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("read import lock {}", path.display())),
    };
    let pid_line = contents
        .lines()
        .find(|line| line.starts_with("pid="))
        .context("existing import lock must contain pid=<pid>")?;
    let pid = pid_line["pid=".len()..]
        .trim()
        .parse::<i32>()
        .context("parse existing import lock pid")?;
    anyhow::ensure!(pid > 0, "existing import lock pid must be positive");

    if import_lock_process_exists(pid)? {
        Ok(Some(ImportLockInspection::LivePid(pid)))
    } else {
        Ok(Some(ImportLockInspection::DeadPid(pid)))
    }
}

#[cfg(unix)]
fn import_lock_process_exists(pid: i32) -> anyhow::Result<bool> {
    // SAFETY: `kill` with signal 0 only probes liveness for the parsed PID and does not alter process state.
    let result = unsafe { libc::kill(pid, 0) };
    if result == 0 {
        return Ok(true);
    }

    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error).with_context(|| format!("probe import-lock pid {pid} liveness")),
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

fn trusted_digest_stamp_path(base_image_path: &Path) -> anyhow::Result<PathBuf> {
    let file_name = base_image_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("resolve trusted base image file name for digest stamp")?;
    let parent = base_image_path
        .parent()
        .with_context(|| format!("resolve trusted base image parent for {}", base_image_path.display()))?;
    Ok(parent.join(format!(".{file_name}.digest-stamp")))
}

fn read_trusted_digest_stamp(base_image_path: &Path) -> anyhow::Result<Option<TrustedDigestStamp>> {
    let stamp_path = trusted_digest_stamp_path(base_image_path)?;
    let bytes = match fs::read(&stamp_path) {
        Ok(bytes) => bytes,
        Err(_) => return Ok(None),
    };

    match serde_json::from_slice::<TrustedDigestStamp>(&bytes) {
        Ok(stamp) => Ok(Some(stamp)),
        Err(_) => Ok(None),
    }
}

fn persist_trusted_digest_stamp(base_image_path: &Path, sha256: &str, file_stamp: &FileStamp) -> anyhow::Result<()> {
    let stamp_path = trusted_digest_stamp_path(base_image_path)?;
    let stamp_file_name = stamp_path
        .file_name()
        .and_then(|value| value.to_str())
        .context("resolve trusted digest stamp file name")?;
    let temp_stamp_path = stamp_path
        .parent()
        .with_context(|| format!("resolve trusted digest stamp parent for {}", stamp_path.display()))?
        .join(format!("{stamp_file_name}.tmp"));
    let temp_guard = TempPathGuard::new(&temp_stamp_path);
    write_json_atomically(
        &temp_stamp_path,
        &TrustedDigestStamp {
            schema_version: TRUSTED_DIGEST_STAMP_SCHEMA_VERSION,
            sha256: sha256.to_owned(),
            file_stamp: file_stamp.clone(),
        },
    )?;
    fs::rename(&temp_stamp_path, &stamp_path).with_context(|| {
        format!(
            "rename trusted digest stamp {} to {}",
            temp_stamp_path.display(),
            stamp_path.display(),
        )
    })?;
    sync_parent_dir(&stamp_path)?;
    temp_guard.disarm();
    Ok(())
}

fn validate_base_image_digest_with_stamp(
    base_image_path: &Path,
    expected_sha256: &str,
    label: &str,
) -> anyhow::Result<ConsumeTrustedImageValidationMode> {
    let pre_hash_stamp = FileStamp::capture(base_image_path.to_path_buf())?;

    if let Some(stamp) = read_trusted_digest_stamp(base_image_path)?
        && stamp.schema_version == TRUSTED_DIGEST_STAMP_SCHEMA_VERSION
        && stamp.sha256 == expected_sha256
        && stamp.file_stamp == pre_hash_stamp
    {
        return Ok(ConsumeTrustedImageValidationMode::Cached);
    }

    let actual_sha256 = sha256_file(base_image_path)?;
    let post_hash_stamp = FileStamp::capture(base_image_path.to_path_buf())?;
    anyhow::ensure!(
        pre_hash_stamp == post_hash_stamp,
        "{label} {} changed while verifying its digest",
        base_image_path.display(),
    );
    anyhow::ensure!(
        actual_sha256 == expected_sha256,
        "{label}.sha256 mismatch for {}: expected {}, got {}",
        base_image_path.display(),
        expected_sha256,
        actual_sha256,
    );
    let _ = persist_trusted_digest_stamp(base_image_path, expected_sha256, &post_hash_stamp);
    Ok(ConsumeTrustedImageValidationMode::Hashed)
}

fn cached_verified_sha256_file(
    cache: &mut HashMap<PathBuf, String>,
    path: &Path,
    expected_sha256: &str,
    label: &str,
) -> anyhow::Result<String> {
    if let Some(digest) = cache.get(path) {
        anyhow::ensure!(
            digest == expected_sha256,
            "{label}.sha256 mismatch for {}: expected {}, got {}",
            path.display(),
            expected_sha256,
            digest,
        );
        return Ok(digest.clone());
    }

    validate_base_image_digest_with_stamp(path, expected_sha256, label)?;
    cache.insert(path.to_path_buf(), expected_sha256.to_owned());
    Ok(expected_sha256.to_owned())
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
    use std::time::Duration;

    use serde_json::json;
    use sha2::{Digest as _, Sha256};

    #[cfg(unix)]
    use super::import_lock_process_exists;
    use super::{
        ConsumeTrustedImageState, ConsumeTrustedImageValidationMode, TrustedImage, TrustedImageCatalog,
        cached_verified_sha256_file, consume_trusted_image, import_lock_path, normalize_sha256,
        read_trusted_image_manifest, sanitize_file_component, trusted_digest_stamp_path, trusted_images,
        validate_trusted_image_identity_in_catalog,
    };
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
    fn cached_verified_sha256_file_reuses_digest_for_duplicate_manifest_base_images() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let base_image_path = tempdir.path().join("shared.qcow2");
        let first_bytes = b"first-image-bytes";
        fs::write(&base_image_path, first_bytes).expect("write first base image");

        let mut cache = std::collections::HashMap::new();
        let first_digest = format!("{:x}", Sha256::digest(first_bytes));
        let cached_digest = cached_verified_sha256_file(&mut cache, &base_image_path, &first_digest, "base_image")
            .expect("hash first base image");

        fs::write(&base_image_path, b"second-image-bytes").expect("overwrite base image");
        let second_digest = cached_verified_sha256_file(&mut cache, &base_image_path, &first_digest, "base_image")
            .expect("reuse cached base image digest");

        assert_eq!(cached_digest, first_digest);
        assert_eq!(second_digest, first_digest);
    }

    #[test]
    fn trusted_image_catalog_returns_cached_trusted_images_when_store_is_unchanged() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(tempdir.path(), "honeypot-import-0", "default", "image-0");

        consume_trusted_image(&paths, &bundle.manifest_path).expect("import trusted image bundle");

        let mut catalog = TrustedImageCatalog::load(paths).expect("load trusted image catalog");
        let inspection = catalog.inspect();
        let trusted_images = catalog.trusted_images().expect("read cached trusted images");

        assert_eq!(inspection.trusted_image_count, 1);
        assert_eq!(inspection.invalid_reason, None);
        assert_eq!(trusted_images.len(), 1);
        assert_eq!(trusted_images[0].vm_name, "honeypot-import-0");
    }

    #[test]
    fn trusted_image_catalog_fails_closed_when_imported_base_image_drifts() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(tempdir.path(), "honeypot-import-0", "default", "image-0");

        let imported = consume_trusted_image(&paths, &bundle.manifest_path).expect("import trusted image bundle");
        let mut catalog = TrustedImageCatalog::load(paths).expect("load trusted image catalog");

        std::thread::sleep(Duration::from_millis(5));
        fs::write(&imported.base_image_path, b"tampered-base-image").expect("tamper imported base image");

        let error = catalog
            .trusted_images()
            .expect_err("drifted trusted image catalog should fail closed");
        assert!(format!("{error:#}").contains("trusted_catalog_invalid"), "{error:#}");

        let inspection = catalog.inspect();
        assert_eq!(inspection.trusted_image_count, 0);
        assert!(
            inspection
                .invalid_reason
                .expect("invalid reason should be recorded")
                .contains("trusted_catalog_invalid"),
        );
    }

    #[test]
    fn trusted_image_identity_validation_accepts_prevalidated_catalog_entries() {
        let trusted_images = vec![TrustedImage {
            pool_name: "default".to_owned(),
            vm_name: "manual-deck-01".to_owned(),
            attestation_ref: "attestation://tiny11-row420-sealed-profile".to_owned(),
            guest_rdp_port: 3391,
            base_image_path: PathBuf::from("/tmp/shared.qcow2"),
            boot_profile_v1: None,
        }];

        validate_trusted_image_identity_in_catalog(
            &trusted_images,
            "default",
            "manual-deck-01",
            "attestation://tiny11-row420-sealed-profile",
            Path::new("/tmp/shared.qcow2"),
        )
        .expect("validate identity against cached trusted image catalog");
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
        assert_eq!(imported.validation_mode, ConsumeTrustedImageValidationMode::Hashed);
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
        assert_eq!(first.validation_mode, ConsumeTrustedImageValidationMode::Hashed);
        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(second.validation_mode, ConsumeTrustedImageValidationMode::Cached);
        assert_eq!(first.base_image_path, second.base_image_path);
        assert_eq!(first.manifest_path, second.manifest_path);
    }

    #[test]
    fn consume_trusted_image_skips_a_matching_lock_when_the_bundle_is_already_present() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(tempdir.path(), "honeypot-import-locked", "default", "image-locked");

        let first = consume_trusted_image(&paths, &bundle.manifest_path).expect("first import should succeed");
        write_import_lock_for_pid(&paths, &first.manifest_path, current_test_pid());

        let second = consume_trusted_image(&paths, &bundle.manifest_path).expect("second import should bypass lock");

        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(second.validation_mode, ConsumeTrustedImageValidationMode::Cached);
        assert_eq!(second.manifest_path, first.manifest_path);
        assert!(
            import_lock_path(&paths.manifest_dir(), &first.manifest_path)
                .expect("resolve import lock path")
                .is_file()
        );
    }

    #[test]
    fn consume_trusted_image_rehashes_when_the_digest_stamp_is_missing() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(
            tempdir.path(),
            "honeypot-import-missing-stamp",
            "default",
            "image-missing-stamp",
        );

        let first = consume_trusted_image(&paths, &bundle.manifest_path).expect("first import should succeed");
        fs::remove_file(trusted_digest_stamp_path(&first.base_image_path).expect("resolve digest stamp path"))
            .expect("remove digest stamp");

        let second = consume_trusted_image(&paths, &bundle.manifest_path).expect("second import should succeed");

        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(second.validation_mode, ConsumeTrustedImageValidationMode::Hashed);
    }

    #[test]
    fn consume_trusted_image_rehashes_when_the_digest_stamp_is_corrupt() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(
            tempdir.path(),
            "honeypot-import-corrupt-stamp",
            "default",
            "image-corrupt-stamp",
        );

        let first = consume_trusted_image(&paths, &bundle.manifest_path).expect("first import should succeed");
        fs::write(
            trusted_digest_stamp_path(&first.base_image_path).expect("resolve digest stamp path"),
            b"{not-json",
        )
        .expect("corrupt digest stamp");

        let second = consume_trusted_image(&paths, &bundle.manifest_path).expect("second import should succeed");

        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(second.validation_mode, ConsumeTrustedImageValidationMode::Hashed);
    }

    #[test]
    fn consume_trusted_image_rehashes_when_base_image_metadata_drifts() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(
            tempdir.path(),
            "honeypot-import-drifted-stamp",
            "default",
            "image-drifted-stamp",
        );

        let first = consume_trusted_image(&paths, &bundle.manifest_path).expect("first import should succeed");
        std::thread::sleep(Duration::from_millis(5));
        let contents = fs::read(&first.base_image_path).expect("read imported base image");
        fs::write(&first.base_image_path, &contents).expect("rewrite imported base image");

        let second = consume_trusted_image(&paths, &bundle.manifest_path).expect("second import should succeed");

        assert_eq!(second.import_state, ConsumeTrustedImageState::AlreadyPresent);
        assert_eq!(second.validation_mode, ConsumeTrustedImageValidationMode::Hashed);
    }

    #[cfg(unix)]
    #[test]
    fn consume_trusted_image_reclaims_a_stale_dead_pid_lock() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(
            tempdir.path(),
            "honeypot-import-stale-lock",
            "default",
            "image-stale-lock",
        );
        let final_manifest_path = expected_imported_manifest_path(&paths, &bundle.manifest_path);
        let dead_pid = dead_test_pid();
        write_import_lock_for_pid(&paths, &final_manifest_path, dead_pid);

        let imported =
            consume_trusted_image(&paths, &bundle.manifest_path).expect("import should reclaim stale dead-pid lock");

        assert_eq!(imported.import_state, ConsumeTrustedImageState::Imported);
        assert!(
            !import_lock_path(&paths.manifest_dir(), &final_manifest_path)
                .expect("resolve import lock path")
                .exists()
        );
    }

    #[cfg(unix)]
    #[test]
    fn consume_trusted_image_reports_live_pid_lock_for_a_new_import() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let paths = test_paths(tempdir.path());
        let bundle = create_source_bundle(
            tempdir.path(),
            "honeypot-import-live-lock",
            "default",
            "image-live-lock",
        );
        let final_manifest_path = expected_imported_manifest_path(&paths, &bundle.manifest_path);
        write_import_lock_for_pid(&paths, &final_manifest_path, current_test_pid());

        let error = consume_trusted_image(&paths, &bundle.manifest_path).expect_err("live-pid lock should fail closed");

        assert!(format!("{error:#}").contains("held by live pid"), "{error:#}");
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

    fn expected_imported_manifest_path(paths: &PathConfig, source_manifest_path: &Path) -> PathBuf {
        let manifest = read_trusted_image_manifest(source_manifest_path).expect("read source manifest");
        let expected_base_image_sha256 =
            normalize_sha256("base_image.sha256", &manifest.base_image.sha256).expect("normalize base image sha256");
        paths.manifest_dir().join(format!(
            "{}-{}.json",
            sanitize_file_component(&manifest.vm_name),
            &expected_base_image_sha256[..12]
        ))
    }

    fn write_import_lock_for_pid(paths: &PathConfig, final_manifest_path: &Path, pid: i32) {
        fs::create_dir_all(paths.manifest_dir()).expect("create manifest dir");
        let lock_path = import_lock_path(&paths.manifest_dir(), final_manifest_path).expect("resolve import lock path");
        fs::write(&lock_path, format!("pid={pid}\n")).expect("write import lock");
    }

    #[cfg(unix)]
    fn dead_test_pid() -> i32 {
        let mut candidate = current_test_pid() + 1024;
        while import_lock_process_exists(candidate).expect("probe candidate pid liveness") {
            candidate += 1;
        }
        candidate
    }

    fn current_test_pid() -> i32 {
        i32::try_from(std::process::id()).expect("current process id should fit in i32")
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
