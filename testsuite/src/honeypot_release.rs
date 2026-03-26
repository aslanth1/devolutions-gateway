use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::Deserialize;

pub const HONEYPOT_IMAGES_LOCK_PATH: &str = "honeypot/docker/images.lock";
pub const HONEYPOT_COMPOSE_PATH: &str = "honeypot/docker/compose.yaml";

const CANONICAL_REGISTRY: &str = "ghcr.io/fork-owner";
const CANONICAL_IMAGE_ROOT: &str = "devolutions-gateway-honeypot";
const SERVICE_NAMES: [&str; 3] = ["control-plane", "frontend", "proxy"];
const FLOATING_TAGS: [&str; 7] = ["latest", "stable", "main", "master", "edge", "dev", "nightly"];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneypotImagesLock {
    #[serde(rename = "control-plane")]
    pub control_plane: HoneypotImageLockEntry,
    pub proxy: HoneypotImageLockEntry,
    pub frontend: HoneypotImageLockEntry,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneypotImageLockEntry {
    pub image: String,
    pub registry: String,
    pub current: HoneypotImageRevision,
    pub previous: HoneypotImageRevision,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneypotImageRevision {
    pub tag: String,
    pub digest: String,
    pub source_ref: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HoneypotComposeFile {
    #[serde(rename = "x-images")]
    image_aliases: std::collections::BTreeMap<String, String>,
    services: std::collections::BTreeMap<String, HoneypotComposeService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HoneypotComposeService {
    image: String,
}

impl HoneypotImagesLock {
    pub fn service_entry(&self, service: &'static str) -> &HoneypotImageLockEntry {
        match service {
            "control-plane" => &self.control_plane,
            "proxy" => &self.proxy,
            "frontend" => &self.frontend,
            _ => panic!("unsupported service name: {service}"),
        }
    }
}

pub fn repo_relative_path(relative_path: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join(relative_path)
}

pub fn load_honeypot_images_lock(path: &Path) -> anyhow::Result<HoneypotImagesLock> {
    let data = std::fs::read_to_string(path).with_context(|| format!("read images lock at {}", path.display()))?;
    validate_honeypot_images_lock_document(&data)
}

pub fn validate_honeypot_images_lock_document(data: &str) -> anyhow::Result<HoneypotImagesLock> {
    let document: serde_yaml::Value = serde_yaml::from_str(data).context("parse images.lock YAML value")?;
    let mapping = document
        .as_mapping()
        .context("images.lock must be a YAML mapping at the top level")?;

    let actual_keys = mapping
        .keys()
        .map(|key| {
            key.as_str()
                .map(ToOwned::to_owned)
                .context("images.lock top-level keys must be strings")
        })
        .collect::<anyhow::Result<BTreeSet<_>>>()?;
    let expected_keys = SERVICE_NAMES
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        actual_keys == expected_keys,
        "images.lock must contain exactly control-plane, proxy, and frontend, found: {}",
        actual_keys.into_iter().collect::<Vec<_>>().join(", "),
    );

    let lockfile: HoneypotImagesLock = serde_yaml::from_str(data).context("deserialize images.lock")?;

    for service in SERVICE_NAMES {
        let entry = lockfile.service_entry(service);
        validate_service_entry(service, entry)?;
    }

    Ok(lockfile)
}

pub fn validate_honeypot_compose_document(data: &str, lockfile: &HoneypotImagesLock) -> anyhow::Result<()> {
    let compose: HoneypotComposeFile = serde_yaml::from_str(data).context("deserialize honeypot compose file")?;

    let alias_keys = compose.image_aliases.keys().cloned().collect::<BTreeSet<_>>();
    let service_keys = compose.services.keys().cloned().collect::<BTreeSet<_>>();
    let expected_keys = SERVICE_NAMES
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();

    anyhow::ensure!(
        alias_keys == expected_keys,
        "compose x-images must contain exactly control-plane, proxy, and frontend aliases",
    );
    anyhow::ensure!(
        service_keys == expected_keys,
        "compose services must contain exactly control-plane, proxy, and frontend",
    );

    for service in SERVICE_NAMES {
        let expected_ref = current_image_ref(lockfile.service_entry(service));
        let alias_ref = compose
            .image_aliases
            .get(service)
            .with_context(|| format!("missing compose x-images entry for {service}"))?;
        anyhow::ensure!(
            alias_ref == &expected_ref,
            "compose x-images entry for {service} must match images.lock current digest",
        );

        let service_image = &compose
            .services
            .get(service)
            .with_context(|| format!("missing compose service {service}"))?
            .image;
        anyhow::ensure!(
            service_image == &expected_ref,
            "compose service {service} image must match images.lock current digest",
        );
    }

    Ok(())
}

pub fn validate_honeypot_release_inputs(lock_path: &Path, compose_path: &Path) -> anyhow::Result<()> {
    let lockfile = load_honeypot_images_lock(lock_path)?;
    let compose_data = std::fs::read_to_string(compose_path)
        .with_context(|| format!("read compose file at {}", compose_path.display()))?;
    validate_honeypot_compose_document(&compose_data, &lockfile)
}

fn validate_service_entry(service: &'static str, entry: &HoneypotImageLockEntry) -> anyhow::Result<()> {
    let expected_image = canonical_image_name(service);
    anyhow::ensure!(
        entry.registry == CANONICAL_REGISTRY,
        "{service} registry must be {CANONICAL_REGISTRY}",
    );
    anyhow::ensure!(
        entry.image == expected_image,
        "{service} image must be {expected_image}"
    );

    validate_revision(service, "current", &entry.current)?;
    validate_revision(service, "previous", &entry.previous)?;

    anyhow::ensure!(
        entry.current.digest != entry.previous.digest,
        "{service} current and previous digests must not be identical",
    );

    Ok(())
}

fn validate_revision(service: &str, slot: &str, revision: &HoneypotImageRevision) -> anyhow::Result<()> {
    validate_tag(service, slot, &revision.tag)?;
    validate_digest(service, slot, &revision.digest)?;
    anyhow::ensure!(
        !revision.source_ref.trim().is_empty(),
        "{service} {slot}.source_ref must not be empty",
    );
    Ok(())
}

fn validate_tag(service: &str, slot: &str, tag: &str) -> anyhow::Result<()> {
    anyhow::ensure!(!tag.trim().is_empty(), "{service} {slot}.tag must not be empty");
    anyhow::ensure!(
        !FLOATING_TAGS.contains(&tag),
        "{service} {slot}.tag must not be a floating tag",
    );
    anyhow::ensure!(
        tag.starts_with('v') || tag.starts_with("git-"),
        "{service} {slot}.tag must start with v or git-",
    );
    Ok(())
}

fn validate_digest(service: &str, slot: &str, digest: &str) -> anyhow::Result<()> {
    anyhow::ensure!(
        digest.starts_with("sha256:"),
        "{service} {slot}.digest must start with sha256:",
    );

    let hex = &digest["sha256:".len()..];
    anyhow::ensure!(
        hex.len() == 64 && hex.chars().all(|ch| ch.is_ascii_hexdigit() && !ch.is_ascii_uppercase()),
        "{service} {slot}.digest must contain exactly 64 lowercase hex characters",
    );

    Ok(())
}

fn current_image_ref(entry: &HoneypotImageLockEntry) -> String {
    format!(
        "{}/{image}@{digest}",
        entry.registry,
        image = entry.image,
        digest = entry.current.digest
    )
}

fn canonical_image_name(service: &str) -> String {
    format!("{CANONICAL_IMAGE_ROOT}/{service}")
}
