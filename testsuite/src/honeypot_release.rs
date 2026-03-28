use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Context as _;
use devolutions_gateway::config::{Conf as GatewayConf, dto as gateway_dto};
use honeypot_contracts::SCHEMA_VERSION;
use honeypot_control_plane::config::{CONTROL_PLANE_CONFIG_ENV, ControlPlaneConfig, DEFAULT_CONTROL_PLANE_CONFIG_PATH};
use honeypot_frontend::config::{DEFAULT_FRONTEND_CONFIG_PATH, FrontendConfig};
use serde::Deserialize;

pub const HONEYPOT_IMAGES_LOCK_PATH: &str = "honeypot/docker/images.lock";
pub const HONEYPOT_PROMOTION_MANIFEST_PATH: &str = "honeypot/docker/promotion-manifest.json";
pub const HONEYPOT_COMPOSE_PATH: &str = "honeypot/docker/compose.yaml";
pub const HONEYPOT_CONTROL_PLANE_DOCKERFILE_PATH: &str = "honeypot/docker/control-plane/Dockerfile";
pub const HONEYPOT_PROXY_DOCKERFILE_PATH: &str = "honeypot/docker/proxy/Dockerfile";
pub const HONEYPOT_FRONTEND_DOCKERFILE_PATH: &str = "honeypot/docker/frontend/Dockerfile";
pub const HONEYPOT_CONTROL_PLANE_ENV_PATH: &str = "honeypot/docker/env/control-plane.env";
pub const HONEYPOT_CONTROL_PLANE_CONFIG_PATH: &str = "honeypot/docker/config/control-plane/config.toml";
pub const HONEYPOT_PROXY_ENV_PATH: &str = "honeypot/docker/env/proxy.env";
pub const HONEYPOT_PROXY_CONFIG_PATH: &str = "honeypot/docker/config/proxy/gateway.json";
pub const HONEYPOT_FRONTEND_ENV_PATH: &str = "honeypot/docker/env/frontend.env";
pub const HONEYPOT_FRONTEND_CONFIG_PATH: &str = "honeypot/docker/config/frontend/config.toml";

const CANONICAL_REGISTRY: &str = "ghcr.io/fork-owner";
const CANONICAL_IMAGE_ROOT: &str = "devolutions-gateway-honeypot";
const SERVICE_NAMES: [&str; 3] = ["control-plane", "frontend", "proxy"];
const FLOATING_TAGS: [&str; 7] = ["latest", "stable", "main", "master", "edge", "dev", "nightly"];
const CONTROL_PLANE_ENV_FILE_REF: &str = "./env/control-plane.env";
const CONTROL_PLANE_CONFIG_MOUNT: &str =
    "./config/control-plane/config.toml:/etc/honeypot/control-plane/config.toml:ro";
const CONTROL_PLANE_SECRET_MOUNT: &str = "./secrets/control-plane:/run/secrets/honeypot/control-plane:ro";
const CONTROL_PLANE_QMP_MOUNT: &str = "/srv/honeypot/run/qmp:/run/honeypot/qmp:rw";
const CONTROL_PLANE_QGA_MOUNT: &str = "/srv/honeypot/run/qga:/run/honeypot/qga:rw";
const CONTROL_PLANE_NETWORK: &str = "honeypot-control";
const CONTROL_PLANE_BIND_ADDR: &str = "0.0.0.0:8080";
const CONTROL_PLANE_DATA_DIR: &str = "/var/lib/honeypot/control-plane";
const CONTROL_PLANE_IMAGE_STORE: &str = "/var/lib/honeypot/images";
const CONTROL_PLANE_LEASE_STORE: &str = "/var/lib/honeypot/leases";
const CONTROL_PLANE_QUARANTINE_STORE: &str = "/var/lib/honeypot/quarantine";
const CONTROL_PLANE_QMP_DIR: &str = "/run/honeypot/qmp";
const CONTROL_PLANE_QGA_DIR: &str = "/run/honeypot/qga";
const CONTROL_PLANE_SECRET_DIR: &str = "/run/secrets/honeypot/control-plane";
const CONTROL_PLANE_BACKEND_CREDENTIALS_FILE: &str = "/run/secrets/honeypot/control-plane/backend-credentials.json";
const CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE: &str =
    "/run/secrets/honeypot/control-plane/proxy-verifier-public-key.pem";
const CONTROL_PLANE_KVM_PATH: &str = "/dev/kvm";
const CONTROL_PLANE_QEMU_BINARY_PATH: &str = "/usr/bin/qemu-system-x86_64";
const CONTROL_PLANE_QEMU_MACHINE_TYPE: &str = "q35";
const CONTROL_PLANE_QEMU_CPU_MODEL: &str = "host";
const CONTROL_PLANE_QEMU_VCPU_COUNT: u8 = 4;
const CONTROL_PLANE_QEMU_MEMORY_MIB: u32 = 8192;
const CONTROL_PLANE_QEMU_NETDEV_ID: &str = "net0";
const CONTROL_PLANE_LIFECYCLE_DRIVER: &str = "process";
const CONTROL_PLANE_STOP_TIMEOUT_SECS: u64 = 5;
const PROXY_ENV_FILE_REF: &str = "./env/proxy.env";
const PROXY_CONFIG_MOUNT: &str = "./config/proxy/gateway.json:/etc/honeypot/proxy/gateway.json:ro";
const PROXY_SECRET_MOUNT: &str = "./secrets/proxy:/run/secrets/honeypot/proxy:ro";
const PROXY_CONFIG_DIR: &str = "/etc/honeypot/proxy";
const PROXY_CONTROL_PLANE_ENDPOINT: &str = "http://control-plane:8080/";
const PROXY_CONTROL_PLANE_TOKEN_FILE: &str = "/run/secrets/honeypot/proxy/control-plane-service-token";
const PROXY_FRONTEND_PUBLIC_URL: &str = "http://frontend:8080/";
const PROXY_HTTP_LISTENER: &str = "http://0.0.0.0:8080";
const PROXY_TCP_LISTENER: &str = "tcp://0.0.0.0:8443";
const FRONTEND_CONFIG_ENV: &str = "HONEYPOT_FRONTEND_CONFIG_PATH";
const FRONTEND_ENV_FILE_REF: &str = "./env/frontend.env";
const FRONTEND_CONFIG_MOUNT: &str = "./config/frontend/config.toml:/etc/honeypot/frontend/config.toml:ro";
const FRONTEND_SECRET_MOUNT: &str = "./secrets/frontend:/run/secrets/honeypot/frontend:ro";
const FRONTEND_BIND_ADDR: &str = "0.0.0.0:8080";
const FRONTEND_PROXY_BASE_URL: &str = "http://proxy:8080/";
const FRONTEND_BOOTSTRAP_PATH: &str = "/jet/honeypot/bootstrap";
const FRONTEND_EVENTS_PATH: &str = "/jet/honeypot/events";
const FRONTEND_STREAM_TOKEN_PATH_TEMPLATE: &str = "/jet/honeypot/session/{session_id}/stream-token";
const FRONTEND_TERMINATE_PATH_TEMPLATE: &str = "/jet/session/{session_id}/terminate";
const FRONTEND_SYSTEM_TERMINATE_PATH: &str = "/jet/session/system/terminate";
const FRONTEND_TITLE: &str = "Observation Deck";

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
pub struct HoneypotPromotionManifest {
    pub schema_version: u32,
    pub generated_at: String,
    pub builder_id: String,
    pub source_commit: String,
    pub source_ref: String,
    pub signature_ref: String,
    pub services: Vec<HoneypotPromotionServiceRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct HoneypotPromotionServiceRecord {
    pub service: String,
    pub image: String,
    pub registry: String,
    pub tag: String,
    pub digest: String,
    pub source_ref: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageSlot {
    Current,
    Previous,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoneypotService {
    ControlPlane,
    Proxy,
    Frontend,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceVersionSelection {
    pub control_plane: ImageSlot,
    pub proxy: ImageSlot,
    pub frontend: ImageSlot,
}

impl Default for ServiceVersionSelection {
    fn default() -> Self {
        Self {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServiceSchemaVersions {
    pub control_plane: u32,
    pub proxy: u32,
    pub frontend: u32,
}

impl Default for ServiceSchemaVersions {
    fn default() -> Self {
        Self {
            control_plane: SCHEMA_VERSION,
            proxy: SCHEMA_VERSION,
            frontend: SCHEMA_VERSION,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HoneypotComposeFile {
    #[serde(rename = "x-images")]
    image_aliases: BTreeMap<String, String>,
    services: BTreeMap<String, HoneypotComposeService>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HoneypotComposeService {
    image: String,
    #[serde(default)]
    env_file: Option<ComposePathRef>,
    #[serde(default)]
    volumes: Vec<String>,
    #[serde(default)]
    networks: Vec<String>,
    #[serde(default)]
    ports: Vec<String>,
    #[serde(default)]
    healthcheck: Option<HoneypotComposeHealthcheck>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct HoneypotComposeHealthcheck {
    #[serde(default)]
    test: Vec<String>,
}

impl HoneypotComposeHealthcheck {
    fn contains_fragment(&self, expected: &str) -> bool {
        self.test.iter().any(|part| part.contains(expected))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
enum ComposePathRef {
    One(String),
    Many(Vec<String>),
}

impl ComposePathRef {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(path) => path == expected,
            Self::Many(paths) => paths.iter().any(|path| path == expected),
        }
    }
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

pub fn load_honeypot_promotion_manifest(path: &Path) -> anyhow::Result<HoneypotPromotionManifest> {
    let data =
        std::fs::read_to_string(path).with_context(|| format!("read promotion manifest at {}", path.display()))?;
    validate_honeypot_promotion_manifest_document(&data)
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

pub fn validate_honeypot_promotion_manifest_document(data: &str) -> anyhow::Result<HoneypotPromotionManifest> {
    let manifest: HoneypotPromotionManifest =
        serde_json::from_str(data).context("deserialize promotion-manifest.json")?;

    anyhow::ensure!(
        manifest.schema_version > 0,
        "promotion-manifest.json schema_version must be greater than zero",
    );

    for (field_name, value) in [
        ("generated_at", manifest.generated_at.as_str()),
        ("builder_id", manifest.builder_id.as_str()),
        ("source_commit", manifest.source_commit.as_str()),
        ("source_ref", manifest.source_ref.as_str()),
        ("signature_ref", manifest.signature_ref.as_str()),
    ] {
        anyhow::ensure!(
            !value.trim().is_empty(),
            "promotion-manifest.json {field_name} must not be empty",
        );
    }

    anyhow::ensure!(
        !manifest.services.is_empty(),
        "promotion-manifest.json must include at least one service record",
    );

    let mut seen_services = BTreeSet::new();
    for record in &manifest.services {
        anyhow::ensure!(
            SERVICE_NAMES.contains(&record.service.as_str()),
            "promotion-manifest.json service {} is not one of control-plane, proxy, or frontend",
            record.service,
        );
        anyhow::ensure!(
            seen_services.insert(record.service.clone()),
            "promotion-manifest.json must not contain duplicate service record {}",
            record.service,
        );
        validate_promotion_service_record(record)?;
    }

    Ok(manifest)
}

pub fn validate_honeypot_compose_document(data: &str, lockfile: &HoneypotImagesLock) -> anyhow::Result<()> {
    validate_honeypot_compose_document_for_selection(
        data,
        lockfile,
        ServiceVersionSelection::default(),
        ServiceSchemaVersions::default(),
    )
}

pub fn validate_honeypot_compose_document_for_selection(
    data: &str,
    lockfile: &HoneypotImagesLock,
    selection: ServiceVersionSelection,
    schema_versions: ServiceSchemaVersions,
) -> anyhow::Result<()> {
    validate_mixed_version_contract_compatibility(selection, schema_versions)
        .context("compose image selection must satisfy the mixed-version contract")?;

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
        let expected_ref = image_ref(
            lockfile.service_entry(service),
            service_selection_slot(selection, service),
        );
        let alias_ref = compose
            .image_aliases
            .get(service)
            .with_context(|| format!("missing compose x-images entry for {service}"))?;
        anyhow::ensure!(
            alias_ref == &expected_ref,
            "compose x-images entry for {service} must match images.lock {} digest",
            service_selection_slot(selection, service).name(),
        );

        let service_image = &compose
            .services
            .get(service)
            .with_context(|| format!("missing compose service {service}"))?
            .image;
        anyhow::ensure!(
            service_image == &expected_ref,
            "compose service {service} image must match images.lock {} digest",
            service_selection_slot(selection, service).name(),
        );
    }

    Ok(())
}

pub fn validate_honeypot_release_inputs(
    lock_path: &Path,
    manifest_path: &Path,
    compose_path: &Path,
) -> anyhow::Result<()> {
    let lockfile = load_honeypot_images_lock(lock_path)?;
    let manifest = load_honeypot_promotion_manifest(manifest_path)?;
    validate_honeypot_promotion_manifest_binding(&lockfile, &manifest)?;
    let compose_data = std::fs::read_to_string(compose_path)
        .with_context(|| format!("read compose file at {}", compose_path.display()))?;
    validate_honeypot_compose_document(&compose_data, &lockfile)
}

pub fn validate_honeypot_promotion_manifest_binding(
    lockfile: &HoneypotImagesLock,
    manifest: &HoneypotPromotionManifest,
) -> anyhow::Result<()> {
    let actual_services = manifest
        .services
        .iter()
        .map(|record| record.service.clone())
        .collect::<BTreeSet<_>>();
    let expected_services = SERVICE_NAMES
        .into_iter()
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    anyhow::ensure!(
        actual_services == expected_services,
        "promotion-manifest.json must bind current entries for control-plane, proxy, and frontend",
    );

    for service in SERVICE_NAMES {
        let record = manifest
            .services
            .iter()
            .find(|record| record.service == service)
            .with_context(|| format!("missing promotion manifest record for {service}"))?;
        let entry = lockfile.service_entry(service);

        anyhow::ensure!(
            record.registry == entry.registry,
            "promotion-manifest.json {} registry {} does not match images.lock current registry {}",
            service,
            record.registry,
            entry.registry,
        );
        anyhow::ensure!(
            record.image == entry.image,
            "promotion-manifest.json {} image {} does not match images.lock current image {}",
            service,
            record.image,
            entry.image,
        );
        anyhow::ensure!(
            record.tag == entry.current.tag,
            "promotion-manifest.json {} tag {} does not match images.lock current tag {}",
            service,
            record.tag,
            entry.current.tag,
        );
        anyhow::ensure!(
            record.digest == entry.current.digest,
            "promotion-manifest.json {} digest {} does not match images.lock current digest {}",
            service,
            record.digest,
            entry.current.digest,
        );
        anyhow::ensure!(
            record.source_ref == entry.current.source_ref,
            "promotion-manifest.json {} source_ref {} does not match images.lock current source_ref {}",
            service,
            record.source_ref,
            entry.current.source_ref,
        );
    }

    Ok(())
}

pub fn validate_honeypot_dockerfile_packaging_contract() -> anyhow::Result<()> {
    for (path, package_name, binary_name, forbid_webapp_bundle) in [
        (
            HONEYPOT_CONTROL_PLANE_DOCKERFILE_PATH,
            "honeypot-control-plane",
            "honeypot-control-plane",
            false,
        ),
        (
            HONEYPOT_PROXY_DOCKERFILE_PATH,
            "devolutions-gateway",
            "devolutions-gateway",
            true,
        ),
        (
            HONEYPOT_FRONTEND_DOCKERFILE_PATH,
            "honeypot-frontend",
            "honeypot-frontend",
            true,
        ),
    ] {
        let dockerfile_path = repo_relative_path(path);
        let dockerfile = std::fs::read_to_string(&dockerfile_path)
            .with_context(|| format!("read dockerfile at {}", dockerfile_path.display()))?;
        validate_honeypot_service_dockerfile(path, &dockerfile, package_name, binary_name, forbid_webapp_bundle)?;
    }

    Ok(())
}

fn validate_honeypot_service_dockerfile(
    path: &str,
    dockerfile: &str,
    package_name: &str,
    binary_name: &str,
    forbid_webapp_bundle: bool,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        dockerfile.contains(&format!("RUN cargo build --release -p {package_name}")),
        "{path} must build the {package_name} package directly"
    );
    anyhow::ensure!(
        dockerfile.contains(&format!(
            "COPY --from=build /workspace/target/release/{binary_name} /usr/local/bin/{binary_name}"
        )),
        "{path} must copy the {binary_name} binary directly from the workspace build stage"
    );
    anyhow::ensure!(
        dockerfile.contains(&format!("ENTRYPOINT [\"/usr/local/bin/{binary_name}\"]")),
        "{path} must use /usr/local/bin/{binary_name} as its direct entrypoint"
    );
    anyhow::ensure!(
        !dockerfile.contains("package/Linux/Dockerfile"),
        "{path} must not reference the legacy package/Linux/Dockerfile bundle"
    );

    if forbid_webapp_bundle {
        anyhow::ensure!(
            !dockerfile.contains("COPY webapp"),
            "{path} must not copy the legacy webapp bundle into the honeypot image"
        );
        anyhow::ensure!(
            !dockerfile.contains(" webapp"),
            "{path} must not reference the legacy webapp bundle"
        );
    }

    Ok(())
}

pub fn resolve_honeypot_images_for_selection(
    lock_path: &Path,
    selection: ServiceVersionSelection,
) -> anyhow::Result<()> {
    let lockfile = load_honeypot_images_lock(lock_path)?;

    for service in SERVICE_NAMES {
        let slot = service_selection_slot(selection, service);
        let entry = lockfile.service_entry(service);
        let revision = match slot {
            ImageSlot::Current => &entry.current,
            ImageSlot::Previous => &entry.previous,
        };

        ensure_promoted_revision(service, slot.name(), revision)?;
        resolve_image_ref_with_docker(service, &image_ref(entry, slot))?;
    }

    Ok(())
}

pub fn build_honeypot_service_image(service: &'static str, tag: &str) -> anyhow::Result<()> {
    let dockerfile = repo_relative_path(service_dockerfile_path(service));
    let context = repo_relative_path(".");
    let args = vec![
        "build".to_owned(),
        "--file".to_owned(),
        dockerfile.display().to_string(),
        "--tag".to_owned(),
        tag.to_owned(),
        context.display().to_string(),
    ];

    run_docker_command_owned(&args).with_context(|| format!("build {service} image as {tag}"))?;

    Ok(())
}

pub fn create_docker_network(name: &str) -> anyhow::Result<()> {
    let args = vec!["network".to_owned(), "create".to_owned(), name.to_owned()];
    run_docker_command_owned(&args).with_context(|| format!("create docker network {name}"))?;
    Ok(())
}

pub fn remove_docker_network_if_exists(name: &str) -> anyhow::Result<()> {
    if docker_network_exists(name)? {
        let args = vec!["network".to_owned(), "rm".to_owned(), name.to_owned()];
        run_docker_command_owned(&args).with_context(|| format!("remove docker network {name}"))?;
    }

    Ok(())
}

pub fn run_docker_container(args: &[String]) -> anyhow::Result<String> {
    let output = run_docker_command_owned(args)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub fn remove_docker_container_if_exists(name: &str) -> anyhow::Result<()> {
    if docker_container_exists(name)? {
        let args = vec![
            "container".to_owned(),
            "rm".to_owned(),
            "--force".to_owned(),
            name.to_owned(),
        ];
        run_docker_command_owned(&args).with_context(|| format!("remove docker container {name}"))?;
    }

    Ok(())
}

pub fn remove_docker_image_if_exists(tag: &str) -> anyhow::Result<()> {
    if docker_image_exists(tag)? {
        let args = vec![
            "image".to_owned(),
            "rm".to_owned(),
            "--force".to_owned(),
            tag.to_owned(),
        ];
        run_docker_command_owned(&args).with_context(|| format!("remove docker image {tag}"))?;
    }

    Ok(())
}

pub fn docker_logs(name: &str) -> anyhow::Result<String> {
    let args = vec!["logs".to_owned(), name.to_owned()];
    let output = run_docker_command_owned(&args).with_context(|| format!("read docker logs for {name}"))?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();

    Ok(match (stdout.is_empty(), stderr.is_empty()) {
        (false, false) => format!("{stdout}\n{stderr}"),
        (false, true) => stdout,
        (true, false) => stderr,
        (true, true) => String::new(),
    })
}

pub fn run_docker_compose(
    compose_path: &Path,
    project_name: &str,
    args: &[String],
) -> anyhow::Result<std::process::Output> {
    let compose_dir = compose_path
        .parent()
        .with_context(|| format!("compose file {} must have a parent directory", compose_path.display()))?;
    let mut docker_args = vec![
        "compose".to_owned(),
        "--file".to_owned(),
        compose_path.display().to_string(),
        "--project-name".to_owned(),
        project_name.to_owned(),
        "--project-directory".to_owned(),
        compose_dir.display().to_string(),
    ];
    docker_args.extend(args.iter().cloned());

    run_docker_command_owned(&docker_args).with_context(|| {
        format!(
            "run docker compose for project {project_name} with {}",
            compose_path.display()
        )
    })
}

pub fn validate_mixed_version_contract_compatibility(
    selection: ServiceVersionSelection,
    schema_versions: ServiceSchemaVersions,
) -> anyhow::Result<()> {
    ensure_matching_schema_version("frontend", schema_versions.frontend, "proxy", schema_versions.proxy)?;
    ensure_matching_schema_version(
        "proxy",
        schema_versions.proxy,
        "control-plane",
        schema_versions.control_plane,
    )?;

    match selection.frontend {
        ImageSlot::Current => {}
        ImageSlot::Previous => anyhow::ensure!(
            selection.proxy == ImageSlot::Current,
            "frontend previous requires proxy current for bootstrap, event replay, and stream-token compatibility",
        ),
    }

    match selection.proxy {
        ImageSlot::Current => {}
        ImageSlot::Previous => anyhow::ensure!(
            selection.control_plane == ImageSlot::Current,
            "proxy previous requires control-plane current for internal RPC compatibility",
        ),
    }

    Ok(())
}

pub fn validate_restored_service_contract_compatibility(
    selection_before_restore: ServiceVersionSelection,
    restored_service: HoneypotService,
    schema_versions: ServiceSchemaVersions,
) -> anyhow::Result<ServiceVersionSelection> {
    validate_mixed_version_contract_compatibility(selection_before_restore, schema_versions)
        .context("restored-service compatibility requires a supported downgraded starting point")?;

    anyhow::ensure!(
        restored_service.slot(selection_before_restore) == ImageSlot::Previous,
        "{} must be previous before restore validation",
        restored_service.name(),
    );

    let restored_selection = restored_service.with_slot(selection_before_restore, ImageSlot::Current);
    validate_mixed_version_contract_compatibility(restored_selection, schema_versions)
        .context("restored-service compatibility requires a supported restored target state")?;

    Ok(restored_selection)
}

pub fn validate_honeypot_control_plane_runtime_contract(
    compose_path: &Path,
    env_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    let compose_data = std::fs::read_to_string(compose_path)
        .with_context(|| format!("read compose file at {}", compose_path.display()))?;
    validate_honeypot_control_plane_compose_runtime_document(&compose_data)?;

    let env_data =
        std::fs::read_to_string(env_path).with_context(|| format!("read env file at {}", env_path.display()))?;
    validate_honeypot_control_plane_env_document(&env_data)?;

    let config_data =
        std::fs::read_to_string(config_path).with_context(|| format!("read {}", config_path.display()))?;
    anyhow::ensure!(
        config_data.contains("[runtime.qemu]"),
        "control-plane runtime config must pin a [runtime.qemu] table",
    );
    let config =
        ControlPlaneConfig::load_from_path(config_path).with_context(|| format!("load {}", config_path.display()))?;
    validate_honeypot_control_plane_config(&config)
}

pub fn validate_honeypot_proxy_runtime_contract(
    compose_path: &Path,
    env_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    let compose_data = std::fs::read_to_string(compose_path)
        .with_context(|| format!("read compose file at {}", compose_path.display()))?;
    validate_honeypot_proxy_compose_runtime_document(&compose_data)?;

    let env_data =
        std::fs::read_to_string(env_path).with_context(|| format!("read env file at {}", env_path.display()))?;
    validate_honeypot_proxy_env_document(&env_data)?;

    let config_data = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config file at {}", config_path.display()))?;
    validate_honeypot_proxy_config_document(&config_data)
}

pub fn validate_honeypot_frontend_runtime_contract(
    compose_path: &Path,
    env_path: &Path,
    config_path: &Path,
) -> anyhow::Result<()> {
    let compose_data = std::fs::read_to_string(compose_path)
        .with_context(|| format!("read compose file at {}", compose_path.display()))?;
    validate_honeypot_frontend_compose_runtime_document(&compose_data)?;

    let env_data =
        std::fs::read_to_string(env_path).with_context(|| format!("read env file at {}", env_path.display()))?;
    validate_honeypot_frontend_env_document(&env_data)?;

    let config_data = std::fs::read_to_string(config_path)
        .with_context(|| format!("read config file at {}", config_path.display()))?;
    validate_honeypot_frontend_config_document(&config_data)
}

pub fn validate_honeypot_control_plane_compose_runtime_document(data: &str) -> anyhow::Result<()> {
    let compose: HoneypotComposeFile = serde_yaml::from_str(data).context("deserialize honeypot compose file")?;
    let service = compose
        .services
        .get("control-plane")
        .context("missing compose service control-plane")?;
    let env_file = service
        .env_file
        .as_ref()
        .context("compose service control-plane must define env_file")?;

    anyhow::ensure!(
        env_file.contains(CONTROL_PLANE_ENV_FILE_REF),
        "compose service control-plane must reference {CONTROL_PLANE_ENV_FILE_REF}",
    );
    anyhow::ensure!(
        service
            .volumes
            .iter()
            .any(|volume| volume == CONTROL_PLANE_CONFIG_MOUNT),
        "compose service control-plane must mount {CONTROL_PLANE_CONFIG_MOUNT}",
    );
    anyhow::ensure!(
        service
            .volumes
            .iter()
            .any(|volume| volume == CONTROL_PLANE_SECRET_MOUNT),
        "compose service control-plane must keep the secret mount separate at {CONTROL_PLANE_SECRET_MOUNT}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == CONTROL_PLANE_QMP_MOUNT),
        "compose service control-plane must mount {CONTROL_PLANE_QMP_MOUNT}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == CONTROL_PLANE_QGA_MOUNT),
        "compose service control-plane must mount {CONTROL_PLANE_QGA_MOUNT}",
    );
    anyhow::ensure!(
        service.networks == [CONTROL_PLANE_NETWORK],
        "compose service control-plane must stay only on the {CONTROL_PLANE_NETWORK} network",
    );
    if let Some(healthcheck) = service.healthcheck.as_ref() {
        anyhow::ensure!(
            healthcheck.contains_fragment("/api/v1/health"),
            "compose service control-plane healthcheck must probe /api/v1/health",
        );
        anyhow::ensure!(
            healthcheck.contains_fragment("Authorization: Bearer"),
            "compose service control-plane healthcheck must send an internal bearer token",
        );
    }
    anyhow::ensure!(
        service.ports.is_empty(),
        "compose service control-plane must not publish host ports",
    );
    ensure_service_omits_control_socket_mounts(
        "proxy",
        compose.services.get("proxy").context("missing compose service proxy")?,
    )?;
    ensure_service_omits_control_socket_mounts(
        "frontend",
        compose
            .services
            .get("frontend")
            .context("missing compose service frontend")?,
    )?;

    Ok(())
}

pub fn validate_honeypot_control_plane_env_document(data: &str) -> anyhow::Result<()> {
    let env = parse_env_document(data)?;
    let config_path = env
        .get(CONTROL_PLANE_CONFIG_ENV)
        .with_context(|| format!("env file must define {CONTROL_PLANE_CONFIG_ENV}"))?;

    anyhow::ensure!(
        config_path == DEFAULT_CONTROL_PLANE_CONFIG_PATH,
        "{CONTROL_PLANE_CONFIG_ENV} must be {DEFAULT_CONTROL_PLANE_CONFIG_PATH}",
    );

    Ok(())
}

pub fn validate_honeypot_proxy_compose_runtime_document(data: &str) -> anyhow::Result<()> {
    let compose: HoneypotComposeFile = serde_yaml::from_str(data).context("deserialize honeypot compose file")?;
    let service = compose.services.get("proxy").context("missing compose service proxy")?;
    let env_file = service
        .env_file
        .as_ref()
        .context("compose service proxy must define env_file")?;

    anyhow::ensure!(
        env_file.contains(PROXY_ENV_FILE_REF),
        "compose service proxy must reference {PROXY_ENV_FILE_REF}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == PROXY_CONFIG_MOUNT),
        "compose service proxy must mount {PROXY_CONFIG_MOUNT}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == PROXY_SECRET_MOUNT),
        "compose service proxy must keep the secret mount separate at {PROXY_SECRET_MOUNT}",
    );
    if let Some(healthcheck) = service.healthcheck.as_ref() {
        anyhow::ensure!(
            healthcheck.contains_fragment("/jet/health"),
            "compose service proxy healthcheck must probe /jet/health",
        );
    }
    ensure_service_omits_control_socket_mounts("proxy", service)?;

    Ok(())
}

pub fn validate_honeypot_proxy_env_document(data: &str) -> anyhow::Result<()> {
    let env = parse_env_document(data)?;
    let config_dir = env
        .get("DGATEWAY_CONFIG_PATH")
        .context("env file must define DGATEWAY_CONFIG_PATH")?;

    anyhow::ensure!(
        config_dir == PROXY_CONFIG_DIR,
        "DGATEWAY_CONFIG_PATH must be {PROXY_CONFIG_DIR}",
    );

    Ok(())
}

pub fn validate_honeypot_frontend_compose_runtime_document(data: &str) -> anyhow::Result<()> {
    let compose: HoneypotComposeFile = serde_yaml::from_str(data).context("deserialize honeypot compose file")?;
    let service = compose
        .services
        .get("frontend")
        .context("missing compose service frontend")?;
    let env_file = service
        .env_file
        .as_ref()
        .context("compose service frontend must define env_file")?;

    anyhow::ensure!(
        env_file.contains(FRONTEND_ENV_FILE_REF),
        "compose service frontend must reference {FRONTEND_ENV_FILE_REF}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == FRONTEND_CONFIG_MOUNT),
        "compose service frontend must mount {FRONTEND_CONFIG_MOUNT}",
    );
    anyhow::ensure!(
        service.volumes.iter().any(|volume| volume == FRONTEND_SECRET_MOUNT),
        "compose service frontend must keep the secret mount separate at {FRONTEND_SECRET_MOUNT}",
    );
    if let Some(healthcheck) = service.healthcheck.as_ref() {
        anyhow::ensure!(
            healthcheck.contains_fragment("/health"),
            "compose service frontend healthcheck must probe /health",
        );
    }
    ensure_service_omits_control_socket_mounts("frontend", service)?;

    Ok(())
}

pub fn validate_honeypot_frontend_env_document(data: &str) -> anyhow::Result<()> {
    let env = parse_env_document(data)?;
    let config_path = env
        .get(FRONTEND_CONFIG_ENV)
        .with_context(|| format!("env file must define {FRONTEND_CONFIG_ENV}"))?;

    anyhow::ensure!(
        config_path == DEFAULT_FRONTEND_CONFIG_PATH,
        "{FRONTEND_CONFIG_ENV} must be {DEFAULT_FRONTEND_CONFIG_PATH}",
    );

    Ok(())
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

fn validate_promotion_service_record(record: &HoneypotPromotionServiceRecord) -> anyhow::Result<()> {
    let expected_image = canonical_image_name(&record.service);
    anyhow::ensure!(
        record.registry == CANONICAL_REGISTRY,
        "promotion-manifest.json {} registry must be {CANONICAL_REGISTRY}",
        record.service,
    );
    anyhow::ensure!(
        record.image == expected_image,
        "promotion-manifest.json {} image must be {expected_image}",
        record.service,
    );
    validate_tag(&record.service, "manifest", &record.tag)?;
    validate_digest(&record.service, "manifest", &record.digest)?;
    anyhow::ensure!(
        !record.source_ref.trim().is_empty(),
        "promotion-manifest.json {} source_ref must not be empty",
        record.service,
    );
    Ok(())
}

fn ensure_matching_schema_version(
    left_service: &str,
    left_version: u32,
    right_service: &str,
    right_version: u32,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        left_version == right_version,
        "{left_service} schema_version {left_version} is incompatible with {right_service} schema_version {right_version}",
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

fn ensure_promoted_revision(service: &str, slot: &str, revision: &HoneypotImageRevision) -> anyhow::Result<()> {
    anyhow::ensure!(
        !revision.tag.contains("placeholder"),
        "{service} {slot}.tag still uses placeholder value {}; promote a real image before host-smoke resolution",
        revision.tag,
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

fn image_ref(entry: &HoneypotImageLockEntry, slot: ImageSlot) -> String {
    let digest = match slot {
        ImageSlot::Current => &entry.current.digest,
        ImageSlot::Previous => &entry.previous.digest,
    };

    format!(
        "{}/{image}@{digest}",
        entry.registry,
        image = entry.image,
        digest = digest
    )
}

fn resolve_image_ref_with_docker(service: &str, image_ref: &str) -> anyhow::Result<()> {
    if run_docker_command(&["image", "inspect", image_ref]).is_ok() {
        return Ok(());
    }

    run_docker_command(&["manifest", "inspect", image_ref])
        .with_context(|| format!("resolve {service} image by pinned digest {image_ref}"))?;

    Ok(())
}

fn run_docker_command(args: &[&str]) -> anyhow::Result<()> {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    run_docker_command_owned(&args).map(|_| ())
}

fn run_docker_command_owned(args: &[String]) -> anyhow::Result<std::process::Output> {
    let output = Command::new("docker")
        .args(args)
        .output()
        .with_context(|| format!("run docker {}", args.join(" ")))?;

    if output.status.success() {
        return Ok(output);
    }

    Err(format_docker_error(args, &output))
}

fn format_docker_error(args: &[String], output: &std::process::Output) -> anyhow::Error {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let detail = if !stderr.is_empty() {
        stderr
    } else if !stdout.is_empty() {
        stdout
    } else {
        format!("exit status {}", output.status)
    };

    anyhow::anyhow!("docker {} failed: {detail}", args.join(" "))
}

fn docker_container_exists(name: &str) -> anyhow::Result<bool> {
    Ok(Command::new("docker")
        .args(["container", "inspect", name])
        .output()
        .with_context(|| format!("inspect docker container {name}"))?
        .status
        .success())
}

fn docker_network_exists(name: &str) -> anyhow::Result<bool> {
    Ok(Command::new("docker")
        .args(["network", "inspect", name])
        .output()
        .with_context(|| format!("inspect docker network {name}"))?
        .status
        .success())
}

fn docker_image_exists(tag: &str) -> anyhow::Result<bool> {
    Ok(Command::new("docker")
        .args(["image", "inspect", tag])
        .output()
        .with_context(|| format!("inspect docker image {tag}"))?
        .status
        .success())
}

fn service_dockerfile_path(service: &str) -> &'static str {
    match service {
        "control-plane" => HONEYPOT_CONTROL_PLANE_DOCKERFILE_PATH,
        "proxy" => HONEYPOT_PROXY_DOCKERFILE_PATH,
        "frontend" => HONEYPOT_FRONTEND_DOCKERFILE_PATH,
        _ => panic!("unsupported service name: {service}"),
    }
}

impl HoneypotService {
    fn name(self) -> &'static str {
        match self {
            Self::ControlPlane => "control-plane",
            Self::Proxy => "proxy",
            Self::Frontend => "frontend",
        }
    }

    fn slot(self, selection: ServiceVersionSelection) -> ImageSlot {
        match self {
            Self::ControlPlane => selection.control_plane,
            Self::Proxy => selection.proxy,
            Self::Frontend => selection.frontend,
        }
    }

    fn with_slot(self, selection: ServiceVersionSelection, slot: ImageSlot) -> ServiceVersionSelection {
        match self {
            Self::ControlPlane => ServiceVersionSelection {
                control_plane: slot,
                ..selection
            },
            Self::Proxy => ServiceVersionSelection {
                proxy: slot,
                ..selection
            },
            Self::Frontend => ServiceVersionSelection {
                frontend: slot,
                ..selection
            },
        }
    }
}

impl ImageSlot {
    fn name(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::Previous => "previous",
        }
    }
}

fn service_selection_slot(selection: ServiceVersionSelection, service: &str) -> ImageSlot {
    match service {
        "control-plane" => selection.control_plane,
        "proxy" => selection.proxy,
        "frontend" => selection.frontend,
        _ => panic!("unsupported service name: {service}"),
    }
}

fn canonical_image_name(service: &str) -> String {
    format!("{CANONICAL_IMAGE_ROOT}/{service}")
}

fn ensure_service_omits_control_socket_mounts(
    service_name: &str,
    service: &HoneypotComposeService,
) -> anyhow::Result<()> {
    for socket_dir in [CONTROL_PLANE_QMP_DIR, CONTROL_PLANE_QGA_DIR] {
        anyhow::ensure!(
            !service
                .volumes
                .iter()
                .any(|volume| volume_target_path(volume) == Some(socket_dir)),
            "compose service {service_name} must not mount control socket path {socket_dir}",
        );
    }

    Ok(())
}

fn volume_target_path(volume: &str) -> Option<&str> {
    volume.split(':').nth(1)
}

fn validate_honeypot_control_plane_config(config: &ControlPlaneConfig) -> anyhow::Result<()> {
    anyhow::ensure!(
        config.http.bind_addr == CONTROL_PLANE_BIND_ADDR.parse::<SocketAddr>().expect("valid bind addr"),
        "control-plane bind_addr must be {CONTROL_PLANE_BIND_ADDR}",
    );
    anyhow::ensure!(
        config.paths.data_dir == Path::new(CONTROL_PLANE_DATA_DIR),
        "control-plane data_dir must be {CONTROL_PLANE_DATA_DIR}",
    );
    anyhow::ensure!(
        config.paths.image_store == Path::new(CONTROL_PLANE_IMAGE_STORE),
        "control-plane image_store must be {CONTROL_PLANE_IMAGE_STORE}",
    );
    anyhow::ensure!(
        config.paths.lease_store == Path::new(CONTROL_PLANE_LEASE_STORE),
        "control-plane lease_store must be {CONTROL_PLANE_LEASE_STORE}",
    );
    anyhow::ensure!(
        config.paths.quarantine_store == Path::new(CONTROL_PLANE_QUARANTINE_STORE),
        "control-plane quarantine_store must be {CONTROL_PLANE_QUARANTINE_STORE}",
    );
    anyhow::ensure!(
        config.paths.qmp_dir == Path::new(CONTROL_PLANE_QMP_DIR),
        "control-plane qmp_dir must be {CONTROL_PLANE_QMP_DIR}",
    );
    anyhow::ensure!(
        config.paths.qga_dir.as_deref() == Some(Path::new(CONTROL_PLANE_QGA_DIR)),
        "control-plane qga_dir must be {CONTROL_PLANE_QGA_DIR}",
    );
    anyhow::ensure!(
        config.paths.secret_dir == Path::new(CONTROL_PLANE_SECRET_DIR),
        "control-plane secret_dir must be {CONTROL_PLANE_SECRET_DIR}",
    );
    anyhow::ensure!(
        config.paths.kvm_path == Path::new(CONTROL_PLANE_KVM_PATH),
        "control-plane kvm_path must be {CONTROL_PLANE_KVM_PATH}",
    );
    anyhow::ensure!(
        config.runtime.qemu.binary_path == Path::new(CONTROL_PLANE_QEMU_BINARY_PATH),
        "control-plane qemu binary_path must be {CONTROL_PLANE_QEMU_BINARY_PATH}",
    );
    anyhow::ensure!(
        matches!(
            config.runtime.lifecycle_driver,
            honeypot_control_plane::config::VmLifecycleDriver::Process
        ),
        "control-plane lifecycle_driver must be {CONTROL_PLANE_LIFECYCLE_DRIVER}",
    );
    anyhow::ensure!(
        config.runtime.stop_timeout_secs == CONTROL_PLANE_STOP_TIMEOUT_SECS,
        "control-plane stop_timeout_secs must be {CONTROL_PLANE_STOP_TIMEOUT_SECS}",
    );
    anyhow::ensure!(
        config.runtime.qemu.machine_type == CONTROL_PLANE_QEMU_MACHINE_TYPE,
        "control-plane qemu machine_type must be {CONTROL_PLANE_QEMU_MACHINE_TYPE}",
    );
    anyhow::ensure!(
        config.runtime.qemu.cpu_model == CONTROL_PLANE_QEMU_CPU_MODEL,
        "control-plane qemu cpu_model must be {CONTROL_PLANE_QEMU_CPU_MODEL}",
    );
    anyhow::ensure!(
        config.runtime.qemu.vcpu_count == CONTROL_PLANE_QEMU_VCPU_COUNT,
        "control-plane qemu vcpu_count must be {CONTROL_PLANE_QEMU_VCPU_COUNT}",
    );
    anyhow::ensure!(
        config.runtime.qemu.memory_mib == CONTROL_PLANE_QEMU_MEMORY_MIB,
        "control-plane qemu memory_mib must be {CONTROL_PLANE_QEMU_MEMORY_MIB}",
    );
    anyhow::ensure!(
        config.runtime.qemu.network.netdev_id == CONTROL_PLANE_QEMU_NETDEV_ID,
        "control-plane qemu network.netdev_id must be {CONTROL_PLANE_QEMU_NETDEV_ID}",
    );
    anyhow::ensure!(
        config.runtime.qemu.network.host_loopback_addr == IpAddr::V4(Ipv4Addr::LOCALHOST),
        "control-plane qemu host_loopback_addr must stay on 127.0.0.1",
    );
    anyhow::ensure!(
        config.runtime.qemu.accelerator.as_qemu_value() == "kvm",
        "control-plane qemu accelerator must stay on kvm",
    );
    anyhow::ensure!(
        config.runtime.qemu.disk_interface.as_qemu_device() == "virtio-blk-pci",
        "control-plane qemu disk_interface must stay on virtio-blk-pci",
    );
    anyhow::ensure!(
        config.runtime.qemu.network.mode.as_qemu_value() == "user",
        "control-plane qemu network mode must stay on user",
    );
    anyhow::ensure!(
        config.runtime.qemu.network.device_model.as_qemu_device() == "virtio-net-pci",
        "control-plane qemu network device_model must stay on virtio-net-pci",
    );
    anyhow::ensure!(
        config.auth.proxy_verifier_public_key_pem.is_none(),
        "control-plane runtime sample config must not check in an inline proxy verifier public key",
    );
    anyhow::ensure!(
        config.auth.proxy_verifier_public_key_pem_file.as_deref()
            == Some(Path::new(CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE)),
        "control-plane proxy verifier public key file must be {CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE}",
    );
    anyhow::ensure!(
        matches!(
            config.backend_credentials.adapter,
            honeypot_control_plane::config::BackendCredentialStoreAdapter::File
        ),
        "control-plane backend credential adapter must stay on file",
    );
    anyhow::ensure!(
        config.backend_credentials.file_path(&config.paths) == Path::new(CONTROL_PLANE_BACKEND_CREDENTIALS_FILE),
        "control-plane backend credential file must be {CONTROL_PLANE_BACKEND_CREDENTIALS_FILE}",
    );

    Ok(())
}

fn validate_honeypot_proxy_config_document(data: &str) -> anyhow::Result<()> {
    let conf_file =
        serde_json::from_str::<gateway_dto::ConfFile>(data).context("deserialize proxy gateway.json config")?;
    let conf = GatewayConf::from_conf_file(&conf_file).context("build proxy runtime config from gateway.json")?;

    anyhow::ensure!(conf.honeypot.enabled, "proxy honeypot mode must be enabled");
    anyhow::ensure!(
        conf.listeners.iter().any(|listener| {
            listener.internal_url.scheme() == "http"
                && listener.internal_url.host_str() == Some("0.0.0.0")
                && listener.internal_url.port_or_known_default() == Some(8080)
        }),
        "proxy config must include HTTP listener {PROXY_HTTP_LISTENER}",
    );
    anyhow::ensure!(
        conf.listeners.iter().any(|listener| {
            listener.internal_url.scheme() == "tcp"
                && listener.internal_url.host_str() == Some("0.0.0.0")
                && listener.internal_url.port() == Some(8443)
        }),
        "proxy config must include TCP listener {PROXY_TCP_LISTENER}",
    );
    anyhow::ensure!(
        conf.honeypot.control_plane.endpoint.as_ref().map(|url| url.as_str()) == Some(PROXY_CONTROL_PLANE_ENDPOINT),
        "proxy honeypot control-plane endpoint must be {PROXY_CONTROL_PLANE_ENDPOINT}",
    );
    anyhow::ensure!(
        conf.honeypot.control_plane.service_bearer_token.is_none(),
        "proxy runtime sample config must not check in an inline control-plane service token",
    );
    anyhow::ensure!(
        conf.honeypot.control_plane.service_bearer_token_file.as_deref()
            == Some(Path::new(PROXY_CONTROL_PLANE_TOKEN_FILE)),
        "proxy honeypot control-plane token file must be {PROXY_CONTROL_PLANE_TOKEN_FILE}",
    );
    anyhow::ensure!(
        conf.honeypot.frontend.public_url.as_ref().map(|url| url.as_str()) == Some(PROXY_FRONTEND_PUBLIC_URL),
        "proxy frontend public url must be {PROXY_FRONTEND_PUBLIC_URL}",
    );
    anyhow::ensure!(
        conf.honeypot.frontend.bootstrap_path == "/jet/honeypot/bootstrap",
        "proxy frontend bootstrap path must be /jet/honeypot/bootstrap",
    );
    anyhow::ensure!(
        conf.honeypot.frontend.events_path == "/jet/honeypot/events",
        "proxy frontend events path must be /jet/honeypot/events",
    );

    Ok(())
}

fn validate_honeypot_frontend_config_document(data: &str) -> anyhow::Result<()> {
    let config: FrontendConfig = toml::from_str(data).context("deserialize frontend config.toml")?;

    anyhow::ensure!(
        config.http.bind_addr
            == FRONTEND_BIND_ADDR
                .parse::<SocketAddr>()
                .expect("valid frontend bind addr"),
        "frontend bind_addr must be {FRONTEND_BIND_ADDR}",
    );
    anyhow::ensure!(
        config.proxy.base_url.as_str() == FRONTEND_PROXY_BASE_URL,
        "frontend proxy base_url must be {FRONTEND_PROXY_BASE_URL}",
    );
    anyhow::ensure!(
        config.proxy.bootstrap_path == FRONTEND_BOOTSTRAP_PATH,
        "frontend bootstrap_path must be {FRONTEND_BOOTSTRAP_PATH}",
    );
    anyhow::ensure!(
        config.proxy.events_path == FRONTEND_EVENTS_PATH,
        "frontend events_path must be {FRONTEND_EVENTS_PATH}",
    );
    anyhow::ensure!(
        config.proxy.stream_token_path_template == FRONTEND_STREAM_TOKEN_PATH_TEMPLATE,
        "frontend stream_token_path_template must be {FRONTEND_STREAM_TOKEN_PATH_TEMPLATE}",
    );
    anyhow::ensure!(
        config.proxy.terminate_path_template == FRONTEND_TERMINATE_PATH_TEMPLATE,
        "frontend terminate_path_template must be {FRONTEND_TERMINATE_PATH_TEMPLATE}",
    );
    anyhow::ensure!(
        config.proxy.system_terminate_path == FRONTEND_SYSTEM_TERMINATE_PATH,
        "frontend system_terminate_path must be {FRONTEND_SYSTEM_TERMINATE_PATH}",
    );
    anyhow::ensure!(
        config.auth.proxy_bearer_token.is_none(),
        "frontend proxy_bearer_token must not be checked into the runtime sample config",
    );
    anyhow::ensure!(
        config.auth.operator_token_validation_disabled,
        "frontend runtime sample config must keep operator_token_validation_disabled enabled",
    );
    anyhow::ensure!(
        config.auth.operator_verifier_public_key_pem.is_none(),
        "frontend runtime sample config must not check in operator_verifier_public_key_pem",
    );
    anyhow::ensure!(
        config.ui.title == FRONTEND_TITLE,
        "frontend ui.title must be {FRONTEND_TITLE}",
    );

    Ok(())
}

fn parse_env_document(data: &str) -> anyhow::Result<BTreeMap<String, String>> {
    let mut entries = BTreeMap::new();

    for (index, raw_line) in data.lines().enumerate() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }

        let (key, value) = line
            .split_once('=')
            .with_context(|| format!("env line {} must contain KEY=VALUE", index + 1))?;
        let key = key.trim();
        let value = value.trim();

        anyhow::ensure!(!key.is_empty(), "env line {} must not use an empty key", index + 1);
        anyhow::ensure!(
            entries.insert(key.to_owned(), value.to_owned()).is_none(),
            "env key {key} must not be repeated",
        );
    }

    Ok(entries)
}
