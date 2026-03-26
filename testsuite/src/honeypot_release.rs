use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::Context as _;
use devolutions_gateway::config::{Conf as GatewayConf, dto as gateway_dto};
use honeypot_control_plane::config::{CONTROL_PLANE_CONFIG_ENV, ControlPlaneConfig, DEFAULT_CONTROL_PLANE_CONFIG_PATH};
use honeypot_frontend::config::{DEFAULT_FRONTEND_CONFIG_PATH, FrontendConfig};
use serde::Deserialize;

pub const HONEYPOT_IMAGES_LOCK_PATH: &str = "honeypot/docker/images.lock";
pub const HONEYPOT_COMPOSE_PATH: &str = "honeypot/docker/compose.yaml";
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
const CONTROL_PLANE_BIND_ADDR: &str = "0.0.0.0:8080";
const CONTROL_PLANE_DATA_DIR: &str = "/var/lib/honeypot/control-plane";
const CONTROL_PLANE_IMAGE_STORE: &str = "/var/lib/honeypot/images";
const CONTROL_PLANE_LEASE_STORE: &str = "/var/lib/honeypot/leases";
const CONTROL_PLANE_QUARANTINE_STORE: &str = "/var/lib/honeypot/quarantine";
const CONTROL_PLANE_QMP_DIR: &str = "/run/honeypot/qmp";
const CONTROL_PLANE_QGA_DIR: &str = "/run/honeypot/qga";
const CONTROL_PLANE_SECRET_DIR: &str = "/run/secrets/honeypot/control-plane";
const CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE: &str =
    "/run/secrets/honeypot/control-plane/proxy-verifier-public-key.pem";
const CONTROL_PLANE_KVM_PATH: &str = "/dev/kvm";
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
        config.auth.proxy_verifier_public_key_pem.is_none(),
        "control-plane runtime sample config must not check in an inline proxy verifier public key",
    );
    anyhow::ensure!(
        config.auth.proxy_verifier_public_key_pem_file.as_deref()
            == Some(Path::new(CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE)),
        "control-plane proxy verifier public key file must be {CONTROL_PLANE_PROXY_VERIFIER_PUBLIC_KEY_FILE}",
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
