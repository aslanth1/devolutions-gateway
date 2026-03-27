use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use anyhow::Context as _;
use base64::prelude::*;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use testsuite::honeypot_control_plane::{HoneypotControlPlaneTestConfig, write_honeypot_control_plane_config};
use testsuite::honeypot_frontend::{HoneypotFrontendTestConfig, write_honeypot_frontend_config};
use testsuite::honeypot_release::{
    HONEYPOT_COMPOSE_PATH, HONEYPOT_CONTROL_PLANE_CONFIG_PATH, HONEYPOT_CONTROL_PLANE_ENV_PATH,
    HONEYPOT_FRONTEND_CONFIG_PATH, HONEYPOT_FRONTEND_ENV_PATH, HONEYPOT_IMAGES_LOCK_PATH, HONEYPOT_PROXY_CONFIG_PATH,
    HONEYPOT_PROXY_ENV_PATH, HoneypotImagesLock, HoneypotService, ImageSlot, ServiceSchemaVersions,
    ServiceVersionSelection, build_honeypot_service_image, create_docker_network, docker_logs,
    load_honeypot_images_lock, remove_docker_container_if_exists, remove_docker_image_if_exists,
    remove_docker_network_if_exists, repo_relative_path, resolve_honeypot_images_for_selection, run_docker_compose,
    run_docker_container, validate_honeypot_compose_document, validate_honeypot_compose_document_for_selection,
    validate_honeypot_control_plane_compose_runtime_document, validate_honeypot_control_plane_env_document,
    validate_honeypot_control_plane_runtime_contract, validate_honeypot_frontend_compose_runtime_document,
    validate_honeypot_frontend_env_document, validate_honeypot_frontend_runtime_contract,
    validate_honeypot_images_lock_document, validate_honeypot_proxy_compose_runtime_document,
    validate_honeypot_proxy_env_document, validate_honeypot_proxy_runtime_contract, validate_honeypot_release_inputs,
    validate_mixed_version_contract_compatibility, validate_restored_service_contract_compatibility,
};
use testsuite::honeypot_tiers::{HoneypotTestTier, require_honeypot_tier};
use tokio::time::{Instant, sleep};
use uuid::Uuid;

const DOCKER_SMOKE_TIMEOUT: Duration = Duration::from_secs(240);
const DOCKER_SMOKE_POLL_INTERVAL: Duration = Duration::from_millis(500);

fn expected_image_ref(lockfile: &HoneypotImagesLock, service: &'static str, slot: ImageSlot) -> String {
    let entry = lockfile.service_entry(service);
    let digest = match slot {
        ImageSlot::Current => &entry.current.digest,
        ImageSlot::Previous => &entry.previous.digest,
    };

    format!("{}/{}@{}", entry.registry, entry.image, digest)
}

fn compose_document_for_selection(lockfile: &HoneypotImagesLock, selection: ServiceVersionSelection) -> String {
    let mut compose_data =
        std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose file");

    for (service, slot) in [
        ("control-plane", selection.control_plane),
        ("proxy", selection.proxy),
        ("frontend", selection.frontend),
    ] {
        let current_ref = expected_image_ref(lockfile, service, ImageSlot::Current);
        let selected_ref = expected_image_ref(lockfile, service, slot);
        compose_data = compose_data.replace(&current_ref, &selected_ref);
    }

    compose_data
}

fn rewrite_compose_image_ref(
    compose_data: &str,
    service: &'static str,
    new_ref: &str,
    update_alias: bool,
    update_service: bool,
) -> String {
    let mut document: serde_yaml::Value = serde_yaml::from_str(compose_data).expect("parse compose document");

    if update_alias {
        let root = document.as_mapping_mut().expect("compose root must be a mapping");
        let x_images_key = serde_yaml::Value::String("x-images".to_owned());
        let service_key = serde_yaml::Value::String(service.to_owned());
        let image_aliases = root
            .get_mut(&x_images_key)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("compose x-images must be a mapping");
        image_aliases.insert(service_key, serde_yaml::Value::String(new_ref.to_owned()));
    }

    if update_service {
        let root = document.as_mapping_mut().expect("compose root must be a mapping");
        let services_key = serde_yaml::Value::String("services".to_owned());
        let service_name_key = serde_yaml::Value::String(service.to_owned());
        let image_key = serde_yaml::Value::String("image".to_owned());
        let services = root
            .get_mut(&services_key)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("compose services must be a mapping");
        let service_entry = services
            .get_mut(&service_name_key)
            .and_then(serde_yaml::Value::as_mapping_mut)
            .expect("compose service entry must be a mapping");
        service_entry.insert(image_key, serde_yaml::Value::String(new_ref.to_owned()));
    }

    serde_yaml::to_string(&document).expect("serialize compose document")
}

fn honeypot_scope_token(scope: &str) -> String {
    let header = BASE64_URL_SAFE_NO_PAD.encode(r#"{"typ":"JWT","alg":"RS256"}"#);
    let payload = BASE64_URL_SAFE_NO_PAD.encode(format!(
        r#"{{"type":"scope","jti":"00000000-0000-0000-0000-000000000099","iat":1733669999,"exp":3331553599,"nbf":1733669999,"scope":"{scope}"}}"#
    ));

    format!("{header}.{payload}.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ")
}

struct DockerSmokeFixture {
    _root: tempfile::TempDir,
    control_plane_config_path: PathBuf,
    control_plane_secret_dir: PathBuf,
    control_plane_data_dir: PathBuf,
    control_plane_image_store_dir: PathBuf,
    control_plane_lease_store_dir: PathBuf,
    control_plane_quarantine_store_dir: PathBuf,
    control_plane_qmp_dir: PathBuf,
    control_plane_qga_dir: PathBuf,
    control_plane_kvm_path: PathBuf,
    proxy_config_dir: PathBuf,
    proxy_secret_dir: PathBuf,
    frontend_config_path: PathBuf,
}

impl DockerSmokeFixture {
    fn create() -> anyhow::Result<Self> {
        let root = tempfile::tempdir().context("create docker smoke fixture root")?;

        let control_plane_root = root.path().join("control-plane");
        let control_plane_config_path = control_plane_root.join("config.toml");
        let control_plane_secret_dir = control_plane_root.join("secrets");
        let control_plane_data_dir = control_plane_root.join("data");
        let control_plane_image_store_dir = control_plane_root.join("images");
        let control_plane_lease_store_dir = control_plane_root.join("leases");
        let control_plane_quarantine_store_dir = control_plane_root.join("quarantine");
        let control_plane_qmp_dir = control_plane_root.join("qmp");
        let control_plane_qga_dir = control_plane_root.join("qga");
        let control_plane_kvm_path = control_plane_root.join("kvm");

        for dir in [
            &control_plane_secret_dir,
            &control_plane_data_dir,
            &control_plane_image_store_dir,
            &control_plane_lease_store_dir,
            &control_plane_quarantine_store_dir,
            &control_plane_qmp_dir,
            &control_plane_qga_dir,
        ] {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }
        std::fs::write(control_plane_kvm_path.as_path(), b"host-safe-kvm-placeholder")
            .with_context(|| format!("write {}", control_plane_kvm_path.display()))?;
        std::fs::write(control_plane_secret_dir.join("backend-credentials.json"), "{}")
            .context("write control-plane backend credentials fixture")?;
        write_trusted_image_fixture(&control_plane_image_store_dir)?;

        write_honeypot_control_plane_config(
            &control_plane_config_path,
            &HoneypotControlPlaneTestConfig::builder()
                .bind_addr("0.0.0.0:8080")
                .service_token_validation_disabled(true)
                .backend_credentials_file_path("/run/secrets/honeypot/control-plane/backend-credentials.json")
                .data_dir("/var/lib/honeypot/control-plane")
                .image_store("/var/lib/honeypot/images")
                .manifest_dir("/var/lib/honeypot/images/manifests")
                .lease_store("/var/lib/honeypot/leases")
                .quarantine_store("/var/lib/honeypot/quarantine")
                .qmp_dir("/run/honeypot/qmp")
                .qga_dir(PathBuf::from("/run/honeypot/qga"))
                .secret_dir("/run/secrets/honeypot/control-plane")
                .kvm_path("/dev/kvm")
                .enable_guest_agent(true)
                .lifecycle_driver("process")
                .stop_timeout_secs(5)
                .qemu_binary_path("/usr/bin/qemu-system-x86_64")
                .qemu_machine_type("q35")
                .qemu_cpu_model("host")
                .qemu_vcpu_count(4)
                .qemu_memory_mib(8192)
                .qemu_netdev_id("net0")
                .build(),
        )
        .context("write control-plane docker smoke config")?;

        let proxy_config_dir = root.path().join("proxy-config");
        let proxy_secret_dir = root.path().join("proxy-secrets");
        std::fs::create_dir_all(&proxy_config_dir).with_context(|| format!("create {}", proxy_config_dir.display()))?;
        std::fs::create_dir_all(&proxy_secret_dir).with_context(|| format!("create {}", proxy_secret_dir.display()))?;
        write_proxy_smoke_config(&proxy_config_dir)?;
        std::fs::write(
            proxy_secret_dir.join("control-plane-service-token"),
            format!("{}\n", honeypot_scope_token("gateway.honeypot.control-plane")),
        )
        .context("write proxy control-plane service token fixture")?;
        std::fs::write(proxy_secret_dir.join("backend-credentials.json"), "{}")
            .context("write proxy backend credentials fixture")?;

        let frontend_config_path = root.path().join("frontend.toml");
        write_honeypot_frontend_config(
            &frontend_config_path,
            &HoneypotFrontendTestConfig::builder()
                .bind_addr("0.0.0.0:8080")
                .proxy_base_url("http://proxy:8080/")
                .proxy_bearer_token(Some(honeypot_scope_token("gateway.honeypot.watch")))
                .operator_token_validation_disabled(true)
                .title("Observation Deck")
                .build(),
        )
        .context("write frontend docker smoke config")?;

        Ok(Self {
            _root: root,
            control_plane_config_path,
            control_plane_secret_dir,
            control_plane_data_dir,
            control_plane_image_store_dir,
            control_plane_lease_store_dir,
            control_plane_quarantine_store_dir,
            control_plane_qmp_dir,
            control_plane_qga_dir,
            control_plane_kvm_path,
            proxy_config_dir,
            proxy_secret_dir,
            frontend_config_path,
        })
    }
}

struct DockerSmokeResources {
    network_name: String,
    control_plane_container: String,
    proxy_container: String,
    frontend_container: String,
    control_plane_image: String,
    proxy_image: String,
    frontend_image: String,
}

impl DockerSmokeResources {
    fn new() -> Self {
        let suffix = Uuid::new_v4().simple().to_string();
        Self {
            network_name: format!("dgw-honeypot-smoke-{suffix}"),
            control_plane_container: format!("dgw-honeypot-control-plane-smoke-{suffix}"),
            proxy_container: format!("dgw-honeypot-proxy-smoke-{suffix}"),
            frontend_container: format!("dgw-honeypot-frontend-smoke-{suffix}"),
            control_plane_image: format!("dgw-honeypot-control-plane:smoke-{suffix}"),
            proxy_image: format!("dgw-honeypot-proxy:smoke-{suffix}"),
            frontend_image: format!("dgw-honeypot-frontend:smoke-{suffix}"),
        }
    }

    fn cleanup(&self) -> anyhow::Result<()> {
        let mut errors = Vec::new();

        for container in [
            &self.frontend_container,
            &self.proxy_container,
            &self.control_plane_container,
        ] {
            if let Err(error) = remove_docker_container_if_exists(container) {
                errors.push(format!("remove container {container}: {error:#}"));
            }
        }

        if let Err(error) = remove_docker_network_if_exists(&self.network_name) {
            errors.push(format!("remove network {}: {error:#}", self.network_name));
        }

        for image in [&self.frontend_image, &self.proxy_image, &self.control_plane_image] {
            if let Err(error) = remove_docker_image_if_exists(image) {
                errors.push(format!("remove image {image}: {error:#}"));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            anyhow::bail!(errors.join("; "));
        }
    }
}

struct DockerComposeFixture {
    _root: tempfile::TempDir,
    compose_path: PathBuf,
}

impl DockerComposeFixture {
    fn create(resources: &DockerSmokeResources, lockfile: &HoneypotImagesLock) -> anyhow::Result<Self> {
        let root = tempfile::tempdir().context("create docker compose fixture root")?;
        let env_dir = root.path().join("env");
        let control_plane_config_dir = root.path().join("config/control-plane");
        let proxy_config_dir = root.path().join("config/proxy");
        let frontend_config_dir = root.path().join("config/frontend");
        let control_plane_secret_dir = root.path().join("secrets/control-plane");
        let proxy_secret_dir = root.path().join("secrets/proxy");
        let frontend_secret_dir = root.path().join("secrets/frontend");
        let image_store_dir = root.path().join("srv/honeypot/images");
        let lease_store_dir = root.path().join("srv/honeypot/leases");
        let quarantine_store_dir = root.path().join("srv/honeypot/quarantine");
        let qmp_dir = root.path().join("srv/honeypot/run/qmp");
        let qga_dir = root.path().join("srv/honeypot/run/qga");

        for dir in [
            &env_dir,
            &control_plane_config_dir,
            &proxy_config_dir,
            &frontend_config_dir,
            &control_plane_secret_dir,
            &proxy_secret_dir,
            &frontend_secret_dir,
            &image_store_dir,
            &lease_store_dir,
            &quarantine_store_dir,
            &qmp_dir,
            &qga_dir,
        ] {
            std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        }

        std::fs::write(
            env_dir.join("control-plane.env"),
            "HONEYPOT_CONTROL_PLANE_CONFIG=/etc/honeypot/control-plane/config.toml\n",
        )
        .context("write compose control-plane env file")?;
        std::fs::write(env_dir.join("proxy.env"), "DGATEWAY_CONFIG_PATH=/etc/honeypot/proxy\n")
            .context("write compose proxy env file")?;
        std::fs::write(
            env_dir.join("frontend.env"),
            "HONEYPOT_FRONTEND_CONFIG_PATH=/etc/honeypot/frontend/config.toml\n",
        )
        .context("write compose frontend env file")?;

        write_honeypot_control_plane_config(
            &control_plane_config_dir.join("config.toml"),
            &HoneypotControlPlaneTestConfig::builder()
                .bind_addr("0.0.0.0:8080")
                .service_token_validation_disabled(true)
                .backend_credentials_file_path("/run/secrets/honeypot/control-plane/backend-credentials.json")
                .data_dir("/var/lib/honeypot/control-plane")
                .image_store("/var/lib/honeypot/images")
                .manifest_dir("/var/lib/honeypot/images/manifests")
                .lease_store("/var/lib/honeypot/leases")
                .quarantine_store("/var/lib/honeypot/quarantine")
                .qmp_dir("/run/honeypot/qmp")
                .qga_dir(PathBuf::from("/run/honeypot/qga"))
                .secret_dir("/run/secrets/honeypot/control-plane")
                .kvm_path("/dev/kvm")
                .enable_guest_agent(true)
                .lifecycle_driver("process")
                .stop_timeout_secs(5)
                .qemu_binary_path("/usr/bin/qemu-system-x86_64")
                .qemu_machine_type("q35")
                .qemu_cpu_model("host")
                .qemu_vcpu_count(4)
                .qemu_memory_mib(8192)
                .qemu_netdev_id("net0")
                .build(),
        )
        .context("write compose control-plane config")?;
        write_proxy_smoke_config(&proxy_config_dir).context("write compose proxy config")?;
        write_honeypot_frontend_config(
            &frontend_config_dir.join("config.toml"),
            &HoneypotFrontendTestConfig::builder()
                .bind_addr("0.0.0.0:8080")
                .proxy_base_url("http://proxy:8080/")
                .proxy_bearer_token(Some(honeypot_scope_token("gateway.honeypot.watch")))
                .operator_token_validation_disabled(true)
                .title("Observation Deck")
                .build(),
        )
        .context("write compose frontend config")?;

        std::fs::write(control_plane_secret_dir.join("backend-credentials.json"), "{}")
            .context("write compose control-plane backend credentials")?;
        std::fs::write(
            proxy_secret_dir.join("control-plane-service-token"),
            format!("{}\n", honeypot_scope_token("gateway.honeypot.control-plane")),
        )
        .context("write compose proxy control-plane token")?;
        std::fs::write(proxy_secret_dir.join("backend-credentials.json"), "{}")
            .context("write compose proxy backend credentials")?;

        write_trusted_image_fixture(&image_store_dir)?;

        let mut compose_data = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH))
            .context("read checked-in compose file")?;
        validate_honeypot_compose_document(&compose_data, lockfile)
            .context("checked-in compose must satisfy the pinned lockfile contract before runtime bring-up")?;

        for (service, image) in [
            ("control-plane", resources.control_plane_image.as_str()),
            ("proxy", resources.proxy_image.as_str()),
            ("frontend", resources.frontend_image.as_str()),
        ] {
            compose_data = rewrite_compose_image_ref(&compose_data, service, image, true, true);
        }

        for (from, to) in [
            (
                "/srv/honeypot/images:/var/lib/honeypot/images:rw",
                format!("{}:/var/lib/honeypot/images:rw", image_store_dir.display()),
            ),
            (
                "/srv/honeypot/leases:/var/lib/honeypot/leases:rw",
                format!("{}:/var/lib/honeypot/leases:rw", lease_store_dir.display()),
            ),
            (
                "/srv/honeypot/quarantine:/var/lib/honeypot/quarantine:rw",
                format!("{}:/var/lib/honeypot/quarantine:rw", quarantine_store_dir.display()),
            ),
            (
                "/srv/honeypot/run/qmp:/run/honeypot/qmp:rw",
                format!("{}:/run/honeypot/qmp:rw", qmp_dir.display()),
            ),
            (
                "/srv/honeypot/run/qga:/run/honeypot/qga:rw",
                format!("{}:/run/honeypot/qga:rw", qga_dir.display()),
            ),
        ] {
            compose_data = compose_data.replace(from, &to);
        }

        compose_data = compose_data.replace("\"0.0.0.0:8443:8443\"", "\"127.0.0.1::8443\"");
        compose_data = compose_data.replace("\"127.0.0.1:8080:8080\"", "\"127.0.0.1::8080\"");

        let compose_path = root.path().join("compose.yaml");
        std::fs::write(&compose_path, compose_data)
            .with_context(|| format!("write executable compose fixture at {}", compose_path.display()))?;

        Ok(Self {
            _root: root,
            compose_path,
        })
    }
}

fn write_trusted_image_fixture(image_store: &Path) -> anyhow::Result<()> {
    let manifest_dir = image_store.join("manifests");
    std::fs::create_dir_all(&manifest_dir).with_context(|| format!("create {}", manifest_dir.display()))?;

    let base_image_contents = b"tiny11-host-smoke-base-image";
    let base_image_path = image_store.join("tiny11-base.qcow2");
    std::fs::write(&base_image_path, base_image_contents)
        .with_context(|| format!("write {}", base_image_path.display()))?;
    let digest = format!("{:x}", Sha256::digest(base_image_contents));

    let manifest = json!({
        "pool_name": "default",
        "vm_name": "tiny11-smoke-1",
        "attestation_ref": "attestation-smoke-1",
        "guest_rdp_port": 3389,
        "base_image_path": "tiny11-base.qcow2",
        "source_iso": {
            "acquisition_channel": "msdn",
            "acquisition_date": "2026-03-26",
            "filename": "tiny11.iso",
            "size_bytes": base_image_contents.len(),
            "edition": "Windows 11 Pro x64",
            "language": "en-us",
            "sha256": digest,
        },
        "transformation": {
            "timestamp": "2026-03-26T12:00:00Z",
            "inputs": [{
                "reference": "tiny11-host-smoke-builder",
                "sha256": digest,
            }],
        },
        "base_image": {
            "sha256": digest,
        },
        "approval": {
            "approved_by": "host-smoke-test",
        }
    });
    let manifest_path = manifest_dir.join("tiny11-smoke.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize trusted image manifest"),
    )
    .with_context(|| format!("write {}", manifest_path.display()))?;

    Ok(())
}

fn write_proxy_smoke_config(config_dir: &Path) -> anyhow::Result<()> {
    let sample_path = repo_relative_path(HONEYPOT_PROXY_CONFIG_PATH);
    let sample = std::fs::read_to_string(&sample_path)
        .with_context(|| format!("read proxy config sample {}", sample_path.display()))?;
    let mut document: Value = serde_json::from_str(&sample).context("parse proxy config sample")?;
    let root = document
        .as_object_mut()
        .context("proxy config sample root must be a JSON object")?;
    root.insert(
        "__debug__".to_owned(),
        json!({
            "disable_token_validation": true,
        }),
    );

    let config_path = config_dir.join("gateway.json");
    std::fs::write(
        &config_path,
        serde_json::to_vec_pretty(&document).expect("serialize proxy config"),
    )
    .with_context(|| format!("write {}", config_path.display()))?;

    Ok(())
}

async fn read_http_response(port: u16, path: &str, headers: &[(&str, &str)]) -> anyhow::Result<(String, Vec<u8>)> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
        .await
        .with_context(|| format!("connect to localhost:{port}"))?;

    let mut request = format!("GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    request.push_str("\r\n");

    stream
        .write_all(request.as_bytes())
        .await
        .with_context(|| format!("send request to {path} on port {port}"))?;

    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .await
        .with_context(|| format!("read response from {path} on port {port}"))?;

    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .context("split HTTP response headers and body")?;
    let headers = std::str::from_utf8(&response[..header_end]).context("decode HTTP response headers")?;
    let status_line = headers.lines().next().context("extract HTTP status line")?.to_owned();

    Ok((status_line, response[(header_end + 4)..].to_vec()))
}

async fn read_json_response(port: u16, path: &str, headers: &[(&str, &str)]) -> anyhow::Result<(String, Value)> {
    let (status_line, body) = read_http_response(port, path, headers).await?;
    let json = serde_json::from_slice(&body).context("decode JSON response")?;
    Ok((status_line, json))
}

async fn wait_for_json_condition<F, G>(
    label: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    is_ready: F,
    diagnostics: G,
) -> anyhow::Result<Value>
where
    F: Fn(&str, &Value) -> bool,
    G: Fn() -> String,
{
    let start = Instant::now();
    let mut last_observation = Vec::new();
    loop {
        match read_json_response(port, path, headers).await {
            Ok((status_line, body)) => {
                if is_ready(&status_line, &body) {
                    return Ok(body);
                }

                last_observation.push((status_line, body.to_string()));
            }
            Err(error) => {
                last_observation.push(("request_failed".to_owned(), format!("request error: {error:#}")));
            }
        }

        if start.elapsed() >= DOCKER_SMOKE_TIMEOUT {
            let (last_status, last_body) = last_observation
                .last()
                .cloned()
                .unwrap_or_else(|| ("no_request".to_owned(), "no request attempts recorded".to_owned()));
            anyhow::bail!(
                "{label} did not satisfy the expected health condition within {:?}; last_status={:?}; last_body={:?}; diagnostics={}",
                DOCKER_SMOKE_TIMEOUT,
                last_status,
                last_body,
                diagnostics(),
            );
        }

        sleep(DOCKER_SMOKE_POLL_INTERVAL).await;
    }
}

fn docker_filtered_names(resource: &str, label: &str) -> anyhow::Result<Vec<String>> {
    let (subcommand, format_flag) = match resource {
        "container" => ("ps", "{{.Names}}"),
        "network" => ("network ls", "{{.Name}}"),
        "volume" => ("volume ls", "{{.Name}}"),
        _ => anyhow::bail!("unsupported docker resource kind {resource}"),
    };
    let mut parts = subcommand.split_whitespace().collect::<Vec<_>>();
    let command = parts.remove(0);
    let mut args = parts.into_iter().map(ToOwned::to_owned).collect::<Vec<_>>();
    if resource == "container" {
        args.push("-a".to_owned());
    }
    args.push("--filter".to_owned());
    args.push(format!("label={label}"));
    args.push("--format".to_owned());
    args.push(format_flag.to_owned());

    let output = Command::new("docker")
        .arg(command)
        .args(&args)
        .output()
        .with_context(|| format!("list docker {resource}s for label {label}"))?;
    anyhow::ensure!(
        output.status.success(),
        "docker {command} {} failed: {}",
        args.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );

    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToOwned::to_owned)
        .collect())
}

fn docker_compose_json(
    compose_path: &Path,
    project_name: &str,
    service: &str,
    curl_args: &[&str],
) -> anyhow::Result<Value> {
    let mut args = vec![
        "exec".to_owned(),
        "-T".to_owned(),
        service.to_owned(),
        "curl".to_owned(),
    ];
    args.extend(curl_args.iter().map(|arg| (*arg).to_owned()));
    let output = run_docker_compose(compose_path, project_name, &args)?;
    serde_json::from_slice(&output.stdout)
        .with_context(|| format!("decode compose exec JSON response for service {service}"))
}

#[test]
fn release_inputs_on_disk_match_the_honeypot_lockfile_contract() {
    require_honeypot_tier(HoneypotTestTier::Contract).expect("contract tier should always be available");

    validate_honeypot_release_inputs(
        &repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH),
        &repo_relative_path(HONEYPOT_COMPOSE_PATH),
    )
    .expect("on-disk release inputs should match the DF-07 contract");
    validate_honeypot_control_plane_runtime_contract(
        &repo_relative_path(HONEYPOT_COMPOSE_PATH),
        &repo_relative_path(HONEYPOT_CONTROL_PLANE_ENV_PATH),
        &repo_relative_path(HONEYPOT_CONTROL_PLANE_CONFIG_PATH),
    )
    .expect("control-plane runtime config injection should match the deployment contract");
    validate_honeypot_proxy_runtime_contract(
        &repo_relative_path(HONEYPOT_COMPOSE_PATH),
        &repo_relative_path(HONEYPOT_PROXY_ENV_PATH),
        &repo_relative_path(HONEYPOT_PROXY_CONFIG_PATH),
    )
    .expect("proxy runtime config injection should match the deployment contract");
    validate_honeypot_frontend_runtime_contract(
        &repo_relative_path(HONEYPOT_COMPOSE_PATH),
        &repo_relative_path(HONEYPOT_FRONTEND_ENV_PATH),
        &repo_relative_path(HONEYPOT_FRONTEND_CONFIG_PATH),
    )
    .expect("frontend runtime config injection should match the deployment contract");
}

#[test]
fn images_lock_rejects_missing_service() {
    let error = validate_honeypot_images_lock_document(
        r#"
control-plane:
  image: devolutions-gateway-honeypot/control-plane
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    source_ref: refs/tags/v0.0.9
proxy:
  image: devolutions-gateway-honeypot/proxy
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    source_ref: refs/tags/v0.0.9
"#,
    )
    .expect_err("images.lock should reject missing frontend");

    assert!(
        format!("{error:#}").contains("exactly control-plane, proxy, and frontend"),
        "{error:#}"
    );
}

#[test]
fn images_lock_rejects_missing_required_field() {
    let error = validate_honeypot_images_lock_document(
        r#"
control-plane:
  image: devolutions-gateway-honeypot/control-plane
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    source_ref: refs/tags/v0.0.9
proxy:
  image: devolutions-gateway-honeypot/proxy
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    source_ref: refs/tags/v0.0.9
frontend:
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    source_ref: refs/tags/v0.0.9
"#,
    )
    .expect_err("images.lock should reject missing image field");

    assert!(format!("{error:#}").contains("missing field `image`"), "{error:#}");
}

#[test]
fn images_lock_rejects_malformed_digest() {
    let error = validate_honeypot_images_lock_document(
        r#"
control-plane:
  image: devolutions-gateway-honeypot/control-plane
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: not-a-digest
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    source_ref: refs/tags/v0.0.9
proxy:
  image: devolutions-gateway-honeypot/proxy
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    source_ref: refs/tags/v0.0.9
frontend:
  image: devolutions-gateway-honeypot/frontend
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    source_ref: refs/tags/v0.0.9
"#,
    )
    .expect_err("images.lock should reject malformed digest");

    assert!(format!("{error:#}").contains("current.digest"), "{error:#}");
}

#[test]
fn images_lock_rejects_floating_tag_and_registry_drift() {
    let error = validate_honeypot_images_lock_document(
        r#"
control-plane:
  image: devolutions-gateway-honeypot/control-plane
  registry: ghcr.io/not-the-fork-owner
  current:
    tag: latest
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
    source_ref: refs/tags/v0.0.9
proxy:
  image: devolutions-gateway-honeypot/proxy
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
    source_ref: refs/tags/v0.0.9
frontend:
  image: devolutions-gateway-honeypot/frontend
  registry: ghcr.io/fork-owner
  current:
    tag: v0.1.0
    digest: sha256:3333333333333333333333333333333333333333333333333333333333333333
    source_ref: refs/tags/v0.1.0
  previous:
    tag: v0.0.9
    digest: sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
    source_ref: refs/tags/v0.0.9
"#,
    )
    .expect_err("images.lock should reject registry drift");

    assert!(format!("{error:#}").contains("registry"), "{error:#}");
}

#[test]
fn compose_rejects_tag_refs_or_digest_drift() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let error = validate_honeypot_compose_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane:v0.0.0-placeholder
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane:v0.0.0-placeholder
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
        &lockfile,
    )
    .expect_err("compose should reject tag-based control-plane image refs");

    assert!(format!("{error:#}").contains("control-plane"), "{error:#}");
}

#[test]
fn compose_lockfile_conformance_rejects_unknown_digest_bypass() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let compose_data = compose_document_for_selection(&lockfile, ServiceVersionSelection::default());
    let bypass_ref = "ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";
    let compose_data = rewrite_compose_image_ref(&compose_data, "proxy", bypass_ref, true, true);

    let error = validate_honeypot_compose_document(&compose_data, &lockfile)
        .expect_err("compose should reject digest refs that bypass images.lock");

    assert!(format!("{error:#}").contains("proxy"), "{error:#}");
    assert!(format!("{error:#}").contains("images.lock current digest"), "{error:#}");
}

#[test]
fn compose_lockfile_conformance_rejects_service_image_bypass_when_alias_stays_pinned() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let compose_data = compose_document_for_selection(&lockfile, ServiceVersionSelection::default());
    let bypass_ref = expected_image_ref(&lockfile, "proxy", ImageSlot::Current);
    let compose_data = rewrite_compose_image_ref(&compose_data, "frontend", &bypass_ref, false, true);

    let error = validate_honeypot_compose_document(&compose_data, &lockfile)
        .expect_err("compose should reject a service image that bypasses the pinned lockfile entry");

    assert!(
        format!("{error:#}").contains("compose service frontend image must match images.lock current digest"),
        "{error:#}"
    );
}

#[test]
fn pull_by_digest_host_smoke_resolves_current_service_images() {
    if let Err(error) = require_honeypot_tier(HoneypotTestTier::HostSmoke) {
        eprintln!("skipping host-smoke pull-by-digest test: {error:#}");
        return;
    }

    resolve_honeypot_images_for_selection(
        &repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH),
        ServiceVersionSelection::default(),
    )
    .expect("host-smoke tier should resolve each current honeypot image by pinned digest");
}

#[tokio::test]
async fn docker_host_smoke_builds_and_starts_three_service_images() {
    if let Err(error) = require_honeypot_tier(HoneypotTestTier::HostSmoke) {
        eprintln!("skipping host-smoke docker image test: {error:#}");
        return;
    }

    let fixture = DockerSmokeFixture::create().expect("create docker smoke fixture");
    let resources = DockerSmokeResources::new();

    let result: anyhow::Result<()> = async {
        build_honeypot_service_image("control-plane", &resources.control_plane_image)
            .context("build control-plane image")?;
        build_honeypot_service_image("proxy", &resources.proxy_image).context("build proxy image")?;
        build_honeypot_service_image("frontend", &resources.frontend_image).context("build frontend image")?;

        create_docker_network(&resources.network_name).context("create docker smoke network")?;

        let control_plane_port = testsuite::honeypot_frontend::find_unused_port();
        let proxy_port = testsuite::honeypot_frontend::find_unused_port();
        let frontend_port = testsuite::honeypot_frontend::find_unused_port();

        let control_plane_args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            resources.control_plane_container.clone(),
            "--network".to_owned(),
            resources.network_name.clone(),
            "--network-alias".to_owned(),
            "control-plane".to_owned(),
            "--publish".to_owned(),
            format!("127.0.0.1:{control_plane_port}:8080"),
            "--env".to_owned(),
            "HONEYPOT_CONTROL_PLANE_CONFIG=/etc/honeypot/control-plane/config.toml".to_owned(),
            "--volume".to_owned(),
            format!(
                "{}:/etc/honeypot/control-plane/config.toml:ro",
                fixture.control_plane_config_path.display()
            ),
            "--volume".to_owned(),
            format!(
                "{}:/run/secrets/honeypot/control-plane:ro",
                fixture.control_plane_secret_dir.display()
            ),
            "--volume".to_owned(),
            format!(
                "{}:/var/lib/honeypot/control-plane:rw",
                fixture.control_plane_data_dir.display()
            ),
            "--volume".to_owned(),
            format!(
                "{}:/var/lib/honeypot/images:rw",
                fixture.control_plane_image_store_dir.display()
            ),
            "--volume".to_owned(),
            format!(
                "{}:/var/lib/honeypot/leases:rw",
                fixture.control_plane_lease_store_dir.display()
            ),
            "--volume".to_owned(),
            format!(
                "{}:/var/lib/honeypot/quarantine:rw",
                fixture.control_plane_quarantine_store_dir.display()
            ),
            "--volume".to_owned(),
            format!("{}:/run/honeypot/qmp:rw", fixture.control_plane_qmp_dir.display()),
            "--volume".to_owned(),
            format!("{}:/run/honeypot/qga:rw", fixture.control_plane_qga_dir.display()),
            "--volume".to_owned(),
            format!("{}:/dev/kvm:ro", fixture.control_plane_kvm_path.display()),
            resources.control_plane_image.clone(),
        ];
        run_docker_container(&control_plane_args).context("start control-plane container")?;

        let control_plane_auth_header = format!("Bearer {}", honeypot_scope_token("gateway.honeypot.control-plane"));
        let control_plane_health = wait_for_json_condition(
            "control-plane health",
            control_plane_port,
            "/api/v1/health",
            &[("Authorization", control_plane_auth_header.as_str())],
            |status_line, body| {
                status_line.contains("200")
                    && body["service_state"] == "ready"
                    && body["trusted_image_count"] == 1
                    && body["kvm_available"] == true
            },
            || {
                docker_logs(&resources.control_plane_container)
                    .unwrap_or_else(|error| format!("failed to read control-plane logs: {error:#}"))
            },
        )
        .await
        .context("control-plane container should report ready health")?;
        assert_eq!(control_plane_health["service_state"], "ready");

        let proxy_args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            resources.proxy_container.clone(),
            "--network".to_owned(),
            resources.network_name.clone(),
            "--network-alias".to_owned(),
            "proxy".to_owned(),
            "--publish".to_owned(),
            format!("127.0.0.1:{proxy_port}:8080"),
            "--env".to_owned(),
            "DGATEWAY_CONFIG_PATH=/etc/honeypot/proxy".to_owned(),
            "--volume".to_owned(),
            format!("{}:/etc/honeypot/proxy:rw", fixture.proxy_config_dir.display()),
            "--volume".to_owned(),
            format!("{}:/run/secrets/honeypot/proxy:ro", fixture.proxy_secret_dir.display()),
            resources.proxy_image.clone(),
        ];
        run_docker_container(&proxy_args).context("start proxy container")?;

        let proxy_health = wait_for_json_condition(
            "proxy health",
            proxy_port,
            "/jet/health",
            &[("Accept", "application/json")],
            |status_line, body| {
                status_line.contains("200")
                    && body["honeypot"]["service_state"] == "ready"
                    && body["honeypot"]["control_plane_reachable"] == true
            },
            || {
                docker_logs(&resources.proxy_container)
                    .unwrap_or_else(|error| format!("failed to read proxy logs: {error:#}"))
            },
        )
        .await
        .context("proxy container should report ready honeypot health")?;
        assert_eq!(proxy_health["honeypot"]["service_state"], "ready");

        let frontend_args = vec![
            "run".to_owned(),
            "--detach".to_owned(),
            "--name".to_owned(),
            resources.frontend_container.clone(),
            "--network".to_owned(),
            resources.network_name.clone(),
            "--network-alias".to_owned(),
            "frontend".to_owned(),
            "--publish".to_owned(),
            format!("127.0.0.1:{frontend_port}:8080"),
            "--env".to_owned(),
            "HONEYPOT_FRONTEND_CONFIG_PATH=/etc/honeypot/frontend/config.toml".to_owned(),
            "--volume".to_owned(),
            format!(
                "{}:/etc/honeypot/frontend/config.toml:ro",
                fixture.frontend_config_path.display()
            ),
            resources.frontend_image.clone(),
        ];
        run_docker_container(&frontend_args).context("start frontend container")?;

        let frontend_health = wait_for_json_condition(
            "frontend health",
            frontend_port,
            "/health",
            &[],
            |status_line, body| {
                status_line.contains("200")
                    && body["service_state"] == "ready"
                    && body["proxy_bootstrap_reachable"] == true
            },
            || {
                docker_logs(&resources.frontend_container)
                    .unwrap_or_else(|error| format!("failed to read frontend logs: {error:#}"))
            },
        )
        .await
        .context("frontend container should report ready health")?;
        assert_eq!(frontend_health["service_state"], "ready");
        Ok(())
    }
    .await;

    let cleanup_result = resources.cleanup();

    match (result, cleanup_result) {
        (Ok(()), Ok(())) => {}
        (Ok(()), Err(cleanup_error)) => panic!("docker smoke cleanup failed: {cleanup_error:#}"),
        (Err(test_error), Ok(())) => panic!("{test_error:#}"),
        (Err(test_error), Err(cleanup_error)) => {
            panic!("{test_error:#}\ncleanup error: {cleanup_error:#}")
        }
    }
}

#[tokio::test]
async fn compose_bring_up_starts_the_three_service_stack_and_tears_it_down_cleanly() {
    if let Err(error) = require_honeypot_tier(HoneypotTestTier::HostSmoke) {
        eprintln!("skipping compose bring-up host-smoke test: {error:#}");
        return;
    }

    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let resources = DockerSmokeResources::new();
    let project_name = format!("dgw-honeypot-compose-{}", Uuid::new_v4().simple());
    let fixture = DockerComposeFixture::create(&resources, &lockfile).expect("create docker compose fixture");

    let compose_logs = || {
        run_docker_compose(
            &fixture.compose_path,
            &project_name,
            &["logs".to_owned(), "--no-color".to_owned()],
        )
        .map(|output| {
            let stdout = String::from_utf8_lossy(&output.stdout).trim().to_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_owned();
            match (stdout.is_empty(), stderr.is_empty()) {
                (false, false) => format!("{stdout}\n{stderr}"),
                (false, true) => stdout,
                (true, false) => stderr,
                (true, true) => String::new(),
            }
        })
        .unwrap_or_else(|error| format!("failed to read compose logs: {error:#}"))
    };

    let result: anyhow::Result<()> = async {
        build_honeypot_service_image("control-plane", &resources.control_plane_image)
            .context("build control-plane compose image")?;
        build_honeypot_service_image("proxy", &resources.proxy_image).context("build proxy compose image")?;
        build_honeypot_service_image("frontend", &resources.frontend_image).context("build frontend compose image")?;

        run_docker_compose(
            &fixture.compose_path,
            &project_name,
            &[
                "up".to_owned(),
                "-d".to_owned(),
                "--wait".to_owned(),
                "--no-build".to_owned(),
                "--remove-orphans".to_owned(),
            ],
        )
        .with_context(|| format!("docker compose up failed\n{}", compose_logs()))?;

        let control_plane_health_auth = format!(
            "Authorization: Bearer {}",
            honeypot_scope_token("gateway.honeypot.control-plane")
        );
        let control_plane_health = docker_compose_json(
            &fixture.compose_path,
            &project_name,
            "control-plane",
            &[
                "-fsS",
                "-H",
                control_plane_health_auth.as_str(),
                "http://127.0.0.1:8080/api/v1/health",
            ],
        )
        .with_context(|| format!("read control-plane compose health\n{}", compose_logs()))?;
        assert_eq!(control_plane_health["service_state"], "ready");
        assert_eq!(control_plane_health["trusted_image_count"], 1);
        assert_eq!(control_plane_health["kvm_available"], true);

        let proxy_health = docker_compose_json(
            &fixture.compose_path,
            &project_name,
            "proxy",
            &[
                "-fsS",
                "-H",
                "Accept: application/json",
                "http://127.0.0.1:8080/jet/health",
            ],
        )
        .with_context(|| format!("read proxy compose health\n{}", compose_logs()))?;
        assert_eq!(proxy_health["honeypot"]["service_state"], "ready");
        assert_eq!(proxy_health["honeypot"]["control_plane_reachable"], true);

        let frontend_health = docker_compose_json(
            &fixture.compose_path,
            &project_name,
            "frontend",
            &["-fsS", "http://127.0.0.1:8080/health"],
        )
        .with_context(|| format!("read frontend compose health\n{}", compose_logs()))?;
        assert_eq!(frontend_health["service_state"], "ready");
        assert_eq!(frontend_health["proxy_bootstrap_reachable"], true);

        Ok(())
    }
    .await;

    let down_result = run_docker_compose(
        &fixture.compose_path,
        &project_name,
        &[
            "down".to_owned(),
            "-v".to_owned(),
            "--remove-orphans".to_owned(),
            "--timeout".to_owned(),
            "10".to_owned(),
        ],
    );
    let mut cleanup_errors = Vec::new();
    if let Err(error) = down_result {
        cleanup_errors.push(format!("docker compose down: {error:#}"));
    }

    let project_label = format!("com.docker.compose.project={project_name}");
    for (resource, label) in [
        ("container", "containers"),
        ("network", "networks"),
        ("volume", "volumes"),
    ] {
        match docker_filtered_names(resource, &project_label) {
            Ok(names) if names.is_empty() => {}
            Ok(names) => cleanup_errors.push(format!("leftover {label}: {}", names.join(", "))),
            Err(error) => cleanup_errors.push(format!("list {label}: {error:#}")),
        }
    }

    for image in [
        &resources.frontend_image,
        &resources.proxy_image,
        &resources.control_plane_image,
    ] {
        if let Err(error) = remove_docker_image_if_exists(image) {
            cleanup_errors.push(format!("remove image {image}: {error:#}"));
        }
    }

    match (result, cleanup_errors.is_empty()) {
        (Ok(()), true) => {}
        (Ok(()), false) => panic!("compose bring-up cleanup failed: {}", cleanup_errors.join("; ")),
        (Err(test_error), true) => panic!("{test_error:#}"),
        (Err(test_error), false) => panic!("{test_error:#}\ncleanup error: {}", cleanup_errors.join("; ")),
    }
}

#[test]
fn downgraded_control_plane_contract_compatibility_is_allowed() {
    validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Previous,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        },
        ServiceSchemaVersions::default(),
    )
    .expect("previous/current/current should stay contract-compatible");
}

#[test]
fn downgraded_control_plane_compose_compatibility_is_allowed() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Previous,
        proxy: ImageSlot::Current,
        frontend: ImageSlot::Current,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect("previous/current/current compose should stay compatible with current peers");
}

#[test]
fn downgraded_control_plane_compose_compatibility_rejects_unsupported_previous_pairings() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Previous,
        proxy: ImageSlot::Previous,
        frontend: ImageSlot::Current,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect_err("previous/previous/current compose must be rejected");

    assert!(
        format!("{error:#}").contains("proxy previous requires control-plane current"),
        "{error:#}"
    );
}

#[test]
fn downgraded_control_plane_compose_compatibility_rejects_schema_version_drift() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Previous,
        proxy: ImageSlot::Current,
        frontend: ImageSlot::Current,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions {
            control_plane: 2,
            proxy: 1,
            frontend: 1,
        },
    )
    .expect_err("schema drift across proxy/control-plane should be rejected");

    assert!(
        format!("{error:#}").contains("proxy schema_version 1 is incompatible with control-plane schema_version 2"),
        "{error:#}"
    );
}

#[test]
fn downgraded_proxy_contract_compatibility_is_allowed() {
    validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Previous,
            frontend: ImageSlot::Current,
        },
        ServiceSchemaVersions::default(),
    )
    .expect("current/previous/current should stay contract-compatible");
}

#[test]
fn downgraded_proxy_compose_compatibility_is_allowed() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Previous,
        frontend: ImageSlot::Current,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect("current/previous/current compose should stay compatible with current peers");
}

#[test]
fn downgraded_proxy_compose_compatibility_rejects_unsupported_previous_pairings() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Previous,
        frontend: ImageSlot::Previous,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect_err("current/previous/previous compose must be rejected");

    assert!(
        format!("{error:#}").contains("frontend previous requires proxy current"),
        "{error:#}"
    );
}

#[test]
fn downgraded_proxy_compose_compatibility_rejects_schema_version_drift() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Previous,
        frontend: ImageSlot::Current,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions {
            control_plane: 1,
            proxy: 2,
            frontend: 2,
        },
    )
    .expect_err("schema drift across proxy/control-plane should be rejected");

    assert!(
        format!("{error:#}").contains("proxy schema_version 2 is incompatible with control-plane schema_version 1"),
        "{error:#}"
    );
}

#[test]
fn downgraded_frontend_contract_compatibility_is_allowed() {
    validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Previous,
        },
        ServiceSchemaVersions::default(),
    )
    .expect("current/current/previous should stay contract-compatible");
}

#[test]
fn downgraded_frontend_compose_compatibility_is_allowed() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Current,
        frontend: ImageSlot::Previous,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect("current/current/previous compose should stay compatible with current peers");
}

#[test]
fn downgraded_frontend_compose_compatibility_rejects_unsupported_previous_pairings() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Previous,
        frontend: ImageSlot::Previous,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions::default(),
    )
    .expect_err("current/previous/previous compose must be rejected");

    assert!(
        format!("{error:#}").contains("frontend previous requires proxy current"),
        "{error:#}"
    );
}

#[test]
fn downgraded_frontend_compose_compatibility_rejects_schema_version_drift() {
    let lockfile =
        load_honeypot_images_lock(&repo_relative_path(HONEYPOT_IMAGES_LOCK_PATH)).expect("load on-disk lockfile");
    let selection = ServiceVersionSelection {
        control_plane: ImageSlot::Current,
        proxy: ImageSlot::Current,
        frontend: ImageSlot::Previous,
    };
    let compose_data = compose_document_for_selection(&lockfile, selection);

    let error = validate_honeypot_compose_document_for_selection(
        &compose_data,
        &lockfile,
        selection,
        ServiceSchemaVersions {
            control_plane: 1,
            proxy: 1,
            frontend: 2,
        },
    )
    .expect_err("schema drift across frontend/proxy should be rejected");

    assert!(
        format!("{error:#}").contains("frontend schema_version 2 is incompatible with proxy schema_version 1"),
        "{error:#}"
    );
}

#[test]
fn downgraded_service_contract_compatibility_rejects_unsupported_previous_pairings() {
    let error = validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Previous,
            proxy: ImageSlot::Previous,
            frontend: ImageSlot::Current,
        },
        ServiceSchemaVersions::default(),
    )
    .expect_err("proxy previous with control-plane previous must be rejected");

    assert!(format!("{error:#}").contains("proxy previous requires control-plane current"));

    let error = validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Previous,
            frontend: ImageSlot::Previous,
        },
        ServiceSchemaVersions::default(),
    )
    .expect_err("frontend previous with proxy previous must be rejected");

    assert!(format!("{error:#}").contains("frontend previous requires proxy current"));
}

#[test]
fn downgraded_service_contract_compatibility_rejects_schema_version_drift() {
    let error = validate_mixed_version_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Previous,
        },
        ServiceSchemaVersions {
            control_plane: 1,
            proxy: 1,
            frontend: 2,
        },
    )
    .expect_err("frontend/proxy schema mismatch must be rejected");

    assert!(format!("{error:#}").contains("frontend schema_version 2 is incompatible with proxy schema_version 1"));
}

#[test]
fn restored_control_plane_contract_compatibility_is_allowed() {
    let restored = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Previous,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        },
        HoneypotService::ControlPlane,
        ServiceSchemaVersions::default(),
    )
    .expect("restoring control-plane to current should stay contract-compatible");

    assert_eq!(
        restored,
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        }
    );
}

#[test]
fn restored_proxy_contract_compatibility_is_allowed() {
    let restored = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Previous,
            frontend: ImageSlot::Current,
        },
        HoneypotService::Proxy,
        ServiceSchemaVersions::default(),
    )
    .expect("restoring proxy to current should stay contract-compatible");

    assert_eq!(
        restored,
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        }
    );
}

#[test]
fn restored_frontend_contract_compatibility_is_allowed() {
    let restored = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Previous,
        },
        HoneypotService::Frontend,
        ServiceSchemaVersions::default(),
    )
    .expect("restoring frontend to current should stay contract-compatible");

    assert_eq!(
        restored,
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        }
    );
}

#[test]
fn restored_service_contract_compatibility_rejects_service_that_is_not_previous() {
    let error = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Current,
        },
        HoneypotService::Frontend,
        ServiceSchemaVersions::default(),
    )
    .expect_err("restoring a current frontend should be rejected");

    assert!(
        format!("{error:#}").contains("frontend must be previous before restore validation"),
        "{error:#}"
    );
}

#[test]
fn restored_service_contract_compatibility_rejects_unsupported_starting_point() {
    let error = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Previous,
            proxy: ImageSlot::Previous,
            frontend: ImageSlot::Current,
        },
        HoneypotService::Proxy,
        ServiceSchemaVersions::default(),
    )
    .expect_err("restoring from an unsupported downgraded starting point must be rejected");

    assert!(
        format!("{error:#}").contains("supported downgraded starting point"),
        "{error:#}"
    );
    assert!(
        format!("{error:#}").contains("proxy previous requires control-plane current"),
        "{error:#}"
    );
}

#[test]
fn restored_service_contract_compatibility_rejects_schema_version_drift() {
    let error = validate_restored_service_contract_compatibility(
        ServiceVersionSelection {
            control_plane: ImageSlot::Current,
            proxy: ImageSlot::Current,
            frontend: ImageSlot::Previous,
        },
        HoneypotService::Frontend,
        ServiceSchemaVersions {
            control_plane: 1,
            proxy: 1,
            frontend: 2,
        },
    )
    .expect_err("schema drift across a restore should be rejected");

    assert!(
        format!("{error:#}").contains("frontend schema_version 2 is incompatible with proxy schema_version 1"),
        "{error:#}"
    );
}

#[test]
fn control_plane_env_rejects_config_path_drift() {
    let error = validate_honeypot_control_plane_env_document(
        "HONEYPOT_CONTROL_PLANE_CONFIG=/etc/honeypot/control-plane/other.toml\n",
    )
    .expect_err("env contract should reject config path drift");

    assert!(
        format!("{error:#}").contains("HONEYPOT_CONTROL_PLANE_CONFIG"),
        "{error:#}"
    );
}

#[test]
fn control_plane_compose_runtime_contract_rejects_missing_env_file() {
    let error = validate_honeypot_control_plane_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
    volumes:
      - ./config/control-plane/config.toml:/etc/honeypot/control-plane/config.toml:ro
      - ./secrets/control-plane:/run/secrets/honeypot/control-plane:ro
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
    )
    .expect_err("compose contract should reject missing control-plane env_file");

    assert!(format!("{error:#}").contains("env_file"), "{error:#}");
}

#[test]
fn control_plane_compose_runtime_contract_rejects_edge_network_exposure() {
    let error = validate_honeypot_control_plane_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
    env_file:
      - ./env/control-plane.env
    networks:
      - honeypot-control
      - honeypot-edge
    volumes:
      - /srv/honeypot/run/qmp:/run/honeypot/qmp:rw
      - /srv/honeypot/run/qga:/run/honeypot/qga:rw
      - ./config/control-plane/config.toml:/etc/honeypot/control-plane/config.toml:ro
      - ./secrets/control-plane:/run/secrets/honeypot/control-plane:ro
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
    )
    .expect_err("compose contract should reject control-plane edge-network exposure");

    assert!(format!("{error:#}").contains("honeypot-control"), "{error:#}");
}

#[test]
fn control_plane_compose_runtime_contract_rejects_published_ports() {
    let error = validate_honeypot_control_plane_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
    env_file:
      - ./env/control-plane.env
    networks:
      - honeypot-control
    ports:
      - "127.0.0.1:8080:8080"
    volumes:
      - /srv/honeypot/run/qmp:/run/honeypot/qmp:rw
      - /srv/honeypot/run/qga:/run/honeypot/qga:rw
      - ./config/control-plane/config.toml:/etc/honeypot/control-plane/config.toml:ro
      - ./secrets/control-plane:/run/secrets/honeypot/control-plane:ro
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
    )
    .expect_err("compose contract should reject published control-plane ports");

    assert!(
        format!("{error:#}").contains("must not publish host ports"),
        "{error:#}"
    );
}

#[test]
fn control_plane_runtime_contract_rejects_localhost_bind_addr() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("control-plane.env");
    let config_path = tempdir.path().join("config.toml");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env = std::fs::read_to_string(repo_relative_path(HONEYPOT_CONTROL_PLANE_ENV_PATH))
        .expect("read on-disk control-plane env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"[http]
bind_addr = "127.0.0.1:8080"

[auth]
service_token_validation_disabled = true
proxy_verifier_public_key_pem_file = "/run/secrets/honeypot/control-plane/proxy-verifier-public-key.pem"

[backend_credentials]
adapter = "file"
file_path = "/run/secrets/honeypot/control-plane/backend-credentials.json"

[runtime]
enable_guest_agent = true

[runtime.qemu]
binary_path = "/usr/bin/qemu-system-x86_64"

[paths]
data_dir = "/var/lib/honeypot/control-plane"
image_store = "/var/lib/honeypot/images"
lease_store = "/var/lib/honeypot/leases"
quarantine_store = "/var/lib/honeypot/quarantine"
qmp_dir = "/run/honeypot/qmp"
qga_dir = "/run/honeypot/qga"
secret_dir = "/run/secrets/honeypot/control-plane"
kvm_path = "/dev/kvm"
"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_control_plane_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("runtime contract should reject localhost bind addr");

    assert!(format!("{error:#}").contains("bind_addr"), "{error:#}");
}

#[test]
fn control_plane_runtime_contract_rejects_inline_verifier_key_regression() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("control-plane.env");
    let config_path = tempdir.path().join("config.toml");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env = std::fs::read_to_string(repo_relative_path(HONEYPOT_CONTROL_PLANE_ENV_PATH))
        .expect("read on-disk control-plane env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"[http]
bind_addr = "0.0.0.0:8080"

[auth]
service_token_validation_disabled = true
proxy_verifier_public_key_pem = '''
-----BEGIN PUBLIC KEY-----
inline-regression
-----END PUBLIC KEY-----
'''

[backend_credentials]
adapter = "file"
file_path = "/run/secrets/honeypot/control-plane/backend-credentials.json"

[runtime]
enable_guest_agent = true

[runtime.qemu]
binary_path = "/usr/bin/qemu-system-x86_64"

[paths]
data_dir = "/var/lib/honeypot/control-plane"
image_store = "/var/lib/honeypot/images"
lease_store = "/var/lib/honeypot/leases"
quarantine_store = "/var/lib/honeypot/quarantine"
qmp_dir = "/run/honeypot/qmp"
qga_dir = "/run/honeypot/qga"
secret_dir = "/run/secrets/honeypot/control-plane"
kvm_path = "/dev/kvm"
"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_control_plane_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("runtime contract should reject inline verifier key regression");

    assert!(
        format!("{error:#}").contains("must not check in an inline proxy verifier public key"),
        "{error:#}"
    );
}

#[test]
fn control_plane_runtime_contract_rejects_backend_credential_file_drift() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("control-plane.env");
    let config_path = tempdir.path().join("config.toml");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env = std::fs::read_to_string(repo_relative_path(HONEYPOT_CONTROL_PLANE_ENV_PATH))
        .expect("read on-disk control-plane env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"[http]
bind_addr = "0.0.0.0:8080"

[auth]
service_token_validation_disabled = true
proxy_verifier_public_key_pem_file = "/run/secrets/honeypot/control-plane/proxy-verifier-public-key.pem"

[backend_credentials]
adapter = "file"
file_path = "/run/secrets/honeypot/control-plane/other-backend-credentials.json"

[runtime]
enable_guest_agent = true

[runtime.qemu]
binary_path = "/usr/bin/qemu-system-x86_64"

[paths]
data_dir = "/var/lib/honeypot/control-plane"
image_store = "/var/lib/honeypot/images"
lease_store = "/var/lib/honeypot/leases"
quarantine_store = "/var/lib/honeypot/quarantine"
qmp_dir = "/run/honeypot/qmp"
qga_dir = "/run/honeypot/qga"
secret_dir = "/run/secrets/honeypot/control-plane"
kvm_path = "/dev/kvm"
"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_control_plane_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("runtime contract should reject backend credential file drift");

    assert!(format!("{error:#}").contains("backend credential file"), "{error:#}");
}

#[test]
fn proxy_env_rejects_config_dir_drift() {
    let error = validate_honeypot_proxy_env_document("DGATEWAY_CONFIG_PATH=/etc/honeypot/proxy-alt\n")
        .expect_err("proxy env contract should reject config dir drift");

    assert!(format!("{error:#}").contains("DGATEWAY_CONFIG_PATH"), "{error:#}");
}

#[test]
fn proxy_compose_runtime_contract_rejects_missing_env_file() {
    let error = validate_honeypot_proxy_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
    volumes:
      - ./config/proxy/gateway.json:/etc/honeypot/proxy/gateway.json:ro
      - ./secrets/proxy:/run/secrets/honeypot/proxy:ro
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
    )
    .expect_err("compose contract should reject missing proxy env_file");

    assert!(format!("{error:#}").contains("env_file"), "{error:#}");
}

#[test]
fn proxy_compose_runtime_contract_rejects_control_socket_mount() {
    let error = validate_honeypot_proxy_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
    env_file:
      - ./env/proxy.env
    volumes:
      - ./config/proxy/gateway.json:/etc/honeypot/proxy/gateway.json:ro
      - ./secrets/proxy:/run/secrets/honeypot/proxy:ro
      - /srv/honeypot/run/qmp:/run/honeypot/qmp:rw
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
"#,
    )
    .expect_err("compose contract should reject proxy control-socket mount");

    assert!(format!("{error:#}").contains("/run/honeypot/qmp"), "{error:#}");
}

#[test]
fn proxy_runtime_contract_rejects_missing_control_plane_endpoint() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("proxy.env");
    let config_path = tempdir.path().join("gateway.json");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env = std::fs::read_to_string(repo_relative_path(HONEYPOT_PROXY_ENV_PATH)).expect("read on-disk proxy env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"{
  "ProvisionerPublicKeyData": {
    "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HgjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
  },
  "Listeners": [
    {
      "InternalUrl": "tcp://0.0.0.0:8443",
      "ExternalUrl": "tcp://0.0.0.0:8443"
    },
    {
      "InternalUrl": "http://0.0.0.0:8080",
      "ExternalUrl": "http://0.0.0.0:8080"
    }
  ],
  "Honeypot": {
    "Enabled": true,
    "ControlPlane": {
      "ServiceBearerTokenFile": "/run/secrets/honeypot/proxy/control-plane-service-token"
    },
    "Frontend": {
      "PublicUrl": "http://frontend:8080",
      "BootstrapPath": "/jet/honeypot/bootstrap",
      "EventsPath": "/jet/honeypot/events"
    }
  }
}"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_proxy_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("proxy runtime contract should reject missing control-plane endpoint");

    assert!(format!("{error:#}").contains("control-plane endpoint"), "{error:#}");
}

#[test]
fn proxy_runtime_contract_rejects_inline_service_token_regression() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("proxy.env");
    let config_path = tempdir.path().join("gateway.json");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env = std::fs::read_to_string(repo_relative_path(HONEYPOT_PROXY_ENV_PATH)).expect("read on-disk proxy env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"{
  "ProvisionerPublicKeyData": {
    "Value": "mMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA4vuqLOkl1pWobt6su1XO9VskgCAwevEGs6kkNjJQBwkGnPKYLmNF1E/af1yCocfVn/OnPf9e4x+lXVyZ6LMDJxFxu+axdgOq3Ld392J1iAEbfvwlyRFnEXFOJNyylqg3bY6LvnWHL/XZczVdMD9xYfq2sO9bg3xjRW4s7r9EEYOFjqVT3VFznH9iWJVtcSEKukmS/3uKoO6lGhacvu0HgjXXdgq0R8zvR4XRJ9Fcnf0f9Ypoc+i6L80NVjrRCeVOH+Ld/2fA9bocpfLarcVqG3RjS+qgOtpyCc0jWVFF4zaGQ7LUDFkEIYILkICeMMn2ll29hmZNzsJzZJ9s6NocgQIDAQAB"
  },
  "Listeners": [
    {
      "InternalUrl": "tcp://0.0.0.0:8443",
      "ExternalUrl": "tcp://0.0.0.0:8443"
    },
    {
      "InternalUrl": "http://0.0.0.0:8080",
      "ExternalUrl": "http://0.0.0.0:8080"
    }
  ],
  "Honeypot": {
    "Enabled": true,
    "ControlPlane": {
      "Endpoint": "http://control-plane:8080",
      "ServiceBearerToken": "inline-regression"
    },
    "Frontend": {
      "PublicUrl": "http://frontend:8080",
      "BootstrapPath": "/jet/honeypot/bootstrap",
      "EventsPath": "/jet/honeypot/events"
    }
  }
}"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_proxy_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("proxy runtime contract should reject inline service token regression");

    assert!(
        format!("{error:#}").contains("must not check in an inline control-plane service token"),
        "{error:#}"
    );
}

#[test]
fn frontend_env_rejects_config_path_drift() {
    let error =
        validate_honeypot_frontend_env_document("HONEYPOT_FRONTEND_CONFIG_PATH=/etc/honeypot/frontend/other.toml\n")
            .expect_err("frontend env contract should reject config path drift");

    assert!(
        format!("{error:#}").contains("HONEYPOT_FRONTEND_CONFIG_PATH"),
        "{error:#}"
    );
}

#[test]
fn frontend_compose_runtime_contract_rejects_missing_env_file() {
    let error = validate_honeypot_frontend_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
    volumes:
      - ./config/frontend/config.toml:/etc/honeypot/frontend/config.toml:ro
      - ./secrets/frontend:/run/secrets/honeypot/frontend:ro
"#,
    )
    .expect_err("compose contract should reject missing frontend env_file");

    assert!(format!("{error:#}").contains("env_file"), "{error:#}");
}

#[test]
fn frontend_compose_runtime_contract_rejects_control_socket_mount() {
    let error = validate_honeypot_frontend_compose_runtime_document(
        r#"
name: dgw-honeypot
x-images:
  control-plane: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
services:
  control-plane:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/control-plane@sha256:1111111111111111111111111111111111111111111111111111111111111111
  proxy:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/proxy@sha256:2222222222222222222222222222222222222222222222222222222222222222
  frontend:
    image: ghcr.io/fork-owner/devolutions-gateway-honeypot/frontend@sha256:3333333333333333333333333333333333333333333333333333333333333333
    env_file:
      - ./env/frontend.env
    volumes:
      - ./config/frontend/config.toml:/etc/honeypot/frontend/config.toml:ro
      - ./secrets/frontend:/run/secrets/honeypot/frontend:ro
      - /srv/honeypot/run/qga:/run/honeypot/qga:rw
"#,
    )
    .expect_err("compose contract should reject frontend control-socket mount");

    assert!(format!("{error:#}").contains("/run/honeypot/qga"), "{error:#}");
}

#[test]
fn frontend_runtime_contract_rejects_proxy_base_url_drift() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let compose_path = tempdir.path().join("compose.yaml");
    let env_path = tempdir.path().join("frontend.env");
    let config_path = tempdir.path().join("config.toml");

    let compose = std::fs::read_to_string(repo_relative_path(HONEYPOT_COMPOSE_PATH)).expect("read on-disk compose");
    let env =
        std::fs::read_to_string(repo_relative_path(HONEYPOT_FRONTEND_ENV_PATH)).expect("read on-disk frontend env");
    std::fs::write(&compose_path, compose).expect("write temp compose");
    std::fs::write(&env_path, env).expect("write temp env");
    std::fs::write(
        &config_path,
        r#"[http]
bind_addr = "0.0.0.0:8080"

[proxy]
base_url = "http://proxy-alt:8080/"
bootstrap_path = "/jet/honeypot/bootstrap"
events_path = "/jet/honeypot/events"
stream_token_path_template = "/jet/honeypot/session/{session_id}/stream-token"
terminate_path_template = "/jet/session/{session_id}/terminate"
system_terminate_path = "/jet/session/system/terminate"
request_timeout_secs = 10
connect_timeout_secs = 5

[auth]
operator_token_validation_disabled = true

[ui]
title = "Observation Deck"
"#,
    )
    .expect("write temp config");

    let error = validate_honeypot_frontend_runtime_contract(&compose_path, &env_path, &config_path)
        .expect_err("frontend runtime contract should reject proxy base_url drift");

    assert!(format!("{error:#}").contains("proxy base_url"), "{error:#}");
}
