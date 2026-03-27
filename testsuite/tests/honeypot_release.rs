use testsuite::honeypot_release::{
    HONEYPOT_COMPOSE_PATH, HONEYPOT_CONTROL_PLANE_CONFIG_PATH, HONEYPOT_CONTROL_PLANE_ENV_PATH,
    HONEYPOT_FRONTEND_CONFIG_PATH, HONEYPOT_FRONTEND_ENV_PATH, HONEYPOT_IMAGES_LOCK_PATH, HONEYPOT_PROXY_CONFIG_PATH,
    HONEYPOT_PROXY_ENV_PATH, ImageSlot, ServiceSchemaVersions, ServiceVersionSelection, load_honeypot_images_lock,
    repo_relative_path, validate_honeypot_compose_document, validate_honeypot_control_plane_compose_runtime_document,
    validate_honeypot_control_plane_env_document, validate_honeypot_control_plane_runtime_contract,
    validate_honeypot_frontend_compose_runtime_document, validate_honeypot_frontend_env_document,
    validate_honeypot_frontend_runtime_contract, validate_honeypot_images_lock_document,
    validate_honeypot_proxy_compose_runtime_document, validate_honeypot_proxy_env_document,
    validate_honeypot_proxy_runtime_contract, validate_honeypot_release_inputs,
    validate_mixed_version_contract_compatibility,
};
use testsuite::honeypot_tiers::{HoneypotTestTier, require_honeypot_tier};

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
