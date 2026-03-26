use testsuite::honeypot_release::{
    HONEYPOT_COMPOSE_PATH, HONEYPOT_CONTROL_PLANE_CONFIG_PATH, HONEYPOT_CONTROL_PLANE_ENV_PATH,
    HONEYPOT_IMAGES_LOCK_PATH, load_honeypot_images_lock, repo_relative_path, validate_honeypot_compose_document,
    validate_honeypot_control_plane_compose_runtime_document, validate_honeypot_control_plane_env_document,
    validate_honeypot_control_plane_runtime_contract, validate_honeypot_images_lock_document,
    validate_honeypot_release_inputs,
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

[runtime]
enable_guest_agent = true

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
