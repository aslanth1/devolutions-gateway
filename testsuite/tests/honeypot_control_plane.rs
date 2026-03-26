use std::fs;

use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, AttackerProtocol, PoolState, RecycleState, RecycleVmRequest,
    RecycleVmResponse, ReleaseState, ReleaseVmRequest, ReleaseVmResponse, ResetState, ResetVmRequest, ResetVmResponse,
    ServiceState, StreamEndpointResponse, StreamPolicy,
};
use honeypot_contracts::error::{ErrorCode, ErrorResponse};
use sha2::{Digest as _, Sha256};
use testsuite::cli::wait_for_tcp_port;
use testsuite::honeypot_control_plane::{
    HoneypotControlPlaneTestConfig, fake_qemu_bin_path, find_unused_port, get_json_response_with_bearer_token,
    honeypot_control_plane_assert_cmd, honeypot_control_plane_tokio_cmd, post_json_response_with_bearer_token,
    read_health_response_with_bearer_token, send_http_request, write_honeypot_control_plane_config,
};

const CONTROL_PLANE_CONFIG_ENV: &str = "HONEYPOT_CONTROL_PLANE_CONFIG";
const CONTROL_PLANE_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAxMDEiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3QuY29udHJvbC1wbGFuZSJ9.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const HONEYPOT_WATCH_SCOPE_TOKEN: &str = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJ0eXBlIjoic2NvcGUiLCJqdGkiOiIwMDAwMDAwMC0wMDAwLTAwMDAtMDAwMC0wMDAwMDAwMDAwMDMiLCJpYXQiOjE3MzM2Njk5OTksImV4cCI6MzMzMTU1MzU5OSwibmJmIjoxNzMzNjY5OTk5LCJzY29wZSI6ImdhdGV3YXkuaG9uZXlwb3Qud2F0Y2gifQ.aW52YWxpZC1zaWduYXR1cmUtYnV0LXZhbGlkYXRpb24tZGlzYWJsZWQ";
const DEFAULT_BACKEND_CREDENTIAL_REF: &str = "backend-credential-default";

async fn read_authed_health_response(port: u16) -> anyhow::Result<honeypot_contracts::control_plane::HealthResponse> {
    read_health_response_with_bearer_token(port, Some(CONTROL_PLANE_SCOPE_TOKEN)).await
}

async fn get_authed_json_response<Response>(port: u16, path: &str) -> anyhow::Result<(String, Response)>
where
    Response: serde::de::DeserializeOwned,
{
    get_json_response_with_bearer_token(port, path, Some(CONTROL_PLANE_SCOPE_TOKEN)).await
}

async fn post_authed_json_response<Request, Response>(
    port: u16,
    path: &str,
    request: &Request,
) -> anyhow::Result<(String, Response)>
where
    Request: serde::Serialize,
    Response: serde::de::DeserializeOwned,
{
    post_json_response_with_bearer_token(port, path, Some(CONTROL_PLANE_SCOPE_TOKEN), request).await
}

#[test]
fn control_plane_fails_closed_when_required_paths_are_missing() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());

    let existing_dir = tempdir.path().join("existing");
    fs::create_dir_all(&existing_dir).expect("create existing dir");
    let qemu_binary_path = existing_dir.join("qemu-system-x86_64");
    fs::write(&qemu_binary_path, []).expect("create fake qemu binary");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(bind_addr)
        .data_dir(existing_dir.join("data"))
        .image_store(existing_dir.join("images"))
        .manifest_dir(existing_dir.join("images").join("manifests"))
        .lease_store(existing_dir.join("leases"))
        .quarantine_store(existing_dir.join("quarantine"))
        .qmp_dir(existing_dir.join("qmp"))
        .secret_dir(existing_dir.join("secrets"))
        .kvm_path(existing_dir.join("missing-kvm"))
        .qemu_binary_path(qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let output = honeypot_control_plane_assert_cmd()
        .env(CONTROL_PLANE_CONFIG_ENV, &config_path)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(stderr.contains("validate control-plane startup contract"), "{stderr}");
    assert!(
        stderr.contains("data_dir does not exist") || stderr.contains("kvm_path does not exist"),
        "{stderr}"
    );
}

#[tokio::test]
async fn control_plane_reports_ready_when_contract_is_satisfied() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    let health = read_authed_health_response(port).await.expect("read health response");

    assert_eq!(health.service_state, ServiceState::Ready);
    assert!(health.kvm_available);
    assert_eq!(health.trusted_image_count, 1);
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 0);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_reports_degraded_without_trusted_images() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 0);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    let health = read_authed_health_response(port).await.expect("read health response");

    assert_eq!(health.service_state, ServiceState::Degraded);
    assert_eq!(health.trusted_image_count, 0);
    assert!(
        health
            .degraded_reasons
            .iter()
            .any(|reason| reason == "no_trusted_images")
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_reports_unsafe_if_kvm_disappears_after_start() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    fs::remove_file(&fixture.kvm_path).expect("remove fake kvm device");
    let health = read_authed_health_response(port).await.expect("read health response");

    assert_eq!(health.service_state, ServiceState::Unsafe);
    assert!(!health.kvm_available);
    assert!(
        health
            .degraded_reasons
            .iter()
            .any(|reason| reason.starts_with("missing_kvm_path:"))
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_rejects_requests_without_a_service_token() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (status_line, response): (String, ErrorResponse) =
        get_json_response_with_bearer_token(port, "/api/v1/health", None)
            .await
            .expect("read unauthorized response");

    assert!(status_line.contains("401"), "{status_line}");
    assert_eq!(response.error_code, ErrorCode::Unauthorized);
    assert!(response.message.contains("service token is missing"));

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_rejects_wrong_scope_tokens() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (status_line, response): (String, ErrorResponse) = post_json_response_with_bearer_token(
        port,
        "/api/v1/vm/acquire",
        Some(HONEYPOT_WATCH_SCOPE_TOKEN),
        &acquire_request("session-authz"),
    )
    .await
    .expect("read forbidden response");

    assert!(status_line.contains("403"), "{status_line}");
    assert_eq!(response.error_code, ErrorCode::Forbidden);
    assert!(response.message.contains("gateway.honeypot.control-plane"));

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[test]
fn control_plane_fails_closed_when_proxy_verifier_key_file_is_missing() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(bind_addr)
        .service_token_validation_disabled(false)
        .proxy_verifier_public_key_pem_file(fixture.secret_dir.join("missing-proxy-verifier-public-key.pem"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let output = honeypot_control_plane_assert_cmd()
        .env(CONTROL_PLANE_CONFIG_ENV, &config_path)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(stderr.contains("build control-plane auth gate"), "{stderr}");
    assert!(stderr.contains("proxy_verifier_public_key_pem_file"), "{stderr}");
}

#[test]
fn control_plane_fails_closed_when_backend_credential_file_is_missing() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    fs::remove_file(fixture.secret_dir.join("backend-credentials.json")).expect("remove backend credential file");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(bind_addr)
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let output = honeypot_control_plane_assert_cmd()
        .env(CONTROL_PLANE_CONFIG_ENV, &config_path)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(stderr.contains("validate control-plane startup contract"), "{stderr}");
    assert!(stderr.contains("backend credential store"), "{stderr}");
}

#[test]
fn control_plane_fails_closed_when_attestation_manifest_is_incomplete() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    fs::write(&fixture.manifest_paths[0], "{}").expect("overwrite manifest with incomplete attestation");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(bind_addr)
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let output = honeypot_control_plane_assert_cmd()
        .env(CONTROL_PLANE_CONFIG_ENV, &config_path)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(stderr.contains("validate control-plane startup contract"), "{stderr}");
    assert!(
        stderr.contains("trusted image") || stderr.contains("vm_name"),
        "{stderr}"
    );
}

#[tokio::test]
async fn control_plane_assigns_resets_streams_and_recycles_a_typed_lease() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (status_line, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
            .await
            .expect("acquire lease");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(
        acquire.lease_state,
        honeypot_contracts::control_plane::LeaseState::Assigned
    );
    assert_eq!(acquire.backend_credential_ref, DEFAULT_BACKEND_CREDENTIAL_REF);
    assert!(acquire.vm_name.starts_with("honeypot-"));

    let (status_line, reset): (String, ResetVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/reset", acquire.vm_lease_id),
        &ResetVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "reset-1".to_owned(),
            session_id: "session-1".to_owned(),
            reset_reason: "operator_requested".to_owned(),
            force: true,
        },
    )
    .await
    .expect("reset lease");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(reset.reset_state, ResetState::ResetComplete);
    assert!(!reset.quarantine_required);

    let runtime_dir = fixture.lease_store.join(&acquire.vm_lease_id);
    let overlay_path = runtime_dir.join("overlay.qcow2");
    let pid_file_path = runtime_dir.join("qemu.pid");
    let qmp_socket_path = fixture.qmp_dir.join(format!("{}.sock", acquire.vm_lease_id));
    let snapshot_path = fixture.lease_store.join(format!("{}.json", acquire.vm_lease_id));
    let snapshot = fs::read_to_string(&snapshot_path).expect("read active lease snapshot after reset");
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).expect("parse lease snapshot after reset");

    assert_eq!(
        snapshot.get("runtime_state").and_then(serde_json::Value::as_str),
        Some("running")
    );
    assert!(overlay_path.is_file(), "missing overlay at {}", overlay_path.display());
    assert!(
        pid_file_path.is_file(),
        "missing pid file at {}",
        pid_file_path.display()
    );
    assert!(
        qmp_socket_path.exists(),
        "missing qmp socket at {}",
        qmp_socket_path.display()
    );

    let stream_path = format!(
        "/api/v1/vm/{}/stream?schema_version={}&request_id=stream-1&session_id=session-1&preferred_transport=sse",
        acquire.vm_lease_id,
        honeypot_contracts::SCHEMA_VERSION
    );
    let (status_line, stream): (String, StreamEndpointResponse) = get_authed_json_response(port, &stream_path)
        .await
        .expect("get stream endpoint");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(stream.vm_lease_id, acquire.vm_lease_id);
    assert!(stream.source_ready);
    assert!(stream.capture_source_ref.starts_with("gateway-recording://"));

    let (status_line, release): (String, ReleaseVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/release", acquire.vm_lease_id),
        &ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "release-1".to_owned(),
            session_id: "session-1".to_owned(),
            release_reason: "session_ended".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        },
    )
    .await
    .expect("release lease");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(release.release_state, ReleaseState::Recycling);
    assert!(release.recycle_required);

    let (status_line, recycle): (String, RecycleVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/recycle", acquire.vm_lease_id),
        &RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "recycle-1".to_owned(),
            session_id: "session-1".to_owned(),
            recycle_reason: "release_cleanup".to_owned(),
            quarantine_on_failure: true,
        },
    )
    .await
    .expect("recycle lease");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(recycle.recycle_state, RecycleState::Recycled);
    assert_eq!(recycle.pool_state, PoolState::Ready);
    assert!(!recycle.quarantined);
    assert!(
        !runtime_dir.exists(),
        "runtime dir should be removed after recycle: {}",
        runtime_dir.display()
    );

    let health = read_authed_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 0);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_rejects_unknown_backend_credential_refs() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (status_line, response): (String, ErrorResponse) = post_json_response_with_bearer_token(
        port,
        "/api/v1/vm/acquire",
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        &AcquireVmRequest {
            backend_credential_ref: "missing-backend-credential".to_owned(),
            ..acquire_request("session-missing-backend-credential")
        },
    )
    .await
    .expect("read missing backend credential response");

    assert!(status_line.contains("400"), "{status_line}");
    assert_eq!(response.error_code, ErrorCode::InvalidRequest);
    assert!(
        response.message.contains("backend credential ref"),
        "{}",
        response.message
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_persists_qemu_launch_plan_metadata_on_acquire() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-launch-plan"))
            .await
            .expect("acquire lease");
    let snapshot_path = fixture.lease_store.join(format!("{}.json", acquire.vm_lease_id));
    let snapshot = fs::read_to_string(&snapshot_path).expect("read active lease snapshot");
    let snapshot: serde_json::Value = serde_json::from_str(&snapshot).expect("parse lease snapshot");
    let launch_plan = snapshot
        .get("launch_plan")
        .and_then(serde_json::Value::as_object)
        .expect("launch_plan should be present");

    assert_eq!(
        snapshot.get("pool_name").and_then(serde_json::Value::as_str),
        Some("default")
    );
    assert_eq!(
        launch_plan.get("qemu_binary_path").and_then(serde_json::Value::as_str),
        fixture.qemu_binary_path.to_str()
    );
    assert_eq!(
        launch_plan.get("base_image_path").and_then(serde_json::Value::as_str),
        fixture.base_image_paths[0].to_str()
    );
    assert_eq!(
        launch_plan.get("overlay_path").and_then(serde_json::Value::as_str),
        fixture
            .lease_store
            .join(&acquire.vm_lease_id)
            .join("overlay.qcow2")
            .to_str()
    );
    assert_eq!(
        launch_plan.get("qmp_socket_path").and_then(serde_json::Value::as_str),
        fixture.qmp_dir.join(format!("{}.sock", acquire.vm_lease_id)).to_str()
    );
    assert_eq!(
        snapshot.get("runtime_state").and_then(serde_json::Value::as_str),
        Some("running")
    );
    assert!(
        launch_plan
            .get("argv")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(serde_json::Value::as_str)
            .any(|arg| arg.contains("hostfwd=tcp:127.0.0.1:3389-:3389")),
    );
    assert!(
        fixture
            .lease_store
            .join(&acquire.vm_lease_id)
            .join("overlay.qcow2")
            .is_file(),
        "expected active lease overlay to exist",
    );
    assert!(
        fixture
            .lease_store
            .join(&acquire.vm_lease_id)
            .join("qemu.pid")
            .is_file(),
        "expected active lease pid file to exist",
    );
    assert!(
        fixture.qmp_dir.join(format!("{}.sock", acquire.vm_lease_id)).exists(),
        "expected active lease qmp socket to exist",
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_reports_no_capacity_when_the_pool_is_exhausted() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let _ =
        post_authed_json_response::<_, serde_json::Value>(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
            .await
            .expect("acquire first lease");
    let request_body = serde_json::to_vec(&acquire_request("session-2")).expect("serialize acquire request");
    let (status_line, body) = send_http_request(
        port,
        "POST",
        "/api/v1/vm/acquire",
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        Some(&request_body),
    )
    .await
    .expect("send second acquire request");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("parse error response");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(error.error_code, ErrorCode::NoCapacity);
    assert!(error.retryable);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_keeps_pool_capacity_isolated_by_requested_pool() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 2);
    write_attested_manifest_with_pool(
        &fixture.manifest_paths[1],
        &fixture.base_image_paths[1],
        1,
        base_image_contents(1).as_bytes(),
        "canary",
    );

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, default_acquire): (String, AcquireVmResponse) = post_authed_json_response(
        port,
        "/api/v1/vm/acquire",
        &acquire_request_for_pool("session-default-1", "default"),
    )
    .await
    .expect("acquire default pool lease");
    assert_eq!(default_acquire.vm_name, "honeypot-image-0");

    let default_request_body = serde_json::to_vec(&acquire_request_for_pool("session-default-2", "default"))
        .expect("serialize default pool request");
    let (status_line, body) = send_http_request(
        port,
        "POST",
        "/api/v1/vm/acquire",
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        Some(&default_request_body),
    )
    .await
    .expect("send second default-pool acquire request");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("parse no capacity error");
    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(error.error_code, ErrorCode::NoCapacity);
    assert!(error.message.contains("pool default"), "{}", error.message);

    let (_, canary_acquire): (String, AcquireVmResponse) = post_authed_json_response(
        port,
        "/api/v1/vm/acquire",
        &acquire_request_for_pool("session-canary-1", "canary"),
    )
    .await
    .expect("acquire canary pool lease");
    assert_eq!(canary_acquire.vm_name, "honeypot-image-1");

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_recycle_returns_capacity_to_the_same_pool() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 2);
    write_attested_manifest_with_pool(
        &fixture.manifest_paths[1],
        &fixture.base_image_paths[1],
        1,
        base_image_contents(1).as_bytes(),
        "canary",
    );

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, first_acquire): (String, AcquireVmResponse) = post_authed_json_response(
        port,
        "/api/v1/vm/acquire",
        &acquire_request_for_pool("session-default-1", "default"),
    )
    .await
    .expect("acquire default pool lease");
    assert_eq!(first_acquire.vm_name, "honeypot-image-0");

    let (_, release): (String, ReleaseVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/release", first_acquire.vm_lease_id),
        &ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "release-default-1".to_owned(),
            session_id: "session-default-1".to_owned(),
            release_reason: "session_ended".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        },
    )
    .await
    .expect("release default pool lease");
    assert_eq!(release.release_state, ReleaseState::Recycling);

    let (_, recycle): (String, RecycleVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/recycle", first_acquire.vm_lease_id),
        &RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "recycle-default-1".to_owned(),
            session_id: "session-default-1".to_owned(),
            recycle_reason: "release_cleanup".to_owned(),
            quarantine_on_failure: true,
        },
    )
    .await
    .expect("recycle default pool lease");
    assert_eq!(recycle.pool_state, PoolState::Ready);

    let (_, second_acquire): (String, AcquireVmResponse) = post_authed_json_response(
        port,
        "/api/v1/vm/acquire",
        &acquire_request_for_pool("session-default-2", "default"),
    )
    .await
    .expect("reacquire default pool lease");
    assert_eq!(second_acquire.vm_name, "honeypot-image-0");

    let (_, canary_acquire): (String, AcquireVmResponse) = post_authed_json_response(
        port,
        "/api/v1/vm/acquire",
        &acquire_request_for_pool("session-canary-1", "canary"),
    )
    .await
    .expect("acquire canary pool lease");
    assert_eq!(canary_acquire.vm_name, "honeypot-image-1");

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_quarantines_orphaned_leases_on_restart() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let first_port = find_unused_port();
    let second_port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let first_config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{first_port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &first_config).expect("write first config");

    let mut first_child = honeypot_control_plane_tokio_cmd();
    first_child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut first_child = first_child.spawn().expect("spawn first control-plane");

    wait_for_tcp_port(first_port)
        .await
        .expect("wait for first control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(first_port, "/api/v1/vm/acquire", &acquire_request("session-orphaned"))
            .await
            .expect("acquire lease");
    let active_snapshot_path = fixture.lease_store.join(format!("{}.json", acquire.vm_lease_id));
    let active_runtime_dir = fixture.lease_store.join(&acquire.vm_lease_id);
    let qmp_socket_path = fixture.qmp_dir.join(format!("{}.sock", acquire.vm_lease_id));

    first_child.kill().await.expect("kill first control-plane");
    let _ = first_child.wait().await.expect("wait for first control-plane exit");

    assert!(
        active_snapshot_path.is_file(),
        "expected active snapshot before restart"
    );
    assert!(active_runtime_dir.is_dir(), "expected runtime dir before restart");
    assert!(qmp_socket_path.exists(), "expected qmp socket before restart");

    let second_config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{second_port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &second_config).expect("write second config");

    let mut second_child = honeypot_control_plane_tokio_cmd();
    second_child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut second_child = second_child.spawn().expect("spawn second control-plane");

    wait_for_tcp_port(second_port)
        .await
        .expect("wait for second control-plane port");

    let health = read_authed_health_response(second_port)
        .await
        .expect("read restart health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 1);

    assert!(
        fixture
            .quarantine_store
            .join(format!("{}.json", acquire.vm_lease_id))
            .is_file(),
        "expected orphaned snapshot to move to quarantine",
    );
    assert!(
        fixture
            .quarantine_store
            .join(format!("{}-runtime", acquire.vm_lease_id))
            .is_dir(),
        "expected orphaned runtime dir to move to quarantine",
    );
    assert!(
        !active_snapshot_path.exists(),
        "expected active snapshot removal after restart reconciliation"
    );
    assert!(
        !active_runtime_dir.exists(),
        "expected active runtime dir removal after restart reconciliation"
    );
    assert!(
        !qmp_socket_path.exists(),
        "expected qmp socket removal after restart reconciliation"
    );

    let (_, reacquire): (String, AcquireVmResponse) =
        post_authed_json_response(second_port, "/api/v1/vm/acquire", &acquire_request("session-recovered"))
            .await
            .expect("reacquire cleaned lease");
    assert_eq!(reacquire.vm_name, "honeypot-image-0");

    second_child.kill().await.expect("kill second control-plane");
    let _ = second_child.wait().await.expect("wait for second control-plane exit");
}

#[tokio::test]
async fn control_plane_removes_untracked_runtime_artifacts_on_startup() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    let stray_runtime_dir = fixture.lease_store.join("lease-stray");
    let stray_overlay_path = stray_runtime_dir.join("overlay.qcow2");
    let stray_pid_path = stray_runtime_dir.join("qemu.pid");
    let stray_qmp_path = fixture.qmp_dir.join("lease-stray.sock");

    fs::create_dir_all(&stray_runtime_dir).expect("create stray runtime dir");
    fs::write(&stray_overlay_path, b"stale-overlay").expect("write stray overlay");
    fs::write(&stray_pid_path, b"999999").expect("write stray pid");
    fs::write(&stray_qmp_path, b"stale-qmp").expect("write stray qmp marker");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");
    let health = read_authed_health_response(port).await.expect("read health response");

    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 0);
    assert!(!stray_runtime_dir.exists(), "expected stray runtime dir cleanup");
    assert!(!stray_qmp_path.exists(), "expected stray qmp cleanup");

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_pre_acquire_cleanup_keeps_live_leases_intact() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 2);
    let stray_runtime_dir = fixture.lease_store.join("lease-stray");
    let stray_overlay_path = stray_runtime_dir.join("overlay.qcow2");
    let stray_pid_path = stray_runtime_dir.join("qemu.pid");
    let stray_qmp_path = fixture.qmp_dir.join("lease-stray.sock");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, first_acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-live"))
            .await
            .expect("acquire first lease");
    let first_runtime_dir = fixture.lease_store.join(&first_acquire.vm_lease_id);
    let first_snapshot_path = fixture.lease_store.join(format!("{}.json", first_acquire.vm_lease_id));
    let first_qmp_path = fixture.qmp_dir.join(format!("{}.sock", first_acquire.vm_lease_id));

    fs::create_dir_all(&stray_runtime_dir).expect("create stray runtime dir");
    fs::write(&stray_overlay_path, b"stale-overlay").expect("write stray overlay");
    fs::write(&stray_pid_path, b"999999").expect("write stray pid");
    fs::write(&stray_qmp_path, b"stale-qmp").expect("write stray qmp marker");

    let (_, second_acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-second"))
            .await
            .expect("acquire second lease");

    assert_eq!(second_acquire.vm_name, "honeypot-image-1");
    assert!(first_runtime_dir.is_dir(), "expected first lease runtime dir to remain");
    assert!(first_snapshot_path.is_file(), "expected first lease snapshot to remain");
    assert!(first_qmp_path.exists(), "expected first lease qmp socket to remain");
    assert!(
        !stray_runtime_dir.exists(),
        "expected stray runtime dir cleanup before second acquire"
    );
    assert!(
        !stray_qmp_path.exists(),
        "expected stray qmp cleanup before second acquire"
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[test]
fn control_plane_fails_closed_when_base_image_is_missing_at_startup() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    fs::remove_file(&fixture.base_image_paths[0]).expect("remove base image");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(bind_addr)
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let output = honeypot_control_plane_assert_cmd()
        .env(CONTROL_PLANE_CONFIG_ENV, &config_path)
        .assert()
        .failure();

    let stderr = String::from_utf8_lossy(&output.get_output().stderr);
    assert!(stderr.contains("validate control-plane startup contract"), "{stderr}");
    assert!(
        stderr.contains("trusted base image") || stderr.contains("canonicalize trusted base image"),
        "{stderr}"
    );
}

#[tokio::test]
async fn control_plane_reports_unsafe_when_base_image_digest_changes_after_start() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");
    fs::write(&fixture.base_image_paths[0], b"tampered-base-image").expect("tamper base image");

    let health = read_authed_health_response(port).await.expect("read health response");
    assert_eq!(health.service_state, ServiceState::Unsafe);
    assert_eq!(health.trusted_image_count, 0);
    assert!(
        health
            .degraded_reasons
            .iter()
            .any(|reason| reason.contains("invalid_trusted_images:")),
        "{:?}",
        health.degraded_reasons
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");
    fs::write(&fixture.base_image_paths[0], b"tampered-base-image").expect("tamper base image");

    let request_body =
        serde_json::to_vec(&acquire_request("session-digest-mismatch")).expect("serialize acquire request");
    let (status_line, body) = send_http_request(
        port,
        "POST",
        "/api/v1/vm/acquire",
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        Some(&request_body),
    )
    .await
    .expect("send acquire request");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("parse error response");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(error.error_code, ErrorCode::HostUnavailable);
    assert!(
        error.message.contains("base_image.sha256 mismatch"),
        "{}",
        error.message
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_quarantines_simulated_recycle_failures() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
            .await
            .expect("acquire lease");

    let (status_line, recycle): (String, RecycleVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/recycle", acquire.vm_lease_id),
        &RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "recycle-fail-1".to_owned(),
            session_id: "session-1".to_owned(),
            recycle_reason: "simulate_failure".to_owned(),
            quarantine_on_failure: true,
        },
    )
    .await
    .expect("recycle with simulated failure");

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(recycle.recycle_state, RecycleState::Quarantined);
    assert_eq!(recycle.pool_state, PoolState::Quarantined);
    assert!(recycle.quarantined);

    let health = read_authed_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 1);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[tokio::test]
async fn control_plane_quarantines_recycle_when_base_image_digest_mismatches() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .qemu_binary_path(fixture.qemu_binary_path.clone())
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-integrity"))
            .await
            .expect("acquire lease");

    let (_, release): (String, ReleaseVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/release", acquire.vm_lease_id),
        &ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "release-integrity".to_owned(),
            session_id: "session-integrity".to_owned(),
            release_reason: "session_ended".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        },
    )
    .await
    .expect("release lease");
    assert_eq!(release.release_state, ReleaseState::Recycling);

    fs::write(&fixture.base_image_paths[0], b"tampered-base-image").expect("tamper base image");

    let (status_line, recycle): (String, RecycleVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/recycle", acquire.vm_lease_id),
        &RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "recycle-integrity".to_owned(),
            session_id: "session-integrity".to_owned(),
            recycle_reason: "release_cleanup".to_owned(),
            quarantine_on_failure: true,
        },
    )
    .await
    .expect("recycle lease after tamper");

    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(recycle.recycle_state, RecycleState::Quarantined);
    assert_eq!(recycle.pool_state, PoolState::Quarantined);
    assert!(recycle.quarantined);

    let health = read_authed_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 1);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[cfg(unix)]
#[tokio::test]
async fn control_plane_process_driver_assigns_and_recycles_a_typed_lease() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    let process_qemu_path = install_fake_qemu_binary(tempdir.path(), "fake-qemu");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .qga_dir(fixture.qga_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .enable_guest_agent(true)
        .lifecycle_driver("process")
        .stop_timeout_secs(1)
        .qemu_binary_path(process_qemu_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-process"))
            .await
            .expect("acquire lease");

    assert!(
        fixture.qmp_dir.join(format!("{}.sock", acquire.vm_lease_id)).exists(),
        "expected qmp socket for process lifecycle driver",
    );
    assert!(
        fixture.qga_dir.join(format!("{}.sock", acquire.vm_lease_id)).exists(),
        "expected qga socket for process lifecycle driver",
    );

    let (_, release): (String, ReleaseVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/release", acquire.vm_lease_id),
        &ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "release-process-1".to_owned(),
            session_id: "session-process".to_owned(),
            release_reason: "session_ended".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        },
    )
    .await
    .expect("release lease");
    assert_eq!(release.release_state, ReleaseState::Recycling);

    let (_, recycle): (String, RecycleVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/recycle", acquire.vm_lease_id),
        &RecycleVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "recycle-process-1".to_owned(),
            session_id: "session-process".to_owned(),
            recycle_reason: "release_cleanup".to_owned(),
            quarantine_on_failure: true,
        },
    )
    .await
    .expect("recycle process-backed lease");
    assert_eq!(recycle.recycle_state, RecycleState::Recycled);
    assert_eq!(recycle.pool_state, PoolState::Ready);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[cfg(unix)]
#[tokio::test]
async fn control_plane_process_driver_reports_qemu_startup_failures() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    let process_qemu_path = install_fake_qemu_binary(tempdir.path(), "fake-qemu-early-exit");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .lifecycle_driver("process")
        .stop_timeout_secs(1)
        .qemu_binary_path(process_qemu_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let request_body =
        serde_json::to_vec(&acquire_request("session-process-early-exit")).expect("serialize acquire request");
    let (status_line, body) = send_http_request(
        port,
        "POST",
        "/api/v1/vm/acquire",
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        Some(&request_body),
    )
    .await
    .expect("send acquire request");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("parse error response");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(error.error_code, ErrorCode::HostUnavailable);
    assert!(
        error
            .message
            .contains("qemu exited before the lease reached running state"),
        "{}",
        error.message
    );

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

#[cfg(unix)]
#[tokio::test]
async fn control_plane_process_driver_reports_stop_timeout_and_preserves_the_lease() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let port = find_unused_port();
    let config_path = tempdir.path().join("control-plane.toml");
    let fixture = create_runtime_fixture(tempdir.path(), 1);
    let process_qemu_path = install_fake_qemu_binary(tempdir.path(), "fake-qemu-ignore-term");

    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr(format!("127.0.0.1:{port}"))
        .data_dir(fixture.data_dir.clone())
        .image_store(fixture.image_store.clone())
        .manifest_dir(fixture.manifest_dir.clone())
        .lease_store(fixture.lease_store.clone())
        .quarantine_store(fixture.quarantine_store.clone())
        .qmp_dir(fixture.qmp_dir.clone())
        .secret_dir(fixture.secret_dir.clone())
        .kvm_path(fixture.kvm_path.clone())
        .lifecycle_driver("process")
        .stop_timeout_secs(1)
        .qemu_binary_path(process_qemu_path)
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_authed_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-process-timeout"))
            .await
            .expect("acquire lease");

    let (_, release): (String, ReleaseVmResponse) = post_authed_json_response(
        port,
        &format!("/api/v1/vm/{}/release", acquire.vm_lease_id),
        &ReleaseVmRequest {
            schema_version: honeypot_contracts::SCHEMA_VERSION,
            request_id: "release-process-timeout-1".to_owned(),
            session_id: "session-process-timeout".to_owned(),
            release_reason: "session_ended".to_owned(),
            terminal_outcome: "disconnected".to_owned(),
        },
    )
    .await
    .expect("release lease");
    assert_eq!(release.release_state, ReleaseState::Recycling);

    let request_body = serde_json::to_vec(&RecycleVmRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: "recycle-process-timeout-1".to_owned(),
        session_id: "session-process-timeout".to_owned(),
        recycle_reason: "release_cleanup".to_owned(),
        quarantine_on_failure: true,
    })
    .expect("serialize recycle request");
    let (status_line, body) = send_http_request(
        port,
        "POST",
        &format!("/api/v1/vm/{}/recycle", acquire.vm_lease_id),
        Some(CONTROL_PLANE_SCOPE_TOKEN),
        Some(&request_body),
    )
    .await
    .expect("send recycle request");
    let error: ErrorResponse = serde_json::from_slice(&body).expect("parse recycle error response");

    assert!(status_line.contains("503"), "{status_line}");
    assert_eq!(error.error_code, ErrorCode::HostUnavailable);
    assert!(error.message.contains("did not exit within"), "{}", error.message);

    let health = read_authed_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 1);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

fn acquire_request(session_id: &str) -> AcquireVmRequest {
    acquire_request_for_pool(session_id, "default")
}

fn acquire_request_for_pool(session_id: &str, requested_pool: &str) -> AcquireVmRequest {
    AcquireVmRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("acquire-{session_id}"),
        session_id: session_id.to_owned(),
        requested_pool: requested_pool.to_owned(),
        requested_ready_timeout_secs: 30,
        stream_policy: StreamPolicy::GatewayRecording,
        backend_credential_ref: DEFAULT_BACKEND_CREDENTIAL_REF.to_owned(),
        attacker_protocol: AttackerProtocol::Rdp,
    }
}

struct RuntimeFixture {
    data_dir: std::path::PathBuf,
    image_store: std::path::PathBuf,
    manifest_dir: std::path::PathBuf,
    lease_store: std::path::PathBuf,
    quarantine_store: std::path::PathBuf,
    qmp_dir: std::path::PathBuf,
    qga_dir: std::path::PathBuf,
    secret_dir: std::path::PathBuf,
    kvm_path: std::path::PathBuf,
    qemu_binary_path: std::path::PathBuf,
    manifest_paths: Vec<std::path::PathBuf>,
    base_image_paths: Vec<std::path::PathBuf>,
}

fn create_runtime_fixture(root: &std::path::Path, manifest_count: usize) -> RuntimeFixture {
    let bin_dir = root.join("bin");
    let data_dir = root.join("data");
    let image_store = root.join("images");
    let manifest_dir = image_store.join("manifests");
    let lease_store = root.join("leases");
    let quarantine_store = root.join("quarantine");
    let qmp_dir = root.join("qmp");
    let qga_dir = root.join("qga");
    let secret_dir = root.join("secrets");
    let kvm_path = root.join("kvm");
    let qemu_binary_path = bin_dir.join("qemu-system-x86_64");

    fs::create_dir_all(&bin_dir).expect("create bin dir");
    fs::create_dir_all(&data_dir).expect("create data dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    fs::create_dir_all(&lease_store).expect("create lease dir");
    fs::create_dir_all(&quarantine_store).expect("create quarantine dir");
    fs::create_dir_all(&qmp_dir).expect("create qmp dir");
    fs::create_dir_all(&qga_dir).expect("create qga dir");
    fs::create_dir_all(&secret_dir).expect("create secret dir");
    fs::write(&kvm_path, []).expect("create fake kvm device");
    fs::write(&qemu_binary_path, []).expect("create fake qemu binary");
    fs::write(
        secret_dir.join("backend-credentials.json"),
        serde_json::to_vec_pretty(&serde_json::json!({
            DEFAULT_BACKEND_CREDENTIAL_REF: {
                "proxy_credential": {
                    "kind": "username-password",
                    "username": "operator",
                    "password": "attacker-password"
                },
                "target_credential": {
                    "kind": "username-password",
                    "username": "backend-user",
                    "password": "backend-password"
                }
            }
        }))
        .expect("serialize backend credentials"),
    )
    .expect("write backend credential store");

    let mut manifest_paths = Vec::new();
    let mut base_image_paths = Vec::new();
    for index in 0..manifest_count {
        let manifest_path = manifest_dir.join(format!("image-{index}.json"));
        let base_image_path = image_store.join(format!("image-{index}.qcow2"));
        let base_image_contents = base_image_contents(index);
        fs::write(&base_image_path, base_image_contents.as_bytes()).expect("write fake base image");
        write_attested_manifest(&manifest_path, &base_image_path, index, base_image_contents.as_bytes());
        manifest_paths.push(manifest_path);
        base_image_paths.push(base_image_path);
    }

    RuntimeFixture {
        data_dir,
        image_store,
        manifest_dir,
        lease_store,
        quarantine_store,
        qmp_dir,
        qga_dir,
        secret_dir,
        kvm_path,
        qemu_binary_path,
        manifest_paths,
        base_image_paths,
    }
}

fn write_attested_manifest(
    manifest_path: &std::path::Path,
    base_image_path: &std::path::Path,
    index: usize,
    base_image_contents: &[u8],
) {
    write_attested_manifest_with_pool(manifest_path, base_image_path, index, base_image_contents, "default");
}

fn write_attested_manifest_with_pool(
    manifest_path: &std::path::Path,
    base_image_path: &std::path::Path,
    index: usize,
    base_image_contents: &[u8],
    pool_name: &str,
) {
    let manifest = serde_json::json!({
        "pool_name": pool_name,
        "vm_name": format!("honeypot-image-{index}"),
        "attestation_ref": format!("attestation://gold-image-{index}"),
        "guest_rdp_port": 3389u16.saturating_add(u16::try_from(index).unwrap_or(0)),
        "base_image_path": base_image_path.file_name().and_then(std::ffi::OsStr::to_str).expect("base image file name"),
        "source_iso": {
            "acquisition_channel": "visual-studio-subscription",
            "acquisition_date": "2026-03-25",
            "filename": "windows11-pro-x64-en-us.iso",
            "size_bytes": 1024u64,
            "edition": "Windows 11 Pro x64",
            "language": "en-US",
            "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
        },
        "transformation": {
            "timestamp": "2026-03-25T12:00:00Z",
            "inputs": [
                {
                    "reference": "tiny11-builder.ps1",
                    "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
                },
                {
                    "reference": "tiny11-base.wim",
                    "sha256": "3333333333333333333333333333333333333333333333333333333333333333"
                }
            ]
        },
        "base_image": {
            "sha256": sha256_hex(base_image_contents)
        },
        "approval": {
            "approved_by": "operator@example.test"
        }
    });

    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize attested manifest"),
    )
    .expect("write attested manifest");
}

fn base_image_contents(index: usize) -> String {
    format!("fake-base-image-{index}")
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

#[cfg(unix)]
fn install_fake_qemu_binary(root: &std::path::Path, file_name: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt as _;

    let target_path = root.join("bin").join(file_name);
    fs::copy(fake_qemu_bin_path(), &target_path).expect("copy fake qemu binary");
    let mut permissions = fs::metadata(&target_path)
        .expect("read fake qemu metadata")
        .permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&target_path, permissions).expect("set fake qemu permissions");
    target_path
}
