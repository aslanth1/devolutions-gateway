use std::fs;

use honeypot_contracts::control_plane::{
    AcquireVmRequest, AcquireVmResponse, AttackerProtocol, PoolState, RecycleState, RecycleVmRequest,
    RecycleVmResponse, ReleaseState, ReleaseVmRequest, ReleaseVmResponse, ResetState, ResetVmRequest, ResetVmResponse,
    ServiceState, StreamEndpointResponse, StreamPolicy,
};
use honeypot_contracts::error::{ErrorCode, ErrorResponse};
use testsuite::cli::wait_for_tcp_port;
use testsuite::honeypot_control_plane::{
    HoneypotControlPlaneTestConfig, find_unused_port, get_json_response, honeypot_control_plane_assert_cmd,
    honeypot_control_plane_tokio_cmd, post_json_response, read_health_response, send_http_request,
    write_honeypot_control_plane_config,
};

const CONTROL_PLANE_CONFIG_ENV: &str = "HONEYPOT_CONTROL_PLANE_CONFIG";

#[test]
fn control_plane_fails_closed_when_required_paths_are_missing() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let config_path = tempdir.path().join("control-plane.toml");
    let bind_addr = format!("127.0.0.1:{}", find_unused_port());

    let existing_dir = tempdir.path().join("existing");
    fs::create_dir_all(&existing_dir).expect("create existing dir");

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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    let health = read_health_response(port).await.expect("read health response");

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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    let health = read_health_response(port).await.expect("read health response");

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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for health port");
    fs::remove_file(&fixture.kvm_path).expect("remove fake kvm device");
    let health = read_health_response(port).await.expect("read health response");

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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (status_line, acquire): (String, AcquireVmResponse) =
        post_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
            .await
            .expect("acquire lease");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(
        acquire.lease_state,
        honeypot_contracts::control_plane::LeaseState::Assigned
    );
    assert_eq!(acquire.backend_credential_ref, "cred-ref-session-1");
    assert!(acquire.vm_name.starts_with("honeypot-"));

    let (status_line, reset): (String, ResetVmResponse) = post_json_response(
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

    let stream_path = format!(
        "/api/v1/vm/{}/stream?schema_version={}&request_id=stream-1&session_id=session-1&preferred_transport=sse",
        acquire.vm_lease_id,
        honeypot_contracts::SCHEMA_VERSION
    );
    let (status_line, stream): (String, StreamEndpointResponse) = get_json_response(port, &stream_path)
        .await
        .expect("get stream endpoint");
    assert!(status_line.contains("200"), "{status_line}");
    assert_eq!(stream.vm_lease_id, acquire.vm_lease_id);
    assert!(stream.source_ready);
    assert!(stream.capture_source_ref.starts_with("gateway-recording://"));

    let (status_line, release): (String, ReleaseVmResponse) = post_json_response(
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

    let (status_line, recycle): (String, RecycleVmResponse) = post_json_response(
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

    let health = read_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 0);

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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let _ = post_json_response::<_, serde_json::Value>(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
        .await
        .expect("acquire first lease");
    let request_body = serde_json::to_vec(&acquire_request("session-2")).expect("serialize acquire request");
    let (status_line, body) = send_http_request(port, "POST", "/api/v1/vm/acquire", Some(&request_body))
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
        .build();

    write_honeypot_control_plane_config(&config_path, &config).expect("write config");

    let mut child = honeypot_control_plane_tokio_cmd();
    child.env(CONTROL_PLANE_CONFIG_ENV, &config_path);
    let mut child = child.spawn().expect("spawn control-plane");

    wait_for_tcp_port(port).await.expect("wait for control-plane port");

    let (_, acquire): (String, AcquireVmResponse) =
        post_json_response(port, "/api/v1/vm/acquire", &acquire_request("session-1"))
            .await
            .expect("acquire lease");

    let (status_line, recycle): (String, RecycleVmResponse) = post_json_response(
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

    let health = read_health_response(port).await.expect("read health response");
    assert_eq!(health.active_lease_count, 0);
    assert_eq!(health.quarantined_lease_count, 1);

    child.kill().await.expect("kill control-plane");
    let _ = child.wait().await.expect("wait for control-plane exit");
}

fn acquire_request(session_id: &str) -> AcquireVmRequest {
    AcquireVmRequest {
        schema_version: honeypot_contracts::SCHEMA_VERSION,
        request_id: format!("acquire-{session_id}"),
        session_id: session_id.to_owned(),
        requested_pool: "default".to_owned(),
        requested_ready_timeout_secs: 30,
        stream_policy: StreamPolicy::GatewayRecording,
        backend_credential_ref: format!("cred-ref-{session_id}"),
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
    secret_dir: std::path::PathBuf,
    kvm_path: std::path::PathBuf,
}

fn create_runtime_fixture(root: &std::path::Path, manifest_count: usize) -> RuntimeFixture {
    let data_dir = root.join("data");
    let image_store = root.join("images");
    let manifest_dir = image_store.join("manifests");
    let lease_store = root.join("leases");
    let quarantine_store = root.join("quarantine");
    let qmp_dir = root.join("qmp");
    let secret_dir = root.join("secrets");
    let kvm_path = root.join("kvm");

    fs::create_dir_all(&data_dir).expect("create data dir");
    fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    fs::create_dir_all(&lease_store).expect("create lease dir");
    fs::create_dir_all(&quarantine_store).expect("create quarantine dir");
    fs::create_dir_all(&qmp_dir).expect("create qmp dir");
    fs::create_dir_all(&secret_dir).expect("create secret dir");
    fs::write(&kvm_path, []).expect("create fake kvm device");

    for index in 0..manifest_count {
        let manifest_path = manifest_dir.join(format!("image-{index}.json"));
        fs::write(manifest_path, "{}").expect("write fake manifest");
    }

    RuntimeFixture {
        data_dir,
        image_store,
        manifest_dir,
        lease_store,
        quarantine_store,
        qmp_dir,
        secret_dir,
        kvm_path,
    }
}
