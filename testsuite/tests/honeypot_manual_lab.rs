use std::fs;
use std::path::{Path, PathBuf};

use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use testsuite::honeypot_control_plane::{
    HoneypotControlPlaneTestConfig, fake_qemu_bin_path, write_honeypot_control_plane_config,
};
use testsuite::honeypot_manual_lab::{
    ManualLabProxyConfigOptions, active_state_path, honeypot_manual_lab_assert_cmd, render_manual_lab_proxy_config,
    render_three_host_trusted_image_manifest,
};
use testsuite::honeypot_release::{HONEYPOT_PROXY_CONFIG_PATH, repo_relative_path};

#[test]
fn manual_lab_trusted_image_manifest_preserves_lineage_and_rebinds_identity() {
    let source_manifest = json!({
        "pool_name": "ingest-pool",
        "vm_name": "gold-image-01",
        "guest_rdp_port": 3389,
        "attestation_ref": "attestation://tiny11-gold",
        "base_image_path": "images/tiny11.qcow2",
        "source_iso": {
            "sha256": "iso-sha",
        },
        "transformation": {
            "script_sha256": "transform-sha",
        },
        "base_image": {
            "sha256": "base-image-sha",
        },
        "approval": {
            "approved_by": "operator",
        },
        "boot_profile_v1": {
            "qemu_args": ["-machine", "q35"],
        }
    });

    let rendered = render_three_host_trusted_image_manifest(&source_manifest, "default", "manual-deck-02", 3392)
        .expect("render manual lab manifest");

    assert_eq!(rendered.get("pool_name"), Some(&json!("default")));
    assert_eq!(rendered.get("vm_name"), Some(&json!("manual-deck-02")));
    assert_eq!(rendered.get("guest_rdp_port"), Some(&json!(3392)));
    assert_eq!(rendered.get("attestation_ref"), source_manifest.get("attestation_ref"));
    assert_eq!(rendered.get("base_image_path"), source_manifest.get("base_image_path"));
    assert_eq!(rendered.get("boot_profile_v1"), source_manifest.get("boot_profile_v1"));
}

#[test]
fn manual_lab_proxy_config_injects_loopback_runtime_overrides() {
    let sample_path = repo_relative_path(HONEYPOT_PROXY_CONFIG_PATH);
    let sample_json = fs::read_to_string(&sample_path).expect("read proxy config sample");

    let rendered = render_manual_lab_proxy_config(
        &sample_json,
        &ManualLabProxyConfigOptions {
            control_plane_http_port: 18080,
            proxy_http_port: 18081,
            proxy_tcp_port: 18443,
            frontend_http_port: 18082,
            control_plane_service_token_file: "/tmp/manual-lab/control-plane-service-token".into(),
            proxy_backend_credentials_file: "/tmp/manual-lab/backend-credentials.json".into(),
        },
    )
    .expect("render proxy config");
    let document: serde_json::Value = serde_json::from_str(&rendered).expect("parse rendered proxy config");

    assert_eq!(
        document.pointer("/Listeners/0/InternalUrl"),
        Some(&json!("tcp://127.0.0.1:18443"))
    );
    assert_eq!(
        document.pointer("/Listeners/1/InternalUrl"),
        Some(&json!("http://127.0.0.1:18081"))
    );
    assert_eq!(
        document.pointer("/Honeypot/ControlPlane/Endpoint"),
        Some(&json!("http://127.0.0.1:18080/"))
    );
    assert_eq!(
        document.pointer("/Honeypot/Frontend/PublicUrl"),
        Some(&json!("http://127.0.0.1:18082/"))
    );
    assert_eq!(
        document.pointer("/__debug__/honeypot_backend_credentials_file"),
        Some(&json!("/tmp/manual-lab/backend-credentials.json"))
    );
    assert!(document.pointer("/ProvisionerPrivateKeyData/Value").is_some());
}

#[test]
fn manual_lab_cli_help_lists_up_status_and_down() {
    let output = honeypot_manual_lab_assert_cmd()
        .arg("help")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("up [--no-browser]"), "{rendered}");
    assert!(rendered.contains("preflight"), "{rendered}");
    assert!(rendered.contains("bootstrap-store"), "{rendered}");
    assert!(rendered.contains("remember-source-manifest"), "{rendered}");
    assert!(rendered.contains("status"), "{rendered}");
    assert!(rendered.contains("down"), "{rendered}");
}

#[test]
fn manual_lab_cli_preflight_reports_missing_store_root_without_side_effects() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    fs::write(
        &gate_path,
        serde_json::to_vec_pretty(&json!({
            "contract_passed": true,
            "host_smoke_passed": true,
        }))
        .expect("serialize gate"),
    )
    .expect("write gate");
    let missing_store_root = tempdir.path().join("missing-store-root");
    let config_path = write_manual_lab_bootstrap_config(
        &tempdir.path().join("control-plane.toml"),
        &missing_store_root,
        &missing_store_root.join("manifests"),
    );

    let active_path = active_state_path();
    assert!(
        !active_path.exists(),
        "manual lab CLI tests require no active state at {}",
        active_path.display()
    );

    let output = honeypot_manual_lab_assert_cmd()
        .arg("preflight")
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
        .env("MANUAL_LAB_CONTROL_PLANE_CONFIG", &config_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(
        rendered.contains("manual lab blocked by missing_store_root"),
        "{rendered}"
    );
    assert!(rendered.contains("manual-lab-remember-source-manifest"), "{rendered}");
    assert!(
        !active_path.exists(),
        "preflight must not create active state at {}",
        active_path.display()
    );
}

#[test]
fn manual_lab_cli_preflight_and_up_share_missing_store_root_blocker() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    fs::write(
        &gate_path,
        serde_json::to_vec_pretty(&json!({
            "contract_passed": true,
            "host_smoke_passed": true,
        }))
        .expect("serialize gate"),
    )
    .expect("write gate");
    let missing_store_root = tempdir.path().join("missing-store-root");
    let config_path = write_manual_lab_bootstrap_config(
        &tempdir.path().join("control-plane.toml"),
        &missing_store_root,
        &missing_store_root.join("manifests"),
    );

    let preflight_output = honeypot_manual_lab_assert_cmd()
        .arg("preflight")
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
        .env("MANUAL_LAB_CONTROL_PLANE_CONFIG", &config_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let preflight_rendered = String::from_utf8(preflight_output).expect("utf8 preflight stdout");

    let up_output = honeypot_manual_lab_assert_cmd()
        .arg("up")
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
        .env("MANUAL_LAB_CONTROL_PLANE_CONFIG", &config_path)
        .assert()
        .code(1)
        .get_output()
        .stderr
        .clone();
    let up_rendered = String::from_utf8(up_output).expect("utf8 up stderr");

    let preflight_lines = blocker_lines(&preflight_rendered);
    let up_lines = blocker_lines(&up_rendered);
    assert_eq!(preflight_lines, up_lines);
}

#[test]
fn manual_lab_cli_preflight_json_reports_missing_store_root() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    fs::write(
        &gate_path,
        serde_json::to_vec_pretty(&json!({
            "contract_passed": true,
            "host_smoke_passed": true,
        }))
        .expect("serialize gate"),
    )
    .expect("write gate");
    let missing_store_root = tempdir.path().join("missing-store-root");
    let config_path = write_manual_lab_bootstrap_config(
        &tempdir.path().join("control-plane.toml"),
        &missing_store_root,
        &missing_store_root.join("manifests"),
    );

    let output = honeypot_manual_lab_assert_cmd()
        .args(["preflight", "--format=json"])
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
        .env("MANUAL_LAB_CONTROL_PLANE_CONFIG", &config_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let report: serde_json::Value = serde_json::from_slice(&output).expect("parse preflight json");

    assert_eq!(report.pointer("/status"), Some(&json!("blocked")));
    assert_eq!(report.pointer("/blocker"), Some(&json!("missing_store_root")));
    assert_eq!(
        report.pointer("/image_store_root"),
        Some(&json!(missing_store_root.display().to_string()))
    );
    assert!(report.pointer("/remediation").is_some(), "{report}");
}

#[test]
fn manual_lab_cli_bootstrap_store_is_dry_run_by_default() {
    let tempdir = tempdir().expect("create tempdir");
    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "dry-run");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--config")
        .arg(&config_path)
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab bootstrap ready"), "{rendered}");
    assert!(rendered.contains("source_manifest_digest="), "{rendered}");
    assert!(rendered.contains("consume_image_command="), "{rendered}");
    assert!(
        !image_store.exists(),
        "dry-run bootstrap-store must not create {}",
        image_store.display()
    );
}

#[test]
fn manual_lab_cli_bootstrap_store_execute_imports_and_rechecks_preflight() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    write_manual_lab_gate(&gate_path);

    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "execute");

    let kvm_path = tempdir.path().join("dev-kvm");
    fs::write(&kvm_path, b"kvm").expect("write fake kvm device");
    let xfreerdp_path = tempdir.path().join("xfreerdp");
    fs::write(&xfreerdp_path, b"#!/bin/sh\nexit 0\n").expect("write fake xfreerdp");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--execute")
        .arg("--config")
        .arg(&config_path)
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .env("DGW_HONEYPOT_INTEROP_QEMU_BINARY", fake_qemu_bin_path())
        .env("DGW_HONEYPOT_INTEROP_KVM_PATH", &kvm_path)
        .env("DGW_HONEYPOT_INTEROP_XFREERDP_PATH", &xfreerdp_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "operator")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "password")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab bootstrap executed"), "{rendered}");
    assert!(rendered.contains("source_manifest_digest="), "{rendered}");
    assert!(rendered.contains("post_import_preflight_status=ready"), "{rendered}");
    assert!(image_store.is_dir(), "{}", image_store.display());
    assert!(manifest_dir.is_dir(), "{}", manifest_dir.display());
    assert!(
        fs::read_dir(&manifest_dir)
            .expect("read imported manifest dir")
            .any(|entry| entry
                .expect("manifest dir entry")
                .path()
                .extension()
                .is_some_and(|ext| ext == "json")),
        "{} should contain an imported manifest",
        manifest_dir.display()
    );
}

#[test]
fn manual_lab_cli_remember_source_manifest_writes_local_hint_for_admissible_manifest() {
    let tempdir = tempdir().expect("create tempdir");
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "remember");
    let selection_path = tempdir.path().join("selected-source-manifest.json");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("remember-source-manifest")
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab source manifest remembered"), "{rendered}");
    assert!(selection_path.is_file(), "{}", selection_path.display());

    let record: serde_json::Value =
        serde_json::from_slice(&fs::read(&selection_path).expect("read selection file")).expect("parse selection file");
    assert_eq!(
        record.pointer("/path"),
        Some(&json!(
            source_manifest
                .canonicalize()
                .expect("canonicalize source manifest")
                .display()
                .to_string()
        ))
    );
    assert_eq!(
        record.pointer("/digest"),
        Some(&json!(sha256_hex(
            &fs::read(&source_manifest).expect("read source manifest")
        )))
    );
}

#[test]
fn manual_lab_cli_bootstrap_store_uses_remembered_source_manifest_when_explicit_source_is_absent() {
    let tempdir = tempdir().expect("create tempdir");
    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "remembered-bootstrap");
    let selection_path = tempdir.path().join("selected-source-manifest.json");

    honeypot_manual_lab_assert_cmd()
        .arg("remember-source-manifest")
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success();

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--config")
        .arg(&config_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab bootstrap ready"), "{rendered}");
    assert!(
        rendered.contains(&format!(
            "source_manifest_path={}",
            source_manifest
                .canonicalize()
                .expect("canonicalize source manifest")
                .display()
        )),
        "{rendered}"
    );
    assert!(rendered.contains("source_manifest_digest="), "{rendered}");
}

#[test]
fn manual_lab_cli_bootstrap_store_explicit_source_overrides_remembered_hint() {
    let tempdir = tempdir().expect("create tempdir");
    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let remembered_manifest = create_manual_lab_source_bundle(tempdir.path(), "remembered");
    let explicit_manifest = create_manual_lab_source_bundle(tempdir.path(), "explicit");
    let selection_path = tempdir.path().join("selected-source-manifest.json");

    honeypot_manual_lab_assert_cmd()
        .arg("remember-source-manifest")
        .arg("--source-manifest")
        .arg(&remembered_manifest)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success();

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--config")
        .arg(&config_path)
        .arg("--source-manifest")
        .arg(&explicit_manifest)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(
        rendered.contains(&format!(
            "source_manifest_path={}",
            explicit_manifest
                .canonicalize()
                .expect("canonicalize explicit manifest")
                .display()
        )),
        "{rendered}"
    );
    assert!(
        !rendered.contains(
            &remembered_manifest
                .canonicalize()
                .expect("canonicalize remembered manifest")
                .display()
                .to_string()
        ),
        "{rendered}"
    );
}

#[test]
fn manual_lab_cli_bootstrap_store_blocks_on_stale_remembered_source_manifest() {
    let tempdir = tempdir().expect("create tempdir");
    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "stale");
    let selection_path = tempdir.path().join("selected-source-manifest.json");

    honeypot_manual_lab_assert_cmd()
        .arg("remember-source-manifest")
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .success();

    fs::write(&source_manifest, b"{\"tampered\":true}").expect("tamper source manifest");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--config")
        .arg(&config_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .env("DGW_HONEYPOT_MANUAL_LAB_SELECTED_SOURCE_MANIFEST", &selection_path)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("remembered_source_manifest_invalid"), "{rendered}");
    assert!(rendered.contains("manual-lab-remember-source-manifest"), "{rendered}");
}

fn blocker_lines(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| line.contains("blocked by") || line.starts_with("remediation:"))
        .collect()
}

fn write_manual_lab_gate(path: &Path) {
    fs::write(
        path,
        serde_json::to_vec_pretty(&json!({
            "contract_passed": true,
            "host_smoke_passed": true,
        }))
        .expect("serialize gate"),
    )
    .expect("write gate");
}

fn write_manual_lab_bootstrap_config(path: &Path, image_store: &Path, manifest_dir: &Path) -> PathBuf {
    let root = path.parent().expect("config path should have parent");
    let config = HoneypotControlPlaneTestConfig::builder()
        .bind_addr("127.0.0.1:18080")
        .data_dir(root.join("data"))
        .image_store(image_store)
        .manifest_dir(manifest_dir)
        .lease_store(root.join("leases"))
        .quarantine_store(root.join("quarantine"))
        .qmp_dir(root.join("qmp"))
        .secret_dir(root.join("secrets"))
        .kvm_path(root.join("dev-kvm"))
        .qemu_binary_path(fake_qemu_bin_path())
        .build();
    write_honeypot_control_plane_config(path, &config).expect("write control-plane config");
    path.to_path_buf()
}

fn create_manual_lab_source_bundle(root: &Path, suffix: &str) -> PathBuf {
    let bundle_root = root.join(format!("source-bundle-{suffix}"));
    fs::create_dir_all(&bundle_root).expect("create bundle root");

    let base_image_path = bundle_root.join("tiny11-base.qcow2");
    let base_image_bytes = format!("tiny11-{suffix}-base-image").into_bytes();
    fs::write(&base_image_path, &base_image_bytes).expect("write base image");
    let base_image_sha256 = sha256_hex(&base_image_bytes);

    let manifest_path = bundle_root.join("bundle-manifest.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&json!({
            "pool_name": "default",
            "vm_name": format!("tiny11-{suffix}-candidate"),
            "attestation_ref": format!("attestation://tiny11-{suffix}-candidate"),
            "guest_rdp_port": 3389,
            "base_image_path": "tiny11-base.qcow2",
            "source_iso": {
                "acquisition_channel": "local-test",
                "acquisition_date": "2026-03-28",
                "filename": "windows11-pro-x64-en-us.iso",
                "size_bytes": 1024,
                "edition": "Windows 11 Pro x64",
                "language": "en-US",
                "sha256": "1111111111111111111111111111111111111111111111111111111111111111"
            },
            "transformation": {
                "timestamp": "2026-03-28T12:00:00Z",
                "inputs": [
                    {
                        "reference": "tiny11-builder.ps1",
                        "sha256": "2222222222222222222222222222222222222222222222222222222222222222"
                    }
                ]
            },
            "base_image": {
                "sha256": base_image_sha256
            },
            "approval": {
                "approved_by": "operator@example.test"
            }
        }))
        .expect("serialize source manifest"),
    )
    .expect("write source manifest");

    manifest_path
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
