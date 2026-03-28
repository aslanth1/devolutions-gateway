use std::fs;

use serde_json::json;
use tempfile::tempdir;
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
    assert!(rendered.contains("consume-image"), "{rendered}");
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

    let preflight_output = honeypot_manual_lab_assert_cmd()
        .arg("preflight")
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
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

    let output = honeypot_manual_lab_assert_cmd()
        .args(["preflight", "--format=json"])
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &missing_store_root)
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

fn blocker_lines(output: &str) -> Vec<&str> {
    output
        .lines()
        .filter(|line| line.contains("blocked by") || line.starts_with("remediation:"))
        .collect()
}
