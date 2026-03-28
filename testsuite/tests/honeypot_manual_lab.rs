use std::fs;

use serde_json::json;
use testsuite::honeypot_manual_lab::{
    ManualLabProxyConfigOptions, honeypot_manual_lab_assert_cmd, render_manual_lab_proxy_config,
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
    assert!(rendered.contains("status"), "{rendered}");
    assert!(rendered.contains("down"), "{rendered}");
}
