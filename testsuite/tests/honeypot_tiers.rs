use std::fs;

use testsuite::honeypot_tiers::{
    HONEYPOT_TIER_GATE_ENV, HoneypotTestTier, HoneypotTierGate, HoneypotTierSelection, load_honeypot_tier_gate,
};

#[test]
fn contract_is_the_default_honeypot_tier() {
    let selection = HoneypotTierSelection {
        active_tier: HoneypotTestTier::Contract,
        gate_path: None,
    };

    assert!(selection.allows(HoneypotTestTier::Contract));
    assert!(!selection.allows(HoneypotTestTier::HostSmoke));
    assert!(!selection.allows(HoneypotTestTier::LabE2e));
}

#[test]
fn lab_e2e_gate_requires_prerequisite_passes() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("honeypot-tier-gate.json");

    fs::write(
        &gate_path,
        serde_json::to_string(&HoneypotTierGate {
            contract_passed: true,
            host_smoke_passed: false,
        })
        .expect("serialize gate"),
    )
    .expect("write gate");

    let selection = HoneypotTierSelection {
        active_tier: HoneypotTestTier::LabE2e,
        gate_path: Some(gate_path),
    };

    let error = selection
        .require(HoneypotTestTier::LabE2e)
        .expect_err("lab gate should fail closed without host-smoke");
    let error_text = format!("{error:#}");

    assert!(error_text.contains(HONEYPOT_TIER_GATE_ENV), "{error_text}");
    assert!(
        error_text.contains("contract_passed=true and host_smoke_passed=true"),
        "{error_text}"
    );
}

#[test]
fn lab_e2e_gate_accepts_ready_manifest() {
    let tempdir = tempfile::tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("honeypot-tier-gate.json");

    fs::write(
        &gate_path,
        serde_json::to_string(&HoneypotTierGate {
            contract_passed: true,
            host_smoke_passed: true,
        })
        .expect("serialize gate"),
    )
    .expect("write gate");

    let selection = HoneypotTierSelection {
        active_tier: HoneypotTestTier::LabE2e,
        gate_path: Some(gate_path.clone()),
    };

    let gate = load_honeypot_tier_gate(&gate_path).expect("load gate");
    assert!(gate.is_ready_for_lab_e2e());
    selection
        .require(HoneypotTestTier::LabE2e)
        .expect("lab gate should accept ready manifest");
}
