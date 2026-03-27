#![cfg(unix)]

use std::fs;
use std::path::Path;

use sha2::{Digest, Sha256};
use tempfile::tempdir;
use testsuite::honeypot_control_plane::{
    MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE, MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
    MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION, MANUAL_HEADED_ANCHOR_IDENTITY_BINDING,
    MANUAL_HEADED_ANCHOR_PREREQ_GATE, MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE,
    MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN, MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
    MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE, MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION, ManualHeadedAnchorResult,
    ManualHeadedAnchorStatus, ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL, ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP,
    ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE, ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY, ROW706_EVIDENCE_SCHEMA_VERSION,
    Row706AnchorResult, Row706AnchorStatus, manual_headed_artifacts_root, manual_headed_begin_run,
    manual_headed_complete_run, row706_begin_run, row706_complete_run, verify_manual_headed_evidence_envelope,
    verify_row706_evidence_envelope, write_manual_headed_anchor_result, write_row706_anchor_result,
};
use uuid::Uuid;

const SESSION_ID: &str = "session-1";
const VM_LEASE_ID: &str = "lease-1";

#[test]
fn manual_headed_profile_accepts_complete_runtime_bound_profile() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();

    write_verified_row706_run(&evidence_root, &run_id);
    manual_headed_begin_run(&evidence_root, &run_id).expect("begin manual-headed run");

    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_PREREQ_GATE,
        None,
        None,
        "preflight/prereq.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_IDENTITY_BINDING,
        None,
        None,
        "preflight/identity.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
        None,
        None,
        "runtime/stack.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        None,
        Some(VM_LEASE_ID),
        "runtime/rdp.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/qemu-chrome.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/interaction.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/video.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE,
        None,
        None,
        "preflight/redaction.json",
    );
    write_manual_anchor(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE,
        None,
        None,
        "preflight/storage.json",
    );

    assert!(
        manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run"),
        "all manual-headed anchors should be present"
    );

    let envelope = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect("verify manual-headed evidence envelope");
    assert_eq!(envelope.row706_run_id, run_id);
    assert_eq!(envelope.anchor_results.len(), 9);
}

#[test]
fn manual_headed_profile_rejects_runtime_anchor_without_verified_row706_binding() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();

    manual_headed_begin_run(&evidence_root, &run_id).expect("begin manual-headed run");
    write_all_manual_anchors(&evidence_root, &run_id);
    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("runtime manual anchors should require verified row706 evidence");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("requires a verified row706 run"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_digest_mismatch() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();

    write_verified_row706_run(&evidence_root, &run_id);
    manual_headed_begin_run(&evidence_root, &run_id).expect("begin manual-headed run");
    write_all_manual_anchors(&evidence_root, &run_id);

    let video_artifact = manual_headed_artifacts_root(&evidence_root, &run_id)
        .expect("manual-headed artifacts root")
        .join("runtime/video.json");
    fs::write(&video_artifact, b"tampered-video").expect("tamper manual-headed video artifact");

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");
    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("tampered artifact should fail digest verification");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("digest mismatch"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_escape_relpath() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();

    write_verified_row706_run(&evidence_root, &run_id);
    manual_headed_begin_run(&evidence_root, &run_id).expect("begin manual-headed run");

    let error = write_manual_headed_anchor_result(
        &evidence_root,
        &run_id,
        &ManualHeadedAnchorResult {
            schema_version: MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
            run_id: run_id.clone(),
            row706_run_id: run_id.clone(),
            anchor_id: MANUAL_HEADED_ANCHOR_PREREQ_GATE.to_owned(),
            executed: true,
            status: ManualHeadedAnchorStatus::Passed,
            producer: "integration-test".to_owned(),
            captured_at_unix_secs: 1,
            source_artifact_relpath: "../escape.json".into(),
            source_artifact_sha256: sha256_hex(b"escape"),
            session_id: None,
            vm_lease_id: None,
            detail: Some("escape attempt".to_owned()),
        },
    )
    .expect_err("escaped artifact relpath should fail");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("must not escape") || rendered.contains("must stay relative"),
        "{rendered}"
    );
}

#[test]
fn manual_headed_profile_rejects_missing_session_binding_for_headed_observation() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();

    write_verified_row706_run(&evidence_root, &run_id);
    manual_headed_begin_run(&evidence_root, &run_id).expect("begin manual-headed run");

    let relpath = Path::new("runtime/qemu-chrome.json");
    let body = b"headed observation";
    write_manual_artifact(&evidence_root, &run_id, relpath, body);
    let error = write_manual_headed_anchor_result(
        &evidence_root,
        &run_id,
        &ManualHeadedAnchorResult {
            schema_version: MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
            run_id: run_id.clone(),
            row706_run_id: run_id.clone(),
            anchor_id: MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION.to_owned(),
            executed: true,
            status: ManualHeadedAnchorStatus::Passed,
            producer: "integration-test".to_owned(),
            captured_at_unix_secs: 1,
            source_artifact_relpath: relpath.into(),
            source_artifact_sha256: sha256_hex(body),
            session_id: None,
            vm_lease_id: Some(VM_LEASE_ID.to_owned()),
            detail: Some("missing session id".to_owned()),
        },
    )
    .expect_err("headed observation must require session_id");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("requires session_id"), "{rendered}");
}

fn write_verified_row706_run(evidence_root: &Path, run_id: &str) {
    row706_begin_run(evidence_root, run_id).expect("begin row706 run");
    let image_store_root = evidence_root.join("interop-store");
    fs::create_dir_all(&image_store_root).expect("create image store");
    let base_image_path = image_store_root.join("tiny11.qcow2");
    fs::write(&base_image_path, b"tiny11-base-image").expect("write base image");

    for anchor_id in [
        ROW706_ANCHOR_GOLD_IMAGE_ACCEPTANCE,
        ROW706_ANCHOR_GOLD_IMAGE_REPEATABILITY,
        ROW706_ANCHOR_EXTERNAL_CLIENT_INTEROP,
    ] {
        write_row706_anchor_result(
            evidence_root,
            run_id,
            &Row706AnchorResult {
                schema_version: ROW706_EVIDENCE_SCHEMA_VERSION,
                run_id: run_id.to_owned(),
                anchor_id: anchor_id.to_owned(),
                executed: true,
                status: Row706AnchorStatus::Passed,
                attestation_ref: Some("attestation/tiny11-1".to_owned()),
                base_image_path: Some(base_image_path.clone()),
                image_store_root: Some(image_store_root.clone()),
                detail: Some("synthetic positive row706 anchor".to_owned()),
            },
        )
        .expect("write positive row706 anchor");
    }

    write_row706_anchor_result(
        evidence_root,
        run_id,
        &Row706AnchorResult {
            schema_version: ROW706_EVIDENCE_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            anchor_id: ROW706_ANCHOR_DIGEST_MISMATCH_NEGATIVE_CONTROL.to_owned(),
            executed: true,
            status: Row706AnchorStatus::Passed,
            attestation_ref: None,
            base_image_path: None,
            image_store_root: None,
            detail: Some("synthetic negative-control anchor".to_owned()),
        },
    )
    .expect("write row706 negative control anchor");

    assert!(row706_complete_run(evidence_root, run_id).expect("complete row706 run"));
    verify_row706_evidence_envelope(evidence_root, run_id).expect("verify row706 run");
}

fn write_all_manual_anchors(evidence_root: &Path, run_id: &str) {
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_PREREQ_GATE,
        None,
        None,
        "preflight/prereq.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_IDENTITY_BINDING,
        None,
        None,
        "preflight/identity.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
        None,
        None,
        "runtime/stack.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_TINY11_RDP_READY,
        None,
        Some(VM_LEASE_ID),
        "runtime/rdp.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/qemu-chrome.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/interaction.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        "runtime/video.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_REDACTION_HYGIENE,
        None,
        None,
        "preflight/redaction.json",
    );
    write_manual_anchor(
        evidence_root,
        run_id,
        MANUAL_HEADED_ANCHOR_ARTIFACT_STORAGE,
        None,
        None,
        "preflight/storage.json",
    );
}

fn write_manual_anchor(
    evidence_root: &Path,
    run_id: &str,
    anchor_id: &str,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
    relpath: &str,
) {
    let relpath = Path::new(relpath);
    let body = format!("manual-headed artifact for {anchor_id}");
    write_manual_artifact(evidence_root, run_id, relpath, body.as_bytes());

    write_manual_headed_anchor_result(
        evidence_root,
        run_id,
        &ManualHeadedAnchorResult {
            schema_version: MANUAL_HEADED_EVIDENCE_SCHEMA_VERSION,
            run_id: run_id.to_owned(),
            row706_run_id: run_id.to_owned(),
            anchor_id: anchor_id.to_owned(),
            executed: true,
            status: ManualHeadedAnchorStatus::Passed,
            producer: "integration-test".to_owned(),
            captured_at_unix_secs: 1,
            source_artifact_relpath: relpath.into(),
            source_artifact_sha256: sha256_hex(body.as_bytes()),
            session_id: session_id.map(ToOwned::to_owned),
            vm_lease_id: vm_lease_id.map(ToOwned::to_owned),
            detail: Some(format!("captured {anchor_id}")),
        },
    )
    .expect("write manual-headed anchor");
}

fn write_manual_artifact(evidence_root: &Path, run_id: &str, relpath: &Path, body: &[u8]) {
    let artifact_path = manual_headed_artifacts_root(evidence_root, run_id)
        .expect("manual-headed artifacts root")
        .join(relpath);
    fs::create_dir_all(artifact_path.parent().expect("artifact path parent"))
        .expect("create manual-headed artifact parent");
    fs::write(&artifact_path, body).expect("write manual-headed artifact");
}

fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
