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
    Row706AnchorResult, Row706AnchorStatus, honeypot_manual_headed_writer_assert_cmd, manual_headed_artifacts_root,
    manual_headed_begin_run, manual_headed_complete_run, row706_begin_run, row706_complete_run,
    verify_manual_headed_evidence_envelope, verify_row706_evidence_envelope, write_manual_headed_anchor_result,
    write_row706_anchor_result,
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
fn manual_headed_profile_rejects_weak_stack_startup_shutdown_artifact() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
        None,
        None,
        Path::new("runtime/stack.json"),
        br#"{"startup_captured_at_unix_secs":1,"teardown_captured_at_unix_secs":2,"services":{"control-plane":{"evidence_kind":"health","startup_status":"healthy"},"proxy":{"evidence_kind":"health","startup_status":"healthy"}},"teardown_disposition":"clean_shutdown"}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("weak stack startup or shutdown artifact should fail verification");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("exactly three services"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_weak_video_evidence_artifact() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        Path::new("runtime/video.json"),
        br#"{"video_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp_window":{"start_unix_secs":1,"end_unix_secs":5},"storage_uri":"target/manual/video.webm","retention_window":{"policy":"manual-review","expires_at_unix_secs":10},"session_id":"session-1","vm_lease_id":"lease-1"}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("weak video evidence artifact should fail verification");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("duration_floor_secs"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_weak_headed_qemu_chrome_observation_artifact() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        Path::new("runtime/qemu-chrome.json"),
        br#"{"qemu_display_mode":"headed","qemu_launch_reference":"target/qemu-display.sock","browser_family":"chrome","correlation_snapshot":{"observed_surface":"tile","observed_session_id":"session-1","observed_vm_lease_id":"lease-1"}}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("weak headed QEMU plus Chrome observation artifact should fail verification");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("frontend_access_path"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_headed_observation_vm_lease_mismatch_with_rdp_ready() {
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
        Some("lease-2"),
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("headed observation should bind to the same vm lease as RDP-ready evidence");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("same vm_lease_id"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_noop_bounded_interaction_artifact() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        Path::new("runtime/interaction.json"),
        br#"{"interaction_window":{"start_unix_secs":2,"end_unix_secs":8},"session_id":"session-1","vm_lease_id":"lease-1","modalities":{"mouse":{"event_count":0,"evidence_refs":["video://mouse"]},"keyboard":{"event_count":3,"evidence_refs":["video://keyboard"]},"browsing":{"event_count":1,"evidence_refs":["video://browsing"]}}}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("no-op bounded interaction artifact should fail verification");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("modalities.mouse.event_count > 0"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_bounded_interaction_session_mismatch_with_headed_observation() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        Some("session-2"),
        Some(VM_LEASE_ID),
        Path::new("runtime/interaction.json"),
        br#"{"interaction_window":{"start_unix_secs":2,"end_unix_secs":8},"session_id":"session-2","vm_lease_id":"lease-1","modalities":{"mouse":{"event_count":2,"evidence_refs":["video://mouse"]},"keyboard":{"event_count":3,"evidence_refs":["video://keyboard"]},"browsing":{"event_count":1,"evidence_refs":["video://browsing"]}}}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("bounded interaction should bind to the same session as headed observation");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("same session_id"), "{rendered}");
}

#[test]
fn manual_headed_profile_rejects_bounded_interaction_window_outside_video_window() {
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
    write_manual_anchor_with_body(
        &evidence_root,
        &run_id,
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
        Some(SESSION_ID),
        Some(VM_LEASE_ID),
        Path::new("runtime/interaction.json"),
        br#"{"interaction_window":{"start_unix_secs":20,"end_unix_secs":30},"session_id":"session-1","vm_lease_id":"lease-1","modalities":{"mouse":{"event_count":2,"evidence_refs":["video://mouse"]},"keyboard":{"event_count":3,"evidence_refs":["video://keyboard"]},"browsing":{"event_count":1,"evidence_refs":["video://browsing"]}}}"#,
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

    manual_headed_complete_run(&evidence_root, &run_id).expect("complete manual-headed run");

    let error = verify_manual_headed_evidence_envelope(&evidence_root, &run_id)
        .expect_err("bounded interaction must stay within the recorded video window");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("must stay within the recorded video timestamp_window"),
        "{rendered}"
    );
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

#[test]
fn manual_headed_writer_preflight_records_blocked_prereq_anchor_without_row706_verification() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("preflight-prereq.json");
    fs::write(
        &source_artifact,
        br#"{"manual_lab_gate":true,"headed_display_available":true,"chrome_binary":"google-chrome","windows_provisioning_key_path":"WINDOWS11-LICENSE.md","interop_store_status":"missing"}"#,
    )
    .expect("write preflight source artifact");

    honeypot_manual_headed_writer_assert_cmd()
        .args([
            "preflight",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_PREREQ_GATE,
            "--status",
            "blocked_prereq",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "preflight/prereq.json",
            "--detail",
            "attested Tiny11 interop store not configured on this host",
        ])
        .assert()
        .success();

    let result_path = evidence_root
        .join("runs")
        .join(&run_id)
        .join("manual_headed")
        .join(format!("{MANUAL_HEADED_ANCHOR_PREREQ_GATE}.json"));
    let result: ManualHeadedAnchorResult =
        serde_json::from_slice(&fs::read(&result_path).expect("read manual-headed result"))
            .expect("parse manual-headed result");
    assert!(!result.executed);
    assert_eq!(result.status, ManualHeadedAnchorStatus::BlockedPrereq);
}

#[test]
fn manual_headed_writer_runtime_rejects_unverified_row706_run() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("runtime-stack.json");
    fs::write(
        &source_artifact,
        br#"{"services":{"control-plane":{"status":"healthy"},"proxy":{"status":"healthy"},"frontend":{"status":"healthy"}},"teardown_disposition":"not_started"}"#,
    )
    .expect("write runtime source artifact");

    let output = honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/stack.json",
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let rendered = String::from_utf8(output).expect("stderr to utf8");
    assert!(rendered.contains("requires a verified row706 run"), "{rendered}");
    assert!(
        !evidence_root
            .join("runs")
            .join(&run_id)
            .join("manual_headed")
            .join(format!("{MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN}.json"))
            .exists()
    );
}

#[test]
fn manual_headed_writer_runtime_accepts_verified_stack_anchor() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("runtime-stack.json");
    fs::write(
        &source_artifact,
        br#"{"startup_captured_at_unix_secs":1,"teardown_captured_at_unix_secs":2,"services":{"control-plane":{"evidence_kind":"health","startup_status":"healthy"},"proxy":{"evidence_kind":"health","startup_status":"healthy"},"frontend":{"evidence_kind":"bootstrap","startup_status":"ready"}},"teardown_disposition":"clean_shutdown"}"#,
    )
    .expect("write runtime source artifact");
    write_verified_row706_run(&evidence_root, &run_id);

    honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/stack.json",
        ])
        .assert()
        .success();

    let result_path = evidence_root
        .join("runs")
        .join(&run_id)
        .join("manual_headed")
        .join(format!("{MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN}.json"));
    assert!(result_path.is_file());
}

#[test]
fn manual_headed_writer_runtime_rejects_weak_stack_anchor() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("runtime-stack.json");
    fs::write(
        &source_artifact,
        br#"{"startup_captured_at_unix_secs":1,"teardown_captured_at_unix_secs":2,"services":{"control-plane":{"evidence_kind":"health","startup_status":"healthy"},"proxy":{"evidence_kind":"health","startup_status":"healthy"},"frontend":{"evidence_kind":"bootstrap","startup_status":"ready"}},"teardown_disposition":"explicit_failure","failure_code":"stack_teardown_failed"}"#,
    )
    .expect("write weak runtime source artifact");
    write_verified_row706_run(&evidence_root, &run_id);

    let output = honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/stack.json",
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let rendered = String::from_utf8(output).expect("stderr to utf8");
    assert!(rendered.contains("failure_reason"), "{rendered}");
}

#[test]
fn manual_headed_writer_runtime_rejects_weak_video_metadata() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("video-metadata.json");
    fs::write(
        &source_artifact,
        br#"{"video_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","timestamp_window":{"start_unix_secs":1,"end_unix_secs":2},"storage_uri":"target/manual/video.webm","retention_window":{"policy":"manual-review","expires_at_unix_secs":3},"session_id":"session-1","vm_lease_id":"lease-1"}"#,
    )
    .expect("write video metadata artifact");
    write_verified_row706_run(&evidence_root, &run_id);

    let output = honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/video-metadata.json",
            "--session-id",
            SESSION_ID,
            "--vm-lease-id",
            VM_LEASE_ID,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let rendered = String::from_utf8(output).expect("stderr to utf8");
    assert!(rendered.contains("duration_floor_secs"), "{rendered}");
}

#[test]
fn manual_headed_writer_runtime_rejects_weak_headed_qemu_chrome_observation_artifact() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("qemu-chrome.json");
    fs::write(
        &source_artifact,
        br#"{"qemu_display_mode":"headed","qemu_launch_reference":"target/qemu-display.sock","browser_family":"chrome","correlation_snapshot":{"observed_surface":"tile","observed_session_id":"session-1","observed_vm_lease_id":"lease-1"}}"#,
    )
    .expect("write headed observation artifact");
    write_verified_row706_run(&evidence_root, &run_id);

    let output = honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/qemu-chrome.json",
            "--session-id",
            SESSION_ID,
            "--vm-lease-id",
            VM_LEASE_ID,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let rendered = String::from_utf8(output).expect("stderr to utf8");
    assert!(rendered.contains("frontend_access_path"), "{rendered}");
}

#[test]
fn manual_headed_writer_runtime_rejects_noop_bounded_interaction_artifact() {
    let tempdir = tempdir().expect("create tempdir");
    let evidence_root = tempdir.path().join("row706");
    let run_id = Uuid::new_v4().to_string();
    let source_artifact = tempdir.path().join("interaction.json");
    fs::write(
        &source_artifact,
        br#"{"interaction_window":{"start_unix_secs":2,"end_unix_secs":8},"session_id":"session-1","vm_lease_id":"lease-1","modalities":{"mouse":{"event_count":0,"evidence_refs":["video://mouse"]},"keyboard":{"event_count":3,"evidence_refs":["video://keyboard"]},"browsing":{"event_count":1,"evidence_refs":["video://browsing"]}}}"#,
    )
    .expect("write bounded interaction artifact");
    write_verified_row706_run(&evidence_root, &run_id);

    let output = honeypot_manual_headed_writer_assert_cmd()
        .args([
            "runtime",
            "--evidence-root",
            &evidence_root.display().to_string(),
            "--run-id",
            &run_id,
            "--anchor-id",
            MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION,
            "--status",
            "passed",
            "--producer",
            "integration-test",
            "--artifact",
            &source_artifact.display().to_string(),
            "--artifact-relpath",
            "runtime/interaction.json",
            "--session-id",
            SESSION_ID,
            "--vm-lease-id",
            VM_LEASE_ID,
        ])
        .assert()
        .failure()
        .get_output()
        .stderr
        .clone();
    let rendered = String::from_utf8(output).expect("stderr to utf8");
    assert!(rendered.contains("modalities.mouse.event_count > 0"), "{rendered}");
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
    let body = manual_anchor_artifact_body(anchor_id, session_id, vm_lease_id);
    write_manual_anchor_with_body(
        evidence_root,
        run_id,
        anchor_id,
        session_id,
        vm_lease_id,
        relpath,
        body.as_bytes(),
    );
}

fn write_manual_anchor_with_body(
    evidence_root: &Path,
    run_id: &str,
    anchor_id: &str,
    session_id: Option<&str>,
    vm_lease_id: Option<&str>,
    relpath: &Path,
    body: &[u8],
) {
    write_manual_artifact(evidence_root, run_id, relpath, body);
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
            source_artifact_sha256: sha256_hex(body),
            session_id: session_id.map(ToOwned::to_owned),
            vm_lease_id: vm_lease_id.map(ToOwned::to_owned),
            detail: Some(format!("captured {anchor_id}")),
        },
    )
    .expect("write manual-headed anchor");
}

fn manual_anchor_artifact_body(anchor_id: &str, session_id: Option<&str>, vm_lease_id: Option<&str>) -> String {
    match anchor_id {
        MANUAL_HEADED_ANCHOR_STACK_STARTUP_SHUTDOWN => serde_json::json!({
            "startup_captured_at_unix_secs": 1u64,
            "teardown_captured_at_unix_secs": 2u64,
            "services": {
                "control-plane": {
                    "evidence_kind": "health",
                    "startup_status": "healthy"
                },
                "proxy": {
                    "evidence_kind": "health",
                    "startup_status": "healthy"
                },
                "frontend": {
                    "evidence_kind": "bootstrap",
                    "startup_status": "ready"
                }
            },
            "teardown_disposition": "clean_shutdown"
        })
        .to_string(),
        MANUAL_HEADED_ANCHOR_HEADED_QEMU_CHROME_OBSERVATION => serde_json::json!({
            "qemu_display_mode": "headed",
            "qemu_launch_reference": "target/qemu-display.sock",
            "browser_family": "chrome",
            "frontend_access_path": "http://127.0.0.1:8080/",
            "correlation_snapshot": {
                "observed_surface": "tile",
                "observed_session_id": session_id,
                "observed_vm_lease_id": vm_lease_id
            }
        })
        .to_string(),
        MANUAL_HEADED_ANCHOR_BOUNDED_INTERACTION => serde_json::json!({
            "interaction_window": {
                "start_unix_secs": 2u64,
                "end_unix_secs": 8u64
            },
            "session_id": session_id,
            "vm_lease_id": vm_lease_id,
            "modalities": {
                "mouse": {
                    "event_count": 4u64,
                    "evidence_refs": ["video://segment/mouse"]
                },
                "keyboard": {
                    "event_count": 6u64,
                    "evidence_refs": ["video://segment/keyboard"]
                },
                "browsing": {
                    "event_count": 2u64,
                    "evidence_refs": ["video://segment/browsing"]
                }
            }
        })
        .to_string(),
        MANUAL_HEADED_ANCHOR_VIDEO_EVIDENCE => serde_json::json!({
            "video_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "duration_floor_secs": 5u64,
            "timestamp_window": {
                "start_unix_secs": 1u64,
                "end_unix_secs": 10u64
            },
            "storage_uri": "target/manual/video.webm",
            "retention_window": {
                "policy": "manual-review",
                "expires_at_unix_secs": 10u64
            },
            "session_id": session_id,
            "vm_lease_id": vm_lease_id
        })
        .to_string(),
        _ => format!("manual-headed artifact for {anchor_id}"),
    }
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
