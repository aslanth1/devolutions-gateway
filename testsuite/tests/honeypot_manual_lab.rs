use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Command;

use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::tempdir;
use testsuite::honeypot_control_plane::{
    HoneypotControlPlaneTestConfig, fake_qemu_bin_path, write_honeypot_control_plane_config,
};
use testsuite::honeypot_manual_lab::{
    ManualLabBlackScreenBranchVerdict, ManualLabBlackScreenEvidence, ManualLabBlackScreenRunReason,
    ManualLabBlackScreenRunVerdict, ManualLabBrowserArtifactCorrelationVerdict, ManualLabBrowserPlayerMode,
    ManualLabBrowserVisibilityDataStatus, ManualLabMultiSessionReadyPathSlotReason,
    ManualLabMultiSessionReadyPathVerdict, ManualLabPlaybackReadyVerdict, ManualLabPlayerPlaybackModeVerdict,
    ManualLabProxyConfigOptions, ManualLabReadyPathSustainVerdict, ManualLabRecordingVisibilityVerdict,
    ManualLabSessionBrowserVisibilitySummary, ManualLabSessionBrowserVisibilityWindowSummary,
    ManualLabSessionDriverEvidence, ManualLabSessionPlaybackReadyCorrelation,
    ManualLabSessionPlayerPlaybackPathSummary, active_state_path, build_manual_lab_black_screen_run_verdict_summary,
    build_manual_lab_multi_session_ready_path_summary, build_manual_lab_ready_path_sustain_summary,
    honeypot_manual_lab_assert_cmd, parse_manual_lab_recording_visibility_probe_result_from_dom,
    render_manual_lab_proxy_config, render_three_host_trusted_image_manifest,
};
use testsuite::honeypot_release::{HONEYPOT_PROXY_CONFIG_PATH, repo_relative_path};

fn create_fake_manual_lab_webplayer_bundle(root: &Path) -> PathBuf {
    let player_root = root.join("recording-player");
    let assets_root = player_root.join("assets");
    fs::create_dir_all(&player_root).expect("create fake manual-lab webplayer root");
    fs::create_dir_all(&assets_root).expect("create fake manual-lab webplayer assets root");
    fs::write(
        player_root.join("index.html"),
        "<!doctype html><script type=\"module\" src=\"./assets/player.js\"></script><title>manual-lab player</title>",
    )
    .expect("write fake manual-lab webplayer index");
    fs::write(assets_root.join("player.js"), "console.log('manual-lab player');")
        .expect("write fake manual-lab webplayer asset");
    player_root
}

fn create_fake_manual_lab_webplayer_index_only_bundle(root: &Path) -> PathBuf {
    let player_root = root.join("recording-player");
    fs::create_dir_all(&player_root).expect("create fake manual-lab webplayer root");
    fs::write(
        player_root.join("index.html"),
        "<!doctype html><title>manual-lab player</title>",
    )
    .expect("write fake manual-lab webplayer index");
    player_root
}

fn write_fake_manual_lab_webplayer_build_root_with_selected_packages(
    build_root: &Path,
    recording_player_private_dep: Option<&str>,
) {
    let recording_player_root = build_root.join("apps/recording-player");
    let multi_video_player_root = build_root.join("packages/multi-video-player");
    let shadow_player_root = build_root.join("packages/shadow-player");

    fs::create_dir_all(&recording_player_root).expect("create fake recording-player root");
    fs::create_dir_all(&multi_video_player_root).expect("create fake multi-video-player root");
    fs::create_dir_all(&shadow_player_root).expect("create fake shadow-player root");

    let private_dep_line = recording_player_private_dep
        .map(|value| format!(",\n    \"@devolutions/icons\": \"{value}\""))
        .unwrap_or_default();
    fs::write(
        recording_player_root.join("package.json"),
        format!(
            "{{\n  \"name\": \"recording-player\",\n  \"dependencies\": {{\n    \"@devolutions/multi-video-player\": \"workspace:*\",\n    \"@devolutions/shadow-player\": \"workspace:*\"{private_dep_line}\n  }}\n}}\n"
        ),
    )
    .expect("write fake recording-player package");
    fs::write(
        multi_video_player_root.join("package.json"),
        "{\n  \"name\": \"@devolutions/multi-video-player\",\n  \"dependencies\": {\n    \"@devolutions/shadow-player\": \"workspace:*\"\n  }\n}\n",
    )
    .expect("write fake multi-video-player package");
    fs::write(
        shadow_player_root.join("package.json"),
        "{\n  \"name\": \"@devolutions/shadow-player\"\n}\n",
    )
    .expect("write fake shadow-player package");
}

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
fn manual_lab_parses_recording_visibility_probe_dom() {
    let dom = r#"<!DOCTYPE html><html><body><pre id="out">{"readyState":4,"duration":478.84,"sampled":33,"maxRatio":0.006076388888888889,"firstVisibleAt":null,"firstSparseAt":0.751268,"verdict":"sparse"}</pre></body></html>"#;

    let parsed =
        parse_manual_lab_recording_visibility_probe_result_from_dom(dom).expect("parse recording visibility probe DOM");

    assert_eq!(parsed.get("readyState"), Some(&json!(4)));
    assert_eq!(parsed.get("sampled"), Some(&json!(33)));
    assert_eq!(parsed.get("verdict"), Some(&json!("sparse")));
}

fn sample_ready_path_evidence() -> ManualLabSessionDriverEvidence {
    ManualLabSessionDriverEvidence {
        playback_ready_correlation: ManualLabSessionPlaybackReadyCorrelation {
            verdict: ManualLabPlaybackReadyVerdict::AlignedReady,
            session_stream_ready_emitted_at_unix_ms: Some(1_000),
            source_ready_at_unix_ms: Some(995),
            probe_observed_at_unix_ms: Some(1_050),
            ..Default::default()
        },
        player_playback_path_summary: ManualLabSessionPlayerPlaybackPathSummary {
            schema_version: 1,
            verdict: ManualLabPlayerPlaybackModeVerdict::ActiveLivePath,
            detail: Some(
                "active playback intent held and no static fallback or missing recording fetch was observed".to_owned(),
            ),
            active_intent_observed: true,
            active_intent_at_unix_ms: Some(900),
            recording_info_fetch_attempted: true,
            recording_info_fetch_succeeded: true,
            ..Default::default()
        },
        browser_visibility_summary: ManualLabSessionBrowserVisibilitySummary {
            schema_version: 1,
            verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
            dominant_mode: ManualLabBrowserPlayerMode::ActiveLive,
            data_status: ManualLabBrowserVisibilityDataStatus::Ready,
            representative_current_time_ms: Some(1),
            valid_window_count: 2,
            windows: vec![
                ManualLabSessionBrowserVisibilityWindowSummary {
                    window_index: 1,
                    window_phase: "stabilize".to_owned(),
                    player_mode: ManualLabBrowserPlayerMode::ActiveLive,
                    data_status: ManualLabBrowserVisibilityDataStatus::Ready,
                    verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
                    valid_sample_count: 3,
                    representative_current_time_ms: Some(1),
                    ..Default::default()
                },
                ManualLabSessionBrowserVisibilityWindowSummary {
                    window_index: 2,
                    window_phase: "steady".to_owned(),
                    player_mode: ManualLabBrowserPlayerMode::ActiveLive,
                    data_status: ManualLabBrowserVisibilityDataStatus::Ready,
                    verdict: ManualLabRecordingVisibilityVerdict::AllBlack,
                    valid_sample_count: 15,
                    representative_current_time_ms: Some(1),
                    ..Default::default()
                },
            ],
            ..Default::default()
        },
        ..Default::default()
    }
}

fn sample_run_slot_evidence(slot: usize) -> ManualLabSessionDriverEvidence {
    let mut evidence = sample_ready_path_evidence();
    evidence.slot = slot;
    evidence.session_id = format!("session-{slot}");
    evidence.black_screen_branch.verdict = ManualLabBlackScreenBranchVerdict::AlignedReady;
    evidence.browser_visibility_summary.verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;
    for window in &mut evidence.browser_visibility_summary.windows {
        window.verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;
    }
    evidence.artifact_visibility_at_browser_time.verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;
    evidence.browser_artifact_correlation_summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::BothVisible;
    evidence.browser_artifact_correlation_summary.browser_verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;
    evidence.browser_artifact_correlation_summary.artifact_verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;
    evidence
}

fn sample_black_screen_run_evidence(
    session_invocations: Vec<ManualLabSessionDriverEvidence>,
    session_count: usize,
) -> ManualLabBlackScreenEvidence {
    let multi_session_ready_path_summary =
        build_manual_lab_multi_session_ready_path_summary(&session_invocations, session_count);

    ManualLabBlackScreenEvidence {
        session_count,
        session_invocations,
        multi_session_ready_path_summary,
        ..Default::default()
    }
}

#[test]
fn manual_lab_ready_path_sustain_accepts_steady_active_live_window() {
    let evidence = sample_ready_path_evidence();

    let summary = build_manual_lab_ready_path_sustain_summary(&evidence);

    assert_eq!(summary.verdict, ManualLabReadyPathSustainVerdict::SustainedActiveLive);
    assert_eq!(summary.ready_verdict, ManualLabPlaybackReadyVerdict::AlignedReady);
    assert_eq!(
        summary.player_path_verdict,
        ManualLabPlayerPlaybackModeVerdict::ActiveLivePath
    );
    assert_eq!(summary.dominant_mode, ManualLabBrowserPlayerMode::ActiveLive);
    assert!(summary.steady_window_observed);
    assert_eq!(summary.steady_window_index, Some(2));
    assert_eq!(summary.static_fallback_started_at_unix_ms, None);
}

#[test]
fn manual_lab_ready_path_sustain_rejects_static_fallback_before_steady_window() {
    let mut evidence = sample_ready_path_evidence();
    evidence.player_playback_path_summary.verdict = ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive;
    evidence.player_playback_path_summary.static_playback_started_observed = true;
    evidence.player_playback_path_summary.static_playback_started_at_unix_ms = Some(1_050);

    let summary = build_manual_lab_ready_path_sustain_summary(&evidence);

    assert_eq!(
        summary.verdict,
        ManualLabReadyPathSustainVerdict::StaticFallbackObserved
    );
    assert_eq!(summary.static_fallback_started_at_unix_ms, Some(1_050));
}

#[test]
fn manual_lab_multi_session_ready_path_summary_accounts_for_three_slots() {
    let mut slot_two = sample_ready_path_evidence();
    slot_two.slot = 2;
    slot_two.session_id = "session-two".to_owned();
    slot_two.black_screen_branch.verdict = ManualLabBlackScreenBranchVerdict::PlayerLoss;
    slot_two.player_playback_path_summary.verdict = ManualLabPlayerPlaybackModeVerdict::StaticFallbackDuringActive;
    slot_two.player_playback_path_summary.static_playback_started_observed = true;
    slot_two.player_playback_path_summary.static_playback_started_at_unix_ms = Some(1_050);
    slot_two.artifact_visibility_at_browser_time.verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;

    let mut slot_three = sample_ready_path_evidence();
    slot_three.slot = 3;
    slot_three.session_id = "session-three".to_owned();
    slot_three.black_screen_branch.verdict = ManualLabBlackScreenBranchVerdict::NoReadyTruthfulness;
    slot_three.player_playback_path_summary.telemetry_gap = true;
    slot_three.browser_visibility_summary.windows.clear();
    slot_three.browser_visibility_summary.valid_window_count = 0;
    slot_three.browser_visibility_summary.representative_current_time_ms = None;
    slot_three.artifact_visibility_at_browser_time.verdict = ManualLabRecordingVisibilityVerdict::AllBlack;

    let mut slot_one = sample_ready_path_evidence();
    slot_one.slot = 1;
    slot_one.session_id = "session-one".to_owned();
    slot_one.black_screen_branch.verdict = ManualLabBlackScreenBranchVerdict::AlignedReady;
    slot_one.artifact_visibility_at_browser_time.verdict = ManualLabRecordingVisibilityVerdict::VisibleFrame;

    let summary = build_manual_lab_multi_session_ready_path_summary(&[slot_two, slot_three, slot_one], 3);

    assert_eq!(
        summary.verdict,
        ManualLabMultiSessionReadyPathVerdict::AllSlotsAccounted
    );
    assert_eq!(summary.expected_slot_count, 3);
    assert_eq!(summary.observed_session_count, 3);
    assert_eq!(summary.slot_summaries.len(), 3);
    assert_eq!(summary.slot_summaries[0].slot, 1);
    assert_eq!(
        summary.slot_summaries[0].reason,
        ManualLabMultiSessionReadyPathSlotReason::UsableLivePlayback
    );
    assert_eq!(
        summary.slot_summaries[0].black_screen_branch_verdict,
        ManualLabBlackScreenBranchVerdict::AlignedReady
    );
    assert_eq!(summary.slot_summaries[1].slot, 2);
    assert_eq!(
        summary.slot_summaries[1].reason,
        ManualLabMultiSessionReadyPathSlotReason::StaticFallbackObserved
    );
    assert_eq!(
        summary.slot_summaries[1].black_screen_branch_verdict,
        ManualLabBlackScreenBranchVerdict::PlayerLoss
    );
    assert_eq!(summary.slot_summaries[2].slot, 3);
    assert_eq!(
        summary.slot_summaries[2].reason,
        ManualLabMultiSessionReadyPathSlotReason::TelemetryGap
    );
    assert_eq!(
        summary.slot_summaries[2].black_screen_branch_verdict,
        ManualLabBlackScreenBranchVerdict::NoReadyTruthfulness
    );
}

#[test]
fn manual_lab_multi_session_ready_path_summary_marks_missing_slot_evidence() {
    let mut slot_one = sample_ready_path_evidence();
    slot_one.slot = 1;
    slot_one.session_id = "session-one".to_owned();

    let mut slot_two = sample_ready_path_evidence();
    slot_two.slot = 2;
    slot_two.session_id = "session-two".to_owned();

    let summary = build_manual_lab_multi_session_ready_path_summary(&[slot_one, slot_two], 3);

    assert_eq!(
        summary.verdict,
        ManualLabMultiSessionReadyPathVerdict::MissingSlotEvidence
    );
    assert_eq!(summary.expected_slot_count, 3);
    assert_eq!(summary.observed_session_count, 2);
    assert_eq!(summary.slot_summaries.len(), 3);
    assert_eq!(summary.slot_summaries[2].slot, 3);
    assert_eq!(
        summary.slot_summaries[2].reason,
        ManualLabMultiSessionReadyPathSlotReason::MissingSlotEvidence
    );
    assert_eq!(summary.slot_summaries[2].session_id, "");
    assert_eq!(
        summary.slot_summaries[2].ready_path_sustain_summary.verdict,
        ManualLabReadyPathSustainVerdict::Inconclusive
    );
}

#[test]
fn manual_lab_black_screen_run_verdict_is_green_for_slot_stable_visible_playback() {
    let evidence = sample_black_screen_run_evidence(
        vec![
            sample_run_slot_evidence(2),
            sample_run_slot_evidence(3),
            sample_run_slot_evidence(1),
        ],
        3,
    );

    let summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);

    assert_eq!(summary.verdict, ManualLabBlackScreenRunVerdict::UsablePlayback);
    assert_eq!(
        summary.primary_reason,
        ManualLabBlackScreenRunReason::AllSlotsUsablePlayback
    );
    assert_eq!(
        summary.reason_codes,
        vec![ManualLabBlackScreenRunReason::AllSlotsUsablePlayback]
    );
    assert_eq!(summary.slot_summaries.len(), 3);
    assert_eq!(summary.slot_summaries[0].slot, 1);
    assert_eq!(summary.slot_summaries[1].slot, 2);
    assert_eq!(summary.slot_summaries[2].slot, 3);
}

#[test]
fn manual_lab_black_screen_run_verdict_is_amber_for_ready_but_black_artifact_correlation() {
    let mut slot_two = sample_run_slot_evidence(2);
    slot_two.browser_visibility_summary.verdict = ManualLabRecordingVisibilityVerdict::AllBlack;
    for window in &mut slot_two.browser_visibility_summary.windows {
        window.verdict = ManualLabRecordingVisibilityVerdict::AllBlack;
    }
    slot_two.artifact_visibility_at_browser_time.verdict = ManualLabRecordingVisibilityVerdict::AllBlack;
    slot_two.browser_artifact_correlation_summary.verdict = ManualLabBrowserArtifactCorrelationVerdict::BothBlack;
    slot_two.browser_artifact_correlation_summary.browser_verdict = ManualLabRecordingVisibilityVerdict::AllBlack;
    slot_two.browser_artifact_correlation_summary.artifact_verdict = ManualLabRecordingVisibilityVerdict::AllBlack;

    let evidence = sample_black_screen_run_evidence(
        vec![sample_run_slot_evidence(1), slot_two, sample_run_slot_evidence(3)],
        3,
    );

    let summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);

    assert_eq!(
        summary.verdict,
        ManualLabBlackScreenRunVerdict::ProducerReadyButCorruptionUnresolved
    );
    assert_eq!(
        summary.primary_reason,
        ManualLabBlackScreenRunReason::ProducerReadyCorruptionUnresolved
    );
    assert!(
        summary
            .reason_codes
            .contains(&ManualLabBlackScreenRunReason::BrowserArtifactBothBlack)
    );
}

#[test]
fn manual_lab_black_screen_run_verdict_is_red_for_missing_third_slot() {
    let evidence = sample_black_screen_run_evidence(vec![sample_run_slot_evidence(1), sample_run_slot_evidence(2)], 3);

    let summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);

    assert_eq!(
        summary.verdict,
        ManualLabBlackScreenRunVerdict::ContractViolationOrMissingProof
    );
    assert_eq!(
        summary.primary_reason,
        ManualLabBlackScreenRunReason::MissingSlotEvidence
    );
    assert_eq!(
        summary.reason_codes,
        vec![ManualLabBlackScreenRunReason::MissingSlotEvidence]
    );
}

#[test]
fn manual_lab_black_screen_run_verdict_is_red_for_duplicate_slot_evidence() {
    let evidence = sample_black_screen_run_evidence(
        vec![
            sample_run_slot_evidence(1),
            sample_run_slot_evidence(1),
            sample_run_slot_evidence(2),
        ],
        3,
    );

    let summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);

    assert_eq!(
        summary.verdict,
        ManualLabBlackScreenRunVerdict::ContractViolationOrMissingProof
    );
    assert_eq!(
        summary.primary_reason,
        ManualLabBlackScreenRunReason::DuplicateSlotEvidence
    );
    assert_eq!(
        summary.reason_codes,
        vec![ManualLabBlackScreenRunReason::DuplicateSlotEvidence]
    );
}

#[test]
fn manual_lab_black_screen_run_verdict_is_red_for_browser_artifact_alignment_gap() {
    let mut slot_three = sample_run_slot_evidence(3);
    slot_three.browser_artifact_correlation_summary.verdict =
        ManualLabBrowserArtifactCorrelationVerdict::InconclusiveAlignmentGap;

    let evidence = sample_black_screen_run_evidence(
        vec![sample_run_slot_evidence(1), sample_run_slot_evidence(2), slot_three],
        3,
    );

    let summary = build_manual_lab_black_screen_run_verdict_summary(&evidence);

    assert_eq!(
        summary.verdict,
        ManualLabBlackScreenRunVerdict::ContractViolationOrMissingProof
    );
    assert_eq!(
        summary.primary_reason,
        ManualLabBlackScreenRunReason::BrowserArtifactAlignmentGap
    );
    assert!(
        summary
            .reason_codes
            .contains(&ManualLabBlackScreenRunReason::BrowserArtifactAlignmentGap)
    );
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
    assert!(rendered.contains("ensure-artifacts"), "{rendered}");
    assert!(rendered.contains("remember-source-manifest"), "{rendered}");
    assert!(rendered.contains("status"), "{rendered}");
    assert!(rendered.contains("down"), "{rendered}");
}

#[cfg(unix)]
#[test]
fn make_manual_lab_selftest_routes_through_ensure_webplayer_and_artifacts_by_default() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-selftest")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-selftest");
    assert!(
        output.status.success(),
        "make -n manual-lab-selftest failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let webplayer_idx = rendered
        .find("manual-lab-selftest-ensure-webplayer")
        .expect("default selftest should route through ensure-webplayer");
    let ensure_idx = rendered
        .find("manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local")
        .expect("default selftest should route through ensure-artifacts");
    let up_idx = rendered
        .find("manual-lab-up MANUAL_LAB_PROFILE=local")
        .expect("selftest should still launch manual-lab-up");

    assert!(
        webplayer_idx < ensure_idx && ensure_idx < up_idx,
        "ensure-webplayer should appear before ensure-artifacts and up:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_auth_check_exposes_private_registry_remediation() {
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-webplayer-auth-check")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-webplayer-auth-check");
    assert!(
        output.status.success(),
        "make -n manual-lab-webplayer-auth-check failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("MANUAL_LAB_WEBPLAYER_NPMRC=/path/to/.npmrc"),
        "auth-check should surface the npmrc remediation anchor:\n{rendered}"
    );
    assert!(
        rendered.contains("@devolutions:registry"),
        "auth-check should mention the scoped registry contract:\n{rendered}"
    );
    assert!(
        rendered.contains("registry.npmjs.org"),
        "auth-check should mention the fallback risk it guards against:\n{rendered}"
    );
    assert!(
        rendered.contains("DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>"),
        "auth-check should surface the prebuilt bundle override anchor:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_status_reports_bundle_state() {
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-webplayer-status")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-webplayer-status");
    assert!(
        output.status.success(),
        "make -n manual-lab-webplayer-status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("manual-lab webplayer bundle status:"),
        "webplayer-status should report bundle state:\n{rendered}"
    );
    assert!(
        rendered.contains("manual-lab webplayer private registry deps:"),
        "webplayer-status should report private-registry detection:\n{rendered}"
    );
    assert!(
        rendered.contains("manual-lab webplayer npm scope registry:"),
        "webplayer-status should report the effective scoped registry state:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_validate_bundle_rejects_index_only_override() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_index_only_bundle(tempdir.path());

    let output = Command::new("make")
        .arg("manual-lab-webplayer-validate-bundle")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make manual-lab-webplayer-validate-bundle");
    assert!(
        !output.status.success(),
        "validate-bundle should reject an index-only override:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        rendered.contains("missing a non-empty assets/ directory"),
        "validate-bundle should explain the stronger bundle contract:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_auth_check_rejects_npmrc_without_devolutions_scope_mapping() {
    let tempdir = tempdir().expect("create tempdir");
    let build_root = tempdir.path().join("webapp");
    fs::create_dir_all(&build_root).expect("create fake webapp root");
    write_fake_manual_lab_webplayer_build_root_with_selected_packages(&build_root, Some("^5.0.11"));
    let npmrc_path = tempdir.path().join(".npmrc");
    fs::write(&npmrc_path, "registry=https://registry.npmjs.org/\n").expect("write fake npmrc");

    let output = Command::new("make")
        .arg("manual-lab-webplayer-auth-check")
        .env("MANUAL_LAB_WEBPLAYER_BUILD_ROOT", &build_root)
        .env("MANUAL_LAB_WEBPLAYER_NPMRC", &npmrc_path)
        .env("MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME", "sh")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make manual-lab-webplayer-auth-check");
    assert!(
        !output.status.success(),
        "auth-check should reject an npmrc without @devolutions:registry:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    assert!(
        rendered.contains("does not configure @devolutions:registry"),
        "auth-check should explain the missing scope registry:\n{rendered}"
    );
    assert!(
        rendered.contains("registry.npmjs.org"),
        "auth-check should explain the npmjs fallback risk:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_auth_check_accepts_scope_mapping_with_matching_host_credentials() {
    let tempdir = tempdir().expect("create tempdir");
    let build_root = tempdir.path().join("webapp");
    fs::create_dir_all(&build_root).expect("create fake webapp root");
    write_fake_manual_lab_webplayer_build_root_with_selected_packages(&build_root, Some("^5.0.11"));
    let npmrc_path = tempdir.path().join(".npmrc");
    fs::write(
        &npmrc_path,
        "@devolutions:registry=https://devolutions.jfrog.io/artifactory/api/npm/npm/\n//devolutions.jfrog.io/artifactory/api/npm/npm/:_authToken=test-token\n",
    )
    .expect("write fake npmrc");

    let output = Command::new("make")
        .arg("manual-lab-webplayer-auth-check")
        .env("MANUAL_LAB_WEBPLAYER_BUILD_ROOT", &build_root)
        .env("MANUAL_LAB_WEBPLAYER_NPMRC", &npmrc_path)
        .env("MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME", "sh")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make manual-lab-webplayer-auth-check");
    assert!(
        output.status.success(),
        "auth-check should accept a matching scoped registry and credentials:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("@devolutions:registry=https://devolutions.jfrog.io/artifactory/api/npm/npm/"),
        "auth-check should echo the effective scoped registry on success:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_webplayer_auth_check_skips_npmrc_for_workspace_only_graph() {
    let tempdir = tempdir().expect("create tempdir");
    let build_root = tempdir.path().join("webapp");
    fs::create_dir_all(&build_root).expect("create fake webapp root");
    write_fake_manual_lab_webplayer_build_root_with_selected_packages(&build_root, None);

    let output = Command::new("make")
        .arg("manual-lab-webplayer-auth-check")
        .env("MANUAL_LAB_WEBPLAYER_BUILD_ROOT", &build_root)
        .env("MANUAL_LAB_WEBPLAYER_CONTAINER_RUNTIME", "sh")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make manual-lab-webplayer-auth-check");
    assert!(
        output.status.success(),
        "auth-check should skip npm auth when the selected build graph is workspace-only:\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("no private npm auth is required"),
        "auth-check should explain why workspace-only builds skip npm auth:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_ensure_webplayer_runs_the_builder_in_the_owned_workspace() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());

    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-ensure-webplayer")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-ensure-webplayer");
    assert!(
        output.status.success(),
        "make -n manual-lab-ensure-webplayer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("-w \"/workspace/honeypot/frontend/webplayer-workspace\""),
        "ensure-webplayer should run the containerized build in the owned webplayer workspace:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_selftest_up_routes_through_ensure_webplayer_and_artifacts_by_default() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-selftest-up")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-selftest-up");
    assert!(
        output.status.success(),
        "make -n manual-lab-selftest-up failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let webplayer_idx = rendered
        .find("manual-lab-selftest-ensure-webplayer")
        .expect("default selftest-up should route through ensure-webplayer");
    let ensure_idx = rendered
        .find("manual-lab-selftest-ensure-artifacts")
        .expect("default selftest-up should route through ensure-artifacts");
    let up_idx = rendered
        .find("manual-lab-up MANUAL_LAB_PROFILE=local")
        .expect("selftest-up should still launch manual-lab-up");

    assert!(
        webplayer_idx < ensure_idx && ensure_idx < up_idx,
        "ensure-webplayer should appear before ensure-artifacts and the local up command:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_selftest_up_can_disable_the_default_webplayer_precheck() {
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-selftest-up")
        .env("MANUAL_LAB_WEBPLAYER_PRECHECK", "0")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-selftest-up with webplayer precheck disabled");
    assert!(
        output.status.success(),
        "make -n manual-lab-selftest-up with webplayer precheck disabled failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains(
            "manual-lab self-test webplayer precheck disabled; skipping containerized recording-player build"
        ),
        "webplayer-disabled selftest-up should print the skip message:\n{rendered}"
    );
    assert!(
        !rendered.contains("make manual-lab-ensure-webplayer"),
        "webplayer-disabled selftest-up should not expand the nested ensure-webplayer make invocation:\n{rendered}"
    );
    assert!(
        rendered.contains("manual-lab-selftest-ensure-artifacts"),
        "webplayer-disabled selftest-up should still expand the artifact ensure step:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_selftest_up_can_disable_the_default_precheck() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-selftest-up")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("MANUAL_LAB_SELFTEST_UP_PRECHECK", "0")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-selftest-up with precheck disabled");
    assert!(
        output.status.success(),
        "make -n manual-lab-selftest-up with precheck disabled failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("manual-lab self-test up precheck disabled; skipping ensure-artifacts"),
        "precheck-disabled selftest-up should print the skip message:\n{rendered}"
    );
    assert!(
        !rendered.contains("make manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local"),
        "precheck-disabled selftest-up should not expand the nested ensure-artifacts invocation:\n{rendered}"
    );
    assert!(
        rendered.contains("manual-lab-up MANUAL_LAB_PROFILE=local"),
        "precheck-disabled selftest-up should still launch the local up target:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_manual_lab_selftest_up_no_browser_routes_through_ensure_artifacts_by_default() {
    let tempdir = tempdir().expect("create tempdir");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());
    let output = Command::new("make")
        .arg("-n")
        .arg("manual-lab-selftest-up-no-browser")
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n manual-lab-selftest-up-no-browser");
    assert!(
        output.status.success(),
        "make -n manual-lab-selftest-up-no-browser failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let webplayer_idx = rendered
        .find("manual-lab-selftest-ensure-webplayer")
        .expect("default selftest-up-no-browser should route through ensure-webplayer");
    let ensure_idx = rendered
        .find("manual-lab-selftest-ensure-artifacts")
        .expect("default selftest-up-no-browser should route through ensure-artifacts");
    let up_idx = rendered
        .find("manual-lab-up-no-browser MANUAL_LAB_PROFILE=local")
        .expect("selftest-up-no-browser should still launch manual-lab-up-no-browser");

    assert!(
        webplayer_idx < ensure_idx && ensure_idx < up_idx,
        "ensure-webplayer should appear before ensure-artifacts and the local up-no-browser command:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_host_smoke_stays_non_mutating_by_default() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-host-smoke")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-host-smoke");
    assert!(
        output.status.success(),
        "make -n test-host-smoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let precheck_idx = rendered
        .find("test-host-smoke-precheck")
        .expect("default host-smoke wrapper should route through the release-input precheck");
    let cargo_idx = rendered
        .find("cargo test -p testsuite --test integration_tests")
        .expect("host-smoke wrapper should still launch the integration test harness");

    assert!(
        rendered.contains("DGW_HONEYPOT_HOST_SMOKE=1"),
        "host-smoke wrapper should export the host-smoke gate:\n{rendered}"
    );
    assert!(
        precheck_idx < cargo_idx,
        "release-input precheck should appear before the host-smoke cargo invocation:\n{rendered}"
    );
    assert!(
        !rendered.contains("manual-lab-ensure-artifacts"),
        "host-smoke wrapper must stay non-mutating by default:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_host_smoke_can_disable_the_default_precheck() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-host-smoke")
        .env("HOST_SMOKE_PRECHECK", "0")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-host-smoke with precheck disabled");
    assert!(
        output.status.success(),
        "make -n test-host-smoke with precheck disabled failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("honeypot host-smoke precheck disabled; skipping release-input preflight"),
        "precheck-disabled host-smoke should print the skip message:\n{rendered}"
    );
    assert!(
        !rendered.contains("honeypot-host-smoke-precheck"),
        "precheck-disabled host-smoke should not expand the nested precheck invocation:\n{rendered}"
    );
    assert!(
        rendered.contains("DGW_HONEYPOT_HOST_SMOKE=1"),
        "precheck-disabled host-smoke should still launch the host-smoke harness:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_host_smoke_ensure_images_routes_through_the_cache_binary() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-host-smoke-ensure-images")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-host-smoke-ensure-images");
    assert!(
        output.status.success(),
        "make -n test-host-smoke-ensure-images failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("honeypot-host-smoke-precheck -- ensure-images"),
        "host-smoke ensure-images should invoke the explicit cache warm mode:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_host_smoke_warm_runs_cache_ensure_before_host_smoke() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-host-smoke-warm")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-host-smoke-warm");
    assert!(
        output.status.success(),
        "make -n test-host-smoke-warm failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let ensure_idx = rendered
        .find("make test-host-smoke-ensure-images")
        .expect("host-smoke warm should route through the explicit ensure-images target");
    let host_smoke_idx = rendered
        .find("make test-host-smoke\n")
        .expect("host-smoke warm should still invoke the ordinary host-smoke lane");

    assert!(
        ensure_idx < host_smoke_idx,
        "ensure-images should appear before the host-smoke wrapper:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_lab_e2e_routes_through_ensure_artifacts_by_default() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-lab-e2e")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-lab-e2e");
    assert!(
        output.status.success(),
        "make -n test-lab-e2e failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    let ensure_idx = rendered
        .find("manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=canonical")
        .expect("default test-lab-e2e should route through ensure-artifacts");
    let cargo_idx = rendered
        .find("cargo test -p testsuite --test integration_tests")
        .expect("test-lab-e2e should still launch the integration test harness");

    assert!(
        ensure_idx < cargo_idx,
        "ensure-artifacts should appear before the lab-e2e cargo invocation:\n{rendered}"
    );
    assert!(
        rendered.contains("DGW_HONEYPOT_LAB_E2E=1"),
        "lab-e2e wrapper should export the lab-e2e gate:\n{rendered}"
    );
    assert!(
        rendered.contains("DGW_HONEYPOT_TIER_GATE="),
        "lab-e2e wrapper should export the tier gate path:\n{rendered}"
    );
}

#[cfg(unix)]
#[test]
fn make_test_lab_e2e_can_disable_the_default_precheck() {
    let output = Command::new("make")
        .arg("-n")
        .arg("test-lab-e2e")
        .env("LAB_E2E_PRECHECK", "0")
        .current_dir(repo_relative_path("."))
        .output()
        .expect("run make -n test-lab-e2e with precheck disabled");
    assert!(
        output.status.success(),
        "make -n test-lab-e2e with precheck disabled failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).expect("utf8 stdout");

    assert!(
        rendered.contains("honeypot lab-e2e precheck disabled; skipping ensure-artifacts"),
        "precheck-disabled test-lab-e2e should print the skip message:\n{rendered}"
    );
    assert!(
        !rendered.contains("cargo run -p testsuite --bin honeypot-manual-lab -- ensure-artifacts"),
        "precheck-disabled test-lab-e2e should not expand the nested ensure-artifacts recipe:\n{rendered}"
    );
    assert!(
        rendered.contains("DGW_HONEYPOT_LAB_E2E=1"),
        "precheck-disabled test-lab-e2e should still launch the lab-e2e harness:\n{rendered}"
    );
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
    assert!(rendered.contains("manual-lab-selftest"), "{rendered}");
    assert!(rendered.contains("manual-lab-show-profile"), "{rendered}");
    assert!(rendered.contains("manual-lab-ensure-artifacts"), "{rendered}");
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
    assert!(
        preflight_rendered.contains("manual-lab-selftest"),
        "{preflight_rendered}"
    );
    assert!(
        preflight_rendered.contains("manual-lab-show-profile"),
        "{preflight_rendered}"
    );
    assert!(
        preflight_rendered.contains("manual-lab-ensure-artifacts"),
        "{preflight_rendered}"
    );
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
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());

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
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab bootstrap executed"), "{rendered}");
    assert!(rendered.contains("import_state=imported"), "{rendered}");
    assert!(rendered.contains("validation_mode=hashed"), "{rendered}");
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
fn manual_lab_cli_bootstrap_store_execute_reports_cached_validation_for_repeated_import() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    write_manual_lab_gate(&gate_path);

    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "execute-repeat");

    let kvm_path = tempdir.path().join("dev-kvm");
    fs::write(&kvm_path, b"kvm").expect("write fake kvm device");
    let xfreerdp_path = tempdir.path().join("xfreerdp");
    fs::write(&xfreerdp_path, b"#!/bin/sh\nexit 0\n").expect("write fake xfreerdp");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());

    honeypot_manual_lab_assert_cmd()
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
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success();

    let repeated = honeypot_manual_lab_assert_cmd()
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
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(repeated).expect("utf8 stdout");

    assert!(rendered.contains("manual lab bootstrap executed"), "{rendered}");
    assert!(rendered.contains("import_state=already_present"), "{rendered}");
    assert!(rendered.contains("validation_mode=cached"), "{rendered}");
    assert!(rendered.contains("post_import_preflight_status=ready"), "{rendered}");
}

#[test]
fn manual_lab_cli_ensure_artifacts_executes_import_when_store_readiness_is_missing() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    write_manual_lab_gate(&gate_path);

    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "ensure-execute");

    let kvm_path = tempdir.path().join("dev-kvm");
    fs::write(&kvm_path, b"kvm").expect("write fake kvm device");
    let xfreerdp_path = tempdir.path().join("xfreerdp");
    fs::write(&xfreerdp_path, b"#!/bin/sh\nexit 0\n").expect("write fake xfreerdp");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());

    let output = honeypot_manual_lab_assert_cmd()
        .arg("ensure-artifacts")
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
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab artifacts ensured"), "{rendered}");
    assert!(rendered.contains("preflight_status=ready"), "{rendered}");
    assert!(rendered.contains("bootstrap_status=executed"), "{rendered}");
    assert!(rendered.contains("import_state=imported"), "{rendered}");
    assert!(rendered.contains("validation_mode=hashed"), "{rendered}");
    assert!(rendered.contains("source_manifest_digest="), "{rendered}");
}

#[test]
fn manual_lab_cli_ensure_artifacts_skips_bootstrap_when_preflight_is_already_ready() {
    let tempdir = tempdir().expect("create tempdir");
    let gate_path = tempdir.path().join("lab-e2e-gate.json");
    write_manual_lab_gate(&gate_path);

    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "ensure-ready");

    let kvm_path = tempdir.path().join("dev-kvm");
    fs::write(&kvm_path, b"kvm").expect("write fake kvm device");
    let xfreerdp_path = tempdir.path().join("xfreerdp");
    fs::write(&xfreerdp_path, b"#!/bin/sh\nexit 0\n").expect("write fake xfreerdp");
    let webplayer_path = create_fake_manual_lab_webplayer_bundle(tempdir.path());

    honeypot_manual_lab_assert_cmd()
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
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success();

    let output = honeypot_manual_lab_assert_cmd()
        .arg("ensure-artifacts")
        .arg("--config")
        .arg(&config_path)
        .env("DGW_HONEYPOT_LAB_E2E", "1")
        .env("DGW_HONEYPOT_TIER_GATE", &gate_path)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .env("DGW_HONEYPOT_INTEROP_QEMU_BINARY", fake_qemu_bin_path())
        .env("DGW_HONEYPOT_INTEROP_KVM_PATH", &kvm_path)
        .env("DGW_HONEYPOT_INTEROP_XFREERDP_PATH", &xfreerdp_path)
        .env("DGATEWAY_WEBPLAYER_PATH", &webplayer_path)
        .env("DGW_HONEYPOT_INTEROP_RDP_USERNAME", "jf")
        .env("DGW_HONEYPOT_INTEROP_RDP_PASSWORD", "ChangeMe123!")
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(rendered.contains("manual lab artifacts ready"), "{rendered}");
    assert!(rendered.contains("preflight_status=ready"), "{rendered}");
    assert!(rendered.contains("skipped bootstrap-store"), "{rendered}");
    assert!(!rendered.contains("bootstrap_status="), "{rendered}");
    assert!(!rendered.contains("import_state="), "{rendered}");
}

#[cfg(unix)]
#[test]
fn manual_lab_cli_bootstrap_store_execute_reports_store_root_not_writable() {
    let tempdir = tempdir().expect("create tempdir");
    let locked_root = tempdir.path().join("locked-root");
    fs::create_dir_all(&locked_root).expect("create locked root");
    fs::set_permissions(&locked_root, fs::Permissions::from_mode(0o555)).expect("lock root permissions");

    let image_store = locked_root.join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "permission-denied");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--execute")
        .arg("--config")
        .arg(&config_path)
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(
        rendered.contains("manual lab bootstrap blocked by store_root_not_writable"),
        "{rendered}"
    );
    assert!(rendered.contains("manual-lab-selftest"), "{rendered}");
    assert!(rendered.contains("manual-lab-show-profile"), "{rendered}");

    fs::set_permissions(&locked_root, fs::Permissions::from_mode(0o755)).expect("restore root permissions");
}

#[test]
fn manual_lab_cli_bootstrap_store_execute_reports_import_lock_held() {
    let tempdir = tempdir().expect("create tempdir");
    let image_store = tempdir.path().join("image-store");
    let manifest_dir = image_store.join("manifests");
    let config_path =
        write_manual_lab_bootstrap_config(&tempdir.path().join("control-plane.toml"), &image_store, &manifest_dir);
    let source_manifest = create_manual_lab_source_bundle(tempdir.path(), "live-lock");
    let lock_path = manual_lab_import_lock_path(&manifest_dir, &source_manifest);

    fs::create_dir_all(&manifest_dir).expect("create manifest dir");
    fs::write(&lock_path, format!("pid={}\n", std::process::id())).expect("write import lock");

    let output = honeypot_manual_lab_assert_cmd()
        .arg("bootstrap-store")
        .arg("--execute")
        .arg("--config")
        .arg(&config_path)
        .arg("--source-manifest")
        .arg(&source_manifest)
        .env("DGW_HONEYPOT_INTEROP_IMAGE_STORE", &image_store)
        .env("DGW_HONEYPOT_INTEROP_MANIFEST_DIR", &manifest_dir)
        .assert()
        .code(2)
        .get_output()
        .stdout
        .clone();
    let rendered = String::from_utf8(output).expect("utf8 stdout");

    assert!(
        rendered.contains("manual lab bootstrap blocked by import_lock_held"),
        "{rendered}"
    );
    assert!(rendered.contains("held by live pid"), "{rendered}");
    assert!(rendered.contains("manual-lab-selftest"), "{rendered}");
    assert!(rendered.contains("manual-lab-show-profile"), "{rendered}");
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

fn manual_lab_import_lock_path(manifest_dir: &Path, source_manifest_path: &Path) -> PathBuf {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(source_manifest_path).expect("read source manifest"))
            .expect("parse source manifest");
    let vm_name = manifest
        .pointer("/vm_name")
        .and_then(|value| value.as_str())
        .expect("vm_name should exist");
    let base_image_sha256 = manifest
        .pointer("/base_image/sha256")
        .and_then(|value| value.as_str())
        .expect("base_image.sha256 should exist");
    manifest_dir.join(format!(".{}-{}.json.lock", vm_name, &base_image_sha256[..12]))
}

fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}
