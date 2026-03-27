use testsuite::honeypot_docs::{
    assert_contains, contains_windows_product_key_like_plaintext, is_checked_checklist_line, read_repo_text,
    section_checklist_lines,
};

#[test]
fn honeypot_docs_keep_decision_freeze_matrix_authoritative() {
    let decisions_path = "docs/honeypot/decisions.md";
    let decisions = read_repo_text(decisions_path);
    assert_contains(
        decisions_path,
        &decisions,
        "Later honeypot docs and milestones must consume these rows instead of restating policy.",
    );
    assert_contains(
        decisions_path,
        &decisions,
        "The `Decision Freeze Matrix` and `Ownership Matrix` in `AGENTS.md` remain authoritative",
    );

    let deployment_path = "docs/honeypot/deployment.md";
    let deployment = read_repo_text(deployment_path);
    assert_contains(
        deployment_path,
        &deployment,
        "It carries the deployment details required by `DF-01`, `DF-06`, `DF-07`, and `DF-08`",
    );

    let release_path = "docs/honeypot/release.md";
    let release = read_repo_text(release_path);
    assert_contains(
        release_path,
        &release,
        "It carries the release details required by `DF-07`",
    );

    let risk_path = "docs/honeypot/risk.md";
    let risk = read_repo_text(risk_path);
    assert_contains(
        risk_path,
        &risk,
        "`DF-02` owns the operator identity, service-to-service auth, and audit envelope that this policy requires.",
    );
    assert_contains(
        risk_path,
        &risk,
        "`DF-05` owns the Windows and Tiny11 provenance decisions that this policy constrains.",
    );
    assert_contains(
        risk_path,
        &risk,
        "`DF-08` owns the exposure, retention, redaction, emergency-stop, and quarantine decisions that this policy constrains.",
    );

    let testing_path = "docs/honeypot/testing.md";
    let testing = read_repo_text(testing_path);
    assert_contains(
        testing_path,
        &testing,
        "This document defines the honeypot verification tiers required by `DF-09`.",
    );
    assert_contains(testing_path, &testing, "## Matrix Authority Evidence");
}

#[test]
fn honeypot_docs_keep_ownership_matrix_authoritative() {
    let architecture_path = "docs/honeypot/architecture.md";
    let architecture = read_repo_text(architecture_path);
    assert_contains(
        architecture_path,
        &architecture,
        "It is the architecture companion to the `DF-*` and `OM-*` rows in `AGENTS.md`.",
    );
    assert_contains(
        architecture_path,
        &architecture,
        "Later milestone work must cite the relevant `DF-*` or `OM-*` rows instead of redefining owners or policy locally.",
    );
    assert_contains(
        architecture_path,
        &architecture,
        "Session, event, and stream ownership must follow `OM-01` through `OM-05` in `AGENTS.md`.",
    );
    assert_contains(
        architecture_path,
        &architecture,
        "If a future milestone replaces any of those seams, the replacement and the reason reuse failed must be recorded first under `DF-03` or `DF-04` in [decisions.md](decisions.md).",
    );

    let contracts_path = "docs/honeypot/contracts.md";
    let contracts = read_repo_text(contracts_path);
    assert_contains(
        contracts_path,
        &contracts,
        "The contract families in this document extend the existing Gateway seam owners from `OM-02` and `OM-03` instead of authorizing a second session bus, subscriber bus, credential API, or stream API.",
    );
    assert_contains(
        contracts_path,
        &contracts,
        "Any future contract family that replaces one of those seams must first record the replaced seam and the reason reuse failed under `DF-03` or `DF-04` in [decisions.md](decisions.md).",
    );

    let research_path = "docs/honeypot/research.md";
    let research = read_repo_text(research_path);
    assert_contains(
        research_path,
        &research,
        "Any future second session bus, subscriber bus, credential API, or stream API requires an explicit replacement note in `DF-03` or `DF-04` before implementation starts.",
    );
}

#[test]
fn honeypot_docs_enforce_milestone_gate_completion_before_later_milestones() {
    let agents_path = "AGENTS.md";
    let agents = read_repo_text(agents_path);

    assert_contains(
        agents_path,
        &agents,
        "- [x] Milestone 0 and Milestone 0.5 are complete before Milestone 1 through Milestone 6 implementation starts.",
    );

    let milestone_zero_rows = section_checklist_lines(&agents, "Milestone 0: Baseline, Safety, and Repo Boundaries");
    assert!(
        !milestone_zero_rows.is_empty(),
        "{agents_path} must contain Milestone 0 checklist rows"
    );
    assert!(
        milestone_zero_rows.iter().all(|row| is_checked_checklist_line(row)),
        "{agents_path} Milestone 0 rows must all be checked before later milestones"
    );

    let milestone_zero_five_rows = section_checklist_lines(&agents, "Milestone 0.5: Research and Design Freeze");
    assert!(
        !milestone_zero_five_rows.is_empty(),
        "{agents_path} must contain Milestone 0.5 checklist rows"
    );
    assert!(
        milestone_zero_five_rows
            .iter()
            .all(|row| is_checked_checklist_line(row)),
        "{agents_path} Milestone 0.5 rows must all be checked before later milestones"
    );

    let late_sections = [
        "Milestone 1: Gold Image and Control Plane Foundations",
        "Milestone 2: Proxy Honeypot Mode",
        "Milestone 3: Frontend Tile Wall And Operator Loop",
        "Milestone 4: Event and Stream Cohesion",
        "Milestone 5: End-to-End Validation and Release Drills",
        "Milestone 6: Hardening and Operational Readiness",
    ];

    let checked_late_rows = late_sections
        .iter()
        .flat_map(|section| section_checklist_lines(&agents, section))
        .filter(|row| is_checked_checklist_line(row))
        .count();
    assert!(
        checked_late_rows > 0,
        "{agents_path} must contain checked Milestone 1 through Milestone 6 rows for gate validation"
    );
}

#[test]
fn honeypot_docs_keep_manual_headed_lab_contract_fail_closed() {
    let agents_path = "AGENTS.md";
    let agents = read_repo_text(agents_path);

    assert_contains(
        agents_path,
        &agents,
        "### Milestone 6a: Manual Headed Tiny11 Walkthrough Contract (Gated)",
    );
    assert_contains(
        agents_path,
        &agents,
        "one `run_id` is created and every committed log, manifest, frontend snapshot, video reference, and service-state capture binds to that same `run_id`, `session_id`, and `vm_lease_id` whenever those identifiers exist.",
    );
    assert_contains(
        agents_path,
        &agents,
        "plaintext RDP credentials, session tokens, and similar secrets are forbidden from git-tracked artifacts",
    );
    assert_contains(
        agents_path,
        &agents,
        "single repo-local Windows provisioning key file is explicitly allowlisted for local Win11 host creation only",
    );
    assert_contains(
        agents_path,
        &agents,
        "raw `.qcow2`, overlay, memory-dump, and equivalent heavy or sensitive VM state are forbidden from normal git history",
    );

    let testing_path = "docs/honeypot/testing.md";
    let testing = read_repo_text(testing_path);
    assert_contains(testing_path, &testing, "## Manual Headed Lab Contract");
    assert_contains(
        testing_path,
        &testing,
        "The manual-headed lane remains supplemental to the canonical Rust `lab-e2e` proof",
    );
    assert_contains(
        testing_path,
        &testing,
        "allows the single repo-local Windows provisioning key file documented in `WINDOWS11-LICENSE.md`",
    );
    assert_contains(
        testing_path,
        &testing,
        "the attested Tiny11 image-store or interop root declaration",
    );
    assert_contains(
        testing_path,
        &testing,
        "The `manual_stack_startup_shutdown` runtime anchor is now machine-validated instead of free-form.",
    );
    assert_contains(
        testing_path,
        &testing,
        "exactly three `services` entries named `control-plane`, `proxy`, and `frontend`",
    );
    assert_contains(
        testing_path,
        &testing,
        "`teardown_disposition` as `clean_shutdown` or `explicit_failure`",
    );
    assert_contains(
        testing_path,
        &testing,
        "The `manual_video_evidence` runtime anchor is now machine-validated in the shared verifier path rather than only at writer time.",
    );
    assert_contains(
        testing_path,
        &testing,
        "`video_sha256`, `duration_floor_secs`, `timestamp_window`, `storage_uri`, and `retention_window`",
    );
    assert_contains(
        testing_path,
        &testing,
        "the metadata artifact must carry matching values instead of detached or free-form notes",
    );
    assert_contains(
        testing_path,
        &testing,
        "The `manual_headed_qemu_chrome_observation` runtime anchor is now machine-validated in the shared verifier path rather than treated as a free-form screenshot note.",
    );
    assert_contains(
        testing_path,
        &testing,
        "`qemu_display_mode`, `qemu_launch_reference`, `browser_family`, `frontend_access_path`, and `correlation_snapshot`",
    );
    assert_contains(
        testing_path,
        &testing,
        "the headed-observation anchor and the Tiny11 RDP-ready anchor to agree on the same `vm_lease_id`",
    );
    assert_contains(
        testing_path,
        &testing,
        "The `manual_bounded_interaction` runtime anchor is now machine-validated in the shared verifier path rather than left as a free-form operator note.",
    );
    assert_contains(
        testing_path,
        &testing,
        "`interaction_window`, `session_id`, `vm_lease_id`, and `modalities`",
    );
    assert_contains(
        testing_path,
        &testing,
        "`modalities.mouse`, `modalities.keyboard`, and `modalities.browsing` must each provide `event_count > 0` and at least one non-empty `evidence_refs` entry",
    );
    assert_contains(
        testing_path,
        &testing,
        "the bounded-interaction anchor to agree on the same `session_id` and `vm_lease_id` as the headed-observation and video anchors",
    );

    let runbook_path = "docs/honeypot/runbook.md";
    let runbook = read_repo_text(runbook_path);
    assert_contains(
        runbook_path,
        &runbook,
        "the attested Tiny11 image-store or interop root is named before startup begins",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "exactly three service entries named `control-plane`, `proxy`, and `frontend`",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "a non-empty failure code and a non-empty failure reason",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "write one machine-readable JSON artifact that records `video_sha256`, `duration_floor_secs`, `timestamp_window`, `storage_uri`, and `retention_window`",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "ensure the stored `session_id` and `vm_lease_id` match the runtime anchor invocation",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "write one machine-readable JSON artifact that records `qemu_display_mode`, `qemu_launch_reference`, `browser_family`, `frontend_access_path`, and `correlation_snapshot`",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "The headed-observation artifact must also agree on `vm_lease_id` with the Tiny11 RDP-ready anchor",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "write one machine-readable JSON artifact that records `interaction_window`, `session_id`, `vm_lease_id`, and `modalities`",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "Keep `interaction_window` ordered and bounded, keep it inside the recorded video `timestamp_window`, and keep its `session_id` plus `vm_lease_id` aligned with the headed-observation anchor.",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "`modalities.mouse`, `modalities.keyboard`, and `modalities.browsing` must each provide `event_count > 0` and at least one non-empty `evidence_refs` entry",
    );
}

#[test]
fn honeypot_docs_keep_windows_provisioning_key_allowlist_narrow() {
    let key_doc_path = "WINDOWS11-LICENSE.md";
    let key_doc = read_repo_text(key_doc_path);
    assert!(
        contains_windows_product_key_like_plaintext(&key_doc),
        "{key_doc_path} must retain the repo-local Windows provisioning key"
    );

    for doc_path in ["AGENTS.md", "docs/honeypot/runbook.md", "docs/honeypot/testing.md"] {
        let body = read_repo_text(doc_path);
        assert!(
            !contains_windows_product_key_like_plaintext(&body),
            "{doc_path} must not duplicate the repo-local Windows provisioning key"
        );
    }

    let runbook_path = "docs/honeypot/runbook.md";
    let runbook = read_repo_text(runbook_path);
    assert_contains(
        runbook_path,
        &runbook,
        "Do not copy that key into manual-headed evidence, screenshots, exports, secondary docs, or any other tracked artifact.",
    );
}

#[test]
fn honeypot_docs_keep_canonical_tiny11_lab_gate_fail_closed() {
    let agents_path = "AGENTS.md";
    let agents = read_repo_text(agents_path);
    assert_contains(
        agents_path,
        &agents,
        "- [x] Add a canonical Tiny11 availability and readiness gate for lab-backed runs.",
    );

    let testing_path = "docs/honeypot/testing.md";
    let testing = read_repo_text(testing_path);
    assert_contains(testing_path, &testing, "## Canonical Tiny11 Lab Gate");
    assert_contains(
        testing_path,
        &testing,
        "The blocker order is `missing_store_root`, `invalid_provenance`, `unclean_state`, `missing_runtime_inputs`, then `ready`.",
    );
    assert_contains(
        testing_path,
        &testing,
        "reuses the existing manifest-backed Tiny11 authority instead of inventing a second verifier",
    );

    let runbook_path = "docs/honeypot/runbook.md";
    let runbook = read_repo_text(runbook_path);
    assert_contains(
        runbook_path,
        &runbook,
        "Relevant Tiny11-backed `lab-e2e` lanes now execute one canonical availability and readiness gate before lease work begins.",
    );
    assert_contains(
        runbook_path,
        &runbook,
        "repopulate it only through `honeypot-control-plane consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>`",
    );
}
