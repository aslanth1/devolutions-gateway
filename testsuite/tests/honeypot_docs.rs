use testsuite::honeypot_docs::{assert_contains, read_repo_text};

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
