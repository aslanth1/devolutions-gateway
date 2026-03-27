# Hypothesis

The honest way to "perform the checklist in AGENTS.md" on this host is to finish the missing Milestone 6a checklist machinery without faking a live Tiny11 closure.

The council voted `2-1` for a single-authority plan:

- keep `row706` as the only runtime authority for row `735`
- add the manual-headed checklist as a profile under the same `target/row706/runs/<run_id>/` root
- tighten docs and tests so preflight-only checklist rows are enforceable
- keep the live Tiny11 production row blocked until real interop prerequisites exist

The user then changed one policy assumption mid-run:

- keep the repo-local Windows provisioning key
- update the rules to allow exactly that one tracked key file for local Win11 host creation
- still forbid copying that key into manual-headed evidence or secondary tracked artifacts

# Steps

1. Re-read open AGENTS rows and prior `target/*/insights.md`.
2. Seat a 3-agent council and collect idea, critique, refinement, plan, and vote phases.
3. Reconcile the user-requested Windows key exception with Milestone 6a policy.
4. Implement the manual-headed profile in the existing `row706` helper module.
5. Add targeted integration tests for:
   - runtime anchors requiring verified `row706` evidence
   - digest mismatch rejection
   - relpath escape rejection
   - missing `session_id` rejection for headed observation
6. Add docs tests for the narrow Windows key allowlist and the manual-headed contract wording.
7. Re-run focused verification, clippy, and the full integration suite.
8. Update AGENTS conservatively.

# Assumptions

- This host still has no `DGW_HONEYPOT_INTEROP_*`, `DGW_HONEYPOT_LAB_E2E`, or `DGW_HONEYPOT_TIER_GATE` env in the current shell.
- `DISPLAY=:0`, Chrome, QEMU, FreeRDP, `/dev/kvm`, and the workstation-local Win11 labs are present, so preflight capability is real.
- Row `735` cannot be checked honestly without a non-skipped live Tiny11-derived interop run.
