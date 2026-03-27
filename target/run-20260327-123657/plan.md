# Plan

## Hypothesis

One canonical Tiny11 lab gate can satisfy `AGENTS.md` row `396` if it reuses the existing manifest-backed interop store authority, blocks missing or invalid Tiny11 state before lease work begins, and enforces clean-state plus required runtime readiness for every relevant lab-backed run.

## Steps

1. Reuse prior `target/*/insights.md` findings and finish the 3-seat council around the new Tiny11 gate row.
2. Implement a typed Tiny11 lab gate in `testsuite/src/honeypot_control_plane.rs`.
3. Rewire the relevant `lab-e2e` control-plane entrypoints to use the shared gate instead of ad hoc env checks.
4. Add focused integration tests for missing store, invalid provenance, unclean state, and ready state.
5. Update `docs/honeypot/testing.md`, `docs/honeypot/runbook.md`, and `AGENTS.md` so the contract matches the code.
6. Run baseline verification and only check the AGENTS row if the baseline stays green.

## Assumptions

- `load_honeypot_interop_store_evidence` remains the single provenance authority for Tiny11 interop manifests.
- The relevant lab-backed entrypoints are the external interop anchor plus the two gold-image acceptance anchors.
- A generic documented `consume-image` remediation is sufficient when no concrete source bundle path is discoverable locally.
