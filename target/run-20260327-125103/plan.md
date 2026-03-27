# Hypothesis

The next honest checklist item to close is `AGENTS.md` row `707`, the manual full-stack startup and shutdown proof checklist.
The existing manual-headed profile already has the right evidence envelope and runtime gate, but the `manual_stack_startup_shutdown` artifact is still too weak unless the verifier and writer enforce a machine-readable contract.

# Steps

1. Reuse recent `target/*/insights.md` artifacts to avoid repeating prior dead ends.
2. Run a 3-seat council and select one AGENTS row to execute now.
3. Tighten the manual-headed runtime artifact contract for `manual_stack_startup_shutdown` inside the existing row-`706` authority.
4. Add focused negative and positive integration coverage for verifier and writer behavior.
5. Update `docs/honeypot/testing.md`, `docs/honeypot/runbook.md`, and `testsuite/tests/honeypot_docs.rs` so the docs describe the exact enforced contract.
6. Review `AGENTS.md` and check row `707` only if the implementation, docs, and tests all align.
7. Run the baseline verification path and save a clean rerun result.

# Assumptions

- The host still lacks admissible Tiny11 runtime proof, so rows `710`, `713`, `716`, `719`, and `738` must remain open.
- The manual-headed profile must remain inside `target/row706/runs/<run_id>/` and must not introduce a second evidence authority.
- Runtime checklist closure is only acceptable if the contract is machine-validated rather than free-form prose.
