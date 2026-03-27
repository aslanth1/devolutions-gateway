# Plan

## Hypothesis

The highest-value honest task among remaining AGENTS rows is row `699`, because rows `396` and `706` still depend on non-skipped Tiny11 live RDP evidence that this workstation does not currently provide.

Row `699` can be completed as enforceable repo policy, not prose, by adding a docs-governance test that fails closed unless Milestone 0 and Milestone 0.5 checklist rows are fully complete whenever Milestone 1 through Milestone 6 rows are marked complete.

## Steps

1. Ingest prior `target/*/insights.md` files and summarize reusable constraints.
2. Run the 3-seat council process and pick one plan with explicit feasibility and evidence criteria.
3. Implement a reusable AGENTS section-check helper in `testsuite/src/honeypot_docs.rs`.
4. Add a `honeypot_docs` integration test that enforces the milestone gate invariant.
5. Update `docs/honeypot/testing.md` with Milestone Gate evidence.
6. Check off AGENTS row `699` only if tests prove the invariant.
7. Run baseline verification (`fmt`, `clippy`, full `integration_tests`), retrying transient flakes cleanly.

## Assumptions

- The remaining unchecked rows are exactly `396`, `699`, and `706`.
- Tiny11 rows stay blocked without non-skipped live-lab evidence.
- AGENTS governance rows are valid to satisfy through enforceable docs tests in `testsuite/tests/honeypot_docs.rs`.
