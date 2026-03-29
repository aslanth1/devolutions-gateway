# BS-40 / BS-41 Plan

## Hypothesis

- `BS-40` is best closed as a docs-contract patch, not a runtime patch.
- The repo already has reducer-owned black-screen evidence, so the remaining gap is operator drift in experiment order, lane naming, artifact naming, and verdict vocabulary.
- `BS-41` should stay a verification gate, not a second design surface.

## Steps

1. Re-ingest recent `target/run-*/insights.md` artifacts to avoid split-authority and prose-only regressions.
2. Run a 3-agent council on the next open `AGENTS.md` rows.
3. Prefer a plan that keeps one canonical authority, likely in `docs/honeypot/runbook.md`.
4. Anchor the runbook text to the real black-screen reducer and emitter names in `testsuite/src/honeypot_manual_lab.rs`.
5. Add a docs-policy test in `testsuite/tests/honeypot_docs.rs` that fails closed if the contract drifts.
6. Update `AGENTS.md` progress only after the docs contract and baseline verification are both green.

## Assumptions

- `docs/honeypot/runbook.md` is the correct operator-facing source of truth for black-screen procedure.
- `docs/honeypot/testing.md` should only point to the canonical runbook section, not duplicate the rule set.
- No runtime changes are required for `BS-40`.
- `BS-41` can be checked off in the same patch if the full baseline Rust trio passes with no unrelated blocker.
