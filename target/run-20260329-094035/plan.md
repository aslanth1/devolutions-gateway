# BS-37 Plan

## Hypothesis

- If `ManualLabBlackScreenEvidence` persists a JSON-owned `do_not_retry_ledger` with explicit `hypothesis_id`, explicit hypothesis text, fixed rejection reasons, and fixed retry-condition codes, then `BS-37` can be closed without pre-implementing retry enforcement from `BS-38`.

## Steps

1. Re-read the recent `target/*/insights.md` artifacts and the next open `BS-*` rows in `AGENTS.md`.
2. Run a 3-agent council on the next black-screen task and force proposal, critique, refinement, detailed-plan, and voting phases.
3. Pick the winning plan and keep it constrained to a record-only ledger on the existing manual-lab evidence path.
4. Extend `testsuite/src/honeypot_manual_lab.rs` with explicit black-screen hypothesis context and a persisted `do_not_retry_ledger`.
5. Add focused `integration_tests` coverage in `testsuite/tests/honeypot_manual_lab.rs`.
6. Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests`.
7. Update `AGENTS.md` and write the run bundle.

## Assumptions

- `BS-37` is about durable recording, not enforcement.
- `ManualLabBlackScreenEvidence` is the canonical owner for black-screen proof artifacts.
- The retry condition should stay machine-checkable and not become prose.
- Guacd’s explicit graphics-policy mindset is still the right design cue for this lane.
