# BS-23 Results

## Success Or Failure

Success.
`BS-23` is now closed in `AGENTS.md`.

## Observable Signals

- `AGENTS.md` now records bounded `Rfx` contract proof evidence for `BS-23`.
- `testsuite/src/honeypot_manual_lab.rs` exposes a small helper that renders the real `xfreerdp-rfx` lane contract.
- `testsuite/tests/honeypot_manual_lab.rs` proves the exact lane identity and exact codec flags survive into per-session evidence.
- The proof also confirms the archived same-day control companion still yields `MeaningfulWithSameDayControl`.
- `docs/honeypot/runbook.md` now names the explicit `BS-23` lane and its archived-control prerequisite.
- `testsuite/tests/honeypot_docs.rs` fails closed if that runbook rule is removed or softened.
- Verification passed:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests`
- Integration suite result: `369 passed; 0 failed`

## Unexpected Behavior

- The only unexpected issue was a pair of clippy warnings about redundant clones in the new test.
- No runtime or contract mismatch surfaced once those bindings were simplified.
