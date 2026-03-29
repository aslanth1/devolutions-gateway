# BS-40 / BS-41 Results

## Success / Failure

- `BS-40`: success
- `BS-41`: success

## Observable Signals

- `docs/honeypot/runbook.md` now contains one canonical `Black-Screen Experiment Contract` section.
- The section names:
  - the cross-run order `control -> variant -> compare`
  - the per-run command order `ensure-artifacts -> preflight -> up -> status -> down`
  - the sanctioned emitted lane names
  - the required run-level and session-local artifact filenames
  - the accepted top-level verdict tokens
  - the exact reducer and emitter anchors in `testsuite/src/honeypot_manual_lab.rs`
- `docs/honeypot/testing.md` now points back to the runbook instead of duplicating the contract.
- `testsuite/tests/honeypot_docs.rs` now fails closed if the canonical runbook section drifts away from those names or tokens.
- Verification passed:
  - focused docs-policy test passed
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests`
- Full suite result: `368 passed; 0 failed`

## Unexpected Behavior

- None.
- The council converged immediately on `BS-40`; the meaningful disagreement was only about how tight the docs-policy assertion should be.
