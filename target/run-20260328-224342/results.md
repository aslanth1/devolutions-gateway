## Success / Failure

- Success for `BS-15`.
- No behavior change was attempted beyond instrumentation and evidence parsing.
- `BS-16`, `BS-17`, `BS-18`, `BS-19`, and `BS-20` remain open.

## Observable Signals

- Validation stayed green:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests -- --nocapture`
  - Result: `348 passed; 0 failed`
- Proof run: `manual-lab-da4c872eafbc494abe40d8dd274fda33`
- Proof artifact:
  - `target/manual-lab/manual-lab-da4c872eafbc494abe40d8dd274fda33/artifacts/black-screen-evidence.json`
- Live probe state during the run:
  - slot 1 `ready`
  - slot 2 `ready`
  - slot 3 truthful `503`
- Final persisted bootstrap evidence after teardown:
  - slot 1 verdict `complete`
  - slot 2 verdict `complete`
  - slot 3 verdict `complete`
  - all three sessions recorded explicit producer start, handshake seam, leftover feed, and first update ordering

## Unexpected Behavior

- Slot 3 changed from live-probe `503` to a teardown-time `complete` bootstrap timeline with `playback.update.wrapped_gfx.first`.
- That means the remaining failure is not “producer never attached” and not “leftovers were never fed”.
- The remaining contradiction is now between playback progress and the observation-ready path, which is the next tranche.
