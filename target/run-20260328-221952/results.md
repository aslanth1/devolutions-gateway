# Results

## Outcome

Success for `BS-14`.

- `rdp_gfx` now emits structured per-session corruption counters instead of only free-form warning text.
- Manual-lab evidence now preserves the parsed warning summary per session in `black-screen-evidence.json`.
- Teardown now repersists evidence after proxy shutdown, so late-flushed summary lines are no longer lost.

## Observable Signals

- New log line: `GFX warning summary`
- New evidence field: `session_invocations[].gfx_warning_summary`
- `AGENTS.md` row `BS-14` is now checked off.

## Validation

- `cargo +nightly fmt --all`: passed
- `cargo clippy --workspace --tests -- -D warnings`: passed
- `cargo test -p testsuite manual_lab_parses_gfx_warning_summary_lines -- --nocapture`: passed
- `cargo test -p testsuite --test integration_tests -- --nocapture`: passed
- Integration result: `348 passed; 0 failed`

## Unexpected Behavior

- The existing `rdp_gfx` unit-test module is host-disabled by `target_os = "none"`, so Cargo name-filtered host runs still show those tests as filtered out.
- That test-gating constraint is now explicit evidence for why `BS-18` should stay open.
