# Results

## Success Or Failure

- Success: `AGENTS.md` row `396` is now implemented and checked honestly.

## Observable Signals

- `evaluate_tiny11_lab_gate` now blocks `missing_store_root`, `invalid_provenance`, `unclean_state`, and `missing_runtime_inputs` before a lab-backed run may proceed.
- The external interop and gold-image acceptance entrypoints now share one fail-closed Tiny11 gate path.
- New focused tests passed for:
  - missing canonical store
  - invalid provenance before runtime inputs
  - unclean state before runtime inputs
  - clean attested store with ready inputs
- Docs-governance now asserts the canonical Tiny11 gate contract.
- Baseline verification ended clean with:
  - `cargo +nightly fmt --all --check`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests` => `284 passed`

## Unexpected Behavior

- The first full integration run failed once in `cli::dgw::honeypot::honeypot_system_terminate_route_respects_kill_switch` with a transient `Connection refused`.
- The exact test passed immediately on rerun, and the full integration suite passed on the next full rerun, so I treated it as an unrelated flake rather than a regression from the Tiny11 gate work.
