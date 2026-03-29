# BS-37 Results

## Success / Failure

- Success.
- `BS-37` is now implemented and checked off in `AGENTS.md`.

## Observable Signals

- `ManualLabBlackScreenEvidence` now persists a JSON-owned `do_not_retry_ledger`.
- The new ledger records explicit `hypothesis_id` and `hypothesis_text` inputs, the failing lane, the artifact root, the primary rejection reason, and a fixed retry-condition code.
- Focused tests passed:
  - `manual_lab_do_not_retry_ledger_records_amber_disproven_hypothesis`
  - `manual_lab_do_not_retry_ledger_records_red_disproven_hypothesis`
  - `manual_lab_do_not_retry_ledger_is_not_required_for_green_run`
  - `manual_lab_do_not_retry_ledger_fails_closed_without_retry_condition`
- Baseline verification passed:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests`
- Full suite signal:
  - `362 passed; 0 failed`

## Unexpected Behavior

- A monolithic patch attempt failed because one source context seam had moved, so the final source edit used smaller patches.
- The first focused test filter did not include the new `manual_lab_do_not_retry_*` names and needed a second targeted run.

## Residual Risk

- The ledger is record-only by design and does not yet enforce retry policy.
- Hypothesis inputs are explicit and persisted, but they still depend on the caller supplying them truthfully during future manual-lab runs.
