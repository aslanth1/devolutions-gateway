# BS-38 Results

## Outcome

Success.
`BS-38` is now closed.

## Observable Signals

- `ManualLabBlackScreenEvidence` now persists a reducer-owned `artifact_contract_summary`.
- `ManualLabBlackScreenEvidence` now persists a reducer-owned `control_run_comparison_summary`.
- Variant runs fail closed unless a sibling control evidence JSON:
  - loads successfully
  - is marked `is_control_lane`
  - carries a current run verdict
  - falls on the same UTC day
  - matches the same persisted artifact contract

## Verification

- `cargo +nightly fmt --all` passed.
- `cargo clippy --workspace --tests -- -D warnings` passed.
- `cargo test -p testsuite --test integration_tests` passed with `366 passed; 0 failed`.

## Unexpected Behavior

- None in the final implementation.
- Early focused test commands initially used a non-existent per-file test target; rerunning them through `integration_tests` resolved that immediately.
