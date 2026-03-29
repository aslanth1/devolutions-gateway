# Results

## Success / Failure

Success.
The proxy no longer advertises a live recording stream when no JREC producer exists.
Manual-lab now reaches a truthful steady state instead of the old fake-live failure mode.

## Observable Signals

- Live manual-lab rerun succeeded with:
  - `manual lab phase=control-plane.ready`
  - `manual lab phase=proxy.ready`
  - `manual lab phase=frontend.ready`
  - `manual lab phase=services.ready`
  - three `manual lab phase=session.assigned`
  - three `manual lab phase=session.stream.unavailable detail=HTTP/1.1 503 Service Unavailable`
  - `manual lab phase=frontend.tiles.ready`
  - `manual lab is live`
- Active run metadata showed:
  - all three service PIDs present
  - all three session lease IDs present
  - all three `stream_id` values `null`
- Tokenized proxy bootstrap returned `200`.
- Validation passed:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests -- --nocapture`
  - result: `348 passed; 0 failed`

## Unexpected Behavior

- Full integration validation initially failed because the proof run remained active and CLI tests intentionally detect that active-state blocker.
- `python` was absent on the host; `python3` had to be used for token extraction during live endpoint checks.
