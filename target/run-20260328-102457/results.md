# Success / Failure
Success, but not as a pure no-op verification run.
The winning proof plan surfaced a real next task, the task was fixed in-turn, and the stronger proof gates passed afterward.

## Observable Signals
- Checklist state:
  - `AGENTS.md` still has zero unchecked `[ ]` rows.
  - only one authoritative `AGENTS.md` exists in-repo.
- Static gates:
  - `cargo +nightly fmt --all` passed.
  - `cargo clippy --workspace --tests -- -D warnings` passed.
- Orthogonal seam gate:
  - `cargo test -p testsuite --test integration_tests honeypot_release:: -- --nocapture` passed with `62 passed; 0 failed`.
  - release-input anchors for `promotion-manifest.json`, `images.lock`, and `signature_ref` remained aligned across docs and tests.
- Failure that surfaced the real next task:
  - `target/flakes/replay-current-20260328-102457/2.log` failed with `cli::jetsocat::mcp_proxy_notification::http_transport_1_true`
  - panic: `Address already in use (os error 98)`
  - source: `testsuite::mcp_server::HttpTransport::bind`
- Post-fix targeted validation:
  - `cli::jetsocat::mcp_proxy_notification::` => `2 passed; 0 failed`
  - `cli::dgw::ai_gateway::` => `5 passed; 0 failed`
  - `mcp_proxy::` => `6 passed; 0 failed`
- Post-fix whole-suite replay:
  - `patched-1.log` => `311 passed; 0 failed`
  - `patched-2.log` => `311 passed; 0 failed`
  - `patched-3.log` => `311 passed; 0 failed`
  - `patched-4.log` => `311 passed; 0 failed`

## Unexpected Behavior
- The earlier low-band allocator stabilization was necessary but not sufficient.
  It correctly protected select-then-bind flows, but it also captured some listeners that should have stayed on true ephemeral `:0`.
- The stronger `4x` replay gate was worth the extra cost.
  It found a flaky seam that the previous `3x` proof did not expose.
