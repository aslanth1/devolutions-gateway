# What Was Done

- Read recent run insights and summarized the stable pattern: fail-closed row706 authority works, free-form runtime evidence does not, and remaining honest progress is shared verifier hardening.
- Ran the 3-seat council with `Singer`, `Rawls`, and `Huygens`.
- All three seats independently chose row `710`.
- The council vote finished `2-1` for Seat B's plan: harden `manual_tiny11_rdp_ready` with explicit probe, provenance, and key-source semantics tied to row `706`.
- Closed all three sub-agents after the vote.
- Implemented the row `710` validator in `testsuite/src/honeypot_control_plane.rs`.
- Extended the manual-headed writer to validate row `710` artifacts against the verified row-`706` envelope at runtime write time.
- Replaced the synthetic `runtime/rdp.json` fixture with a real JSON contract in `testsuite/tests/honeypot_manual_headed.rs`.
- Added verifier-side negatives for weak probe evidence and provenance drift.
- Added a writer-side negative for leaking an absolute secret path through `key_source.alias`.
- Updated `docs/honeypot/testing.md`, `docs/honeypot/runbook.md`, `testsuite/tests/honeypot_docs.rs`, and checked row `710` in `AGENTS.md`.

# Commands And Actions Taken

- `git status --short`
- `rg -n "manual_tiny11_rdp_ready|MANUAL_HEADED_ANCHOR_TINY11_RDP_READY|manual_headed_tiny11|tiny11_rdp_ready" ...`
- `cargo test -p testsuite --test integration_tests honeypot_manual_headed -- --nocapture`
- `cargo test -p testsuite --test integration_tests honeypot_docs -- --nocapture`
- `cargo +nightly fmt --all`
- `cargo +nightly fmt --all --check`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests`
- targeted reruns for unrelated transient failures:
  - `cargo test -p testsuite --test integration_tests cli::dgw::honeypot::honeypot_command_proposal_route_returns_typed_deferred_placeholder_when_enabled -- --nocapture`
  - `cargo test -p testsuite --test integration_tests cli::dgw::honeypot::honeypot_session_quarantine_route_requires_honeypot_kill_scope -- --nocapture`
  - `cargo test -p testsuite --test integration_tests cli::dgw::ai_gateway::ai_gateway_requires_gateway_api_key -- --nocapture`
  - `cargo test -p testsuite --test integration_tests honeypot_control_plane::control_plane_force_quarantines_active_leases -- --nocapture`
  - `cargo test -p testsuite --test integration_tests cli::dgw::honeypot::honeypot_bootstrap_route_uses_the_configured_path -- --nocapture`

# Deviations From Plan

- The first three full-suite attempts hit unrelated host or port startup flakes before the final exact rerun passed cleanly.
- No design deviation was needed for row `710`; the winning plan held.
