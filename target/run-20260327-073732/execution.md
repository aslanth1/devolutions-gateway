# What Was Done

1. Ran memory ingest over prior `target/*/insights.md` and summarized repeated patterns:
   - reuse existing consume/acceptance/xfreerdp seams
   - do not count skipped lab runs as evidence
   - avoid stale shared `target/row706` artifacts
2. Ran a 3-seat council with full proposal, critique, refinement, plan, and vote phases.
3. Implemented the winning run-scoped verifier plan in `testsuite/src/honeypot_control_plane.rs`.
4. Updated `testsuite/tests/honeypot_control_plane.rs` so row-706 synthetic tests and live anchor emitters use explicit run ids and manifests.
5. Updated `docs/honeypot/testing.md` to describe the new run-scoped evidence contract.

# Commands / Actions

- `rg -n "row706|verify_row706_evidence_envelope|record_row706_|write_row706|Row706" testsuite/src testsuite/tests docs/honeypot/testing.md`
- `cargo test -p testsuite --test integration_tests control_plane_row706_evidence_envelope_ -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_ -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_external_client_interoperability_smoke_uses_xfreerdp -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire -- --nocapture`
- `cargo +nightly fmt --all`
- `cargo +nightly fmt --all --check`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests`

# Deviations

- The council winner did not require destructive cleanup or auto-selection, so I did not add preflight deletion or “latest run” heuristics.
- I did not mark `AGENTS.md:706` complete because the host still lacks the required live Tiny11-derived interop proof.
