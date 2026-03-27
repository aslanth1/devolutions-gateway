# Outcome

- Council winner: `AGENTS.md:706`
- Vote: `2-1`
- Tie-break: not needed

## Observable Signals

- The repo already had:
  - one-shot gold-image acceptance coverage
  - external-client interop smoke coverage
  - digest-mismatch negative control coverage
- This turn added:
  - repeated gold-image acceptance and recycle coverage in one control-plane run
  - explicit row `706` evidence criteria in the testing doc
- Focused verification passed:
  - `cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_ -- --nocapture`
  - `DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE=/tmp/honeypot-lab-gate.json cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_ -- --nocapture`
  - `cargo test -p testsuite --test integration_tests control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire -- --nocapture`
  - `cargo +nightly fmt --all`
  - `cargo +nightly fmt --all --check`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests` with `249 passed`

## Unexpected Behavior

- The first exact full-suite run hit an unrelated transient `404` in `frontend_dashboard_requires_operator_token`.
- That test passed immediately in isolation, and the final exact full-suite rerun passed cleanly.

## Success Or Failure

- Partial success.
- The proof lane for row `706` is stronger and more explicit.
- Row `706` itself was not completed on this workstation because no prepared Tiny11-derived interop image store was available for a truthful non-skipped `lab-e2e` run.
