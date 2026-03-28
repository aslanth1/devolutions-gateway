## Result

Partial success with a meaningful DF-07 improvement.

The repo now has a checked-in promotion manifest contract artifact and the always-on release-input validator fails if `promotion-manifest.json` is malformed or drifts from `images.lock current` entries.

## Observable Signals

- Added [promotion-manifest.json](/home/jf/src/devolutions-gateway/honeypot/docker/promotion-manifest.json).
- The on-disk release-input test now includes the manifest path and still passes.
- New targeted negative tests all passed:
  - `honeypot_release::promotion_manifest_rejects_missing_signature_ref`
  - `honeypot_release::promotion_manifest_rejects_unknown_or_duplicate_service_records`
  - `honeypot_release::promotion_manifest_rejects_floating_tags`
  - `honeypot_release::release_inputs_reject_promotion_manifest_lock_mismatch`
- `cargo +nightly fmt --all` passed.
- `cargo clippy --workspace --tests -- -D warnings` passed.

## Unexpected Behavior

The full `cargo test -p testsuite --test integration_tests` binary did not give a stable all-green result during this turn.
Three different unrelated tests failed across three full-suite runs:

- `cli::dgw::preflight::provision_credentials_passwords_not_logged`
- `honeypot_control_plane::control_plane_process_driver_reports_qemu_startup_failures`
- `honeypot_frontend::frontend_dashboard_shows_quarantine_button_and_forwards_requests`

Each of those tests passed immediately when rerun in isolation.
That is strong evidence of existing whole-binary flakiness or order-sensitive interference, not a localized deterministic regression in the DF-07 release-input seam.

## Scope Boundary

This run proves that the DF-07 contract tier is stronger than before:
one checked-in manifest-shaped rollout input is now required and bound to the checked-in lockfile.

This run does not prove that protected-branch cryptographic verification of `signature_ref` is complete, and it does not resolve the observed full-suite flakiness.
