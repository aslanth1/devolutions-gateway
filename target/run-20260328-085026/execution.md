## What Was Actually Done

1. Rechecked repo state and memory-ingested recent `target/*/insights.md` artifacts.
2. Spawned a fresh 3-seat council with `gpt-5.3-codex` at high reasoning effort.
3. Ran all requested council phases:
   - idea generation
   - adversarial critic review
   - refinement
   - detailed planning
   - voting
4. Verified locally that:
   - `AGENTS.md` still had no unchecked rows
   - `release.md` required `promotion-manifest.json` and forbade direct manual `images.lock` edits
   - executable release checks were mainly validating lockfile/compose structure and promoted-placeholder guards
   - `honeypot/docker/images.lock` still used placeholder values
5. Executed the winning Seat 3 plan by:
   - adding [promotion-manifest.json](/home/jf/src/devolutions-gateway/honeypot/docker/promotion-manifest.json)
   - extending [honeypot_release.rs](/home/jf/src/devolutions-gateway/testsuite/src/honeypot_release.rs) with:
     - `HONEYPOT_PROMOTION_MANIFEST_PATH`
     - typed promotion-manifest structs
     - manifest parsing and validation
     - manifest-to-lockfile binding
     - updated `validate_honeypot_release_inputs(...)`
   - extending [honeypot_release.rs](/home/jf/src/devolutions-gateway/testsuite/tests/honeypot_release.rs) with negative tests for:
     - missing `signature_ref`
     - duplicate/unknown service records
     - floating tags
     - manifest-lock drift
   - updating [release.md](/home/jf/src/devolutions-gateway/docs/honeypot/release.md) and [testing.md](/home/jf/src/devolutions-gateway/docs/honeypot/testing.md) to document the executable contract-tier behavior

## Commands And Actions Taken

Key commands:

```bash
rg -n '^\s*[-*]\s+\[ \]|\[ \]' AGENTS.md
sed -n '1,220p' docs/honeypot/release.md
sed -n '1,260p' testsuite/src/honeypot_release.rs
sed -n '820,930p' testsuite/src/honeypot_release.rs
sed -n '1,200p' honeypot/docker/images.lock
```

Targeted validation commands:

```bash
cargo test -p testsuite --test integration_tests honeypot_release::release_inputs_on_disk_match_the_honeypot_lockfile_contract -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_release::promotion_manifest_rejects_missing_signature_ref -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_release::promotion_manifest_rejects_unknown_or_duplicate_service_records -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_release::promotion_manifest_rejects_floating_tags -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_release::release_inputs_reject_promotion_manifest_lock_mismatch -- --nocapture
cargo +nightly fmt --all
cargo clippy --workspace --tests -- -D warnings
cargo test -p testsuite --test integration_tests
cargo test -p testsuite --test integration_tests cli::dgw::preflight::provision_credentials_passwords_not_logged -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_control_plane::control_plane_process_driver_reports_qemu_startup_failures -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_frontend::frontend_dashboard_shows_quarantine_button_and_forwards_requests -- --nocapture
```

## Deviations From Plan

The winning plan suggested an optional narrow smoke/evidence pass after the contract work.
Instead of adding new smoke-only coverage, I used the repo baseline path and recorded the outcome honestly:
the targeted DF-07 contract tests passed, `fmt` passed, `clippy` passed, and the full `integration_tests` binary showed unrelated order-sensitive failures that passed when rerun individually.

## Important Findings

- The DF-07 contract seam now has executable manifest binding instead of docs-only policy.
- `AGENTS.md` still has no unchecked boxes.
- No AGENTS rows were toggled because none remained open.
