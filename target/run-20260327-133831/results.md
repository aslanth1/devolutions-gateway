# Success Or Failure

Success.
Row `710` is now enforced and checked.
Row `738` remains open.

# Observable Signals

- `manual_tiny11_rdp_ready` now requires:
  - `probe.method`, `probe.endpoint`, `probe.captured_at_unix_secs`, `probe.ready`, and `probe.evidence_ref`
  - `identity.vm_lease_id` and optional `identity.session_id`
  - `provenance.row706_run_id`, `provenance.attestation_ref`, and `provenance.interop_store_root`
  - `key_source.class` and `key_source.alias`
- The validator rejects:
  - non-ready probe claims
  - row706 provenance drift
  - raw Windows product-key leakage
  - absolute or host-specific secret-path leakage
- The manual-headed writer now enforces the same row `710` contract against a verified row-`706` envelope before recording runtime evidence.
- `AGENTS.md` row `710` is checked.

# Verification

- Passed: `cargo test -p testsuite --test integration_tests honeypot_manual_headed -- --nocapture`
- Passed: `cargo test -p testsuite --test integration_tests honeypot_docs -- --nocapture`
- Passed: `cargo +nightly fmt --all`
- Passed: `cargo +nightly fmt --all --check`
- Passed: `cargo clippy --workspace --tests -- -D warnings`
- Passed: final exact `cargo test -p testsuite --test integration_tests` with `297 passed`

# Unexpected Behavior

- Intermediate full-suite attempts showed unrelated transient failures:
  - honeypot route startup timeouts
  - one AI gateway status assertion returning `0`
  - one control-plane lease test seeing a transient malformed response
  - one transient bind conflict on a control-plane listener port
- Each affected exact test passed immediately on rerun, and the final exact full-suite rerun passed cleanly.
