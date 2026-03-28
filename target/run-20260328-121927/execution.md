# What Was Done

- Ingested recent insights and summarized the repeated lessons:
  - shared Rust authority and thin Make wrappers work,
  - docs-only fixes do not unblock host failures,
  - fail-closed manifest logic should be reused,
  - the new blocker is `/srv` writability, not source-manifest ambiguity.
- Ran a 3-seat council with `gpt-5.3-codex` at `high` reasoning effort.
- The winning plan was unanimous in practice: keep canonical `/srv` as default, add an explicit local profile for non-root hosts, and add typed store-root remediation.

# Commands And Actions

Council and host diagnosis:

```bash
make manual-lab-bootstrap-store-exec
ls -ld /srv /srv/honeypot /srv/honeypot/images
sudo -n true
```

Implementation:

- Updated `AGENTS.md`.
- Updated `Makefile`.
- Added `honeypot/docker/config/control-plane/manual-lab-bootstrap.local.toml`.
- Updated `docs/honeypot/runbook.md` and `docs/honeypot/testing.md`.
- Updated `testsuite/src/honeypot_manual_lab.rs`.
- Updated `testsuite/tests/honeypot_docs.rs`.
- Updated `testsuite/tests/honeypot_manual_lab.rs`.

Focused verification:

```bash
cargo +nightly fmt --all
cargo test -p testsuite --test integration_tests honeypot_manual_lab:: -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_docs::honeypot_docs_define_manual_lab_preflight_first_flow -- --nocapture
cargo clippy --workspace --tests -- -D warnings
cargo test -p testsuite --test integration_tests -- --nocapture
```

Live host validation:

```bash
make manual-lab-bootstrap-store-exec
make manual-lab-bootstrap-store-exec MANUAL_LAB_PROFILE=local
make manual-lab-preflight MANUAL_LAB_PROFILE=local
```

# Deviations From Plan

- I did not force `up` under the local profile because post-import preflight correctly stopped at the next missing runtime-input gate:
  `DGW_HONEYPOT_INTEROP_RDP_USERNAME` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD`.
- I left the imported local state in `target/manual-lab/state/` so the operator is closer to a real manual run rather than farther away.
