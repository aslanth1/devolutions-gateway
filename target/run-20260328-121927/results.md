# Success Or Failure

Success.
The repo now has explicit AGENTS scope and implementation for the real Makefile failure class that appears on non-root hosts.

# Observable Signals

- `AGENTS.md` now includes `Milestone 6f: Manual Deck Rootless Host-State Profile`.
- The repo root `Makefile` now accepts `MANUAL_LAB_PROFILE=canonical|local`.
- The canonical profile still fails closed:

```text
manual lab bootstrap blocked by store_root_not_writable
... create image store /srv/honeypot/images
... Permission denied (os error 13)
remediation: fix the configured store-root ownership, or rerun `make manual-lab-bootstrap-store-exec MANUAL_LAB_PROFILE=local` ...
```

- The local profile no longer fails on `/srv` permissions.
- `make manual-lab-bootstrap-store-exec MANUAL_LAB_PROFILE=local` successfully imported into `target/manual-lab/state/` and then advanced to the next real gate:

```text
manual lab bootstrap blocked by post_import_preflight_still_blocked
... missing required Tiny11 lab runtime inputs: DGW_HONEYPOT_INTEROP_RDP_USERNAME, DGW_HONEYPOT_INTEROP_RDP_PASSWORD
```

- `make manual-lab-preflight MANUAL_LAB_PROFILE=local` now reports only the missing RDP runtime inputs, which proves the old `/srv` permission wall is gone in the local lane.
- Verification passed:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests honeypot_manual_lab:: -- --nocapture`
  - `cargo test -p testsuite --test integration_tests honeypot_docs::honeypot_docs_define_manual_lab_preflight_first_flow -- --nocapture`
  - `cargo test -p testsuite --test integration_tests -- --nocapture` with `322 passed, 0 failed`

# Unexpected Behavior

- The local import step took several minutes because it performed a real trusted-image import into repo-local state before post-import preflight completed.
- That was expected once the permission blocker was removed, but it is much slower than the canonical permission failure path.
