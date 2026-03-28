# Success / Failure

- Success:
  the repo now has explicit `AGENTS.md` scope for manual-deck readiness, a shared Rust `preflight` path, a preflight-first Make flow, parity tests, and updated docs.
- Success:
  `make manual-lab-preflight` now surfaces the real blocker directly.
- Success:
  `make manual-lab-up` now stops at the same preflight blocker instead of attempting launch first.
- Success:
  `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests -- --nocapture` all passed.

# Observable Signals

- `make manual-lab-preflight` now emits:
  `manual lab blocked by missing_store_root: canonical Tiny11 interop image store root /srv/honeypot/images is absent or not a directory`
  plus the sanctioned `consume-image` remediation.
- `make manual-lab-up` now exits from `manual-lab-preflight` with the same blocker and does not proceed to launch.
- New integration tests passed for:
  - CLI help including `preflight`
  - text preflight blocker reporting
  - JSON preflight blocker reporting
  - `preflight` / `up` blocker parity
  - docs-governance coverage for the new manual-lab preflight flow

# Unexpected Behavior

- The repo still exposes all tests through the single `integration_tests` target, so targeted verification had to use filtered selectors rather than per-file test binaries.
- `clippy` flagged the new preflight outcome enum as a large enum variant even though the functional behavior was already correct.
