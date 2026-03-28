# Success / Failure

Success.
The repo now provides a one-command local self-test lane for manual operators, and the live canonical blocker points to that command instead of a multi-command checklist.

# Observable Signals

- `make manual-lab-show-profile` now prints:
  - `manual self-test quick path: make manual-lab-selftest`
- `make manual-lab-up` still fails canonically on this non-root host, but now reports:
  - `for local manual self-test on a non-root host, run make manual-lab-selftest`
  - `if you want to inspect the active lane first, run make manual-lab-show-profile`
  - canonical `/srv` proof remains separate
- `make manual-lab-selftest-preflight` reports:
  - `manual lab preflight ready`
  - `image_store_root=target/manual-lab/state/images`
  - `manifest_dir=target/manual-lab/state/images/manifests`
- `make -n manual-lab-selftest` shows the intended local chain:
  - `manual-lab-bootstrap-store-exec MANUAL_LAB_PROFILE=local`
  - `manual-lab-up MANUAL_LAB_PROFILE=local`
- `make -n manual-lab-selftest-no-browser` shows the same chain with `manual-lab-up-no-browser`
- `cargo +nightly fmt --all` passed
- `cargo clippy --workspace --tests -- -D warnings` passed
- `cargo test -p testsuite --test integration_tests -- --nocapture` passed with `322 passed, 0 failed`

# Unexpected Behavior

The biggest drift found during implementation was in `AGENTS.md`, not the code.
The completed `6i` pass-condition still described the older multi-command self-test remediation, so it had to be generalized before the new `6j` milestone was added.
The first save-point commit attempt also exposed a shell-quoting hazard: backticks in a double-quoted `git commit -m` body triggered command substitution and launched unintended local commands.
The bad commit attempt did not land, the stray processes were terminated, and the commit was retried with a backtick-safe message.
