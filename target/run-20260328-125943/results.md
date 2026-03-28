# Success Or Failure

Success.
The canonical lane still fails closed on non-root hosts, but the remediation now points directly at the sanctioned self-test lane instead of the older profile override wording.

# Observable Signals

- `make manual-lab-up` now reports:
  - `make manual-lab-show-profile`
  - `make manual-lab-selftest-bootstrap-store-exec`
  - `make manual-lab-selftest-preflight`
  - `make manual-lab-selftest-up`
- The same remediation still preserves canonical `/srv` proof guidance with:
  - `make manual-lab-bootstrap-store-exec`
  - `make manual-lab-preflight`
- `make manual-lab-selftest-preflight` reports `manual lab preflight ready`.
- `make manual-lab-show-profile` reports the effective canonical lane plus the self-test quick path.
- `cargo +nightly fmt --all` passed.
- `cargo clippy --workspace --tests -- -D warnings` passed.
- `cargo test -p testsuite --test integration_tests -- --nocapture` passed with `322 passed, 0 failed`.

# Unexpected Behavior

The unexpected part was not a new runtime blocker.
It was a documentation and remediation drift: the repo already had explicit self-test aliases, but the live Rust blocker still taught operators the superseded local-profile syntax.
