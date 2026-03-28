# Hypothesis

The remaining manual-lab failure is no longer a missing readiness feature.
It is an operator-memory problem.
Canonical `make manual-lab-up` now explains the self-test lane correctly, but it still asks a non-root operator to remember multiple commands.
If the repo exposes one explicit local self-test entrypoint and moves the operator guidance to that command, the manual-testing path becomes simple without weakening canonical `/srv` proof semantics.

# Steps

1. Re-read recent `target/*/insights.md` artifacts to summarize what already worked and what still failed.
2. Run a fresh 3-seat council with `gpt-5.3-codex` at `high` reasoning.
3. Pick the winning plan by feasibility, testability, likely real-world success, and clarity.
4. Add a one-command self-test Make entrypoint plus a no-browser variant.
5. Update Rust blocker remediation, `make manual-lab-show-profile`, docs, parity tests, and `AGENTS.md` together.
6. Validate:
   - `make manual-lab-up`
   - `make manual-lab-show-profile`
   - `make manual-lab-selftest-preflight`
   - `make -n manual-lab-selftest`
   - `make -n manual-lab-selftest-no-browser`
   - `cargo +nightly fmt --all`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests -- --nocapture`

# Assumptions

- The local self-test bootstrap path is safe and sufficiently idempotent for a convenience wrapper.
- Canonical `manual-lab-*` defaults must remain unchanged and fail closed.
- The Rust manual-lab authority stays the source of truth; Make only orchestrates existing verbs.
