# Hypothesis

The remaining manual-lab failure mode is not missing functionality.
It is a wrong-lane operator experience.
Canonical `make manual-lab-up` fails closed on non-root hosts as designed, but its remediation still points at the older `MANUAL_LAB_PROFILE=local` pattern instead of the newer `manual-lab-selftest-*` path.
If the Rust blocker text, docs, and tests are updated to advertise the explicit self-test lane first while still preserving canonical `/srv` proof guidance, operators can manually test successfully without weakening the fail-closed policy.

# Steps

1. Re-read prior `target/*/insights.md` artifacts and summarize repeated wins and dead ends for the council.
2. Run a 3-seat council with `gpt-5.3-codex` and `high` reasoning to choose the next justified task.
3. Update the Rust manual-lab blocker remediation for `missing_store_root` and non-writable canonical store paths.
4. Extend `AGENTS.md` with a checked milestone for this wrong-lane remediation bridge.
5. Update docs and tests so the self-test quick path and canonical proof lane stay in sync.
6. Validate:
   - `make manual-lab-up`
   - `make manual-lab-selftest-preflight`
   - `make manual-lab-show-profile`
   - `cargo +nightly fmt --all`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests -- --nocapture`

# Assumptions

- The local self-test lane added in the previous turn is already the sanctioned non-root operator path.
- Canonical `/srv` proof must remain explicit and must not silently auto-fallback to local state.
- The blocker contract is owned in Rust, with Make and docs acting as thin projections of that authority.
