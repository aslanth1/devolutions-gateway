# Hypothesis

The next real Makefile blocker is host-state permissions, not manifest ambiguity.
The repo should keep the canonical `/srv/honeypot/...` lane as the default, but add an explicit local profile for non-root manual testing so operators can progress without weakening the canonical policy.

# Steps

1. Run a 3-seat council after ingesting recent `target/*/insights.md` artifacts.
2. Add new `AGENTS.md` scope for a manual-lab rootless host-state profile and typed store-root remediation.
3. Add an explicit `MANUAL_LAB_PROFILE=canonical|local` lane to the Makefile while keeping wrappers thin.
4. Add a checked-in local control-plane bootstrap config that uses repo-local state under `target/manual-lab/state/`.
5. Improve Rust bootstrap failure reporting so store-root permission errors become a typed blocker with actionable remediation.
6. Update runbook and testing docs to explain canonical versus local profile usage.
7. Add tests for docs parity and store-root permission failures.
8. Validate both profile lanes on the live host and rerun the baseline verification path.

# Assumptions

- The user wants to manually self-test on this host without sudo.
- Canonical `/srv` paths must remain the default and must not silently fall back to a local profile.
- A repo-local state root is acceptable for manual operator self-test when chosen explicitly.
