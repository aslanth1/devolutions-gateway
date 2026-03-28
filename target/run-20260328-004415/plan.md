# Hypothesis

The real next task is not a legacy checklist row because `AGENTS.md` had no unchecked items.
The correct next task is to formalize a new Milestone `6b` for a three-host manual observation deck, finish the in-progress Rust launcher, and leave only the runtime live-proof row open if this host cannot prove it honestly.

# Steps

1. Re-read `AGENTS.md` and the latest `target/*/insights.md` artifacts.
2. Run a fresh 3-seat council and choose the next task framing.
3. Finish the in-progress `testsuite::honeypot_manual_lab` lane.
4. Add the missing CLI binary and focused tests.
5. Update `AGENTS.md`, `runbook.md`, and `testing.md`.
6. Verify with focused manual-lab tests, CLI smoke, `fmt`, and `clippy`.
7. Check whether a live operator proof run is honest on this host.
8. Write artifacts and commit a save point.

# Assumptions

- The user’s prior manual-deck objective is still the intended new scope.
- Host-process topology is required for the live deck because guest RDP forwards are loopback-scoped.
- Compose remains the readiness and rollback topology.
- A live proof run should not be claimed complete if the host lacks isolated helper-display support such as `Xvfb`.
