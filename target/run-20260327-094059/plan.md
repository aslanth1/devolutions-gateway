# Hypothesis

- Reuse the useful part of `~/src/hellsd-gateway`'s E2E composition pattern: explicit layered validation around the real stack.
- Reject the brittle part: script-heavy dev-stack orchestration and assumptions that a host browser can always reach Docker-published ports.
- Add one saner Rust-native proof in `testsuite/tests/honeypot_release.rs` that starts the real `control-plane`, `proxy`, and `frontend` compose stack and validates the frontend operator path through a deterministic driver.

# Steps

1. Ingest prior `target/*/insights.md` artifacts and carry forward the reuse-first and fail-closed lessons.
2. Review `~/src/hellsd-gateway` locally to extract useful E2E structure without copying its orchestration style.
3. Add a focused compose-backed full-stack smoke test in Rust.
4. Verify the frontend health, dashboard bootstrap HTML, and `/events` SSE headers through a compose-network driver.
5. Document the new proof in `docs/honeypot/testing.md`.
6. Run focused verification, then the baseline format, clippy, and full `integration_tests` suite.

# Assumptions

- The three-service compose harness is already the correct runtime seam for a stack-level smoke proof.
- A peer-container driver is a more portable frontend-surface probe than direct host-loopback probing on this workstation.
- This slice should improve `host-smoke` evidence without claiming live Tiny11 or Chrome-driven interaction proof.
