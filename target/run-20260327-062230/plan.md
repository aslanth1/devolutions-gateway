# Plan

## Hypothesis

The council winner for this turn is the row-699 guardrail plan, but if that exact winner is already present in `HEAD`, the only honest unsaved work to bundle is the staged row-396 proof, provided it passes a non-skipped `lab-e2e` check and the baseline Rust verification path.

## Steps

1. Reuse prior `target/*/insights.md` notes to avoid repeated Tiny11 evidence dead ends.
2. Run the 3-seat council and choose the best remaining AGENTS row.
3. If the winning plan is already landed in `HEAD`, inspect the unsaved staged bundle instead of pretending there is fresh winner implementation left to do.
4. Validate the staged row-396 bundle with a real `lab-e2e` gate and the baseline verification path.
5. Keep row `396` checked only if its focused proof runs non-skipped and the full suite reruns cleanly.
6. Record the exact adjustment in the run-memory bundle and save the resulting accumulated work intentionally.

## Assumptions

- The existing docs-governance row-699 winner can be treated as already executed if it is the current `HEAD`.
- The staged row-396 bundle is safe to evaluate locally because it only touches `AGENTS.md`, `docs/honeypot/testing.md`, one control-plane test, and matching run-memory notes.
- Verifying guest-side `tcp/3389` forwarding plus reachable RDP readiness in the Rust `lab-e2e` harness is sufficient evidence for row `396`, while row `706` still requires stricter Tiny11 interop inputs.
