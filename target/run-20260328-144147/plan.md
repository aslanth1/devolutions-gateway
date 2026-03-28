# Plan

## Hypothesis

QEMU-backed Make test flows are still slower and more error-prone than they need to be because the repo has a fast artifact precheck for manual-lab, but no first-class Make entrypoints for the actual `host-smoke` and `lab-e2e` tiers.

## Steps

1. Read recent `target/*/insights.md` files and summarize reusable patterns and dead ends.
2. Run a 3-seat council and choose the smallest feasible improvement.
3. Add first-class Make targets for the prepared-host tiers.
4. Keep `host-smoke` non-mutating by default.
5. Route `lab-e2e` through `manual-lab-ensure-artifacts` by default.
6. Document the new commands, profile behavior, and opt-out knob.
7. Add contract tests that pin the Make target graph and docs text.
8. Validate with `make -n`, targeted real Make invocations, `cargo clippy`, and the full integration suite.

## Assumptions

- The existing Rust `ensure-artifacts` path is already the sanctioned authority for checking or creating trusted interop artifacts.
- `host-smoke` should not silently mutate lab state.
- Non-root workstations still need `MANUAL_LAB_PROFILE=local` for artifact-aware `lab-e2e` shortcuts.
