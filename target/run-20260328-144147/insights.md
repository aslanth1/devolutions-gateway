# Insights

## What Worked

- Reusing the existing Rust `ensure-artifacts` authority kept the Make change small and safe.
- `make -n` contract tests are still the best way to pin wrapper behavior.
- `MANUAL_LAB_PROFILE=local` remains the right non-root escape hatch for artifact-aware QEMU flows.

## What Failed

- Using `--exact` against the integration harness filtered out the intended tests.
- A negative assertion against raw `make -n` text was too strict because the disabled shell branch still prints the conditional body.

## Avoid Next Time

- Do not assume a printed shell conditional means the nested Make target actually executed.
- Do not use the placeholder-tag host-smoke lane as a “should pass” smoke proof until release inputs are promoted.

## Promising Next Directions

- Add a release-input readiness shortcut that checks for placeholder image refs before expensive host-smoke runs.
- Route any future QEMU-backed Make tier through the same explicit artifact ensure seam rather than duplicating bootstrap logic.
