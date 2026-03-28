# Plan

## Hypothesis

Runtime-only row-706 proof anchors should fail closed when an operator explicitly asks for runtime proof.
The smallest safe fix is a shared strict-mode helper at invocation time rather than a second verifier surface.

## Steps

1. Ingest prior `target/*/insights.md` artifacts and summarize reusable patterns, failures, and dead ends.
2. Run a three-seat council and choose the smallest plan that closes the skip-as-green gap without changing default suite behavior.
3. Implement a shared strict runtime-proof helper in the honeypot tier utilities.
4. Wire the runtime-only row-706 anchors to require `lab-e2e` prerequisites when strict mode is enabled.
5. Add focused tests for disabled, failing, and passing strict-mode cases.
6. Update the honeypot testing docs to record the strict runtime-proof contract.
7. Validate default skip-safe behavior, strict negative behavior, strict positive lab-backed behavior, and the baseline Rust verification path.

## Assumptions

- The canonical complete row-706 envelope remains `5c6c2ece-0c30-4694-a569-353ee88ffae9`.
- Default non-strict behavior must remain unchanged for ordinary `contract`-tier runs.
- Runtime-proof strict mode should be opt-in through environment, not a new command surface.
- The existing Tiny11 interop store and `lab-e2e` gate from prior successful runs remain usable on this host.
