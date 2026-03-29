# BS-38 Plan

## Hypothesis

`BS-38` should close by making variant black-screen runs fail closed unless they can point at a same-day control run that persisted the same artifact contract and a current control verdict in sibling evidence JSON.

## Steps

1. Read prior `target/*/insights.md` artifacts and summarize reusable patterns and dead ends.
2. Run the 3-agent council through proposal, critique, refinement, detailed-plan, and vote phases.
3. Break any vote tie in favor of the most explicit fail-closed evidence-seam design.
4. Extend `ManualLabBlackScreenEvidence` with run timestamp, artifact-contract summary, and control-run comparison summary.
5. Load sibling `artifacts/black-screen-evidence.json` from an explicit control artifact root env var.
6. Treat non-control runs as meaningful only when the sibling evidence is control-lane, same-day, and contract-matched.
7. Add focused tests for accepted same-day control, missing control JSON, stale control, and contract mismatch.
8. Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests`.

## Assumptions

- `same-day` is enforced as the same UTC calendar day.
- The explicit control companion path is supplied through `DGW_HONEYPOT_BS_CONTROL_ARTIFACT_ROOT`.
- The artifact contract should stay reducer-owned and compare persisted contract summaries, not infer meaning from lane names or prose.
