# Plan

## Hypothesis

There is no unchecked task left in `AGENTS.md`.
The correct action is to verify that conclusion with one checklist-state check, one semantic drift scan, and one evidence-freshness read, then close the turn without inventing new scope.

## Steps

1. Ingest prior `target/*/insights.md` artifacts to reuse the known fail-closed lessons.
2. Convene a three-seat council and have each seat independently inspect the current `AGENTS.md` state.
3. Use adversarial review to test whether a no-op conclusion would be too shallow.
4. Refine and vote on the best evidence-only closeout plan.
5. Execute the winning plan with:
   - one unchecked-row check,
   - one clean-tree check,
   - one semantic drift scan across AGENTS, docs, and tests,
   - one evidence-freshness read.
6. Record the result in a run-scoped bundle and save it as an evidence-only checkpoint.

## Assumptions

`AGENTS.md` is still the authoritative checklist.
No new failing evidence has appeared since the previous no-next-task conclusion.
Adding a new AGENTS row without a demonstrated uncovered gap would be checklist inflation.
