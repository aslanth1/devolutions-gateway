# BS-23 Insights

## What Worked

- Reusing the existing `ManualLabXfreerdpGraphicsMode::Rfx` path avoided speculative parallel surfaces.
- A small exported helper was enough to make the lane contract integration-testable.
- The existing `control_run_comparison_summary` remained the right proof seam for archived control provenance.
- Keeping the operator rule in the canonical runbook plus a docs-policy test prevented drift.

## What Failed

- Initial test code used unnecessary `clone()` calls that clippy rejected.
- Soft prose alone would not have been enough to close `BS-23`; the lane needed machine-checkable proof.

## What To Avoid Next Time

- Do not add a fresh reducer or verdict surface when the current evidence JSON already carries the needed proof.
- Do not reopen codec experiments with vague names or undocumented flag bundles.
- Do not split the contract across multiple docs when one canonical runbook section already exists.

## Promising Next Directions

- Use the same bounded-contract approach for remaining black-screen rows that only need explicit lane identity and archived-control proof.
- Keep favoring explicit graphics-policy names and exact emitted flags over inferred behavior summaries.
- Continue using Guacamole-style explicit graphics capability thinking as a validation cue rather than inventing heuristic interpretations.
