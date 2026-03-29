# BS-40 / BS-41 Insights

## What Worked

- One canonical runbook section was the right authority surface for this row.
- The docs-policy seam remained the best enforcement mechanism for repo-level procedure contracts.
- Lifting exact reducer and emitter names from `testsuite/src/honeypot_manual_lab.rs` kept the docs from drifting into aspirational prose.
- Treating `BS-41` as a pure acceptance gate kept the patch small and intentional.

## What Failed

- Nothing material failed in this tranche.

## What To Avoid Next Time

- Do not duplicate the black-screen procedure contract across `runbook.md`, `testing.md`, and `AGENTS.md`.
- Do not invent new artifact filenames in prose when the reducer already has fixed emitter paths.
- Do not soften the docs-policy assertions back into generic “mention the seam” wording.

## Promising Next Directions

- Reuse this same docs-contract pattern for any remaining black-screen rows that are primarily about operator discipline rather than runtime behavior.
- Keep future black-screen work anchored to explicit emitted lane names and persisted verdict tokens before opening any new investigation branch.
