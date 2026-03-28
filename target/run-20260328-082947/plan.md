## Hypothesis

`AGENTS.md` has no remaining actionable unchecked task at `HEAD` `4d41fb6001884f2637875a00b6c00abbbd410d07`.
The next honest action is a bounded completion audit rather than new implementation.

## Council Outcome

The 3-seat council completed idea generation, critic review, refinement, detailed planning, and voting.
Seat 3 won `2-1`.
Its plan won because it balanced feasibility with stronger falsification gates than the lighter no-op plans.

## Memory Ingest

- What worked:
  - fail-closed evidence passes beat heuristic “looks done” claims
  - anchored docs or code or tests mapping plus deterministic seam checks gives high signal
  - explicit scope language prevents overclaiming
- What failed:
  - repeated turns still found no real unchecked AGENTS work
- Dead ends to avoid:
  - inventing backlog
  - relying on one checkbox regex
  - treating a single seam test as broad runtime proof
- Promising reuse:
  - clean-tree plus AGENTS scan
  - bounded hidden-source scan
  - targeted deterministic seam tests

## Steps

1. Capture `HEAD`, clean-tree state, and discover all `AGENTS.md` files.
2. Scan all discovered AGENTS files for unchecked boxes and review unresolved `Pass when:` usage.
3. Sweep bounded hidden task sources in `docs/honeypot` and `testsuite`.
4. Verify high-risk completed seams against current docs, code, and tests.
5. Run deterministic seam tests for bootstrap contract, stream lifecycle, recycle cleanup, and manual-lab CLI behavior.
6. Re-run `HEAD`, clean-tree, and unchecked-task gates before writing artifacts.
7. Write run artifacts, review `AGENTS.md`, and create a save-point commit with the fresh evidence bundle.

## Assumptions

- `AGENTS.md` is the primary execution ledger for this repo.
- Existing non-honeypot `TODO` markers outside the honeypot queue are advisory unless they contradict checked AGENTS claims.
- The selected exact-name tests remain deterministic in the current environment.
