# BS-38 Insights

## What Worked

- Keeping the comparison logic inside the existing black-screen evidence reducer preserved one machine-readable decision surface.
- Persisted contract summaries were a cleaner comparator than lane names, filenames, or prose.
- An explicit control artifact root env var was simpler and safer than trying to infer sibling runs implicitly.

## What Failed

- Trying to run focused cases via a non-existent per-file test target.
- Treating metadata-only capture as sufficient; `BS-38` needed a real fail-closed comparison verdict.

## Avoid Next Time

- Do not infer control companions from naming conventions alone.
- Do not treat same-day as advisory text; persist the timestamps and make the reducer decide.
- Do not widen into fallback capture or seam-replacement work while the proxy-owned evidence lane is still viable.

## Promising Next Directions

- Reuse the explicit control-companion pattern for later runbook and experiment-order work.
- Keep future black-screen rows reducer-owned and contract-checked before adding any new runtime surface.
