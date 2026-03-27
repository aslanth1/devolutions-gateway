# Insights

## What Worked

- Governance rows close cleanly when tied to fail-closed tests rather than narrative claims.
- Parsing AGENTS checklist rows by section in a reusable helper reduced brittle string checks.
- Running a focused failing test in isolation before a final full rerun efficiently separated flake from regression.

## What Failed

- Assuming the first full-suite pass would be stable wasted time; transient socket races still occur.
- Treating Tiny11 rows as candidates without required environment inputs would have forced dishonest completion.

## Dead Ends To Avoid

- Do not mark Tiny11 or RDP rows complete from skipped `lab-e2e` runs.
- Do not close milestone-sequencing rows with prose only when tests can enforce the claim.
- Do not stop at one failed full-suite attempt when the failure is likely transient.

## Promising Next Directions

- Use the existing consume-image path plus a prepared Tiny11-backed interop store to pursue row `396`.
- Then close row `706` by running non-skipped Tiny11 acquire/RDP/recycle proofs with host cleanup evidence.
