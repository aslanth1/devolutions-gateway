# Insights

## What Worked

- Reusing prior `target/*/insights.md` artifacts kept the council from pretending skipped Tiny11 evidence was good enough.
- Auditing `HEAD` before coding avoided duplicating the already-landed row-699 winner.
- Explicitly asserting guest-side `-:3389` forwarding in the active snapshot made the staged row-396 proof portable across shared developer hosts where local port `3389` may already be occupied.

## What Failed

- The workspace can diverge from the expected execution path when `HEAD` and the staged index represent different AGENTS rows.
- The baseline suite still has unrelated transient flakes, so one clean full rerun may require isolated retries first.

## Dead Ends To Avoid

- Do not restart a council when the real issue is that the winning plan is already committed.
- Do not throw away an accumulated staged bundle without validating whether it is coherent and already nearly done.
- Do not require host port `3389` itself to be free for row-396 local proof.

## Promising Next Directions

- Row `706` remains the main technical gap and still needs non-skipped Tiny11-derived interop inputs plus the existing acceptance and repeatability lanes.
- If the repo keeps accumulating staged work between turns, inspect `HEAD`, index, and AGENTS state first so the next council votes on the real remaining problem.
