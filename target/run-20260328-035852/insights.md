# Insights

## What Worked

Run-scoped proof artifacts made it easy to compare the failing and successful manual-deck runs without relying on newest-directory guesses.
Fail-closed teardown notes were high-signal because they distinguished HTTP failures from lease-drain failures.
Reusing a validated trusted-image catalog during recycle removed redundant hashing from the hot teardown path.
Focused regression tests plus the full baseline gate caught the stale-catalog quarantine regression before the save point.

## What Failed

Treating active-state removal as proof of successful teardown was a dead end because leases could still remain active.
The old recycle path was too expensive for live manual-deck teardown because it revalidated the whole trusted-image store on each recycle.
A fast path that ignores stale trusted-image catalog state is incorrect because recycle must still quarantine on drift.

## What To Avoid Next Time

Do not infer live-proof success from partial `up` evidence or from helper-process cleanup alone.
Do not add a second verifier surface when the runtime can emit explicit fail-closed notes.
Do not optimize trusted-image checks in a way that changes quarantine semantics under drift.

## Promising Next Directions

Keep using catalog-backed validation for hot control-plane paths, but preserve quarantine behavior whenever freshness cannot be proved.
Continue storing live proof logs beside plan and result notes so later councils can reuse exact evidence instead of recollection.
