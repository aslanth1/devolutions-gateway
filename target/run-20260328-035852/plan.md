# Plan

## Hypothesis

The next honest AGENTS task is the live operator proof row for the three-host manual deck.
The best plan is fail-closed: keep the row open until one sanctioned `honeypot-manual-lab up` run produces three live Tiny11 sessions, three ready frontend tiles, and one `down` run drains control-plane leases to zero without orphaned helper processes.
The council preferred this plan because it tests the exact operator workflow instead of inferring success from unit coverage, active-state cleanup alone, or stale artifacts.

## Steps

1. Reuse prior `target/*/insights.md` findings to avoid known dead ends such as skip-as-pass proof, newest-directory heuristics, and duplicate verifier surfaces.
2. Use the council to compare implementation and proof strategies, then adopt the plan that keeps runtime proof fail-closed.
3. Run a sanctioned manual-deck proof attempt and collect `up`, `status`, and `down` artifacts under a run-scoped directory.
4. If teardown fails, diagnose the blocking recycle path with direct runtime evidence instead of guessing.
5. Patch the smallest safe path that restores honest teardown semantics without weakening trusted-image checks.
6. Re-run focused verification, then the full baseline gate.
7. Check the AGENTS row only after the live proof and baseline verification both hold.

## Assumptions

The host provides isolated helper-display support and the sanctioned Tiny11 interop inputs required by `honeypot-manual-lab`.
The live proof may require multiple attempts, but only a complete `up` plus `down` cycle with explicit success signals counts.
Trusted-image validation must remain fail-closed even if recycle is optimized to avoid redundant store re-hashing.
