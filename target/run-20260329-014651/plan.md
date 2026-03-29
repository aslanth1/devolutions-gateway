# BS-30 Plan

## Hypothesis

`BS-30` is the highest-signal next row after `BS-29`.
The current player telemetry already captures websocket lifecycle and fallback markers, but the repo lacks one per-session verdict that says whether an active session stayed on the live path, fell back to static playback, or probed a missing recording artifact while still live.
Guacd is a useful reference because it treats graphics capability as an explicit policy switch rather than an inferred side effect.

## Steps

1. Read prior `target/*/insights.md` files and summarize what worked, failed, repeated, and remains reusable.
2. Review guacd RDP settings and plugin-loading code for graphics-policy guidance.
3. Run a 3-agent council on the next `BS-*` row and select a winning execution plan.
4. Add explicit player telemetry for active or static intent plus `recording.json` fetch start, success, and failure.
5. Extend manual-lab evidence so each session gets a `player_playback_path_summary` verdict.
6. Add targeted reducer tests for:
   - active live path
   - static fallback during active playback
   - missing artifact probe while active
7. Rebuild the player bundle and rerun manual-lab proof captures until at least one ready session yields authoritative player telemetry.
8. Run the baseline Rust validation path.

## Assumptions

- `BS-30` can be closed with one explicit ready-slot proof rather than a larger multi-lane experiment.
- The current player telemetry sink in `/jet/jrec/telemetry/{id}` is the right seam to extend instead of inventing a second browser evidence path.
- A truthful `503` shell-only run does not satisfy `BS-30` because it never exercises the active player.
