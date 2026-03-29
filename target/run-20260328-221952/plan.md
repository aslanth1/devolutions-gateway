# Plan

## Hypothesis

If `rdp_gfx` emits stable per-session corruption counters and manual-lab evidence captures the final flushed summary after teardown, then black-screen runs can be sorted into concrete warning classes instead of generic "still black" guesses.

## Memory Ingest

- What worked:
  - Keeping `xfreerdp` as the same-day control lane produced comparable evidence across runs.
  - Teardown-time summaries were higher signal than mid-run console snapshots.
  - Browser-attached ready-path runs proved that live websocket traffic can coexist with a black screen.
- What failed:
  - Early `503` observations were too weak to explain the ready-path black screen.
  - Existing logs did not attribute corruption classes to specific sessions.
- Repeated dead ends to avoid:
  - Do not reopen driver or encoder churn before the control lane records the missing warning taxonomy.
  - Do not infer root cause from free-form log tails without a machine-readable summary.
- Promising techniques to reuse:
  - Per-session teardown summaries.
  - Stable log field names that can be parsed back into `black-screen-evidence.json`.
  - Keeping the next tranche narrow enough to preserve comparability with prior runs.

## Winning Council Plan

The council selected the bounded instrumentation-first version of `BS-14`.

1. Add stable per-session `rdp_gfx` counters for unknown-surface, unknown-cache-slot, decode-skipped, and replay-failed classes.
2. Emit a single idempotent `GFX warning summary` line per session during playback summary or drop.
3. Parse that summary back into manual-lab evidence and persist it again after teardown so final proxy logs are captured.
4. Add targeted summary-parsing coverage, then rerun the standard validation lane.

## Assumptions

- The existing `xfreerdp` control lane remains the comparison baseline.
- `BS-17` and `BS-18` stay open unless this tranche grows into a broader evidence envelope.
- The existing `rdp_gfx` in-file unit module remains host-disabled behind `target_os = "none"` unless explicitly promoted in a later tranche.
