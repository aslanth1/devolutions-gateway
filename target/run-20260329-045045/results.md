# BS-34 Results

## Success Or Failure

Success.
`BS-34` is now complete in `AGENTS.md`.

## Observable Signals

- New reducer:
  - `build_manual_lab_ready_path_sustain_summary`
- New targeted proofs:
  - `manual_lab_ready_path_sustain_accepts_steady_active_live_window`
  - `manual_lab_ready_path_sustain_rejects_static_fallback_before_steady_window`
- The positive proof requires:
  - `playback_ready_correlation.verdict == aligned_ready`
  - `player_playback_path_summary.verdict == active_live_path`
  - a ready `steady` browser window with `player_mode == active_live`
  - no static fallback before that point
- The negative proof fails on:
  - `static_playback_started_observed == true`
  - `player_playback_path_summary.verdict == static_fallback_during_active`

Validation results:
- targeted test slice: `2 passed`
- full baseline: `351 passed; 0 failed`

## Unexpected Behavior

- The council tool path was less reliable in the later phases than in the early phases, so the winning-plan decision had to be finalized locally from the already-returned critique and refinement material.
- No live manual-lab rerun was required for this tranche because the row's pass condition was explicitly a targeted `testsuite/tests/` proof.
