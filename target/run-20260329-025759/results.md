# BS-32 Results

## Success / Failure

- Success: `BS-32` is now complete.
- Proof run: `manual-lab-70c3636dba2f41d584f258f8c2669598`
- Session: `f43795cb-b8f5-4079-aff5-15c3158f4ed7`

## Observable Signals

- The repaired run created a real playback bundle:
  - `recording.json`
  - `recording-0.webm`
  - `player-websocket.ndjson`
- `recording-0.webm` grew from about `306K` to `483K` during the live soak.
- Session-local websocket telemetry recorded:
  - `player_mode_configured`
  - `websocket_open`
  - `websocket_first_message`
- Final persisted evidence in `black-screen-evidence.json` recorded:
  - `recording_visibility_summary.verdict = "sparse_pixels"`
  - `confidence = "high"`
  - `sampled_frame_count = 33`
  - `first_sparse_offset_ms = 501`
  - `max_non_black_ratio_per_mille = 7`
  - `analysis_backend = "Google Chrome 146.0.7680.80"`

## Unexpected Behavior

- The live probe still saw the initial truthful `503` before the source was ready, so `playback_ready_correlation` remained `probe_before_ready`.
- The repaired one-session proof still ended with `player_playback_path_summary.verdict = "active_live_path"` while `playback_artifact_timeline_summary.verdict = "websocket_attached_without_ready"`, which means `BS-33` still needs the browser-vs-artifact comparison layer instead of assuming those two views agree.
