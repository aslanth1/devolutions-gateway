# BS-30 Results

## Outcome

Success.
`BS-30` is now complete.

## Observable Signals

- `AGENTS.md` now marks `BS-30` complete.
- The ready slot in run `manual-lab-28266918fda643189d4dd827c8c1dd46` was session `d42df6c4-f4d2-4b48-b22b-96b7ef16e8b6`.
- Its persisted evidence reported:
  - `stream_probe_status=ready`
  - `playback_ready_correlation.verdict=aligned_ready`
  - `player_playback_path_summary.verdict=active_live_path`
  - `active_intent_observed=true`
  - `static_playback_started_observed=false`
  - `recording_info_fetch_attempted=false`
  - `missing_artifact_while_active=false`
- The second slot in the same run stayed truthful and inconclusive:
  - `stream_probe_status=unavailable`
  - `player_playback_path_summary.verdict=inconclusive`
- Targeted reducer tests now lock:
  - `active_live_path`
  - `static_fallback_during_active`
  - `missing_artifact_probe_while_active`
- Baseline validation finished green:
  - `348 passed; 0 failed`

## Unexpected Behavior

- The first proof run did not reach the player seam even though the session page was opened.
- A ready slot was required to produce authoritative `BS-30` evidence.
- The same telemetry sink that was added for websocket evidence in `BS-29` was sufficient for `BS-30`; no new browser evidence pipeline was needed.
