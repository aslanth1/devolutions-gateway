# BS-33 Results

## Success Or Failure

Success.
`BS-33` is now closed.

## Observable Signals

- Proof run: `manual-lab-7174734b82e549ee8162b382e389d348`
- Session: `303f40b3-946e-40d8-b0d5-f8ce941d42ca`
- Browser summary:
  - `dominant_mode=active_live`
  - `verdict=all_black`
  - `data_status=ready`
  - `representative_current_time_ms=1`
- Artifact-at-browser-time summary:
  - `verdict=all_black`
  - `probe_seek_to_ms=1`
  - `sampled_frame_count=0`
- Correlation summary:
  - `verdict=both_black`
  - `confidence=low`
- Session-wide artifact summary remains different:
  - `recording_visibility_summary.verdict=sparse_pixels`

The decisive artifact is:
`target/manual-lab/manual-lab-7174734b82e549ee8162b382e389d348/artifacts/black-screen-evidence.json`

## Unexpected Behavior

- The focus page still reported `Stream state failed` while exposing a usable iframe player URL with a concrete `stream_id`.
- The aligned artifact probe returned `ready_state=1` and `sampled_frame_count=0` at `1ms`, while the broader session-level artifact reducer still found later sparse pixels.
- This means the new `BS-33` result is about the aligned playback instant, not the entire lifetime of the recording artifact.
