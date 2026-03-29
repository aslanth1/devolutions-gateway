## What Worked
- Keeping `xfreerdp` as the control lane and delaying variant churn made the evidence coherent.
- Teardown-finalized proxy summaries are high-signal: they already expose `drdynvc_channel_id`, `rdpgfx_dynamic_channel_open_count`, and `rdpegfx_pdu_count`.
- A browser-attached ready-path capture is enough to prove "live data reached the player but the screen stayed black".

## What Failed
- Treating the first no-browser `503` as the whole story was misleading.
- The current logs still do not scope every corruption warning class to a session id.

## Avoid Next Time
- Do not reopen encoder or driver churn before refreshing the same-day control-lane evidence.
- Do not assume a black screen means the player never received live data.

## Promising Next Directions
- Add explicit per-session warning counters for `WireToSurface1` and related decode failures so `BS-14` can close honestly.
- Correlate ready-state timing with the producer attach timeline to decide whether the third-slot branch is producer starvation or decode corruption.
- Port the same summary fields into machine-readable test assertions after the warning attribution gap is fixed.
