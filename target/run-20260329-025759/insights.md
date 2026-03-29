# BS-32 Insights

## What Worked

- Teardown-flushed evidence plus session-local artifacts are still the most reliable way to close a row honestly.
- A Chrome-backed reducer is enough to distinguish `all_black`, `sparse_pixels`, and `visible_frame` without adding a new media toolchain.
- A one-session control proof is viable again once the proxy exclusively owns the recording directory lifecycle.

## What Failed

- Writing `recording-visibility-summary.json` before teardown created `recordings/<session>/` too early and broke playback bootstrap.
- Trying to infer artifact visibility from live HTTP state alone was insufficient; the truthful early `503` did not predict the final WebM contents.

## What To Avoid Next Time

- Do not create per-session recording directories from testside evidence code before the proxy reserves them.
- Do not check off browser-vs-producer rows from websocket or ready-state data alone when the artifact itself can now be inspected directly.

## Promising Next Directions

- `BS-33`: compare browser-visible output with the new `recording_visibility_summary` at the same session point.
- `BS-34`: add a focused ready-path test that proves active playback stays live long enough to avoid immediate fallback.
- Keep the guacd lesson in mind: explicit graphics-policy lanes are more trustworthy than ad hoc client-flag inference.
