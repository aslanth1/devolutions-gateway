# BS-30 Insights

## What Worked

- `player_mode_configured` was the missing active-intent anchor.
- Extending the existing `/jet/jrec/telemetry/{id}` seam was enough to classify playback-path outcomes.
- Explicit session-page attach on a ready slot remains the reliable browser-proof path.
- Guacd is a useful reference because it makes graphics capability explicit.

## What Failed

- A one-session shell-only proof did not satisfy `BS-30`.
- Truthful `503` evidence is valuable, but it does not answer player-path questions by itself.

## What To Avoid Next Time

- Do not check off browser rows from shell navigation alone.
- Do not mix ready and not-ready slots into one verdict.
- Do not infer active playback intent only from websocket events when the player can state its mode directly.

## Promising Next Directions

- `BS-31` should reuse the new playback-path timestamps to align session events with recording artifact creation and growth.
- The same telemetry structure can support later first-visible-frame checks without inventing a second classification system.
