## Success / Failure
- Success: `BS-04` through `BS-13` are now backed by concrete evidence files and proxy summaries, except for `BS-14`.
- Failure: the visual black-screen bug is still real on the ready path even when the browser receives live websocket data.

## Observable Signals
- One-session control:
  - clean-state booleans all true before launch
  - initial stream probe truthful `503`
  - later player websocket opened and received messages
  - screenshot remained almost entirely black
  - `drdynvc_channel_id=1007`
  - `rdpgfx_dynamic_channel_open_count=1`
  - `rdpegfx_pdu_count=1175`
- Two-session control:
  - slot 1 ready, slot 2 truthful `503`
  - ready slot player screenshot remained black
  - slot 1 `rdpegfx_pdu_count=1281`
  - slot 2 `rdpegfx_pdu_count=1215`
- Three-session control:
  - slot 1 ready
  - slot 2 ready
  - slot 3 truthful `503`
  - slot 3 still negotiated `drdynvc` and `rdpgfx`
  - slot 3 `rdpegfx_pdu_count=772`

## Unexpected Behavior
- The one-session control run contradicted its first `503` later in the same session: the player eventually opened a live websocket and still rendered black.
- The third-slot failing session still negotiated dynamic graphics instead of dying earlier at channel-open time.
- `WireToSurface1` mismatch warnings are visible, but they are still not tagged with `session_id`, which prevents a clean close on `BS-14`.
