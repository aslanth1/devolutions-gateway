## What Worked

- A single sequence-stamped bootstrap trace across proxy and playback made `BS-15` mechanically testable.
- Parsing those events into `black-screen-evidence.json` removed the need to scrape free-form proxy logs by hand.
- Re-persisting evidence after teardown captured late-flushed playback events that the live probe alone missed.

## What Failed

- The live `503` probe was not sufficient to classify slot 3 as a producer-order failure.
- The `ironrdp-graphics` source review did not change the immediate next step; the blocker remains the ready-state seam, not generic decode helpers.

## What To Avoid Next Time

- Do not treat a live `503` as proof that playback never started.
- Do not reopen encoder or driver churn before the ready-state timestamps are added to the structured evidence.

## Promising Next Directions

- `BS-16`: add structured timestamps for first chunk emitted, recording-manager connected state, and `session.stream.ready`.
- `BS-17`: elevate the most important negotiation and playback counters into the evidence JSON instead of leaving them split between logs and summaries.
- `BS-20`: use the new bootstrap truth to reduce the third-session issue into a named ready-path contradiction branch.
