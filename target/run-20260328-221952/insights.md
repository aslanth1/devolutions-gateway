# Insights

## What Worked

- A stable teardown-time summary line is the right seam for black-screen forensics.
- Parsing proxy stdout back into `black-screen-evidence.json` keeps the run bundle comparable without scraping ad hoc notes.
- Bounded warning taxonomy is enough to distinguish missing-surface churn from decode-skip or replay-failure paths.

## What Failed

- Host-targeted `cargo test` filters still miss the in-file `rdp_gfx` unit module because it is gated behind `target_os = "none"`.
- This tranche still does not explain producer ordering or third-session failure branches by itself.

## What To Avoid Next Time

- Do not mark `BS-18` complete while the host harness still excludes the `rdp_gfx` unit module.
- Do not reopen encoder or driver churn until the next run captures these new warning counters in a real black-screen proof bundle.

## Promising Next Directions

- `BS-15`: add handshake and producer-order timestamps beside the new warning counters.
- `BS-17`: promote the parsed playback evidence into a broader stable summary document for every run.
- `BS-19` and `BS-20`: correlate FastPath noise and third-session failure branches against the new per-session warning taxonomy.
