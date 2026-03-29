## Hypothesis
The instrumentation-first `xfreerdp` control tranche can close the remaining baseline black-screen rows by proving three things with same-day evidence:

1. clean-state guards are real before each control run
2. one-, two-, and three-session control runs can be named precisely instead of hand-waved
3. `drdynvc`, `rdpgfx`, and `rdpegfx_pdu_count` truth can be read directly from proxy summaries, leaving only the warning-class attribution row open

## Steps
1. Re-read the latest `target/*/insights.md` files and preserve the current `xfreerdp` control lane.
2. Use the already-completed 3-agent council to confirm the winning plan stays instrumentation-first.
3. Capture one-session, two-session, and three-session control runs with `make manual-lab-selftest-up-no-browser`.
4. Attach a browser only where needed to prove the ready-path stays live but visually black.
5. Tear the last run down so teardown summaries flush into the proxy log and the baseline test path can run cleanly.
6. Write canonical artifact summaries under each run root.
7. Update `AGENTS.md` only for rows backed by concrete files and log summaries.
8. Run fmt, clippy, and integration tests.

## Assumptions
- The sanctioned local self-test path is the right substitute for the `/srv` manual-lab lane on this workstation.
- Session-end wrapped-gfx summaries may only flush after teardown.
- `BS-14` remains open unless every warning class can be counted per session rather than only at run scope.
