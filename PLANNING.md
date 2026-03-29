# Planning

## Objective

- Build a honeypot streaming platform that can provision attacker-facing RDP sessions and stream them live to operators without black-screen failures.
- Keep the Askama-backed honeypot frontend stable while tracing the remaining corruption or alignment seam after the dashboard-root playback proof.
- Use the operator dashboard and the direct player page as paired controls until the remaining live-stream corruption issue is falsified or fixed.

## Council

- Default council shape: `3` sub-agents.
- Default council model: `gpt-5.4-mini`.
- Default council reasoning effort: `high`.
- Tie-break rule: if council voting ties, break the tie with the same criteria while keeping the tie-break on `gpt-5.4-mini` with reasoning `high`.

## Current Focus

- The Askama templatization phase is done and the dashboard root now auto-loads the only live session into the focus panel.
- The truthful dashboard-root proof is now in hand: both control and variant dashboard runs reached `/jet/jrec/play`, `/jet/jrec/telemetry`, `/jet/jrec/shadow`, and a steady `active_live` browser window from `/?token=...`.
- The dashboard-fragment self-retry patch is now a kept stability fix: the clean rerun restored `player-websocket.ndjson`, reached steady `active_live` on both lanes, preserved a valid same-day control compare, and matched repeated operator-visible video.
- The BS-48 early-finalizer patch is now a kept probe fix: the clean control plus variant rerun preserved a truthful same-day compare and made the aligned browser-time artifact parseable again.
- The new retained BS-48 baseline roots are `manual-lab-563588fc582b44b48d93df537135ba3a` for control and `manual-lab-b4342575f7364976a8212d8d0f3ec512` for the `ironrdp-rdpgfx` variant.
- Those retained roots now archive `run_verdict_summary.verdict=usable_playback` on both lanes, with control `sparse_pixels` at browser time and variant `visible_frame` at browser time.
- The previous control-only `manual-lab-025e...` hang is now treated as transient evaluator noise, not the active blocker on this seam.
- The recent failure streak resets to `0 / 3`.
- Keep the next cycle bounded to confirming and operationalizing the new truthful aligned-artifact baseline rather than reopening dashboard bootstrap churn or speculative driver changes.
- Treat the favicon `404` and `/events` `ERR_INCOMPLETE_CHUNKED_ENCODING` reconnect noise as secondary unless a concrete change shows they block player mount or token refresh.

## Evaluator

- Primary evaluator for phase 1: the dashboard, tile, and session routes render through the chosen Rust template engine while preserving current route contracts and operator actions.
- Primary evaluator for phase 2: compare the embedded dashboard or session path against the direct `/jet/jrec/play` path using the retained `black-screen-evidence.json` contract plus live browser and proxy observations.
- Treat a direct player mount as the control shape: the change should prove that the dashboard path now boots the same player-owned startup sequence rather than merely rendering an iframe URL.
- The result does not count unless the dashboard path reaches a steady `active_live` browser window or the code change proves why the dashboard must stop using the current embed seam.
- Treat sustained visible playback and advancing browser time as the quality bar, not ready events, redirect success, or token issuance alone.

## Active Tasks

- [ ] Use the retained BS-48 roots `manual-lab-563588fc582b44b48d93df537135ba3a` and `manual-lab-b4342575f7364976a8212d8d0f3ec512` as the truthful aligned-artifact baseline.
- [ ] Compare the retained BS-48 `usable_playback` roots against the earlier kept dashboard baseline `manual-lab-b3f101cc771d46d9951760ff2a973c0c` and `manual-lab-76c2cab5e7cc42d89652a163d189c272` to explain exactly which aligned-artifact fields let the reducer stop failing closed on corruption.
- [ ] Treat the discarded control root `manual-lab-33e6f627d26c4798af721b4cc4633359` and variant root `manual-lab-9887cb8379224000ab6b1dc970b99855` as a failed probe cycle, not as a new playback baseline.
- [ ] Treat the discarded control root `manual-lab-30d51d70fd764fd7ad2fefa8a19ed30b` and variant root `manual-lab-c737a499646040b69fa718b8f8e2b74d` as an unexercised-retry cycle, not as proof that the early IronRDP failure is fixed.
- [ ] Decide whether the next bounded cycle should lock in the BS-48 ordering with a narrower test or return to higher-level black-screen analysis now that the reducer-owned verdict surface is truthful again.
- [ ] Decide whether the recurring `ironrdp-rdpgfx` `read frame by hint / not enough bytes` failure during `manual-lab-up` is true flake or needs a more directly observable timing experiment before touching the aligned probe again.
- [ ] Keep the direct `/jet/jrec/play` page and the dashboard-root page as paired controls for future playback experiments.
- [ ] Continue moving inline page JavaScript out of the template only when that cleanup directly helps the remaining corruption or alignment investigation.
- [ ] Reuse the previously working direct-attach and `/session/{id}` findings from `target/run-20260329-043514/` and `target/run-20260329T180229Z/`.
- [ ] Test the user's start-of-stream missing-keyframe hypothesis only after the corruption or alignment seam has a smaller falsifiable probe.
- [ ] Update `AGENTS.md`, docs, and the next run bundle only after new evidence changes the state of the blocker.

## Guardrails

- [ ] Reuse the existing reducer-owned evidence contract and sanctioned run order.
- [ ] Use `Askama` as the single Rust templating engine for this frontend lane instead of mixing multiple engines or adding more ad hoc HTML string assembly.
- [ ] Reuse `/jet/jrec/play`, `/jet/jrec/shadow`, and the existing telemetry reducers instead of inventing another playback surface.
- [ ] Treat the dashboard-root bootstrap seam and the focused-fragment retry patch as proven until a future run loses `/jet/jrec/play`, telemetry, or shadow traffic again.
- [ ] Treat user-observed video as supporting evidence, not as a substitute for a valid same-day control compare root.
- [ ] Do not judge an aligned artifact probe tweak on a run that already lost steady browser visibility telemetry or player-websocket evidence.
- [ ] Do not keep recovery logic that never fired during the evaluator; unexercised retries are not proof.
- [ ] Do not keep aligned-probe replay tweaks that turn a parseable black verdict into `analysis_failed`; losing the JSON marker is a regression even when the live page shows video.
- [ ] Do not treat a council-picked patch as validated if the evaluator dies earlier on control-lane instability and never writes recording artifacts, but do retry the same bounded patch on a clean seam before discarding the underlying hypothesis forever.
- [ ] Do not stop at markup-only frontend tests that assert iframe presence; the next proof must cover real player boot.
- [ ] Do not lock in the missing-keyframe explanation as fact until the post-templatization playback investigation proves it.
- [ ] Do not spend the next cycle on new driver variants, codec labels, or keyframe speculation unless the dashboard fix fails while the direct player page keeps working.
- [ ] Do not treat dashboard-root SSE reconnect noise alone as the root cause.
- [ ] Do not confuse reducer-level corruption with dashboard mount failure now that both dashboard-root lanes reach steady `active_live`.
- [ ] Keep the platform goal larger than the current black-screen blocker so the plan does not collapse into one stale checklist forever.
- [ ] Archive stale detailed task lists in `PLANNING_HISTORY.md` instead of letting `PLANNING.md` accumulate dead branches.
