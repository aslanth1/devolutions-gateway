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
- The remaining blocker is the downstream corruption or alignment seam, because both latest retained runs still archive `producer_ready_corruption_unresolved` even after the dashboard path boots correctly.
- The latest aligned-probe replay attempt was discarded and reverted even though both lanes preserved steady live playback: replaying after the aligned seek regressed the artifact from parseable `all_black` to `analysis_failed`, and both probe DOM captures stayed at `<pre id="out">starting</pre>`.
- The latest one-shot IronRDP retry attempt was also discarded and reverted: the variant completed the run, but the retry path never fired, so the cycle did not prove that the early `read frame by hint / not enough bytes` failure is timing-related.
- The recent failure streak is now `3 / 3`, so the next blocked cycle may use the 3-agent council on the `--dump-dom` versus async-seek timing seam.
- Keep the next cycle bounded to corruption or alignment analysis rather than more dashboard bootstrap churn.
- Treat the favicon `404` and `/events` `ERR_INCOMPLETE_CHUNKED_ENCODING` reconnect noise as secondary unless a concrete change shows they block player mount or token refresh.

## Evaluator

- Primary evaluator for phase 1: the dashboard, tile, and session routes render through the chosen Rust template engine while preserving current route contracts and operator actions.
- Primary evaluator for phase 2: compare the embedded dashboard or session path against the direct `/jet/jrec/play` path using the retained `black-screen-evidence.json` contract plus live browser and proxy observations.
- Treat a direct player mount as the control shape: the change should prove that the dashboard path now boots the same player-owned startup sequence rather than merely rendering an iframe URL.
- The result does not count unless the dashboard path reaches a steady `active_live` browser window or the code change proves why the dashboard must stop using the current embed seam.
- Treat sustained visible playback and advancing browser time as the quality bar, not ready events, redirect success, or token issuance alone.

## Active Tasks

- [ ] Use the latest truthful dashboard proof roots `manual-lab-b3f101cc771d46d9951760ff2a973c0c` and `manual-lab-76c2cab5e7cc42d89652a163d189c272` as the retained playback baseline while investigating the remaining `producer_ready_corruption_unresolved` state.
- [ ] Treat the discarded control root `manual-lab-8c3684c5394e482f9b835ade62900a61` and variant root `manual-lab-1c54d41020d140918440c2f3b0db6d80` as a truthful but insufficient-evidence cycle: both lanes stayed live, yet the aligned probe DOM never advanced past `starting`.
- [ ] Treat the discarded control root `manual-lab-33e6f627d26c4798af721b4cc4633359` and variant root `manual-lab-9887cb8379224000ab6b1dc970b99855` as a failed probe cycle, not as a new playback baseline.
- [ ] Treat the discarded control root `manual-lab-30d51d70fd764fd7ad2fefa8a19ed30b` and variant root `manual-lab-c737a499646040b69fa718b8f8e2b74d` as an unexercised-retry cycle, not as proof that the early IronRDP failure is fixed.
- [ ] Compare the retained control `sparse_pixels` versus variant `visible_frame` dashboard artifacts from the truthful run to explain why the reducer still collapses both lanes into the same unresolved corruption verdict.
- [ ] Compare the new control `both_black` versus variant `browser_visible_artifact_black` dashboard artifacts from the kept retry run to see whether the player retry changed decode timing without changing the final verdict code.
- [ ] Explain why the aligned probe regresses from parseable `all_black` to `analysis_failed` when the async seek path replays, with special attention to headless Chrome `--dump-dom` timing versus the final JSON marker write.
- [ ] Decide whether the recurring `ironrdp-rdpgfx` `read frame by hint / not enough bytes` failure during `manual-lab-up` is true flake or needs a more directly observable timing experiment before retrying another artifact-probe tweak.
- [ ] If the async seek timing seam remains blocked next cycle, use the now-available 3-agent council to split DOM-capture timing, Chrome behavior, and reducer-surface options without reopening dashboard bootstrap work.
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
- [ ] Do not stop at markup-only frontend tests that assert iframe presence; the next proof must cover real player boot.
- [ ] Do not lock in the missing-keyframe explanation as fact until the post-templatization playback investigation proves it.
- [ ] Do not spend the next cycle on new driver variants, codec labels, or keyframe speculation unless the dashboard fix fails while the direct player page keeps working.
- [ ] Do not treat dashboard-root SSE reconnect noise alone as the root cause.
- [ ] Do not confuse reducer-level corruption with dashboard mount failure now that both dashboard-root lanes reach steady `active_live`.
- [ ] Keep the platform goal larger than the current black-screen blocker so the plan does not collapse into one stale checklist forever.
- [ ] Archive stale detailed task lists in `PLANNING_HISTORY.md` instead of letting `PLANNING.md` accumulate dead branches.
