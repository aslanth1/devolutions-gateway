# Program

Objective: Build a honeypot streaming platform that can provision attacker-facing RDP sessions and stream them live to operators without black-screen failures.
Current execution lane: Introduce `Askama`-based Rust-side templatization for the honeypot frontend pages and router first, then return to the dashboard focus-player path so it reuses the proven direct player or test-page mount contract instead of stalling in the current embedded session flow.
Primary evaluator: Phase 1 succeeds when the dashboard, tile, and session routes are template-backed without changing their operator-facing contract. Phase 2 succeeds when the dashboard path boots the same player-owned startup sequence as the direct `/jet/jrec/play` path and reaches sustained `active_live` playback with advancing browser time, or the evidence proves the current embed seam must be replaced.
Prompt mode: autoresearch
Council after failures: 3
Council model: gpt-5.4-mini
Council reasoning effort: high
Council tie-break model: gpt-5.4-mini
Council tie-break reasoning effort: high
Checkpoint commits: true

## Constraints

- Keep one bounded hypothesis per cycle.
- Templatization comes before renewed streaming-debug cycles on this lane.
- Reuse the existing reducer-owned black-screen evidence contract instead of adding a new summary or verdict surface.
- Reuse `/jet/jrec/play`, `/jet/jrec/shadow`, and the current recording-player telemetry rather than inventing a second dashboard player stack.
- Keep the sanctioned run order `ensure-artifacts -> preflight -> up -> status -> down`.
- Use the direct `/jet/jrec/play` page and the test pages that mount `recording-player` or `shadow-player` directly as the working browser-playback controls for this cycle.
- There is no existing Rust HTML templating crate in the workspace today, so the frontend migration should introduce one explicit templating engine instead of adding another layer of string assembly.
- The selected templating engine is `Askama`, with file-backed templates and typed Rust template contexts as the target rendering model.
- Treat sustained visible playback and advancing browser time as the decision input, not ready events, redirect success, or token issuance alone.
- Treat dashboard-root `/events` `ERR_INCOMPLETE_CHUNKED_ENCODING` and favicon noise as secondary unless a concrete change shows they block player mount or refresh.
- Do not reopen `BS-27` or `BS-28` driver churn until the dashboard or session-player seam is fixed or falsified.
- Prefer a session page, direct player route, or same-origin wrapper that boots the shared player contract directly over the current cross-origin iframe plus redirect seam.
- Do not count iframe-presence assertions as playback proof; the next kept change must show downstream `/jet/jrec/play`, telemetry, and shadow-websocket activity.
- Treat the missing-start-keyframe idea as a hypothesis to validate after the frontend templatization pass, not as a settled root cause.

## Notes

- The platform goal is broader than the current black-screen blocker.
- The immediate cleanup step is to replace hand-built HTML in `honeypot/frontend/src/lib.rs` with `Askama` templates so the operator pages, fragments, and router are easier to reason about.
- Inline page JavaScript should move toward static assets or narrowly scoped boot data during that migration rather than staying embedded in long Rust strings.
- The direct `/jet/jrec/play` page currently advances `currentTime` and `duration` while the recording file grows and proxy logs keep `/jet/jrec/shadow/*` at `101`.
- The working test pages succeed because they make the shared player runtime the page's primary job: they either navigate straight to `/jet/jrec/play` or call `shadow-player.srcChange(...); play()` directly.
- The dashboard focus panel currently embeds a cross-origin iframe from frontend `:21638` to proxy `:21636`, starting at `/jet/honeypot/session/{id}/stream?...` and relying on a redirect into `/jet/jrec/play`.
- The current frontend tests for this seam mostly prove token renewal and iframe HTML, not that the player bundle actually boots and reaches the live shadow websocket path.
- Prior repo evidence already says direct iframe attach and standalone `/session/{id}` were the truthful playback seams, while dashboard-only proofs were misleading.
- The current user-visible symptom is “black until repaint, then stale or stalled”, which fits the dashboard embed seam better than a dead producer path.
- The canonical operator-facing contract lives in `docs/honeypot/runbook.md`, and the latest repo evidence lives under `target/run-*/`.
