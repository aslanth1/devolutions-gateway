# Program

Objective: Build a honeypot streaming platform that can provision attacker-facing RDP sessions and stream them live to operators without black-screen failures.
Program status: the original Phase 1 templating gate, the original dashboard-bootstrap gate, and the focused-plus-one-preview dashboard contract are complete through the Askama migration, the kept `/session/{id}/frame` same-origin wrapper, retained runtime proof, frontend regression coverage, and the docs-policy lock.
Current execution lane: Paused.
Current evaluator: No active evaluator while `agent-paused.lock` is present; remove the pause lock only to open a new product-expansion lane such as broader simultaneous previews.
Prompt mode: autoresearch
Council after failures: 3
Council model: gpt-5.4-mini
Council reasoning effort: high
Council tie-break model: gpt-5.4-mini
Council tie-break reasoning effort: high
Checkpoint commits: true

## Constraints

- Keep one bounded hypothesis per cycle.
- Treat Askama templatization as a completed baseline rather than as active work.
- Reuse the existing reducer-owned black-screen evidence contract instead of adding a new summary or verdict surface.
- Reuse `/jet/jrec/play`, `/jet/jrec/shadow`, and the current recording-player telemetry rather than inventing a second dashboard player stack.
- Keep the sanctioned run order `ensure-artifacts -> preflight -> up -> status -> down`.
- Use the live dashboard root with multiple sessions as the primary reproduction surface and the direct `/jet/jrec/play` page only as paired control evidence.
- Keep the frontend-owned `/session/{id}/frame` wrapper as the active baseline unless fresh evidence proves it is the problem.
- Treat sustained visible playback and advancing browser time as the decision input, not ready events, redirect success, or token issuance alone.
- Treat dashboard-root `/events` `ERR_INCOMPLETE_CHUNKED_ENCODING` and favicon noise as secondary unless a concrete change shows they block player mount or refresh.
- Do not reopen `BS-27` or `BS-28` driver churn until the dashboard or session-player seam is fixed or falsified.
- Prefer the same-origin wrapper and shared player contract over the older cross-origin iframe plus redirect seam.
- Do not count iframe-presence assertions as playback proof; the next kept change must show downstream `/jet/jrec/play`, telemetry, and shadow-websocket activity.
- Treat driver, codec, and missing-start-keyframe ideas as deferred hypotheses unless the kept wrapper baseline regresses.

## Notes

- The platform goal is broader than the current black-screen blocker.
- The Askama migration is complete for the dashboard, tile, session, action, and notice routes.
- The kept runtime baseline is the same-origin focused-player wrapper introduced in commit `5a78cb0e`.
- The canonical docs-policy lock for that seam is commit `1f398e8d`.
- The current user-visible symptom is that the live multi-session dashboard deck can still appear black even though the retained BS-72 dashboard-root proof reached sustained `active_live`.
- The current planning question is therefore about multi-session dashboard visual correctness, not initial player bootstrap survival.
- Future regression tests for the wrapper should assert on rendered DOM or body markers rather than brittle absence of class-name substrings.
- The canonical operator-facing contract lives in `docs/honeypot/runbook.md`, and the latest repo evidence lives under `target/run-*/`.
