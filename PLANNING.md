# Planning

## Objective

- Build a honeypot streaming platform that can provision attacker-facing RDP sessions and stream them live to operators without black-screen failures.
- Preserve the completed Askama frontend migration and the kept same-origin wrapper seam while diagnosing any remaining operator-visible dashboard black screens.
- Treat the current lane as multi-session dashboard visual correctness, not as a replay of the already-solved bootstrap investigation.

## Status

- Phase 1 templating is complete for the core operator surface.
- The kept dashboard playback baseline is commit `5a78cb0e` (`Wrap honeypot focus player in same-origin frame`), which routes the focused operator view through `/session/{id}/frame`.
- The canonical runbook lock is complete in commit `1f398e8d` (`Lock in session frame runbook contract`).
- The dashboard now auto-boots the first live session even when multiple live sessions exist, and the exact frontend integration case `honeypot_frontend::frontend_dashboard_bootstraps_first_live_session_when_multiple_live_sessions_exist` is green under checkpoint commit `2d2e8f09` (`Bootstrap first live dashboard session`).
- The sanctioned dashboard-root selftest now retains focused-slot steady-window evidence on a live 3-session deck after the manual-lab harness stopped returning early on `session_count != 1`; run `manual-lab-5b34bb53779f4d8da0f87b441468fe12` recorded slot 1 `sustained_active_live` at steady browser time `2990ms`.
- The focused-slot reducer truthfulness gap is now closed under checkpoint commit `6e3847d7` (`Accept focused dashboard playback verdict`), which lets dashboard-root multi-session runs report `UsablePlayback` when the focused slot is healthy and the other tiles were never the active player path.
- The initial dashboard HTML now renders the first live session focus panel under checkpoint commit `0e20556d` (`Render initial dashboard focus panel`), so the operator no longer lands on an empty focus placeholder before JS boots the already-selected session.
- The dashboard tiles now render same-origin preview frames under checkpoint commit `5297c7f1` (`Render live dashboard tile previews`), and dashboard-root run `manual-lab-36e4221986ba45ef86adf1c20b3422dd` showed all three sessions configuring `active_live` and opening `/jet/jrec/shadow` websockets from the tile grid.
- The dashboard now suppresses the focused session's duplicate tile preview under checkpoint commit `96d21c49` (`Suppress focused dashboard tile preview`), and dashboard-root run `manual-lab-0fb65f1cadd64b61a3c778939113d5ee` reduced slot 1 to a single shadow websocket while improving slot 2 from `telemetry_gap` to `usable_live_playback`.
- The dashboard tile grid now lays out live previews in desktop columns under checkpoint commit `60a498c0` (`Lay out dashboard tiles in columns`), and dashboard-root run `manual-lab-f7e6f69792c84e799b0fd65480af9c55` moved slot 3 from `telemetry_gap` to `usable_live_playback` while improving the run verdict from missing proof to `producer_ready_but_corruption_unresolved`.
- The dashboard now reuses the already server-rendered focus iframe on boot under checkpoint commit `1f1ea62e` (`Reuse initial dashboard focus on boot`), and dashboard-root run `manual-lab-635c4b16423e40559db23c6d3484cc42` cleared slot 1's `both_black` artifact branch and restored a top-level `usable_playback` verdict, but slot 3 stayed `missing_ready_alignment` with `ready_tile_count=2`.
- A one-shot proxy-side retry for retryable `stream_unavailable` tile bootstraps was discarded after dashboard-root run `manual-lab-f224ef64725247e784f65f024fb7baa8` recovered slot 3 to `stream.ready` and `ready_tile_count=3`, but regressed the overall run back to `telemetry_gap` with black artifact correlations on slots 1 and 3.
- The dashboard now limits itself to one active non-focused live tile preview under checkpoint commit `20aa0a84` (`Limit dashboard live tile previews`), and dashboard-root run `manual-lab-51477677f62441fcbaced14667cb23b7` preserved top-level `usable_playback` with slots 1 and 2 both `usable_live_playback` plus `both_visible` while slot 3 moved into an intentional paused-preview `missing_active_intent` state with no websocket activity.
- The focused-plus-one-preview dashboard contract is now locked by exact frontend regression under checkpoint commit `5c5c7be6` (`Lock dashboard preview budget contract`), and `honeypot_frontend::frontend_dashboard_caps_live_tile_previews_to_focus_plus_one_non_focused_session` proves the dashboard renders one focused suppressed tile preview, one active non-focused preview iframe, and one intentional paused-preview tile using precise rendered-body markers.
- The canonical runbook now also states that same focused-plus-one-preview rule under checkpoint commit `d3ba107e` (`Lock capped dashboard preview runbook contract`), so the current dashboard-root operator contract is aligned across runtime evidence, frontend regression, and docs-policy.
- The focused-plus-one-preview dashboard contract is now the finished lane for the current operator-facing requirement, and broader simultaneous live previews are a future product-expansion lane rather than an active black-screen blocker.
- The original phase-1 and phase-2 primary evaluator is satisfied, but the current live operator report says black screens still appear on the dashboard deck.
- The current reproduction anchor is the live 3-session self-test deck rooted at `target/manual-lab/manual-lab-9c62892dac5d4a02830256f937835436`.

## Current Problem Statement

- Do not ask whether the dashboard can boot the shared player at all.
- That bootstrap seam was already solved by the same-origin `/session/{id}/frame` wrapper and locked by docs-policy.
- Do not ask whether the focused pane is still the primary black-screen blocker.
- Commits `0e20556d`, `60a498c0`, and `1f1ea62e` already proved the dashboard can server-render the focused session, keep it visible on the shared wrapper seam, and avoid the boot-time refresh that previously reloaded it into the black artifact branch.
- Do not assume that recovering every live tile stream ID is automatically a win.
- The discarded proxy retry showed that fixing slot 3 bootstrap alone can still make the judged dashboard run worse overall.
- The current black-screen lane is closed under the protected focused-plus-one-preview contract.
- Only reopen active dashboard work if retained evidence disproves that contract or product explicitly requires broader simultaneous live previews without regressing the focused-player contract.

## Active Tasks

- [ ] No active dashboard black-screen tasks remain while the protected focused-plus-one-preview contract stays accepted.
- [ ] Remove `agent-paused.lock` and open a new lane only if product explicitly requires broader simultaneous live previews or retained evidence disproves the locked contract.

## Deferred Follow-Up

- [ ] Palette or fidelity investigation such as blue-to-orange swaps, but only after the current multi-session black-screen report is classified.
- [ ] Old BS-48 through BS-71 artifact archaeology unless the fresh dashboard reproduction maps directly onto one of those retained roots.
- [ ] Driver, codec, or missing-keyframe speculation unless the kept wrapper baseline regresses below the BS-72 proof.

## Guardrails

- [ ] Reuse the existing reducer-owned evidence contract and the sanctioned manual-lab run order.
- [ ] Reuse `/jet/jrec/play`, `/jet/jrec/shadow`, and the current recording-player telemetry rather than inventing a second dashboard player stack.
- [ ] Treat sustained visible playback and advancing browser time as the quality bar, not ready events, redirect success, token issuance, or iframe presence alone.
- [ ] Do not reopen autoplay, lazy iframe loading, old redirect churn, or focus-refresh suppression unless a retained artifact regresses below the kept BS-72 baseline.
- [ ] Use the dashboard root as the primary reproduction surface for operator-visible problems and the direct player path only as paired control evidence.
- [ ] Treat tile previews as a reuse-first extension of the kept wrapper seam, not as permission to introduce a second dashboard-specific player stack.
- [ ] Keep stale detailed task inventories in `target/PLANNING_HISTORY.md` instead of letting `PLANNING.md` collapse back into a historical backlog.
