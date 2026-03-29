# Planning History

## 2026-03-29: Archived `BS-27` Versus `BS-28` Driver-Decision Lane

- This entry was moved out of `PLANNING.md` when the active plan was widened back to the broader platform goal and the detailed black-screen task list no longer needed to be the top-level planning surface.

### Objective

- Make the live streaming of honeypot RDP sessions stop presenting a black screen, with the current bounded lane deciding `BS-27` versus `BS-28` through the existing same-day control comparison seam instead of opening another client, codec, or evidence branch.

### Council

- Default council shape: `3` sub-agents.
- Default council model: `gpt-5.4-mini`.
- Default council reasoning effort: `high`.
- Tie-break rule: if council voting ties, break the tie with the same criteria while keeping the tie-break on `gpt-5.4-mini` with reasoning `high`.

### Evaluator

- Primary evaluator: run the sanctioned manual-lab experiment order `control -> variant -> compare`, then inspect the archived `artifacts/black-screen-evidence.json` for `control_run_comparison_summary`, `run_verdict_summary`, `black_screen_branch`, `rdpgfx_dynamic_channel_open_count`, `rdpegfx_pdu_count`, emitted surface updates, and the recording visibility summaries.
- The result does not count unless `control_run_comparison_summary.verdict=meaningful_with_same_day_control` for the variant lane.
- A `BS-27` keep requires both protocol proof and visible output improvement, while session assignment, truthful negative-path reporting, and teardown semantics remain intact.
- A `BS-28` keep requires the comparison set to show that `ironrdp-rdpgfx`, `ironrdp-no-rdpgfx`, and the control lane leave counters, branch verdicts, and visible output materially unchanged.

### Task List

- [ ] Run a fresh same-day control lane and archive its run root before any variant lane opens.
- [ ] Re-run the opt-in `ironrdp-rdpgfx` lane with `DGW_HONEYPOT_INTEROP_DRIVER_KIND=ironrdp-gfx` and `DGW_HONEYPOT_BS_CONTROL_ARTIFACT_ROOT=<control-run-root>`.
- [ ] Re-run the opt-in `ironrdp-no-rdpgfx` lane with `DGW_HONEYPOT_INTEROP_DRIVER_KIND=ironrdp-no-gfx` and the same control root when the gfx-enabled result is still ambiguous.
- [ ] Keep the within-run command order `ensure-artifacts -> preflight -> up -> status -> down`.
- [ ] Compare only the existing reducer-owned evidence fields and retained run artifacts rather than inventing new summaries.
- [ ] Record the outcome as either `promote default lane candidate`, `plateau stop`, or `return to decode/player analysis`.
- [ ] Update `AGENTS.md`, the runbook, and the next `target/run-<timestamp>/` bundle only after the evaluator result is clear.

### Blocked / Non-Goals

- [ ] Do not add new driver kinds, new codec names, or ad hoc lane labels in this cycle.
- [ ] Do not widen `ManualLabBlackScreenEvidence` or create a second verdict surface for the decision.
- [ ] Do not claim a lane win from protocol counters alone when browser-visible output stays black, static, or corrupted.
- [ ] Do not reopen docs or tracker rows before the same-day comparison result is machine-checkable.
- [ ] Do not run parallel `cargo` validations while another Rust build or test is already in flight.

### Acceptance Criteria

- [ ] `BS-27` is actionable only if the candidate lane proves whether `rdpgfx` was really on or off, improves visible playback relative to the same-day control, and preserves truthful assignment plus teardown behavior.
- [ ] `BS-28` is actionable only if the candidate lanes reach meaningful same-day comparison and still fail to materially improve counters or visible output versus control.
- [ ] A blocked result remains blocked if the run never reaches a meaningful same-day control comparison or the retained artifacts do not let us distinguish protocol movement from player or decode failure.

### Open Questions

- What exact visible-output delta should count as material improvement for `BS-27` beyond raw protocol counters?
- If `ironrdp-rdpgfx` proves graphics negotiation but still lands on the same user-visible outcome, should the next loop pivot directly to decode or player analysis without any more driver churn?
