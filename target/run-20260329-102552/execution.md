# BS-23 Execution

## What Was Done

1. Reviewed recent prior artifacts in:
   - `target/run-20260329-101424/insights.md`
   - `target/run-20260329-100453/insights.md`
   - `target/run-20260329-095629/insights.md`
2. Re-reviewed Apache Guacamole's RDP configuration and connection flow for explicit graphics-policy cues:
   - `src/protocols/rdp/settings.c`
   - `src/protocols/rdp/rdp.c`
3. Spawned three `gpt-5.4-mini` sub-agents with `high` reasoning effort and ran the required council phases.
4. Accepted the winning plan: reuse the existing `Rfx` lane, avoid a new reducer, prove the lane contract in integration tests, and pin the operator-facing rule in the canonical runbook.
5. Added `render_manual_lab_xfreerdp_lane_contract` to expose the real `ManualLabXfreerdpGraphicsMode::Rfx` path as a small reusable proof helper.
6. Added `manual_lab_rfx_lane_records_exact_codec_flags_and_same_day_control_provenance` to prove:
   - `driver_lane=xfreerdp-rfx`
   - `/dynamic-resolution`
   - `/gfx:RFX`
   - no `-gfx`
   - meaningful same-day control provenance through `DGW_HONEYPOT_BS_CONTROL_ARTIFACT_ROOT`
7. Updated `docs/honeypot/runbook.md` with the explicit `BS-23` lane contract.
8. Extended `testsuite/tests/honeypot_docs.rs` so the docs contract fails closed if that rule drifts.
9. Marked `BS-23` complete in `AGENTS.md` and recorded the new evidence note.

## Commands And Actions Taken

- `cargo test -p testsuite --test integration_tests manual_lab_rfx_lane_records_exact_codec_flags_and_same_day_control_provenance`
- `cargo test -p testsuite --test integration_tests honeypot_docs_keep_black_screen_runbook_contract_canonical`
- `cargo +nightly fmt --all`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests`

## Deviations From Plan

- `cargo clippy` first failed on redundant `clone()` usage inside the new integration proof.
- The test was adjusted to move the lane contract into local `driver_lane` and `driver_args` bindings, then clippy passed cleanly.
- No reducer or new runtime surface was added because the existing evidence contract proved sufficient.
