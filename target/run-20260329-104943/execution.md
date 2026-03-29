# What Was Done

1. Read recent black-screen research artifacts:
   - `target/run-20260329-102552/insights.md`
   - `target/run-20260329-101424/insights.md`
   - `target/run-20260329-100453/insights.md`
   - `target/run-20260329-095629/insights.md`
2. Reviewed the open `BS-25`, `BS-27`, and `BS-28` rows in `AGENTS.md`.
3. Re-checked Guacamole for graphics-policy cues and kept the same inference as earlier tranches: explicit graphics capability policy is better than inferred blended behavior.
4. Spawned the 3-agent council with `gpt-5.4-mini` at `high` reasoning and ran all requested phases:
   - idea generation
   - critic review
   - refinement
   - detailed plans
   - evidence-based voting
5. Chose the winning plan:
   - bounded `BS-25` rdpgfx DVC probe
   - no fake graphics-on label
   - stop immediately if the seam proved unbounded
6. Terminated all three sub-agents after the vote.
7. Added `ironrdp-dvc` as a direct `testsuite` dependency.
8. Added `testsuite/src/honeypot_manual_ironrdp_rdpgfx.rs` with a repo-owned `ManualLabIronRdpRdpgfxProbe`.
9. Wired the repo-owned IronRDP manual driver to accept `--rdpgfx`, attach the rdpgfx DVC probe, and emit rdpgfx summary counters in stderr logs.
10. Extended `ManualLabDriverKind` with `IronRdpGfx`, added `render_manual_lab_ironrdp_lane_contract`, and added the `ironrdp-rdpgfx` lane mapping without changing black-screen evidence JSON shape.
11. Added focused integration tests for:
    - the `ironrdp-rdpgfx` lane contract
    - the rdpgfx probe advertising capabilities and acknowledging frames
12. Updated the canonical runbook, docs-policy test, and `AGENTS.md` after the protocol proof existed.

# Commands / Actions Taken

- `sed -n '1116,1146p' AGENTS.md`
- `rg -n "ironrdp-no-rdpgfx|xfreerdp-rfx|control_run_comparison_summary|run_verdict_summary|do_not_retry_ledger" ...`
- `rg -n "Rdpgfx|rdpgfx|DisplayControlClient|DvcProcessor|with_dynamic_channel|attach_static_channel|DrdynvcClient" /home/jf/.cargo/registry/...`
- `cargo test -p testsuite --test integration_tests -- --list | rg "manual_lab_ironrdp_(gfx_lane_contract_sets_rdpgfx_flag|rdpgfx_probe_advertises_caps_and_acknowledges_frames)"`
- `cargo +nightly fmt --all`
- `cargo test -p testsuite --test integration_tests honeypot_manual_lab::manual_lab_ironrdp_gfx_lane_contract_sets_rdpgfx_flag -- --exact`
- `cargo test -p testsuite --test integration_tests honeypot_manual_lab::manual_lab_ironrdp_rdpgfx_probe_advertises_caps_and_acknowledges_frames -- --exact`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests`

# Deviations From Plan

- The first compile attempt failed because `testsuite/src/honeypot_manual_ironrdp_rdpgfx.rs` was missing the `Decode` trait import for `ServerPdu::decode`; this was fixed immediately.
- The first targeted test runs used bare test names under `tests/main.rs` and matched zero tests; the rerun used fully qualified test names and passed.
- Two targeted `cargo test` commands were launched in parallel once, which only caused lock contention; subsequent validation was effectively serialized.
