# Execution

## What Was Actually Done

1. Read the latest run insights and extracted the stable lessons:
   - same-day `xfreerdp` controls matter
   - teardown-flushed evidence matters more than live `503` alone
   - `xfreerdp -gfx` was a fake no-gfx lane
   - FastPath warnings were not root cause proof
2. Reviewed guacd source and repo docs.
   - In `src/protocols/rdp/rdp.c`, guacd only loads the `rdpgfx` plugin when graphics are enabled.
   - In its RDP settings/docs, graphics capability is treated as an explicit policy choice.
3. Ran a fresh 3-agent council.
   - Winning plan: re-run a fresh `BS-26` gate, then only widen to `BS-25` if the current branch is still apples-to-apples.
4. Ran targeted tests for the new IronRDP no-gfx groundwork.
5. Re-ran a fresh one-session `xfreerdp` control proof and tore it down.
6. Re-ran a fresh one-session `ironrdp-no-rdpgfx` proof and tore it down.
7. Compared the refreshed evidence JSONs and proxy summaries.
8. Inspected the pinned IronRDP dependency surface for a bounded graphics-on spike.
9. Updated `AGENTS.md` with the new proof state.
10. Ran baseline validation.

## Commands / Actions Taken

- `cargo test -p testsuite manual_lab_emits_zero_fastpath_warning_summary_when_no_events_exist -- --nocapture`
- `cargo test -p testsuite manual_lab_driver_kind_parser_accepts_supported_values -- --nocapture`
- `cargo test -p testsuite manual_lab_irondrdp_driver_args_include_association_token -- --nocapture`
- `make manual-lab-selftest-down`
- `make manual-lab-selftest-up-no-browser DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=1 DGW_HONEYPOT_BS_ROWS=BS-21,BS-24,BS-26`
- `make manual-lab-selftest-down`
- `make manual-lab-selftest-up-no-browser DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=1 DGW_HONEYPOT_BS_ROWS=BS-21,BS-24,BS-26 DGW_HONEYPOT_INTEROP_DRIVER_KIND=ironrdp-no-gfx`
- `make manual-lab-selftest-down`
- `jq` comparisons of refreshed `black-screen-evidence.json`
- `rg -n "Wrapped graphics extractor summary|GFX filter summary|GFX warning summary" .../proxy.stdout.log`
- `cargo tree -p testsuite | rg "ironrdp|dvc|gfx|graphics"`
- `cargo +nightly fmt --all`
- `git diff --check`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests -- --nocapture`

## Deviations From Plan

- The hybrid plan did not proceed to an `ironrdp-gfx` implementation patch.
- The fresh `BS-26` rerun showed the current branch was already emitting a non-`null` zero `fastpath_warning_summary`, so there was no measurement fix to land first.
- The bounded `BS-25` spike stopped at source inspection because the pinned IronRDP crates in this repo do not expose a ready-made `RdpgfxClient`-style surface for a small client-only graphics-on lane.
