# What Was Done

1. Read prior insights from:
   - `target/run-20260328-182818/insights.md`
   - `target/run-20260328-194520/insights.md`
   - `target/run-20260328-210448/insights.md`
2. Ran a 3-agent council with `gpt-5.3-codex-spark` at high reasoning and chose the instrumentation-first control-lane tranche.
3. Removed the unfinished direct IronRDP dependency branch from `testsuite/Cargo.toml`.
4. Updated `testsuite/src/honeypot_manual_lab.rs` to:
   - restore `xfreerdp` default behavior to the pre-experiment HEAD control lane,
   - support opt-in graphics lanes by env,
   - stamp each run with `black-screen-evidence.json`,
   - record per-session driver identity, args, lease, stream outcome, and `503` detail or stream id,
   - allow explicit 1/2/3-session control captures.
5. Kept the existing playback summary instrumentation in:
   - `devolutions-gateway/src/rdp_playback.rs`
   - `devolutions-gateway/src/rdp_gfx/mod.rs`
6. Updated `AGENTS.md` to check off `BS-01`, `BS-02`, and `BS-03`.

# Commands / Actions Taken

- `cargo test -p testsuite manual_lab_ -- --nocapture`
- `make manual-lab-selftest-down`
- `make manual-lab-selftest-status`
- `env DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=1 DGW_HONEYPOT_BS_ROWS=BS-01,BS-02,BS-03,BS-04,BS-05,BS-08,BS-09,BS-10 make manual-lab-selftest-up-no-browser`
- `env DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=2 DGW_HONEYPOT_BS_ROWS=BS-01,BS-02,BS-03,BS-04,BS-06,BS-08,BS-10 make manual-lab-selftest-up-no-browser`
- `env DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=3 DGW_HONEYPOT_BS_ROWS=BS-01,BS-02,BS-03,BS-04,BS-07,BS-08,BS-10 make manual-lab-selftest-up-no-browser`
- Re-ran the same 1/2/3-session captures after the final evidence-schema tweak with:
  - `MANUAL_LAB_WEBPLAYER_PRECHECK=0`
  - `MANUAL_LAB_SELFTEST_UP_PRECHECK=0`
- `cargo +nightly fmt --all`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests -- --nocapture`

# Deviations From Plan

- I did not check off `BS-04`, `BS-05`, `BS-06`, `BS-07`, `BS-08`, `BS-09`, or `BS-10` even though fresh control captures were gathered.
  The artifacts were useful, but they did not satisfy every explicit pass condition in the matrix.
- I added per-session stream probe outcome fields to the evidence JSON mid-run, then reran the 1/2/3-session controls so the final saved roots matched the final code.
