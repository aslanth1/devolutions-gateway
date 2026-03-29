# BS-33 Execution

## What Was Actually Done

1. Reviewed recent `target/*/insights.md` artifacts and summarized the durable wins, failures, dead ends, and reusable techniques.
2. Reviewed guacd's RDP implementation and graphics settings surface for comparative design cues.
3. Ran a 3-agent council with `gpt-5.3-codex-spark` at `high` reasoning effort.
4. Implemented browser visibility telemetry in the player runtime and extended manual-lab evidence reducers.
5. Ran targeted reducer tests while shaping the new summaries.
6. Rebuilt the webplayer packages so the runtime bundle actually contained the new browser telemetry.
7. Ran fresh local manual-lab proof attempts until the browser attach path and artifact probe were both trustworthy.
8. Fixed the artifact probe virtual-time budget so Chrome had enough time to emit final DOM JSON after metadata wait, seek settle, and the full sample window.
9. Ran the decisive one-session proof `manual-lab-7174734b82e549ee8162b382e389d348`.
10. Updated `AGENTS.md` to mark `BS-33` complete.
11. Ran the baseline Rust verification path.

## Commands And Actions Taken

- Read prior research:
  - `rg --files target | rg 'insights\\.md$'`
  - `sed -n '1,220p' target/run-*/insights.md`
- Reviewed guacd:
  - opened `src/protocols/rdp/settings.c`
  - opened `src/protocols/rdp/rdp.c`
- Built player packages:
  - `npm run build` in `packages/shadow-player`
  - `npm run build` in `packages/multi-video-player`
  - `npm run build` in `apps/recording-player`
- Proof runs:
  - `env DGW_HONEYPOT_BS_ROWS=BS-33 DGW_HONEYPOT_MANUAL_LAB_SESSION_COUNT=1 make manual-lab-up-no-browser MANUAL_LAB_PROFILE=local`
  - direct Chrome attach to the extracted iframe player URL
  - `target/debug/honeypot-manual-lab down`
- Validation:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests -- --nocapture`

## Deviations From Plan

- The first proof attempt used the outer session page and missed the lazy iframe path, so the execution switched to attaching Chrome directly to the player iframe URL.
- The first browser-artifact alignment attempts still produced `analysis_failed` because the artifact probe's virtual-time budget was too short.
- After reproducing the probe manually and confirming the DOM was still stuck at `starting`, the execution widened the virtual-time budget to `14000ms` and reran the proof instead of accepting another inconclusive result.
