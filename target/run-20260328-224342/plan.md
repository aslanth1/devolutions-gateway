## Hypothesis

If the black-screen control lane is instrumented with a single sequence-true bootstrap timeline across playback startup, `intercept_connect_confirm`, leftover-byte feeds, and first playback updates, then `BS-15` can be resolved without changing behavior and the next tranche can target the remaining ready-state contradiction with evidence instead of guesswork.

## Steps

1. Keep the `xfreerdp` control lane unchanged.
2. Emit stable bootstrap trace events from `rdp_proxy.rs` around playback start, `intercept_connect_confirm`, leftover client and server byte feeds, and inspector installation.
3. Emit stable bootstrap trace events from `rdp_playback.rs` for playback thread start, first packet, first FastPath update, first wrapped-GFX update, first chunk append, and no-update fallback.
4. Parse those events into `black-screen-evidence.json` with per-session `complete`, `incomplete`, and `contradiction` verdicts.
5. Add focused parser tests so the evidence schema fails closed during refactors.
6. Re-run the Rust validation path and a same-day no-browser manual-lab proof run tagged with `BS-15`.

## Assumptions

- The current `xfreerdp` control lane remains the baseline and is not modified in this tranche.
- The existing `target/manual-lab/*/artifacts/black-screen-evidence.json` artifact is the right machine-readable sink for new playback evidence.
- The local manual-lab self-test is sufficient proof for `BS-15`, while canonical `/srv` readiness proof remains a separate concern.
