# Hypothesis

The next safe black-screen tranche is the council-selected instrumentation-first control-lane pass.
Restore the manual-lab `xfreerdp` default to the pre-experiment HEAD arguments, stamp every run with immutable evidence, and capture fresh 1-session, 2-session, and 3-session control roots before reopening more aggressive driver or codec churn.

# Steps

1. Re-ingest prior `target/*/insights.md` artifacts and summarize the stable lessons.
2. Run a 3-agent council and pick one concrete execution tranche.
3. Remove the unfinished direct IronRDP dependency branch from `testsuite` and keep `xfreerdp` as the control lane.
4. Add machine-readable black-screen evidence capture to manual-lab state, including `git rev`, row IDs, env fingerprint, driver identity, exact args, and per-session stream outcomes.
5. Restore the default manual-lab `xfreerdp` invocation to the pre-experiment HEAD control arguments unless an explicit env opts into another lane.
6. Run fresh 1-session, 2-session, and 3-session control-lane manual-lab captures and preserve the artifact roots.
7. Check off only the `BS-*` rows that the resulting artifacts prove.
8. Re-run baseline Rust verification and package the run bundle.

# Assumptions

- `BS-01`, `BS-02`, and `BS-03` can be completed in this tranche without solving the whole black-screen issue.
- No-browser control captures are still useful for baseline and negative-path truth, even if they cannot satisfy every browser-correlation row.
- The existing playback summary logging in `rdp_playback.rs` and `rdp_gfx/mod.rs` remains useful for later `BS-11..19` work.
- `.pnpm-store/` remains unrelated and must stay out of the save-point scope.
