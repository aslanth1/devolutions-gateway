# BS-34 Plan

## Hypothesis

The best next black-screen task is `BS-34`.
A focused ready-path proof in `testsuite/tests/` is the smallest high-signal guardrail because it turns the already-observed active-live path into an explicit regression contract before the heavier three-slot proof in `BS-35`.

## Memory Ingest

What worked:
- teardown-flushed evidence
- direct iframe player attach
- explicit player telemetry
- same-day controls
- session-local artifact reducers
- guacd's explicit graphics capability policy

What failed:
- dashboard-only proofs
- stale control comparisons
- early test-created recording directories
- websocket-only or ready-only inference
- too-short virtual-time budgets

Repeated dead ends to avoid:
- checking off browser rows without browser-native evidence
- reopening lane churn before browser/artifact discrimination
- treating parse failures as meaningful black-screen verdicts
- treating shell stream state as authoritative

Promising techniques to reuse:
- the existing startup/stabilize/steady browser windows
- reducer-driven named verdicts
- explicit insufficiency classes
- same-day control discipline
- aligned browser/artifact evidence

## Winning Council Plan

The council split between `BS-34` and `BS-35`, but refinement pushed the practical winner toward `BS-34`.
The winning shape was:
- add a reusable ready-path sustain reducer
- define success as `AlignedReady` + `ActiveLivePath` + a ready `steady` browser window in `active_live`
- fail if static fallback is observed before that point
- encode the proof in `testsuite/tests/`

## Steps

1. Add a reusable reducer in `testsuite/src/honeypot_manual_lab.rs` for ready-path sustain.
2. Add targeted positive and negative proof tests in `testsuite/tests/honeypot_manual_lab.rs`.
3. Update `AGENTS.md` to record the new proof contract and check off `BS-34`.
4. Run:
   - `cargo +nightly fmt --all`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests -- --nocapture`

## Assumptions

- The existing browser visibility windows are a better readiness sustain signal than inventing a new raw timeout.
- `BS-34` can be closed by a targeted regression test in `testsuite/tests/` without a fresh live manual-lab proof run.
- `BS-35` remains the next heavier tranche after this guard is in place.
