# Hypothesis
There was no literal unchecked `AGENTS.md` row left, so the winning council plan was a terminal-state proof run:
verify checklist completeness, revalidate baseline quality, add one orthogonal DF-07 seam check, and stop unless a hard gate failed.
Because the repo had recent whole-suite flake history, the winning plan required stronger evidence than the previous run:
`fmt`, `clippy`, a DF-07 release-input seam pass, and `4x` repeated `integration_tests`.

## Winning Plan
- Winning seat: Seat 3.
- Vote: `2-1`.
- Why it won:
  - strongest testability because it required `4x` full-suite replay instead of `3x`
  - explicit comparison against the previous run's proof strength
  - orthogonal non-testsuite seam check to avoid tunnel vision
- Key risks and assumptions:
  - `AGENTS.md` is authoritative for backlog, but not sufficient alone for runtime correctness.
  - Recent flake history means one green run is not enough.
  - Any failing gate becomes the real next task and execution must pivot immediately.

## Memory Ingest Summary
- What worked:
  - closing real seams instead of inventing backlog
  - repeated whole-suite replays
  - explicit boundary statements when `AGENTS.md` stayed complete
- What failed:
  - earlier whole-suite flakiness
  - fixed low-port reuse across repeated `cargo test` processes
  - low-signal evidence-only loops when nothing new was proven
- Repeated dead ends to avoid:
  - assuming one green baseline pass is enough
  - using the low-band allocator for listeners that bind immediately and hold the socket open
  - inventing backlog when `AGENTS.md` is fully checked
- Promising techniques to reuse:
  - targeted log capture
  - repeated whole-suite replays
  - orthogonal seam checks such as DF-07 release-input validation

## Steps
1. Confirm `AGENTS.md` still has zero unchecked rows and is the only authoritative file in-repo.
2. Record `HEAD`, clean tree state, and compare the prior proof strength from `target/run-20260328-101811/results.md`.
3. Run `cargo +nightly fmt --all` and `cargo clippy --workspace --tests -- -D warnings`.
4. Run the DF-07 release-input seam check with anchor greps and `honeypot_release::` tests.
5. Run `cargo test -p testsuite --test integration_tests -- --nocapture` four times.
6. If any run fails, pivot to the first surfaced failing gate and fix only that seam.
7. Re-run the relevant targeted slices, static gates, DF-07 seam check, and the `4x` full-suite replay.
8. Write artifacts, commit a save point, and recheck `AGENTS.md`.

## Assumptions
- No hidden backlog superseded `AGENTS.md`.
- The most recent substantive regression risk was still testsuite-only, not product runtime logic.
- The same criteria that surfaced the prior port-allocation regression would surface any remaining one this turn.
