# BS-39 Plan

## Hypothesis

`BS-39` should close by turning the control-plane-assisted capture fallback into a single canonical blocker record in `docs/honeypot/decisions.md`, then enforcing that record through the existing docs-policy test harness so fallback work cannot open on generic prose.

## Steps

1. Ingest recent `target/*/insights.md` artifacts and summarize what to reuse and what to avoid.
2. Run a 3-agent council on the next AGENTS row.
3. Choose the winning plan using feasibility, testability, likelihood of success, and clarity.
4. Add one canonical `BS-39` blocker record with separate fields for seam ownership, rejection reason, exhausted lanes, and fallback status.
5. Add a reference-only enforcement note in `docs/honeypot/testing.md`.
6. Add a focused `testsuite/tests/honeypot_docs.rs` assertion that fails if the blocker record is missing or softened.
7. Update `AGENTS.md` to check off the matching Milestone 6u fallback gate row and `BS-39`.
8. Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests`.

## Assumptions

- `docs/honeypot/decisions.md` is the right single authority for this blocker record.
- `testsuite/tests/honeypot_docs.rs` is the correct enforcement seam for a repo-level policy gate.
- The fallback must remain blocked now because the repo has not recorded an explicit proxy-seam insufficiency after the required exhausted lanes.
