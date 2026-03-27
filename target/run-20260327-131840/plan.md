## Hypothesis

The next honest checklist row to close is `AGENTS.md` row `716`.
`manual_bounded_interaction` should become a shared verifier-enforced runtime contract with cross-anchor coherence, not a free-form operator note.

## Steps

1. Ingest recent `target/*/insights.md` files and summarize what worked, what failed, dead ends, and reuse opportunities.
2. Run a 3-seat `gpt-5.3-codex` council across the remaining unchecked rows `710`, `716`, and `738`.
3. Use the council critiques to refine the winning row into a concrete implementation plan.
4. Implement shared validator semantics for `manual_bounded_interaction`.
5. Add cross-anchor checks against headed observation identity and the recorded video timestamp window.
6. Extend manual-headed tests, docs, docs-governance checks, and `AGENTS.md`.
7. Run focused verification for `honeypot_manual_headed` and `honeypot_docs`.
8. Run the baseline verification path:
   - `cargo +nightly fmt --all`
   - `cargo +nightly fmt --all --check`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests`

## Assumptions

- Row `706` remains the single runtime authority for manual-headed evidence.
- Row `716` can close via contract hardening without pretending the still-blocked live Tiny11 rows are complete.
- The best reuse path is the same one used for rows `707`, `713`, and `719`: one shared validator, one writer path, one docs-governance lock.
