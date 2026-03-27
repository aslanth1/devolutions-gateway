## Hypothesis

The next honest checklist item to close is `AGENTS.md` row `713`.
`manual_headed_qemu_chrome_observation` should stop being treated as a free-form note and should become a shared verifier-enforced runtime anchor under the existing row-`706` authority.

## Steps

1. Ingest prior `target/*/insights.md` artifacts and summarize what worked, what failed, dead ends, and reuse opportunities.
2. Use a 3-seat council to compare remaining open checklist rows and pick the most feasible, testable next item.
3. Implement shared verifier-side validation for the row `713` headed QEMU plus Chrome observation anchor.
4. Extend writer-side rejection coverage and docs governance so the same contract is enforced across verifier, writer, and docs.
5. Run the focused suites for `honeypot_manual_headed` and `honeypot_docs`.
6. Run the baseline verification path:
   - `cargo +nightly fmt --all`
   - `cargo +nightly fmt --all --check`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests`
7. Review `AGENTS.md`, check the completed row, and leave blocked runtime rows open.

## Assumptions

- Row `706` remains the single runtime authority for manual-headed evidence.
- This host still lacks new admissible Tiny11-backed runtime proof, so only contract-hardening rows can close honestly.
- Shared verifier-side evidence contracts are the sanest reuse path because prior runs already established the same pattern for rows `707` and `719`.
