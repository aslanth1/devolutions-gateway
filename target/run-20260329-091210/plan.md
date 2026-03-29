# Hypothesis

`BS-35` can be closed by extending the sanctioned manual-lab evidence contract so it records a slot-scoped ready-path verdict for every expected session slot, including the historically weak third slot, instead of leaving multi-session truthfulness in raw per-session evidence only.

Guacd review reinforced one design choice: capability and graphics state should be made explicit in the contract, not inferred later from aggregate behavior.

# Steps

1. Re-read prior `target/*/insights.md` artifacts and reuse the successful ready-path reducer pattern while avoiding aggregate-only summaries.
2. Run a three-agent council and force plan selection against feasibility, testability, and slot-three coverage.
3. Extend `testsuite/src/honeypot_manual_lab.rs` with a top-level multi-session ready-path summary and named per-slot reasons.
4. Persist that summary in `black-screen-evidence.json` during the sanctioned manual-lab evidence write path.
5. Add focused `testsuite/tests/honeypot_manual_lab.rs` coverage for:
   - three accounted slots with distinct outcomes
   - missing third-slot evidence failing loudly
6. Run the baseline verification path:
   - `cargo +nightly fmt --all`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests`
7. If verification stays green, mark `BS-35` complete in `AGENTS.md`.

# Assumptions

- Closing `BS-35` does not require a new runtime lane or a same-turn live lab rerun if the sanctioned persisted proof contract now truthfully accounts for slots `1`, `2`, and `3`.
- Existing per-session evidence already contains enough signal to compute named slot outcomes.
- The historically weak third-slot problem is primarily a proof-contract gap, not a missing transport primitive.
