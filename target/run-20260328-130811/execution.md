# What Was Actually Done

1. Confirmed there were still no unchecked rows in `AGENTS.md`.
2. Re-read the latest manual-lab `insights.md` artifacts and summarized the repeated wins and failures:
   - thin Make wrappers over one Rust authority worked
   - explicit self-test aliases worked
   - operators still had to remember too many commands
   - auto-fallback and hidden state remained forbidden
3. Ran a fresh 3-seat council:
   - `Erdos`
   - `Huygens`
   - `Nietzsche`
4. All three seats converged on the same plan family: add a single-command local self-test entrypoint instead of more prose or hidden fallback behavior.
5. Chose the winning plan: add `make manual-lab-selftest` and `make manual-lab-selftest-no-browser`, then update the Rust remediation and docs to prefer that one command.
6. Implemented the plan in:
   - `Makefile`
   - `testsuite/src/honeypot_manual_lab.rs`
   - `docs/honeypot/runbook.md`
   - `docs/honeypot/testing.md`
   - `testsuite/tests/honeypot_manual_lab.rs`
   - `testsuite/tests/honeypot_docs.rs`
   - `AGENTS.md`

# Commands / Actions Taken

```bash
grep -n '^- \[ \]' AGENTS.md || true
find target -path '*/insights.md' | sort
make manual-lab-up
make manual-lab-show-profile
make manual-lab-selftest-preflight
make -n manual-lab-selftest
make -n manual-lab-selftest-no-browser
cargo +nightly fmt --all
cargo clippy --workspace --tests -- -D warnings
cargo test -p testsuite --test integration_tests -- --nocapture
```

# Deviations From Plan

The council considered richer read-only helper variants such as `manual-lab-selftest-plan` or `manual-lab-show-commands`, but they were rejected as weaker than a true one-command entrypoint.
No runtime auto-fallback was attempted.
Canonical `/srv` behavior remained untouched.
One save-phase attempt used an unsafe shell-quoted commit message with backticks, which caused shell command substitution instead of creating the commit.
The stray shell and `honeypot-manual-lab bootstrap-store --execute` subprocess were killed, no new commit was created, and the save phase was retried with a backtick-safe message.
