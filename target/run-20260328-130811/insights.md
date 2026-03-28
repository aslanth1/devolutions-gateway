# What Worked

- The council converged quickly because the problem had narrowed to operator ergonomics, not missing runtime behavior.
- One-command self-test entrypoints are a better fix than adding more remediation prose once the lane separation is already correct.
- Keeping Make thin and Rust authoritative continues to scale well.
- Docs-parity tests remain the fastest way to catch drift across AGENTS, docs, and blocker text.

# What Failed

- Multi-command self-test guidance was still too much to remember in the real failure path.
- `make manual-lab-show-profile` still advertised a shorter path than the real canonical blocker, which would have become another drift source if left untouched.

# What To Avoid Next Time

- Do not solve operator-memory problems with more prose when a small explicit command surface can solve them directly.
- Do not let completed AGENTS milestones preserve stale pass conditions after a later milestone supersedes the exact command sequence.
- Do not add hidden fallback from canonical to local state.

# Promising Next Directions

- If manual operators still ask “what should I run?”, a read-only `manual-lab-selftest-plan` helper could be added later without changing behavior.
- Keep reviewing `manual-lab-show-profile` whenever the preferred quick path changes so it stays aligned with the live blocker contract.
