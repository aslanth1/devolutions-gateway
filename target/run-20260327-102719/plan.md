# Hypothesis

- The right response to the user's live Tiny11 or Chrome walkthrough objective is to harden `AGENTS.md` into a gated fail-closed contract, not to promise an ad hoc manual run that would commit VM disks or plaintext credentials into the repo.
- Prior `target/run-*/insights.md` artifacts already show the key constraints:
  - honest Tiny11 proof requires explicit gated evidence
  - host-specific assumptions must fail closed
  - repo hygiene matters as much as runtime proof
- The existing `Milestone 6a` checklist block should be refined rather than duplicated.

# Steps

1. Re-read prior `target/run-*/insights.md` artifacts and summarize the recurring lessons.
2. Review `~/src/hellsd-gateway` again for E2E composition patterns worth reusing.
3. Run a 3-seat council and force proposal, critique, refinement, plan, and vote phases.
4. Implement the winning plan by tightening the existing `Milestone 6a` AGENTS block into a gated fail-closed contract.
5. Add a short supporting note in `docs/honeypot/testing.md`.
6. Add one docs-governance test that locks the new contract language in place.
7. Run the standard baseline verification, then save the run bundle and commit.

# Assumptions

- The immediate task is checklist design and repo policy, not a truthful live Tiny11 walkthrough execution.
- Raw VM disks, memory dumps, and plaintext credentials should not be added to normal git history even if the user initially asked for them.
- Existing Rust verification remains the correct baseline for this change.
