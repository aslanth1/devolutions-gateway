# Plan

## Hypothesis

The current branch already has enough code to prove `BS-24`, but the next decision should follow a hybrid gate:

1. re-run a fresh same-day `BS-26` control pair to ensure the evidence contract is still apples-to-apples on the current worktree
2. only if that gate passes, attempt a bounded `BS-25` viability check for an explicit `ironrdp-gfx` lane

Guacd was reviewed as a reference implementation because it treats graphics as an explicit capability policy, not a guessed side effect.

## Steps

1. Read recent `target/run-*/insights.md` files and summarize what worked, what failed, repeated dead ends, and promising techniques.
2. Review `apache/guacamole-server` for relevant RDP proxy patterns, especially how graphics capability is gated.
3. Run a 3-agent council and choose the next bounded tranche.
4. Validate the existing IronRDP no-gfx groundwork with targeted tests.
5. Run a fresh one-session same-day pair:
   - `xfreerdp` control
   - `ironrdp-no-rdpgfx`
6. Compare the refreshed evidence contract and protocol counters.
7. If the gate passes, inspect the current IronRDP dependency surface for a bounded `ironrdp-gfx` spike.
8. Update `AGENTS.md` only for the rows actually proven or clearly blocked.
9. Run baseline validation and create a save-point commit.

## Assumptions

- One-session proofs are enough for the current `BS-24` and `BS-26` gate.
- If the pinned IronRDP crates do not expose a minimal graphics-client surface, `BS-25` should remain open rather than be faked.
- Guacd can be used as a design reference, but not as proof that the current IronRDP stack can negotiate RDPEGFX with only a small local change.
