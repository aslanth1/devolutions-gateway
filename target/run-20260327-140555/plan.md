# Hypothesis

The next honest checklist slice is to complete the new Tiny11 prep prerequisite lane first.
That means proving the `kvm-win11` gold snapshot can be cloned into an isolated prep workspace and booted independently under QEMU, then treating Tiny11 transformation as a separate provenance and runtime gate rather than faking row `405`.

# Steps

1. Re-ingest recent `target/*/insights.md` files and summarize what worked, what failed, repeated dead ends, and promising reuse.
2. Run a 3-seat council and force proposals through critique, refinement, detailed plans, and evidence-based voting.
3. Execute the winning plan by splitting work into two gates:
   - operational gate for AGENTS rows `399` and `402`
   - provenance plus runtime gate for AGENTS row `405`
4. Clone `win11-base` into a dedicated prep state root that does not mutate the stable lab.
5. Boot the clone under QEMU and capture guest readiness evidence through QGA.
6. Validate a Tiny11 transformation source against explicit provenance requirements.
7. Attempt the transformation only if the source and host path are concrete enough to observe honestly.
8. Write run artifacts, update AGENTS with only the rows proven this turn, and create a save-point commit.

# Assumptions

- `/home/jf/research/ned/labs/windows/kvm-win11/win11.sh` is the authoritative stable launcher on this host.
- The stable lab snapshot `win11-base` is healthy and cloneable.
- `/home/jf/src/devolutions-gateway/target/` is acceptable as a repo-local prep and evidence root.
- The approved upstream Tiny11 source is `https://github.com/ntdevlabs/tiny11builder` unless local policy rejects it.
- Row `405` is not complete unless a real transformation run produces a transformed output artifact plus provenance inputs.
