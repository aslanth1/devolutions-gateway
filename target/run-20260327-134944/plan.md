# Hypothesis

Row `738` can only be completed if this workstation has a real Tiny11-derived source manifest or attested interop store that allows a fresh row-`706` live evidence run to verify.
If provenance inputs are absent, the honest outcome is a fail-closed blocked row-`706` run and row `738` remains open.

# Steps

1. Read recent `target/*/insights.md` artifacts and summarize the recurring lessons.
2. Run a 3-seat council and force every proposal through idea, critique, refinement, detailed planning, and voting.
3. Freeze immutable host facts before any boot or import attempt:
   - search `/home/jf` for Tiny11 or source-manifest artifacts
   - inspect `/srv/honeypot/images`
   - inspect the local `kvm-win11` and `kvm-win11-canary` labs for Tiny11 lineage signals
4. Confirm the sanctioned import path and the row-`706` verifier contract from checked-in Rust code and docs.
5. If provenance inputs are absent, do not boot or import anything.
6. Instead, run one fresh row-`706` attempt with `lab-e2e` enabled and the generic `kvm-win11` VM directory wired in as the would-be interop store so the run fails closed on provenance.
7. Inspect the new row-`706` run envelope and decide whether row `738` can be checked.
8. Write run artifacts and save a commit.

# Assumptions

- The checked-in row-`706` verifier remains the only authority for closing row `738`.
- Generic `kvm-win11` labs do not count as Tiny11-derived unless first imported into an attested Tiny11 interop store through the sanctioned Rust path.
- A blocked row-`706` run is valid evidence of non-completion but never sufficient to close row `738`.
