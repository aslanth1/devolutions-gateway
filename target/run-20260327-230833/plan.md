# Hypothesis

`AGENTS.md` is already fully complete, so the best next pass is a bounded closure revalidation rather than new implementation work.
A tiered proof should provide the right balance:
1. cheap deterministic closure integrity via explicit row-706 verification plus zero unchecked `AGENTS.md` rows, and
2. one real focused lab-e2e acceptance lane to catch runtime drift that static checks cannot see.

# Steps

1. Re-ingest recent `target/*/insights.md` artifacts and carry forward what worked, what failed, repeated dead ends, and promising reuse paths.
2. Run a 3-seat council with independent proposals, adversarial review, refinement, detailed planning, and evidence-based voting.
3. Execute the winning plan:
   - confirm clean git state,
   - confirm zero unchecked rows in `AGENTS.md`,
   - run explicit `verify-row706 --run-id 5c6c2ece-0c30-4694-a569-353ee88ffae9`,
   - run the focused live acceptance lane under the sanctioned `lab-e2e` env contract.
4. If the live lane emits a fresh partial row-706 stub, remove it so the canonical complete run remains the explicit authority.
5. Record a fresh `target/run-<timestamp>/` bundle and create a save-point commit.

# Assumptions

- The canonical row-706 authority remains `5c6c2ece-0c30-4694-a569-353ee88ffae9`.
- The sealed imported Tiny11 store under `target/run-20260327-173919/artifacts/live-proof/import/images` remains valid for the focused acceptance lane.
- The gate manifest at `target/run-20260327-173919/artifacts/live-proof/import/honeypot-tier-gate.json` remains the sanctioned `lab-e2e` gate input.
- Closure integrity should stay bounded: one real focused runtime lane is enough unless it fails and forces escalation.
