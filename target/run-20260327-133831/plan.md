# Hypothesis

The next honest checklist closeout is `AGENTS.md` row `710`.
The host still lacks fresh admissible Tiny11 live-runtime proof for row `738`, but row `710` can be completed by turning `manual_tiny11_rdp_ready` into a shared verifier-enforced artifact contract that ties key-source disclosure and Tiny11 lineage back to the verified row-`706` envelope.

# Steps

1. Ingest recent `target/*/insights.md` artifacts and summarize what worked, what failed, repeated dead ends, and promising reuse points.
2. Run a 3-seat council with independent proposals, cross-critique, refinement, detailed plans, and evidence-based voting.
3. Implement the winning row `710` plan in the shared manual-headed verifier and the manual-headed writer path.
4. Update test fixtures, add focused verifier-side negatives, and add a writer-side parity check.
5. Update `docs/honeypot/testing.md`, `docs/honeypot/runbook.md`, and docs-governance tests.
6. Check off row `710` in `AGENTS.md`.
7. Run focused verification, then the baseline Rust verification path, and record transient deviations if reality differs from expectation.

# Assumptions

- `row706` remains the only runtime authority for Tiny11 lineage and attestation.
- Row `710` can be closed without claiming live Tiny11 walkthrough completion for row `738`.
- The existing manual-headed writer should reject malformed row `710` artifacts with the same semantics the verifier uses.
