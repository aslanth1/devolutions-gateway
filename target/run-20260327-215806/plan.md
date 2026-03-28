# Hypothesis

`AGENTS.md` is already fully complete, so the highest-value checklist pass is a closure-hardening improvement rather than reopening implementation work.
The winning proposal is to add a first-class Rust command that verifies the canonical row-706 evidence envelope by explicit `run_id`, reusing the existing verifier logic instead of relying on ad hoc shell inspection.

# Steps

1. Ingest prior `target/*/insights.md` artifacts and summarize what worked, what failed, repeated dead ends, and promising reuse paths.
2. Run a 3-seat council with independent proposals, adversarial review, refinement, detailed planning, and evidence-based voting.
3. Implement the winning plan by extending `honeypot-manual-headed-writer` with `verify-row706 --run-id <uuid> [--evidence-root <path>]`.
4. Add focused tests that prove the command rejects missing `run_id`, rejects incomplete envelopes, and accepts the canonical complete envelope.
5. Add one short doc update naming the command as the static verifier for row-706 closure checks.
6. Validate with formatting, clippy, focused tests, and a direct command smoke against the authoritative run `5c6c2ece-0c30-4694-a569-353ee88ffae9`.
7. Review `AGENTS.md`, confirm whether any rows must be reopened, and record the outcome.
8. Save a git commit with a verbose description of the attempt, results, and insights.

# Assumptions

- The existing `testsuite::honeypot_control_plane::verify_row706_evidence_envelope` helper remains the single source of truth for row-706 envelope validation.
- The canonical authoritative run remains `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/manifest.json`.
- A closure-hardening improvement is acceptable even when `AGENTS.md` already has zero unchecked rows, as long as the pass remains evidence-driven and does not invent new checklist scope.
