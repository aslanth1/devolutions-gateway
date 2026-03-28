# Hypothesis

The current manual-lab blocker is not missing functionality in the Make wrapper itself.
It is missing operator-visible readiness scope.
If `AGENTS.md` gains an explicit manual-deck preflight block, and the repo adds one shared Rust preflight authority plus a preflight-first wrapper flow, then manual testing can fail fast on real blockers like `missing_store_root` without hidden side effects or trial-and-error launch attempts.

# Steps

1. Re-read prior `target/*/insights.md` artifacts and summarize reusable patterns.
2. Run a 3-seat council to choose the best new `AGENTS.md` block and the first implementation task.
3. Add a new Milestone `6c` block in `AGENTS.md` for manual-deck preflight and interop-store readiness.
4. Implement one shared Rust readiness evaluator in `testsuite::honeypot_manual_lab`.
5. Add `honeypot-manual-lab preflight` and wire `up` through the same evaluator.
6. Add thin `Makefile` targets for preflight and make `manual-lab-up` stop at preflight when blocked.
7. Add targeted parity and no-side-effect tests, then rerun the baseline verification path.
8. Write run artifacts and create a save-point commit.

# Assumptions

- The sanctioned `consume-image` path remains the only approved interop-store bootstrap path.
- Manual-lab readiness belongs to the manual-lab testsuite seam, not a new shell or Python runner.
- Fail-closed behavior must remain intact even if preflight passes and the host drifts before `up`.
