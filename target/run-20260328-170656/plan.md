# Plan

## Hypothesis

The best remaining improvement is not a new build orchestration layer.
The existing `make manual-lab-selftest` containerized webplayer lane is already the right default.
The missing hardening is stricter validation for prebuilt bundle roots so manual-lab rejects placeholder or partial `recording-player` outputs before launch.
The `hellsd-gateway` commit `77805e210c75c0a5d6f7e3a613e195ad0a4a266d` is expected to be reference-only because it improves a separate wall UI rather than this repo's `/jet/jrec/play` bundle contract.

## Steps

1. Re-read prior `target/*/insights.md` artifacts and summarize what worked, failed, and should be avoided.
2. Review this repo's manual-lab and frontend bundle contract plus `hellsd-gateway` commit `77805e210c75c0a5d6f7e3a613e195ad0a4a266d`.
3. Run a 3-seat council, collect proposals, criticism, refinements, detailed plans, and evidence-based votes.
4. Execute the winning plan with the smallest durable patch.
5. Update docs, tests, and `AGENTS.md`.
6. Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests -- --nocapture`.

## Assumptions

- Manual-lab still depends on a built `recording-player` bundle for `/jet/jrec/play`.
- A valid Vite production bundle root contains `index.html` and a non-empty `assets/` directory.
- Private npm auth remains an external host input and should stay separate from bundle validation.
