# Execution

## Council

- Memory ingest reviewed recent `target/run-20260328-165009/insights.md`, `target/run-20260328-163030/insights.md`, `target/run-20260328-162507/insights.md`, and `target/run-20260328-162034/insights.md`.
- Prior work that held up:
  - keep the Docker-based webplayer builder as the default
  - keep `DGATEWAY_WEBPLAYER_PATH` as the explicit prebuilt override
  - fail fast on bad npm scope or host auth
- Prior dead ends to avoid:
  - readable `.npmrc` without `@devolutions:registry`
  - assuming sibling repos are valid artifact sources
  - treating missing auth as a Make orchestration bug

- Seats:
  - Averroes proposed B
  - Godel proposed A
  - Harvey proposed C
- Voting:
  - Averroes voted B
  - Harvey voted B
  - Godel voted A
- Winner: plan B, `2-1`

## Review

- Reviewed `hellsd-gateway` commit `77805e210c75c0a5d6f7e3a613e195ad0a4a266d` with:
  - `git show --stat --oneline 77805e210c75c0a5d6f7e3a613e195ad0a4a266d`
  - `rg -n "/jet/jrec/play|recording-player|webapp_wall|observer/sessions|selected-session" ...`
- Confirmed that commit modifies `webapp_wall.js` and `webapp_wall.html` for `/jet/webapp/wall` and `/observer/sessions`, not this repo's `recording-player` bundle contract for `/jet/jrec/play`.

## Implementation

- Added a new read-only Make helper:
  - `manual-lab-webplayer-validate-bundle`
- Strengthened the selected prebuilt bundle contract in `Makefile`:
  - require `index.html`
  - require a non-empty `assets/` directory
  - treat missing `assets/` as `invalid` in `manual-lab-webplayer-status`
  - rebuild the repo-default bundle when `assets/` is missing
- Kept `manual-lab-selftest` and the containerized builder flow unchanged as the primary lane.
- Tightened Rust-side readiness in `testsuite/src/honeypot_manual_lab.rs` so preflight checks both:
  - `webapp/dist/recording-player/index.html`
  - `webapp/dist/recording-player/assets`
- Updated docs and contract tests to describe the stronger prebuilt-bundle contract.
- Updated `AGENTS.md` with Milestone `6t`.

## Deviation

- First implementation reused recursive `$(MAKE)` inside `manual-lab-webplayer-auth-check` and `manual-lab-ensure-webplayer`.
- That broke `make -n manual-lab-webplayer-auth-check` because recursive `make` still executes in dry-run mode.
- Fixed by keeping the new helper target for direct use but inlining explicit-path validation in those two recipe branches.

## Commands Run

- `git show --stat --oneline 77805e210c75c0a5d6f7e3a613e195ad0a4a266d`
- `make manual-lab-webplayer-validate-bundle DGATEWAY_WEBPLAYER_PATH=/tmp/does-not-exist`
- `make -n manual-lab-webplayer-auth-check`
- `make manual-lab-webplayer-status`
- `make manual-lab-webplayer-validate-bundle`
- `cargo test -p testsuite --test integration_tests make_manual_lab_webplayer_validate_bundle_rejects_index_only_override -- --nocapture`
- `cargo test -p testsuite --test integration_tests manual_lab_ -- --nocapture`
- `cargo +nightly fmt --all`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests -- --nocapture`
