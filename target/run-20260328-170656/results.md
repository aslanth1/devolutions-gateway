# Results

## Outcome

Success.
The repo now keeps the existing one-command containerized `manual-lab-selftest` flow while rejecting incomplete prebuilt `recording-player` bundle roots earlier and more accurately.

## Observable Signals

- `hellsd-gateway` commit `77805e210c75c0a5d6f7e3a613e195ad0a4a266d` touched the standalone wall frontend and did not replace this repo's `/jet/jrec/play` bundle contract.
- `make manual-lab-webplayer-status` on this host reports:
  - docker available
  - private registry deps present
  - npm auth missing at `/home/jf/.npmrc`
  - bundle missing because `webapp/dist/recording-player/index.html` is absent
- `make manual-lab-webplayer-validate-bundle` now fails fast on the repo default bundle with the correct remediation.
- `cargo test -p testsuite --test integration_tests manual_lab_ -- --nocapture` passed: `28 passed, 0 failed`.
- `cargo test -p testsuite --test integration_tests -- --nocapture` passed: `346 passed, 0 failed`.

## Unexpected Behavior

- Recursive `$(MAKE)` inside a recipe caused `make -n manual-lab-webplayer-auth-check` to execute the helper and fail.
- Fix: keep the helper target for direct use, but inline explicit-path validation in the two recipe branches that must remain dry-run safe.

## Residual Constraints

- The host still needs a real Devolutions-scoped npm auth file or a prebuilt bundle override to actually build `recording-player`.
- An unrelated untracked `.Makefile.swp` existed in the worktree and was not included in the save-point.
