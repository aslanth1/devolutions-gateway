# Hypothesis

`make manual-lab-selftest` already owns the containerized webplayer build lane.
The real blocker is a false-positive auth precheck that accepts a readable `.npmrc` even when it does not map `@devolutions` to the private JFrog registry.
If the Make auth and status helpers validate the scoped registry plus matching host credentials before `pnpm install`, the one-command flow will fail early with the real remediation instead of wasting time on a later npmjs 404.

# Prior Research

- Worked:
  - thin Make wrappers over the Rust manual-lab authority
  - containerized `manual-lab-ensure-webplayer`
  - `DGATEWAY_WEBPLAYER_PATH` as the explicit offline override
  - read-only status and auth helper targets
- Failed:
  - assuming any readable `.npmrc` means the private registry is ready
  - chasing host-specific auth files without proving the `@devolutions` scope mapping
- Dead ends to avoid:
  - more Make churn when the issue is external npm scope config
  - copying assets from sibling repos without a versioned contract
- Promising reuse:
  - keep the existing builder image and `manual-lab-selftest` command surface
  - tighten the preflight instead of replacing the build lane

# Council Winner

Seat A won with `2-1`.
Winning plan:

1. Keep the containerized build path in `Makefile`.
2. Make `manual-lab-webplayer-auth-check` reject readable-but-wrong `.npmrc` files.
3. Reuse that verdict from `manual-lab-ensure-webplayer`.
4. Teach `manual-lab-webplayer-status` to show scoped-registry state separately from auth-host state.
5. Add tests and docs that pin the npmjs fallback risk and the exact remediation anchors.

# Assumptions

- `webapp/` remains the authoritative source for the recording-player bundle in this repo.
- `hellsd-gateway` commit `77805e210c75c0a5d6f7e3a613e195ad0a4a266d` is informative for frontend streaming behavior, but not a drop-in replacement for `/jet/jrec/play`.
- Private registry access still requires an operator-provided `.npmrc` or a prebuilt `DGATEWAY_WEBPLAYER_PATH`.

# Steps

1. Review `target/*/insights.md`.
2. Review the current Make webplayer lane and the failing host behavior.
3. Review `hellsd-gateway` commit `77805e...` and compare its shipped wall frontend to this repo’s recording-player path.
4. Patch `Makefile`, docs, tests, and `AGENTS.md`.
5. Validate targeted host behavior, then run `fmt`, `clippy`, and the full integration baseline.
6. Write results, close sub-agents, and create a save-point commit.
