# What Worked

- Tightening the Make auth helper around `@devolutions:registry` and `devolutions.jfrog.io` immediately exposed the real blocker.
- Reusing `manual-lab-webplayer-auth-check` from `manual-lab-ensure-webplayer` kept the failure contract consistent.
- A fake explicit `DGATEWAY_WEBPLAYER_PATH` makes the dry-run selftest graph tests host-independent.

# What Failed

- A readable `.npmrc` alone was not a trustworthy signal.
- The candidate `/home/jf/src/paperclip/.npmrc` still failed the real contract because it does not define `@devolutions:registry`.

# What To Avoid Next Time

- Do not assume sibling frontend repos are artifact sources without a bundle contract and versioned path.
- Do not treat `make -n` wrapper tests as safe unless recursive targets are neutralized.

# Promising Next Directions

- If a real Devolutions-scoped `.npmrc` exists elsewhere on the host, wire it in with `MANUAL_LAB_WEBPLAYER_NPMRC` and re-run `make manual-lab-selftest`.
- If a trusted prebuilt recording-player bundle exists, use `DGATEWAY_WEBPLAYER_PATH=<recording-player-dir>` for offline bring-up.
