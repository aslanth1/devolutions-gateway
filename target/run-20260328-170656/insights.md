# Insights

## What Worked

- Keeping the existing Docker-based webplayer builder as the primary path was still the right decision.
- Strengthening the prebuilt-bundle contract to `index.html` plus `assets/` caught the real incomplete-bundle failure mode without changing the command graph.
- Treating `hellsd-gateway` wall work as reference-only avoided a false shortcut.

## What Failed

- Recursive `$(MAKE)` inside a recipe is not safe for `make -n` contract tests.
- Trusting `index.html` alone was too weak for `DGATEWAY_WEBPLAYER_PATH`.

## Avoid Next Time

- Do not assume a sibling repo's HTML or wall frontend is a drop-in replacement for this repo's `recording-player` bundle.
- Do not treat readable `.npmrc` files as sufficient without scoped-registry validation.

## Promising Next Directions

- If a future prebuilt-bundle import path is added, keep it bound to the same `index.html` plus `assets/` contract.
- Keep auth diagnostics and bundle-shape diagnostics separate so operator remediation stays obvious.
