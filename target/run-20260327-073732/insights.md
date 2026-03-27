# What Worked

- Run-scoped manifests were the cleanest way to remove stale-fragment ambiguity without inventing a second runner.
- Explicit run selection plus manifest-before-write gave deterministic fail-closed behavior.
- Reusing the existing four row-706 anchors was better than adding new proof surfaces.

# What Failed

- This host still cannot produce honest live Tiny11 closure evidence for row `706`.
- Focused filtered test invocations only generate partial runs, so they are useful for plumbing checks but not for closure evidence.

# Avoid Next Time

- Do not read row-706 evidence from a shared flat directory.
- Do not auto-pick “latest” evidence when explicit run selection is possible.
- Do not treat skipped lab anchors as anything other than blocker evidence.

# Promising Next Directions

- Add a small explicit row-706 runner that intentionally creates one run id, invokes the four canonical anchors together, and verifies that run when real Tiny11 inputs are available.
- Add optional retention pruning for stale `running` manifests and superseded complete runs if `target/row706/runs/` starts to accumulate heavily.
