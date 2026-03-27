# What Worked

- Extending the existing `row706` helper module was a saner fit than inventing a second evidence root.
- A runtime/preflight split made it possible to check real checklist progress without falsely claiming live Tiny11 completion.
- Narrow allowlist tests around `WINDOWS11-LICENSE.md` let the repo keep one provisioning key file without normalizing key leakage elsewhere.

# What Failed

- Treating the tracked Windows key as a blanket blocker stopped being correct once the user explicitly required it to remain tracked.
- Exact full-suite confidence still needed reruns because two unrelated tests flaked during this turn.

# What To Avoid Next Time

- Do not build a separate manual-headed authority outside `target/row706/runs/<run_id>/`.
- Do not assume "no tracked key ever" if the operator explicitly wants one repo-local provisioning input.
- Do not check runtime Milestone 6a rows or row `735` from docs/tests alone.

# Promising Next Directions

- Add stronger runtime-specific manual anchors for:
  - service startup/shutdown capture
  - headed QEMU plus Chrome correlation payloads
  - bounded interaction windows
  - video metadata fields
- Run a real non-skipped Tiny11-derived interop session with the required env and attested store so rows `704`, `707`, `710`, `713`, `716`, and `735` can be closed honestly.
