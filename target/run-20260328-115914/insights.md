# What Worked

- A minimal remembered-manifest helper solved the operator friction without weakening the fail-closed bootstrap gate.
- Keeping explicit overrides authoritative preserved debuggability and avoided hidden state surprises.
- Revalidating the remembered hint by both admissibility and digest kept the shortcut safe.
- Thin Make targets around one Rust authority remain the right pattern for this repo.

# What Failed

- Placeholder remediation text that only said `consume-image --source-manifest <bundle-manifest.json>` was not enough when more than one admissible manifest existed.

# What To Avoid Next Time

- Do not auto-pick among multiple admissible manifests.
- Do not move selection logic into Make or docs-only guidance.
- Do not let remembered local state silently fall back to a different manifest after drift.

# Promising Next Directions

- If operators still need help, add a read-only `show-selected-source-manifest` or `clear-selected-source-manifest` helper without changing the precedence model.
- When the user is ready to mutate the host, the next manual step is `make manual-lab-bootstrap-store-exec`, then `make manual-lab-preflight`, then `make manual-lab-up`.
