# What Worked

- Reusing the existing compose harness was the right foundation for stack-level E2E proof.
- Structured YAML mutation was much safer than post-serialization string replacement.
- A compose-network driver gave deterministic full-stack frontend proof without depending on workstation-local Docker port reachability.
- The `hellsd-gateway` idea worth keeping was layered validation around a real stack, not its orchestration style.

# What Failed

- Host-loopback probing of Docker-published compose ports was not reliable on this workstation.
- Treating serialized compose YAML as a string-rewrite target was brittle.

# Avoid Next Time

- Do not assume Docker-published localhost ports are reachable from every execution namespace.
- Do not mix YAML AST mutation with later string patching of the same document.
- Do not import script-heavy dev-stack flows when the repo already has a workable Rust compose harness.

# Promising Next Directions

- Add one higher-tier browser-driven lane later that is explicitly gated for hosts where Chrome or a real browser path is known-good.
- Reuse the new compose-network driver pattern for additional full-stack operator flows such as fullscreen fragments or guarded action routes.
