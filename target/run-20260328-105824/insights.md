# What Worked

- Turning the live operator error into explicit `AGENTS.md` scope produced a better fix than another no-op “no next task” pass.
- A shared Rust evaluator for `preflight` and `up` is the right seam.
- Thin Make wrappers are useful when they stay pure callers of the Rust authority.
- A direct real-world check of `make manual-lab-preflight` and `make manual-lab-up` gave better proof than docs-only updates.

# What Failed

- A first verification attempt assumed nonexistent per-file test binaries in `testsuite`.
- The first preflight refactor triggered a `clippy::large-enum-variant` warning that had to be fixed before save-point.

# What To Avoid Next Time

- Do not mark manual operator flows complete only because `up` exists; operator-visible readiness needs its own checklist rows.
- Do not let wrappers own gate logic.
- Do not treat a missing interop-store directory as the only readiness check forever; richer store-usability checks can follow later if new evidence demands them.

# Promising Next Directions

- If manual operators keep hitting store-shape issues after `consume-image`, widen Milestone `6c` with deeper interop-store usability checks.
- If a concrete source-manifest path can be discovered safely on the local host, upgrade remediation from a template to a fully resolved command.
