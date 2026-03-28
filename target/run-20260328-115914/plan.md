# Hypothesis

The right fix for the repeated `missing_store_root` manual-lab failure is not to weaken the guard.
It is to make the manual bootstrap path explicit, repeatable, and operator-friendly.
For hosts with more than one admissible bundle manifest, the repo should support a local remembered manifest hint that stays subordinate to explicit flags and still revalidates before use.

# Steps

1. Add explicit AGENTS scope for a remembered source-manifest helper that supports repeated manual bootstrap runs without retyping long paths.
2. Extend the Rust manual-lab authority with a `remember-source-manifest` command and a git-ignored local selection file under `target/manual-lab/`.
3. Keep explicit `--source-manifest` and `MANUAL_LAB_SOURCE_MANIFEST` overrides authoritative over any remembered hint.
4. Revalidate the remembered hint on every bootstrap attempt and fail closed if the file disappeared, drifted, or is no longer admissible.
5. Add thin Make targets and docs that teach the sequence `preflight -> remember-source-manifest -> bootstrap-store --execute -> preflight -> up` when multiple admissible manifests exist.
6. Add tests for help output, remembered-hint writes, override precedence, stale-hint rejection, and docs parity.
7. Run targeted and baseline verification, then exercise the live host flow up to dry-run bootstrap readiness.

# Assumptions

- The existing `missing_store_root` failure is correct and should remain a hard gate until the canonical interop store is populated.
- Operators may have multiple admissible bundle manifests on disk and should not be forced to retype one for every manual bootstrap attempt.
- A local remembered hint is acceptable if it is git-ignored, subordinate to explicit overrides, and revalidated before use.
- Leaving `bootstrap-store-exec` to the operator is preferable because it mutates the host-owned canonical image store.
