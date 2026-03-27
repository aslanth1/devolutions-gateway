# Success / Failure

Success.

- Row-706 evidence is now written under `target/row706/runs/<run_id>/`.
- Verification now requires one explicit completed run instead of reading mixed flat fragments from `target/row706/`.
- Pre-manifest writes, duplicate manifest creation, malformed fragments, skipped positive anchors, incomplete runs, and symlinked run dirs all fail closed.
- A normal full `integration_tests` run now produced one `complete` row-706 run manifest while focused runs remained partial and non-authoritative.

# Observable Signals

- Focused row-706 verifier tests: `8 passed`
- Full baseline integration suite: `263 passed`
- Full-suite evidence tree included a completed run manifest under `target/row706/runs/`

# Unexpected Behavior

- Old flat fragments from earlier turns are still present under `target/row706/`, but they no longer affect verification because the verifier now only reads explicit run directories.
- Focused single-test invocations naturally create partial `running` manifests because they do not execute all four anchors in one process.
