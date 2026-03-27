# Hypothesis

Row `706` is still blocked on real Tiny11 lab inputs, so the best honest next step is to harden the evidence pipeline against stale-fragment contamination and ambiguous run selection.

# Steps

1. Add a run-scoped row-706 manifest and per-run fragment layout under `target/row706/runs/<run_id>/`.
2. Require manifest creation before any fragment write.
3. Require explicit run selection during verification and stop auto-discovering shared flat files.
4. Reject malformed, partial, duplicate, or path-escaped evidence.
5. Rewire the live anchor emitters to write into one process-scoped run per integration invocation.
6. Add focused adversarial tests and rerun the baseline verification path.

# Assumptions

- This workstation still lacks the live Tiny11 interop inputs needed to close `AGENTS.md:706`.
- Existing row-706 anchors remain the right proof surfaces.
- Fail-closed evidence integrity is valuable even when live closure is blocked.
