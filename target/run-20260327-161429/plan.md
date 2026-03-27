# Hypothesis

The newly imported Tiny11-derived qcow2 can satisfy AGENTS row `747` through the sanctioned `consume-image` path and the existing row-706 live evidence tests.

# Steps

1. Reuse the prior Tiny11 prep artifacts, the pinned `tiny11builder` commit, and the extracted host-side `tiny11.iso`.
2. Confirm the compacted qcow2 bundle hash, import it into an isolated run-local interop store with `honeypot-control-plane consume-image`, and verify the imported manifest.
3. Run `cargo test -p testsuite --test integration_tests honeypot_control_plane -- --nocapture` against the isolated interop store so the four row-706 anchors share one evidence envelope.
4. If the live proof fails, investigate the first concrete blocker and adjust only the minimal repo surface needed to keep the attempt honest and testable.
5. Update AGENTS progress based on observed evidence rather than intent.

# Assumptions

- The compacted qcow2 bundle is the correct trusted artifact once its final SHA-256 is known.
- The credentials `jf` and `ChangeMe123!` remain valid for RDP after import and control-plane lease startup.
- The qcow2-only trusted-image contract is sufficient for the control-plane boot path unless the evidence proves otherwise.
- Extending test startup waits is acceptable if the blocker is image-validation cost rather than guest failure.
