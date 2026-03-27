# What Was Done

1. Reused the existing Tiny11 prep outputs and host-side extracted ISO from the earlier prep run.
2. Re-hashed the compacted bundle qcow2 and discovered the original manifest hash had been captured before `qemu-img convert` fully settled.
3. Updated `target/run-20260327-161429/artifacts/bundle/bundle-manifest.json` so `base_image.sha256` matched the final stable qcow2 digest `ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f`.
4. Re-ran `cargo run -p honeypot-control-plane -- consume-image --config target/run-20260327-161429/artifacts/import/control-plane.toml --source-manifest target/run-20260327-161429/artifacts/bundle/bundle-manifest.json`.
5. Confirmed the sanctioned import succeeded and produced `target/run-20260327-161429/artifacts/import/images/sha256-ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f.qcow2` plus `target/run-20260327-161429/artifacts/import/images/manifests/tiny11-row747-20260327-ee889e408248.json`.
6. Ran the row-706 proof slice with the isolated interop store through `cargo test -p testsuite --test integration_tests honeypot_control_plane -- --nocapture`.
7. Observed that the three positive anchors all failed before boot proof because the control-plane startup wait used the generic 30-second helper while the imported-image startup path spent longer hashing the trusted image.
8. Added `wait_for_tcp_port_with_timeout` to `testsuite/src/cli.rs` and wired only the three row-706 positive anchors in `testsuite/tests/honeypot_control_plane.rs` to use the interop readiness budget for control-plane startup.
9. Removed one stale disposable prep QEMU process rooted under `target/w11/instances/t11t-215344` so it could not distort the next lab-backed run.
10. Re-ran the same row-706 proof slice with `DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS=300`.
11. Confirmed the startup-timeout blocker was resolved and the three positive anchors progressed into the real acquire and RDP path.
12. Observed a remaining failure mode: the imported control-plane lease path booted and exposed RDP, but `xfreerdp /auth-only` failed under the default NLA path with `ERRCONNECT_AUTHENTICATION_FAILED`.
13. Ran a focused interoperability retry with `DGW_HONEYPOT_INTEROP_RDP_SECURITY=tls`.
14. Confirmed the TLS-only retry also failed because the guest reported `HYBRID_REQUIRED_BY_SERVER`.
15. Added two follow-up AGENTS tasks to track the unresolved auth gap and the open question about whether the trusted-image contract needs boot-critical firmware or NVRAM state in addition to the qcow2.

# Commands And Actions

- `cargo run -p honeypot-control-plane -- consume-image --config ... --source-manifest ...`
- `cargo test -p testsuite --test integration_tests honeypot_control_plane -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_external_client_interoperability_smoke_uses_xfreerdp -- --nocapture`
- `cargo +nightly fmt --all --check`
- `sha256sum target/run-20260327-161429/artifacts/bundle/tiny11-base.qcow2`
- `qemu-img check target/run-20260327-161429/artifacts/bundle/tiny11-base.qcow2`
- Direct process inspection through `ps`, `pstree`, `/proc/<pid>/environ`, and tempdir inspection.

# Deviations From Plan

- The first `consume-image` attempt failed because the bundle manifest hash was captured too early.
- The initial row-706 run exposed a test-harness startup-timeout issue, so I patched the helper before retrying the proof.
- The final blocker was not startup or port readiness.
  It was RDP auth mismatch under the control-plane-launched imported lease path.
