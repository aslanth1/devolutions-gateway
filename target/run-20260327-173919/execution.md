# What Was Actually Done

1. Read prior `target/*/insights.md` artifacts and summarized the prior wins, failures, dead ends, and reuse points before doing new work.
2. Ran the required three-agent council with `gpt-5.3-codex` at high reasoning effort and selected the provenance-first sealed boot-profile plan.
3. Extended the control-plane config and launch path to represent the missing boot-critical inputs:
   - disk interface
   - NIC model
   - RTC base
   - firmware mode
   - firmware code path
   - writable vars seed path
4. Extended trusted-image import and trusted-image loading to accept, validate, import, and replay `boot_profile_v1`.
5. Added QEMU unit coverage for the allowlisted boot profile replay and trusted-image unit coverage for imported firmware and vars artifacts.
6. Added a process-backed integration test that imports a bundle with `boot_profile_v1` and proves the active lease snapshot contains the imported firmware path, vars seed path, runtime vars path, and the expected AHCI, `e1000`, `localtime`, and pflash argv.
7. Ran the deterministic verification path for the new code.
8. Built a fresh run-local live-proof source bundle under `target/run-20260327-173919/artifacts/live-proof/source-bundle/` from:
   - `target/run-20260327-161429/artifacts/import/images/sha256-ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f.qcow2`
   - `/usr/share/OVMF/OVMF_CODE_4M.fd`
   - `target/run-20260327-165747/artifacts/diff/c-manual/OVMF_VARS.fd`
9. Imported that bundle into a fresh run-local store under `target/run-20260327-173919/artifacts/live-proof/import/images/`.
10. Pointed the existing lab-e2e `xfreerdp` interoperability smoke at that imported sealed-profile store with the manually verified `jf / ChangeMe123!` credentials.
11. Observed that the live replay never reached QEMU launch and stopped it after collecting enough evidence to classify the blocker honestly.
12. Updated `AGENTS.md` to check the completed contract rows and add the new validation-latency blocker row.

# Commands / Actions Taken

- `cargo test -p honeypot-control-plane`
- `cargo test -p testsuite --test integration_tests control_plane_consume_image_command_preserves_boot_profile_v1_in_active_lease_snapshot -- --nocapture`
- `cargo +nightly fmt --all`
- `cargo +nightly fmt --all --check`
- `cargo clippy --workspace --tests -- -D warnings`
- `sha256sum /usr/share/OVMF/OVMF_CODE_4M.fd target/run-20260327-165747/artifacts/diff/c-manual/OVMF_VARS.fd target/run-20260327-161429/artifacts/import/images/sha256-ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f.qcow2`
- `cargo run -p honeypot-control-plane -- consume-image --config target/run-20260327-173919/artifacts/live-proof/import/control-plane.toml --source-manifest target/run-20260327-173919/artifacts/live-proof/source-bundle/bundle-manifest.json`
- `DGW_HONEYPOT_LAB_E2E=1 ... cargo test -p testsuite --test integration_tests control_plane_external_client_interoperability_smoke_uses_xfreerdp -- --nocapture`
- Inspected `/proc/<pid>/fd` and `/proc/<pid>/io` for the live control-plane process to classify the stall.

# Deviations From Plan

- The live replay did not reach the intended auth result.
  The run exposed a new blocker earlier in the path: authenticated health and acquire stayed inside `trusted_images()` long enough that QEMU never launched.
- The `cargo run ... consume-image` foreground invocation did not return promptly even after the final qcow2, manifest, and imported boot artifacts were present on disk.
  I treated the import as complete based on the materialized store contents rather than waiting indefinitely on the wrapper process.
- I did not rerun the full `cargo test -p testsuite --test integration_tests` baseline.
  The new deterministic coverage passed, but the current live imported-store path would make the full honeypot matrix slow and misleading until the validation-latency issue is fixed.
