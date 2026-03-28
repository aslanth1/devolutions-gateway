# Success / Failure

## Succeeded

- The trusted-image contract now carries a sealed `boot_profile_v1` instead of assuming the imported qcow2 is self-contained.
- The import path now records and validates the manual-good launch-shape inputs that mattered in the earlier differential run:
  - firmware code
  - writable vars seed
  - disk interface
  - NIC model
  - RTC base
  - firmware mode
- The process-backed integration proof passed and showed that the imported boot profile survives all the way into the active lease snapshot and lease-local `OVMF_VARS.fd` copy.
- `AGENTS.md` rows 414 and 417 were completed truthfully.

## Failed Or Blocked

- The live imported Tiny11 replay did not reach guest auth.
- The sealed-profile `xfreerdp` interoperability attempt never launched QEMU before it was stopped.
- `AGENTS.md` rows 411 and 420 remain open.

# Observable Signals

- `cargo test -p honeypot-control-plane` passed.
- `cargo test -p testsuite --test integration_tests control_plane_consume_image_command_preserves_boot_profile_v1_in_active_lease_snapshot -- --nocapture` passed.
- `cargo +nightly fmt --all --check` passed.
- `cargo clippy --workspace --tests -- -D warnings` passed.
- The imported live-proof manifest exists at `target/run-20260327-173919/artifacts/live-proof/import/images/manifests/tiny11-row420-sealed-profile-ee889e408248.json`.
- That imported manifest records:
  - `disk_interface = ahci_ide`
  - `network_device_model = e1000`
  - `rtc_base = localtime`
  - `firmware_mode = uefi_pflash`
  - digest-bound imported firmware and vars artifacts
- During the live replay, `pgrep` showed only:
  - the integration test process
  - the spawned `honeypot-control-plane`
  - no `qemu-system-x86_64`
  - no `xfreerdp`
- During that same live replay, `/tmp/.tmpkRuzXO/leases`, `/tmp/.tmpkRuzXO/qmp`, and `/tmp/.tmpkRuzXO/qga` stayed empty.
- The live control-plane process held the imported base image open on `/proc/1579474/fd/11`.
- `/proc/1579474/io` showed repeated large reads while no lease artifacts appeared:
  - `rchar: 67613603414`
  - `read_bytes: 3787649024`
- Unauthenticated `GET /api/v1/health` returned `401` immediately.
- Authenticated `GET /api/v1/health` with the real test token timed out, which is consistent with the process spending the request path inside trusted-image validation.

# Unexpected Behavior

- The foreground `cargo run -p honeypot-control-plane -- consume-image ...` command remained alive even after the final qcow2, manifest, and imported boot artifacts were fully materialized on disk.
- The biggest blocker in the live replay was not guest auth, OVMF, or launch argv.
  It was the current validation strategy for imported trusted images, which kept the control plane busy on full-image reads before QEMU launch.
