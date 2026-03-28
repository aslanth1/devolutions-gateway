# Success Or Failure

Success.

This turn closed the three open Tiny11 control-plane rows that were blocked on imported-store request-path validation:
- row 411
- row 420
- row 423

# Observable Signals

- `cargo test -p honeypot-control-plane` passed.
- `cargo clippy --workspace --tests -- -D warnings` passed.
- `cargo test -p testsuite --test integration_tests` passed with `298 passed; 0 failed`.
- `control_plane_consume_image_command_preserves_boot_profile_v1_in_active_lease_snapshot` passed.
- `control_plane_external_client_interoperability_smoke_uses_xfreerdp` passed.
- During the live replay, the control-plane created a lease snapshot, replayed the sealed boot-profile argv, and launched QEMU from the imported Tiny11 image before the final full-suite confirmation.

# Unexpected Behavior

- The imported 7.8 GiB Tiny11 qcow2 is still fully hashed on control-plane startup, so the service can spend significant time validating before it binds its port.
- That startup cost did not block row 423 anymore because authenticated health and acquire no longer rehash the qcow2 on every request, and the live lane still reached QEMU launch plus `xfreerdp` auth within the documented readiness window.
- The startup-time full-hash cost is worth tracking separately, so AGENTS now includes a new follow-up row for deciding whether that cost should remain on the boot path.
