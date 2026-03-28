# Overall Result

Partial success.
This run did not close the auth gap, but it did rule out the imported qcow2 itself as the primary culprit and narrowed the remaining issue to the launch profile used by the control-plane-style path.

# Successes

- The imported Tiny11 qcow2 remained usable.
- The preserved manual-good launch profile still accepted the approved credentials through default negotiation and forced NLA.
- The manual-good TLS-only probe still failed with `HYBRID_REQUIRED_BY_SERVER`, which is consistent with an NLA-capable guest rather than a dead image.
- Both stripped launch variants booted far enough to open the forwarded RDP port.

# Failures

- The control-plane-style qcow2-only replay did not preserve the manual-good auth behavior.
- Restoring the preserved OVMF code and writable vars to the same stripped launch profile also did not preserve the manual-good auth behavior.
- Row 411 remains open because the sanctioned `consume-image` plus control-plane-style lease path still does not accept the same credentials that succeed in the manual-good lane.
- Row 414 remains open under its current pass condition because the runtime and trusted-image contract have not yet been extended to carry the full sealed boot profile required for proof.
- Row 753 remains open because the control plane still cannot yet produce the required imported Tiny11 lease with verified RDP success and recycle evidence.

# Observable Signals

## Pinned Inputs

- Imported qcow2 SHA-256: `ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f`
- OVMF code SHA-256: `4f3197348f45f06d078c79836fc5041a983e335868d00568f037a2c2169d2a08`
- Reused manual-good vars SHA-256: `8338dc28a6665c2454d7750d1b512615d4e399170d7c3ae840b361958b026c91`

## Manual-Good Baseline

- `xfreerdp` default auth-only: success
- `xfreerdp` forced NLA auth-only: success
- `xfreerdp` forced TLS auth-only: `HYBRID_REQUIRED_BY_SERVER`

## Control-Plane-Style Replay

- Forwarded port opened on `127.0.0.1:33942`
- Default, forced NLA, and forced TLS all ended with `BIO_read returned a system error 104: Connection reset by peer`

## Control-Plane-Style Replay With Reused OVMF Inputs

- Forwarded port opened on `127.0.0.1:33943`
- Default, forced NLA, and forced TLS again ended with `BIO_read returned a system error 104: Connection reset by peer`
- QEMU stayed alive after the reset
- The forwarded port reopened after the failed auth attempt
- The QGA socket remained present after the failed auth attempt

# Unexpected Behavior

- Adding preserved OVMF code and writable vars back into the stripped launch did not restore the manual-good auth behavior.
- The failing stripped launches did not look like full guest crashes.
They stayed alive and kept reopening the forwarded RDP port after the reset.

# Conclusion

The imported Tiny11 qcow2 is not enough to reproduce the manual-good auth lane.
The remaining difference is a broader launch-profile contract issue, not a simple "bad qcow2" problem and not a simple "missing OVMF files only" problem.
The next honest step is to seal and replay the full manual-good boot profile through the trusted-image contract and control-plane runtime.
