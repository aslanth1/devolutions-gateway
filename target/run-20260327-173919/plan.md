# Hypothesis

Sealing the manually verified Tiny11 boot profile into the trusted-image contract and replaying it through the control-plane launch path should remove the old qcow2-only ambiguity.
If live auth still fails, the next blocker should be an explicit runtime assumption outside the sealed boot profile rather than a hidden firmware or launch-shape gap.

# Steps

1. Reuse the prior research memory from `target/*/insights.md` to avoid the known dead ends.
2. Run the required three-agent council and pick the most feasible plan.
3. Add a minimal allowlisted `boot_profile_v1` to the trusted-image import contract.
4. Thread `boot_profile_v1` through trusted-image loading, QEMU launch planning, and lease-local vars seeding.
5. Add unit and integration coverage that proves the imported boot profile reaches the active lease snapshot.
6. Build a fresh run-local live-proof store from the previously validated imported Tiny11 qcow2 plus the preserved manual-good firmware and vars inputs.
7. Attempt a real `xfreerdp +auth-only` interoperability replay against the imported sealed-profile store.
8. Update `AGENTS.md` honestly, then record the run.

# Assumptions

- The manually verified Tiny11 launch profile from the prior differential run was accurate: AHCI plus IDE disk, `e1000`, `-rtc base=localtime`, preserved OVMF code, and preserved writable vars.
- The preserved manual-good vars file remained usable as a sealed seed input for a control-plane replay.
- The workstation-local `/usr/bin/qemu-system-x86_64`, `/usr/bin/xfreerdp`, and `/dev/kvm` were sufficient to run the live replay without inventing a new harness.
