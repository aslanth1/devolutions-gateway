# What Was Actually Done

1. Read prior `target/*/insights.md` artifacts and distilled the prior wins, failures, dead ends, and reuse points into the current run plan.
2. Ran a three-agent council with `gpt-5.3-codex` at high reasoning effort.
3. Collected the winning plan from the tie-break: validate the imported qcow2 against a manual-good baseline, then compare it to stripped control-plane-style launch variants.
4. Created fresh per-variant overlays under `target/run-20260327-165747/artifacts/diff/`.
5. Revalidated the imported qcow2 with the preserved manual-good launch profile.
6. Replayed the imported qcow2 with a control-plane-style launch profile that matched the current `honeypot/control-plane/src/qemu.rs` shape.
7. Replayed the same stripped launch profile again with preserved OVMF code and writable vars restored.
8. Cleaned up the temporary QEMU processes after the experiment.

# Commands And Actions Taken

## Inputs And Artifacts

- `sha256sum target/run-20260327-161429/artifacts/import/images/sha256-ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f.qcow2 /usr/share/OVMF/OVMF_CODE_4M.fd target/run-20260327-165747/artifacts/diff/c-manual/OVMF_VARS.fd`
- `qemu-img create -f qcow2 -b ... -F qcow2 target/run-20260327-165747/artifacts/diff/<variant>/overlay.qcow2`

## Manual-Good Baseline

- Launched `row414-manual-baseline` with:
  - preserved OVMF code and writable vars
  - AHCI plus IDE disk
  - `e1000`
  - `-rtc base=localtime`
  - forwarded `127.0.0.1:33941 -> guest:3389`
- Probed:
  - `xfreerdp /v:127.0.0.1:33941 /u:jf /p:ChangeMe123! /auth-only /cert:ignore`
  - `xfreerdp /v:127.0.0.1:33941 /u:jf /p:ChangeMe123! /auth-only /cert:ignore /sec:nla`
  - `xfreerdp /v:127.0.0.1:33941 /u:jf /p:ChangeMe123! /auth-only /cert:ignore /sec:tls`

## Control-Plane-Style Replay

- Read the effective launch shape from `honeypot/control-plane/src/qemu.rs`.
- Launched `row414-current-like` with:
  - no pflash firmware inputs
  - `virtio-blk-pci`
  - `virtio-net-pci`
  - `-nodefaults`
  - `-no-user-config`
  - QMP and QGA sockets
  - forwarded `127.0.0.1:33942 -> guest:3389`
- Probed the same three `xfreerdp /auth-only` modes.

## Control-Plane-Style Replay With Preserved OVMF Inputs

- Launched `row414-ovmf-reused` with:
  - the same stripped launch shape as `row414-current-like`
  - `-drive if=pflash,format=raw,readonly=on,file=/usr/share/OVMF/OVMF_CODE_4M.fd`
  - `-drive if=pflash,format=raw,file=target/run-20260327-165747/artifacts/diff/b2-ovmf-reused/OVMF_VARS.fd`
  - forwarded `127.0.0.1:33943 -> guest:3389`
- Probed the same three `xfreerdp /auth-only` modes.
- Verified after reset that QEMU was still running, the RDP port reopened, and the QGA socket still existed.

# Deviations From Plan

- I did not expand to the fresh-vars variant in this run.
The reused-vars replay already failed in the same way as qcow2-only, so the immediate result was no longer a simple "missing OVMF files" story.
- I did not patch the runtime code in the same turn.
This run was used to narrow the contract gap honestly before changing the control-plane launch path or import contract.
