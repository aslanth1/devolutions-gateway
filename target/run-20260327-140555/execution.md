# What Was Actually Done

## Memory ingest

I read recent `target/*/insights.md` artifacts and reused the consistent lessons:

- what worked: fail-closed gates, single-authority proof, explicit host-fact capture
- what failed: generic Win11 labs treated as Tiny11, stale skipped evidence, path mistakes, host-specific theater
- repeated dead ends to avoid: inferring provenance from `kvm-win11`, treating local key notes as attestation, inventing second authorities
- promising reuse: row-`706` style provenance discipline, bounded preflight gates, exact host-state recording

## Council

I used three sub-agents with `model="gpt-5.3-codex"` and `reasoning_effort="high"`:

- `Sagan`
- `Avicenna`
- `Euler`

They completed all required council phases.
All three converged on the same next lane.
Seat A won the evidence-based vote `2-1` because it most cleanly separated operational proof from provenance proof and required explicit attestation-binding fields for row `405`.

## Operational gate

### Preflight

- Verified no running QEMU guests.
- Verified `win11-base` exists in `/home/jf/research/ned/labs/windows/kvm-win11/snapshots`.

### First clone and first boot path

- Created `tiny11-prep-20260327-140555` under `/home/jf/src/devolutions-gateway/target/windows-prep-state`.
- Recorded `source_snapshot=win11-base`.
- First headless boot attempt failed before guest startup because the repo-local UNIX socket path exceeded the 108-byte kernel limit.

### Adjusted clone root

- Switched to shorter state root `/home/jf/src/devolutions-gateway/target/w11`.
- Created clone `t11p-140555`.
- Verified clone files existed:
  - `windows11.qcow2`
  - `OVMF_VARS.fd`
  - `source_snapshot.txt`
  - `created_at.txt`
- Booted the clone headless under QEMU.
- Captured pre-transform readiness through QGA:
  - `guest-ping` succeeded
  - `guest-get-host-name` returned `W-`
  - `guest-get-osinfo` reported Windows 11 client x86_64

## Provenance gate

### Source discovery

- Confirmed no approved Tiny11 scripts existed locally before this run.
- Located the official upstream source at `https://github.com/ntdevlabs/tiny11builder`.
- Captured upstream head commit `00e7d8a151a39ccffccab4a267bb81fb3756a01d`.
- Captured local SHA-256 values:
  - `tiny11maker.ps1`: `7a7baffa75742d9ae9512936d72887931c8bc2a91ac16ccd451a8869752b6f5e`
  - `tiny11Coremaker.ps1`: `16b921f930a92b31927806a06a7af823f700eeb2d57aff66b4074a85b0dbc19b`
  - `autounattend.xml`: `ed9837ab4a19c812d28e20f5278ca5bb25815a6a01d1caddbce157be5d519dba`
- Confirmed the local official Windows 11 ISO exists at `/home/jf/ISOs/Win11_25H2_English_x64.iso`.
- Captured ISO SHA-256 `d141f6030fed50f75e2b03e1eb2e53646c4b21e5386047cb860af5223f102a32`.

## Row 405 runtime attempts

### Attempt 1: shared `tools-media` plus direct ISO

- Staged Tiny11 scripts into `/home/jf/research/ned/labs/windows/kvm-win11/tools-media/tiny11builder`.
- Attached the official ISO directly as a QEMU CD-ROM.
- Verified inside the guest that:
  - `D:` was the QEMU `vvfat` tools drive
  - `E:` was the mounted Windows 11 ISO
  - ISO image index `6` is `Windows 11 Pro`
- Started the upstream script from `D:\tiny11builder`.
- The transcript proved real progress through:
  - image copy
  - install image mount
- The run then crashed at the QEMU layer with:
  - `cluster 0 used more than once`
  - `qemu-system-x86_64: block/vvfat.c:2432: commit_direntries: Assertion 'mapping' failed.`
- No `tiny11.iso` was produced.

### Attempt 2: upload-based workaround

- Created a fresh clone `t11u-141832` from `win11-base`.
- Booted it headless under QEMU with the official ISO attached directly and no `vvfat` tools disk.
- Used QGA to create `C:\tiny11builder`.
- Uploaded:
  - `autounattend.xml`
  - `tiny11maker.ps1` as `C:\tiny11builder\t11.ps1`
  - `tiny11Coremaker.ps1` as `C:\tiny11builder\t11c.ps1`
- Started the upstream script with:
  - execution policy bypass
  - preseeded `$index=6`
  - `-ISO E`
  - `-SCRATCH C`
- Observed that the guest created `C:\tiny11builder\tiny11_20260327_142046.log`.
- Confirmed the script progressed far beyond the mount phase.
  The transcript showed:
  - package removal
  - registry edits
  - unmount
  - cleanup
  - `Exporting image...`
- Confirmed `dism.exe` remained active with large working set and high CPU during the bounded observation window.
- Confirmed no `C:\tiny11builder\tiny11.iso` existed before the observation window ended.
- Stopped the disposable QEMU process cleanly from the host after bounding the run.

## Deviations From Plan

- The first repo-local prep root was too long for UNIX socket paths, so I shortened the state root to `/home/jf/src/devolutions-gateway/target/w11`.
- The first transformation attempt exposed a real QEMU `vvfat` backend crash, so I changed strategy and uploaded the scripts onto the guest `C:` drive instead of writing through shared FAT.
- The second transformation attempt did not complete within the bounded observation window even though transcript and process evidence showed real progress.
