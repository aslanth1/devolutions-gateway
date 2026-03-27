# Success Or Failure

- row `399`: success
- row `402`: success
- row `405`: not complete this turn
- row `747`: still open

# Observable Signals

## Row 399 success signals

- `win11-base` clone `t11p-140555` was created under `/home/jf/src/devolutions-gateway/target/w11/instances/`.
- The clone has its own overlay disk and copied firmware vars.
- `source_snapshot.txt` records `win11-base`.

## Row 402 success signals

- Headless QEMU boot succeeded for the prep clone.
- `guest-ping` succeeded.
- `guest-get-host-name` returned `W-`.
- `guest-get-osinfo` reported a Windows 11 client guest on x86_64.

## Row 405 progress signals

- Official upstream Tiny11 source identified and hashed.
- Official Windows 11 ISO identified and hashed.
- Guest-side transcript grew to `8426` bytes.
- Transcript reached `Exporting image...`.
- `dism.exe` remained active with high CPU and multi-gigabyte working set.

## Row 405 blocker signals

- Attempt 1 failed due QEMU `vvfat` assertion while the guest wrote through the shared tools drive.
- Attempt 2 avoided `vvfat` and progressed deep into the pipeline, but no host-visible or guest-visible `tiny11.iso` existed before the bounded observation window ended.
- The upstream script also contains a final `Read-Host "Press Enter to continue"` after ISO creation, so even a successful unattended run still needs an explicit final-enter bypass or synthetic input for clean automation.

# Unexpected Behavior

- The first clone boot failed because the initial repo-local socket path was too long for UNIX domain sockets.
- Uploading `tiny11maker.ps1` to `C:\tiny11builder\tiny11maker.ps1` failed through QGA, but uploading the same file as the shorter name `C:\tiny11builder\t11.ps1` succeeded.
- The transcript file on `C:` stayed zero bytes for several minutes and only became useful later, so transcript presence alone was not an immediate progress indicator.
