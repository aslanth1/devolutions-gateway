# What Worked

- Shortening the prep state root under `target/w11` avoided the 108-byte UNIX socket limit and made repo-local clone boot practical.
- QGA is sufficient to prove pre-transform readiness for the cloned guest.
- The official Tiny11 upstream source can be pinned cleanly by commit and file SHA-256.
- Uploading the Tiny11 scripts onto the guest `C:` drive avoids the QEMU `vvfat` crash that occurs when the guest writes through the shared FAT tools disk.
- Transcript tail reads through QGA are a reliable way to see deep script progress even when full file download fails.

# What Failed

- The first prep root `/home/jf/src/devolutions-gateway/target/windows-prep-state` was too long for QEMU monitor and QGA UNIX sockets.
- Running the Tiny11 transform from the shared `vvfat` tools disk caused a QEMU assertion and aborted the attempt.
- The bounded observation window was not long enough to reach a completed `tiny11.iso` from the upload-based workaround.

# What To Avoid Next Time

- Do not use long repo-local state roots for active QEMU clones on this host.
- Do not rely on QEMU `vvfat` as a writable workspace for long-running Windows image transforms.
- Do not assume transcript file size changes immediately; tail the transcript content and inspect guest processes instead.

# Promising Next Directions

- Keep using the upload-based workaround on a short-path disposable clone.
- Patch the automation wrapper around upstream `tiny11maker.ps1` by pre-seeding the image index and by handling the final `Read-Host "Press Enter to continue"` prompt after ISO creation.
- Once `tiny11.iso` exists, download or otherwise extract it from the guest and record it as the transformed output for row `405`.
