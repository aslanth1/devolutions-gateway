# What Worked

- A narrow allowlisted `boot_profile_v1` was enough to capture the meaningful launch-shape inputs from the manual-good Tiny11 lane without opening arbitrary QEMU argv injection.
- Importing firmware and vars artifacts by digest into the trusted-image store worked cleanly.
- Copying the vars seed into a lease-local `OVMF_VARS.fd` gave the runtime an explicit writable NVRAM path instead of reusing shared state in place.
- The process-backed integration proof is a reliable regression guard for the contract-to-launch path.

# What Failed

- The live imported-store replay did not reach guest auth, so rows 411 and 420 are still not proven.
- Authenticated health and acquire are currently too expensive for large imported Tiny11 images because they re-enter full trusted-image validation and effectively rehash the multi-gigabyte qcow2 on the request path.
- The current `cargo run ... consume-image` foreground behavior was not a trustworthy completion signal even after the store contents were already finalized.

# What To Avoid Next Time

- Do not rerun the full live sealed-profile auth lane until the trusted-image validation path is bounded or cached.
- Do not treat an authenticated health timeout on a large imported store as a guest boot or RDP failure without checking whether QEMU ever launched.
- Do not assume the remaining gap is still firmware-related now that the boot profile is sealed and propagated deterministically in tests.

# Promising Next Directions

- Cache or otherwise bound trusted-image validation for imported qcow2 artifacts so authenticated health and acquire can reach QEMU launch promptly.
- Re-run the live `xfreerdp` interoperability smoke against the same run-local sealed-profile store after the validation-latency fix.
- If the live replay then reaches auth but still fails, classify the remaining gap using the now-sealed launch profile rather than reopening the contract surface again.
