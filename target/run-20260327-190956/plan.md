# Hypothesis

A startup-validated trusted-image catalog can remove multi-gigabyte qcow2 hashing from authenticated `/api/v1/health` and `/api/v1/vm/acquire` without weakening fail-closed behavior for imported Tiny11 stores.

# Memory Ingest

What worked:
- sealing the manual-good Tiny11 boot profile into `boot_profile_v1`
- replaying the sealed firmware and vars inputs through the trusted-image contract
- using the existing external-client interop smoke as the strongest auth proof

What failed:
- request-path `trusted_images()` rehashed the imported qcow2 on authenticated health and acquire
- earlier live lanes stalled before QEMU launch, so auth results were not meaningful

Repeated dead ends to avoid:
- reopening qcow2-only import assumptions
- blaming guest auth before a control-plane launch actually happens
- adding broad arbitrary QEMU-argv escape hatches

Promising techniques to reuse:
- preserve the sealed boot profile contract
- keep fail-closed behavior on image-store drift
- validate the lane with the real `xfreerdp` interop smoke instead of synthetic-only checks

# Council

Seats:
- Euler
- Hubble
- Archimedes

Winning plan:
- Seat 3 won `2-1`
- keep strict startup validation
- add a trusted-image catalog for hot-path reads
- use cheap manifest and file-metadata drift checks on authenticated health and acquire
- fail closed on drift instead of synchronously rehashing large qcow2 images in request handlers
- accept restart or a future explicit refresh path as the recovery contract for now

Why it won:
- smallest safe delta for this repo
- directly addressed row 423 without adding a larger refresh API contract in the same turn
- easiest to validate with the existing imported Tiny11 interop lane

# Steps

1. Implement a `TrustedImageCatalog` in `honeypot/control-plane/src/image.rs` that loads via existing strict validation once at startup and stores manifest plus file drift stamps.
2. Route authenticated health inspection and acquire through the catalog instead of direct `trusted_images()` calls.
3. Keep fail-closed behavior when the trusted-image store drifts after startup.
4. Add unit coverage for the cached steady-state path and the fail-closed drift path.
5. Re-run Rust verification and the imported Tiny11 interop lane.
6. Update AGENTS progress, capture results, and save a commit.

# Assumptions

- startup-time full validation is acceptable for this turn even if it is still expensive on a 7.8 GiB imported store
- request-path latency is the blocker row 423 is explicitly about
- post-start store drift may fail closed until restart without breaking the current checklist goal
