# Plan

## Hypothesis

The best feasible next task is [AGENTS.md](/home/jf/src/devolutions-gateway/AGENTS.md#L393): build or consume the Tiny11-derived Windows 11 gold image flow without Bash or Python wrappers.

A Rust-native consume flow can satisfy that row honestly even without a local Tiny11 lab by importing an attested image bundle into the control-plane trusted image store, validating confinement and digest binding, and proving the imported artifact is immediately usable by the lease path.

## Steps

1. Reuse the existing `trusted_images()` seam instead of inventing a parallel image-store contract.
2. Add a Rust-native image consume path that imports a bundle manifest plus qcow2 into the trusted store with atomic writes.
3. Reject path traversal, symlink escape, duplicate conflicting identities, and partial-import visibility.
4. Expose the consume flow through the control-plane binary so it is usable without Bash or Python wrappers.
5. Add unit and integration tests that prove the imported image is accepted by health checks and the acquire path.
6. Update honeypot docs and AGENTS progress based on the validated evidence.

## Assumptions

- The existing trusted-image manifest format is already the canonical consume target.
- Row `393` can be satisfied by a Rust-native consume flow even if rows `396` and `706` still require live Tiny11 and RDP evidence.
- The imported bundle can be represented as a manifest plus bundle-local qcow2 without changing current attestation fields.
