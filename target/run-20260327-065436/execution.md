# Execution

## What Was Done

1. Read prior `target/*/insights.md` files and summarized the repeatable wins, blockers, and dead ends.
2. Ran the 3-seat council across idea generation, adversarial review, refinement, detailed planning, and evidence-based voting.
3. Confirmed the local host had `xfreerdp`, `qemu-system-x86_64`, and `/dev/kvm`, but no configured `DGW_HONEYPOT_*` interop env and no clearly Tiny11-labeled interop store.
4. Reviewed the local Windows lab skill and existing lab roots, which showed generic `win11` and `win11-canary` assets rather than trustworthy Tiny11 evidence.
5. Added interop-store evidence loading and attestation-binding helpers in `testsuite/src/honeypot_control_plane.rs`.
6. Wired those helpers into the existing external-client interop and gold-image acceptance lanes in `testsuite/tests/honeypot_control_plane.rs`.
7. Added focused contract-tier tests for the valid binding, manifest path escape rejection, and unattested base-image rejection paths.
8. Updated `docs/honeypot/testing.md` so row `706` now explicitly requires the validated store-binding proof and still remains blocked without non-skipped Tiny11-backed evidence.

## Commands And Actions

- `env | rg '^DGW_HONEYPOT_'`
- `command -v xfreerdp`
- `command -v qemu-system-x86_64`
- `test -e /dev/kvm`
- `rg -n "Tiny11|tiny11|win11" /home/jf/research/ned/labs/windows`
- `cargo test -p testsuite --test integration_tests control_plane_interop_store_evidence_ -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_ -- --nocapture`
- `cargo test -p testsuite --test integration_tests control_plane_external_client_interoperability_smoke_uses_xfreerdp -- --nocapture`
- `cargo +nightly fmt --all`
- `cargo +nightly fmt --all --check`
- `cargo clippy --workspace --tests -- -D warnings`
- `cargo test -p testsuite --test integration_tests`

## Deviations From Plan

- The winning plan originally targeted row `699`, but that row was already complete in `HEAD`, so the only honest accumulated work was the narrower row `706` hardening path.
- Live Tiny11-backed `lab-e2e` closure was not attempted because the prerequisite interop env and trustworthy store evidence were still absent.
