# What Was Actually Done

- Read the latest prior `target/*/insights.md` artifacts and summarized the stable lessons before proposing work.
- Spawned a 3-seat council with `gpt-5.3-codex` at `high` reasoning, ran idea generation, critic review, refinement, detailed planning, and voting, and selected the single-process authoritative row-`706` proof plan.
- Verified the sealed Tiny11 interop prerequisites on disk and launched one authoritative `cargo test -p testsuite --test integration_tests control_plane_ -- --nocapture --test-threads=1` run with the `DGW_HONEYPOT_INTEROP_*` environment wired to the sealed import from `target/run-20260327-173919/artifacts/live-proof/import/images`.
- Let that one process produce the live row-`706` envelope under `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/`, then validated that the manifest is `complete` and that the positive anchors plus the negative control all passed with shared store-binding provenance on the positive path.
- Measured startup-time trusted-image attestation twice against the same sealed import with a standalone temp-script harness that booted `target/x86_64-unknown-linux-gnu/debug/honeypot-control-plane` and waited for authenticated `/api/v1/health` readiness.
- Updated `docs/honeypot/testing.md` and `AGENTS.md` to record the accepted startup budget and the authoritative row-`706` run.

# Commands / Actions Taken

- `rg -n "^- \\[ \\]" AGENTS.md`
- `rg -n "write_honeypot_control_plane_config|CONTROL_PLANE_SCOPE_TOKEN|health" testsuite/src/honeypot_control_plane.rs testsuite/tests/honeypot_control_plane.rs honeypot/control-plane/src`
- `DGW_HONEYPOT_LAB_E2E=1 ... cargo test -p testsuite --test integration_tests control_plane_ -- --nocapture --test-threads=1`
- `ps`, `ss`, and `lsof` checks during the live row-`706` run to confirm when the control plane was still reading the imported qcow2 before QEMU launch.
- `/tmp/measure_cp_startup.sh` against the sealed imported store on ports `39091` and `39092`.

# Deviations From Plan

- An earlier ad hoc shell measurement attempt had quoting drift and stale overlapping harnesses, so it was discarded and replaced with one clean temp-script measurement.
- The filtered `control_plane_` cargo run was interrupted after the row-`706` envelope was complete because it had moved into unrelated release and docker checks that were not part of the winning proof plan.
