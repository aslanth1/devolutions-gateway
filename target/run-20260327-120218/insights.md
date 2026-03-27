# Insights

## What Worked

- Reusing the existing row-`706` run and manual-headed writer kept this turn tied to the single authoritative evidence system.
- Gate-0 provenance checks were enough to block dishonest manual execution before any guest boot or service bring-up.
- Replaying `runtime` and `finalize` against the blocked run gave a durable proof that the manual-headed lane still fails closed.

## What Failed

- The host still lacks an admissible Tiny11-derived attestation chain for the local Win11 lab assets.
- The local `win11-hellsd-gateway-base` snapshot name is not evidence by itself.
- Without a verified row-`706` run, Milestone 6a runtime rows remain uncloseable even though the manual-headed writer exists.

## What To Avoid Next Time

- Do not boot or record the generic `kvm-win11` lab as if it were Tiny11 proof.
- Do not treat `WINDOWS11-LICENSE.md` or the repo-local key file as provenance.
- Do not try to bypass the row-`706` verifier by writing manual-headed runtime anchors first.

## Promising Next Directions

- Import or build a real Tiny11-derived base image into the canonical trusted image store through the documented Rust consume path.
- Re-run the row-`706` positive anchors with explicit `DGW_HONEYPOT_LAB_E2E`, `DGW_HONEYPOT_TIER_GATE`, and `DGW_HONEYPOT_INTEROP_*` inputs on a host with that attested store.
- Once row `706` verifies, use the sanctioned manual-headed writer to capture `manual_stack_startup_shutdown`, Tiny11 RDP proof, headed QEMU plus Chrome observation, bounded interaction, and video metadata under the same `run_id`.
