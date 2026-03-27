# Insights

## What Worked

- Reusing `load_honeypot_interop_store_evidence` kept Tiny11 provenance single-authority and avoided checklist drift.
- A typed gate with explicit blocker ordering made the row easy to test and document.
- Wiring one shared loader path into the lab-backed anchors was enough to cover the relevant run entrypoints without touching contract-tier behavior.

## What Failed

- The first full integration rerun produced one unrelated transient CLI startup failure, so a single full-suite pass was not enough evidence by itself.

## What To Avoid Next Time

- Do not add a second Tiny11 verifier or another ad hoc env-only skip path.
- Do not treat env presence alone as Tiny11 readiness.
- Do not hardcode `/srv/honeypot/images` as the only valid root when an explicit configured interop root is present.

## Promising Next Directions

- Add one explicit host-smoke or lab-e2e probe that exercises the shared gate under an active `DGW_HONEYPOT_LAB_E2E=1` tier manifest, so the entrypoint-level blocked path is covered without relying only on helper tests.
- If a stable local source bundle location becomes canonical, thread it into the gate remediation so the suggested `consume-image` command can be fully concrete.
