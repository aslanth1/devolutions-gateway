# Insights

## What Worked

- Reusing the existing acceptance and interop seams gave a precise place to add fail-closed attestation checks.
- Contract-tier negative tests for path escape and unattested binding are cheap, durable guardrails for future lab work.
- Tightening the docs at the same time kept the row `706` blocker honest and explicit.

## What Failed

- This workstation still did not provide the explicit Tiny11-derived interop store and credential inputs needed for a non-skipped row `706` proof.
- Generic Windows lab assets were not good enough to substitute for Tiny11 lineage.

## Avoid Next Time

- Do not count skipped `lab-e2e` runs as closure evidence.
- Do not treat env presence alone as provenance.
- Do not use generic `win11` or `win11-canary` labs as Tiny11 proof unless they are imported through the validated consume path.

## Promising Next Directions

- Provision a real Tiny11-derived interop image store plus `DGW_HONEYPOT_INTEROP_*` inputs, then rerun the acceptance, repeatability, and external-client interop anchors without skip.
- Add an explicit runtime assertion that the accepted interop manifest set matches the consume-image provenance bundle used to populate the store.
