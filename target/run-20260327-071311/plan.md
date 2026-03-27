# Plan

## Hypothesis

Row `706` needs a machine-enforced evidence gate that reuses the existing canonical Tiny11 proof anchors.
If the row-`706` anchors emit structured fragments and one verifier rejects skipped, missing, malformed, or provenance-inconsistent fragments, the repo can fail closed on ordinary workstations while still being ready for honest live Tiny11 closure later.

## Prior Memory Summary

- What worked: reusing the existing consume-image, gold-image acceptance, repeatability, and `xfreerdp` interop seams.
- What worked: keeping skipped `lab-e2e` runs as non-evidence and adding small Rust helpers instead of new runtime services.
- What failed: this workstation still lacked `DGW_HONEYPOT_INTEROP_*` inputs and a prepared Tiny11-derived interop store for non-skipped row `706` proof.
- Dead ends to avoid: generic `win11` or `win11-canary` labs are not Tiny11 proof, and env presence alone is not provenance.
- Promising reuse: the new interop-store attestation and lease-binding checks were the right base for a row-`706` verifier.

## Winning Council Plan

1. Add a typed row-`706` fragment schema and verifier in `testsuite`.
2. Have the four canonical proof anchors emit pass-or-skip fragments under `target/row706/`.
3. Add synthetic verifier tests for complete, missing, skipped, malformed, and inconsistent evidence.
4. Update `docs/honeypot/testing.md` so row `706` completion requires verifier-grade evidence.
5. Keep `AGENTS.md:706` unchecked unless live non-skipped proof exists.

## Assumptions

- The existing four anchors remain the source of truth for row `706`.
- A verifier is more trustworthy than a new wrapper runner because it keeps the canonical tests authoritative.
- The current host will still fail closed with skipped live anchors under the contract tier.
