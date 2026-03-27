# Plan

## Hypothesis

Row `706` can be advanced honestly on this workstation only by fail-closing the evidence path around a validated Tiny11-derived interop store.
If live Tiny11-backed `lab-e2e` inputs are still missing, the correct outcome is stronger guardrails plus an explicit blocker, not a false completion.

## Prior Memory Summary

- What worked: reuse the existing consume-image, gold-image acceptance, repeatability, external-client interop, and digest-mismatch seams instead of inventing a new lane.
- What worked: add small focused Rust helpers and tests, then tie docs and AGENTS progress to those exact proof points.
- What failed: skipped `lab-e2e` runs, missing `DGW_HONEYPOT_INTEROP_*` inputs, and generic Windows 11 labs do not count as Tiny11 runtime evidence.
- Dead ends to avoid: do not treat env presence as proof, do not use non-Tiny11 Win11 labs as substitute evidence, and do not duplicate rows already completed in `HEAD`.
- Promising reuse: shared attestation and store-root binding across the existing acceptance, repeatability, and `xfreerdp` interop lanes.

## Winning Council Plan

1. Add contract-tier helpers that validate the configured interop manifest store and bind lease-time `attestation_ref` plus `base_image_path` back to that validated store.
2. Reuse those helpers inside the existing gold-image acceptance and external-client interop `lab-e2e` lanes so future row `706` evidence is store-bound and fail-closed.
3. Add focused contract-tier tests for the positive binding path and negative escaped or unattested path.
4. Update `docs/honeypot/testing.md` so row `706` explicitly requires non-skipped Tiny11-backed evidence plus the new store-binding checks.
5. Keep `AGENTS.md:706` unchecked unless a real Tiny11-derived interop store and live credentials are present and exercised.

## Assumptions

- The existing `lab-e2e` gold-image and interop lanes are the right long-term anchors for row `706`.
- This workstation still lacks a prepared Tiny11-derived interop store plus `DGW_HONEYPOT_INTEROP_*` inputs.
- Contract-tier hardening is still worthwhile because it prevents future false positives.
