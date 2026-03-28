## Hypothesis

The next honest task is not another no-op checklist closeout.
There is a real DF-07 policy-to-enforcement gap:
`docs/honeypot/release.md` requires `promotion-manifest.json` as the sole writer for `honeypot/docker/images.lock`, but the executable release-input path was only validating lockfile shape and compose consumption.

## Council Outcome

The 3-seat council completed all required phases.
Seat 3 won `2-1`.
It won because it closed the DF-07 gap with contract-tier enforcement that is feasible in the current repo:
add a checked-in promotion manifest, bind it to `images.lock current` entries in the existing release validator, add deterministic negative tests, and keep broader release-tooling or trust-root hardening as follow-on work.

## Memory Ingest Summary

- What worked:
  - fail-closed evidence passes and critic rounds still prevent rubber-stamp work
  - broad AGENTS discovery and targeted seam checks remain useful
  - repeated no-op turns only stay justified when they add fresh evidence
- What failed:
  - there was still no unchecked AGENTS row
- Dead ends to avoid:
  - inventing backlog
  - broad re-audits that only rediscover known green or blocked coverage
  - building overly large release tooling when a smaller always-on contract seam exists
- Promising techniques to reuse:
  - extend existing validators instead of adding a second enforcement path
  - prefer deterministic contract-tier tests before tier-gated smoke or lab work

## Steps

1. Verify the suspected DF-07 gap in current docs, tests, and lockfile state.
2. Run the required council phases and choose a plan.
3. Add `honeypot/docker/promotion-manifest.json`.
4. Extend `testsuite/src/honeypot_release.rs` with typed promotion-manifest validation and lockfile binding.
5. Update the on-disk release-input validation path to require the manifest.
6. Add focused negative tests in `testsuite/tests/honeypot_release.rs`.
7. Update release and testing docs to describe the executable contract accurately.
8. Validate with targeted tests, formatting, clippy, and the full integration binary.

## Assumptions

- The checked-in contract-tier path can require a non-empty `signature_ref` and manifest-lock binding even before protected-branch cryptographic verification is fully implemented.
- Existing unrelated integration-test flakes are not introduced by this DF-07 change and can be recorded separately if they recur.
