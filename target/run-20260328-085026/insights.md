## What Worked

- The council found a real policy-to-enforcement gap instead of defaulting to another no-op checklist closeout.
- Extending the existing release validator was the right seam; it avoided adding a second release-enforcement stack.
- Deterministic contract-tier negative tests gave immediate, high-signal proof that the new DF-07 invariant works.

## What Failed

- The full `integration_tests` binary remained flaky under whole-suite execution in this environment.
- This turn did not implement full cryptographic verification for `signature_ref`; it implemented manifest presence and lockfile binding first.

## What To Avoid Next Time

- Do not assume a clean targeted seam means the whole integration binary is stable.
- Do not jump straight to a broad release toolchain when a smaller always-on contract seam can close the highest-value gap first.
- Do not claim complete DF-07 closure until protected-branch or release-time signature or attestation verification is executable.

## Promising Next Directions

- Add stricter verification of the artifact referenced by `signature_ref` in protected-branch or release workflows without changing the single-manifest contract.
- Investigate and isolate the order-sensitive failures in the full `integration_tests` binary now that the DF-07 seam itself is covered.
