# Insights

## What Worked

- A shared strict runtime-proof helper closed the exact gap at the point where runtime-only proof anchors are invoked.
- Keeping `verify-row706` evidence-only preserved a single authority for row-706 validation.
- Explicit strict mode plus the sanctioned `lab-e2e` env contract produced a real positive proof run without changing baseline suite semantics.

## What Failed

- Treating a skipped `lab-e2e` acceptance anchor as meaningful proof remains invalid.
- Running `fmt --check` while `fmt` is still mutating files produces noisy false negatives.

## What To Avoid Next Time

- Do not add a second runtime-proof verifier or wrapper-only policy surface for the same constraint.
- Do not leave fresh partial row-706 directories behind after focused proof experiments.
- Do not infer runtime proof from an `ok` result unless the invocation contract proves the anchor actually ran.

## Promising Next Directions

- Reuse `DGW_HONEYPOT_RUNTIME_PROOF_STRICT=1` for future closure passes that need fail-closed runtime anchors.
- Apply the same shared helper to any future runtime-only proof anchors so the policy stays centralized.
