# BS-39 Insights

## What Worked

- The docs-policy harness was the right seam for this gate.
- One canonical blocker record in `decisions.md` was cleaner than splitting authority across architecture and research docs.
- Explicit field-style lines were easier to test than generic prose warnings.

## What Failed

- Backticks in a shell search pattern caused an avoidable quoting error.
- A soft prose-only gate would have been too easy to bypass.

## What To Avoid Next Time

- Do not spread blocker authority across multiple docs when one canonical record is enough.
- Do not let fallback-gate rules degrade into “mention the seam somewhere” wording.
- Do not use shell patterns with unescaped backticks when collecting final references.

## Promising Next Directions

- Reuse the docs-policy seam for `BS-40` if the runbook and artifact-order contract needs repo-level enforcement.
- Keep future black-screen guardrails explicit and single-sourced before any new runtime surface is opened.
