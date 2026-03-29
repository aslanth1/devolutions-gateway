# BS-33 Insights

## What Worked

- Direct attachment to the iframe player URL produced trustworthy browser telemetry.
- Multi-window browser sampling gave enough structure to distinguish startup insufficiency from steady black playback.
- Extending the artifact probe timeout to cover metadata wait, seek settle, and the full sample window removed the false parse failures.
- Explicit reducer verdicts made it safe to close the row without overstating confidence.

## What Failed

- Attaching only to the outer session page was too indirect because the iframe is lazy-loaded.
- A `sample_window + 2000ms` virtual-time budget was not enough for the aligned artifact probe.
- Session shell state alone was misleading: the focus page said `failed` while the iframe still exposed a usable player path.

## What To Avoid Next Time

- Do not accept DOM parse failures from the visibility probe without checking whether Chrome simply exited too early.
- Do not treat focus-page stream state as authoritative for player behavior.
- Do not collapse aligned-time results and whole-recording results into one verdict.

## Promising Next Directions

- `BS-34`: prove that a ready active session stays on the live path instead of collapsing immediately into fallback.
- Reuse the new browser-artifact alignment machinery for the historically weak third-slot proofs.
- Keep borrowing guacd's explicit-capability mindset: prefer named playback or graphics lanes over inferred behavior.
