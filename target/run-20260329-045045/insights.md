# BS-34 Insights

## What Worked

- Reusing the existing startup/stabilize/steady browser windows gave a better sustain contract than inventing a fresh millisecond timer.
- Encoding the ready-path rule as a reducer plus `testsuite/tests` proof was enough to close `BS-34` without needing another live lab run.
- Guacd remained a useful design cue because it reinforces explicit capability policy over inferred behavior.

## What Failed

- The first implementation reached for a crate that is not already in the workspace.
- The later council-tool responses were less reliable than the earlier ones.

## What To Avoid Next Time

- Do not add a new dependency for enum-name formatting when `Debug` is enough.
- Do not overfit `BS-34` to raw websocket timing when the browser probe already provides a more stable multi-window signal.
- Do not jump to `BS-35` before the single-session ready-path contract is encoded and green.

## Promising Next Directions

- `BS-35`: reuse the new sustain reducer in a sanctioned three-slot proof.
- `BS-36`: the new reducer makes it easier to define green/amber/red run verdicts from existing evidence instead of inventing labels ad hoc.
