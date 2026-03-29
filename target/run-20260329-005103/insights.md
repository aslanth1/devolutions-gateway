# Insights

## What Worked

- Re-running a fresh same-day control pair was enough to separate stale artifact confusion from real contract drift.
- The repo-owned `ironrdp-no-rdpgfx` lane is now a real proof lane, not a guessed flag experiment.
- Guacd was a useful reference because it makes graphics capability explicit; that reinforces the current direction of using named lanes instead of ambiguous client flags.

## What Failed

- A bounded `BS-25` graphics-on spike could not be justified with the current pinned IronRDP surface.
- There is still no small in-tree `RdpgfxClient`-style hook to turn on as a one-tranche experiment.

## What To Avoid Next Time

- Do not reopen `BS-26` drift debates without a fresh same-day rerun.
- Do not fake an `ironrdp-gfx` lane by inferring graphics capability from unrelated crates or generic image-processing code.
- Do not treat `ironrdp-graphics` primitives alone as proof that the current client path can negotiate RDPEGFX.

## Promising Next Directions

- Keep `BS-25` open until there is a real explicit graphics-on client surface to attach or import.
- If driver churn resumes, keep guacd’s model in mind: graphics should be a first-class capability policy, not a side effect.
- The latest evidence still points more at the graphics-on proxy or player seam than at the no-gfx lane; the control path carries RDPEGFX while the no-gfx lane truthfully does not.
