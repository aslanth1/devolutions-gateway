# BS-32 Plan

## Hypothesis

The next highest-signal open task is `BS-32`: add one repeatable post-run check that can classify a session recording artifact as `visible_frame`, `all_black`, or `sparse_pixels`.
If the reducer runs only after teardown and only against a real `recording-0.webm`, it will close the artifact-visibility gap without destabilizing playback bootstrap.

## Steps

1. Fix the new visibility-summary writer so it does not create per-session recording directories before the proxy owns them.
2. Keep the council-selected Chrome-backed artifact probe and wire its result into `black-screen-evidence.json` plus a session-local summary file.
3. Re-run a fresh one-session `BS-32` manual-lab proof with a real browser attached to the live session page.
4. Tear the run down, let teardown repersist evidence, and confirm the session received a non-placeholder visibility verdict.
5. If the verdict is `visible_frame`, `all_black`, or `sparse_pixels`, check off `BS-32`, write the run artifacts, and commit a save point.

## Assumptions

- A Chrome-family browser is available locally for both the live player attach and the post-run artifact probe.
- A one-session control run is still the cheapest truthful way to produce a usable `recording-0.webm`.
- The existing `black-screen-evidence.json` flow remains the canonical place to store the new verdict.
- Guacd's explicit graphics-policy pattern is a useful design cue, but not the direct implementation path for this tranche.
