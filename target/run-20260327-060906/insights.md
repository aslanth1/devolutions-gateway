# Insights

## What Worked

- Reusing the existing trusted-image seam was enough to add a real consume flow without widening the control-plane contract.
- Atomic temp-file plus rename writes gave a clean way to avoid partial manifests and partial qcow2 visibility.
- The strongest proof for this row was not a docs note but an end-to-end import-to-acquire integration test.

## What Failed

- Canonicalizing the source image path before rejecting symlinks erased the evidence needed for the safety check.
- Treating row `393` as if it required live Tiny11 RDP proof would have blocked honest progress and mixed it with rows `396` and `706`.

## Dead Ends To Avoid

- Do not count skipped `lab-e2e` or generic Windows 11 runs as Tiny11 evidence.
- Do not import bundle images by trusting arbitrary absolute paths from source manifests.
- Do not expose a consume command that only writes metadata without proving lease-path compatibility.

## Promising Next Directions

- Use the new consume path as the handoff for a real Tiny11-derived interop image store.
- Close row `396` by producing live RDP-ready evidence from an imported Tiny11 image.
- Close row `706` by running the existing repeated acquire or recycle proofs against that same non-skipped Tiny11-backed store.
