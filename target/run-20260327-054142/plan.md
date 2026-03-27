# Hypothesis

Row `AGENTS.md:706` can be completed by strengthening the existing Rust `lab-e2e` gold-image acceptance lane so it proves one Tiny11-derived image-backed VM can boot, accept RDP, recycle cleanly, and do so repeatably.

## Steps

1. Ingest any prior `target/*/insights.md` artifacts and reuse only proven techniques.
2. Run a 3-seat council to choose the best remaining task and refine a concrete execution plan.
3. Audit the existing gold-image acceptance and external-client interop tests instead of inventing a second lane.
4. Add a repeated acquire, RDP, recycle, and cleanup proof to the existing `lab-e2e` path.
5. Update the test doc so row `706` has explicit positive, repeatability, and negative-control anchors.
6. Validate locally.
7. Check off only the AGENTS rows the repo can now prove truthfully.

## Assumptions

- The repo already contains the right control-plane and interop seams for row `706`.
- A truthful completion of row `706` requires a non-skipped run against a prepared Tiny11-derived interop image store.
- If the local workstation lacks that image store, the correct outcome is to strengthen the proof lane and record the blocker rather than falsely check the row off.
