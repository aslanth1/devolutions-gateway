# Hypothesis

The imported Tiny11 qcow2 is not itself bad.
The remaining auth gap is caused by a launch-profile mismatch between the manually verified Tiny11 boot path and the control-plane-style imported lease path.
The missing or changed inputs may include firmware, writable NVRAM, disk interface, NIC model, RTC baseline, or another boot-critical launch-shape detail.

# Memory Ingest

## What Worked

- Fail-closed `consume-image` import and provenance checks.
- Short path roots and run-local artifact stores.
- Pinned Tiny11 script provenance.
- Manual-good Tiny11 boot path with approved RDP credentials.
- The row-706 startup-timeout fix narrowed prior failures down to auth-time behavior.

## What Failed

- Treating the imported qcow2 as self-contained.
- Repeating row-706 without isolating the launch delta.
- Assuming the manual-good lane and the control-plane lease lane were equivalent once the qcow2 digest matched.

## Repeated Dead Ends To Avoid

- Dirty prep clones.
- Writable `vvfat`.
- Reusing generic Win11 evidence as Tiny11 proof.
- Blindly retrying the full lease path before classifying the launch mismatch.

## Promising Techniques To Reuse

- The preserved manual-good Tiny11 verification lane.
- Fresh overlays per launch variant.
- Direct `xfreerdp /auth-only` probes in default, forced NLA, and forced TLS modes.
- Effective runtime capture from the live QEMU process rather than relying on assumptions.

# Winning Plan

The council produced a `1-1-1` vote tie.
I broke the tie in favor of the smallest evidence-first parity matrix that could execute on this host today.

## Steps

1. Revalidate the imported Tiny11 qcow2 with the previously successful manual-good launch profile.
2. Replay the imported qcow2 with the current control-plane-style launch shape and classify the auth outcome.
3. Replay the same stripped launch shape with the preserved OVMF code and writable vars restored.
4. Use the three outcomes to determine whether the remaining gap tracks a bad qcow2, missing firmware or NVRAM, or a broader launch-profile mismatch.
5. Update `AGENTS.md`, write the run bundle, and keep only the tasks this run actually unblocked.

# Assumptions

- The approved RDP credential remained `jf / ChangeMe123!`.
- The imported qcow2 at `target/run-20260327-161429/artifacts/import/images/sha256-ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f.qcow2` was still the correct artifact to test.
- The preserved writable vars file from the manual-good lane remained trustworthy enough for a differential replay.
- A small launch matrix was sufficient to decide whether the next step should be contract expansion or some other lane.
