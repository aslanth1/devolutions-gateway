# Success

- The sanctioned `consume-image` path succeeded for the Tiny11-derived bundle.
- The imported interop store now contains a trusted qcow2 and manifest rooted under `target/run-20260327-161429/artifacts/import/images`.
- The startup-timeout blocker for the row-706 positive anchors was fixed by scoping a longer control-plane port wait to the live interop tests.
- The row-706 negative control still wrote its fragment in both fresh run envelopes.

# Failure

- AGENTS row `747` is still not complete.
- The full control-plane-backed proof did not produce a complete row-706 evidence envelope.
- The three positive anchors all failed at the `xfreerdp` auth step after real control-plane acquisition.
- Default security mode reached NLA and failed with `ERRCONNECT_AUTHENTICATION_FAILED`.
- Forced TLS failed with `HYBRID_REQUIRED_BY_SERVER`, which means the guest still requires the hybrid or NLA path.
- One unrelated module run also hit an existing flaky failure in `control_plane_force_quarantines_active_leases` with an empty JSON response body.

# Observable Signals

- Imported base image digest: `ee889e408248f64239016a5c2f7c02de74a72f3e86f16ffde9a9f33d936abc0f`.
- Imported manifest: `target/run-20260327-161429/artifacts/import/images/manifests/tiny11-row747-20260327-ee889e408248.json`.
- First post-import row-706 live run: `target/row706/runs/97ae848c-8c6f-48ac-ab87-7fc1de6f7090`.
- Second row-706 live run after the startup-timeout helper fix: `target/row706/runs/b7b695d7-0b99-43db-b154-ec863ed40b98`.
- Both row-706 run manifests remained in `status: "running"` because the harness panicked before `row706_complete_run` could finalize them.
- The only persisted fragment in those run directories was `digest_mismatch_negative_control.json`.
- The focused TLS retry failed with `HYBRID_REQUIRED_BY_SERVER`.

# Unexpected Behavior

- The compacted qcow2 hash changed after the first hash because the compaction output had not actually settled yet.
- A stale disposable prep QEMU process from the earlier Tiny11 prep lane kept burning CPU until I terminated it explicitly.
- The imported control-plane lease path reached RDP but still rejected the same credentials that had succeeded against the earlier manual verification overlay.
