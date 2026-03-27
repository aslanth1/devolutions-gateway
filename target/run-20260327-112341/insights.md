# What Worked

- The shared `integration_tests` binary produced one authoritative row-706 run envelope when executed in a single process with `--test-threads=1`.
- The row-706 live anchors failed closed under missing lab prerequisites instead of silently succeeding.
- GStreamer is a viable host video capture fallback on this workstation even without `ffmpeg`.

# What Failed

- No attested Tiny11 manifest set was available under the obvious runtime locations.
- The positive row-706 anchors could not execute because the host remained at the contract tier with no `DGW_HONEYPOT_LAB_E2E` or validated interop inputs.
- No non-test manual-headed runtime writer path exists yet for producing `manual_headed/` runtime artifacts from a real run.

# What To Avoid Next Time

- Do not target a nonexistent standalone `honeypot_control_plane` test binary.
- Do not treat generic `kvm-win11` lab assets as Tiny11 evidence without attested import and manifest binding.
- Do not confuse host video capability with completion of the manual-headed checklist rows.

# Promising Next Directions

- Prepare a real Tiny11-derived interop store and rerun the same single-process row-706 attempt with `DGW_HONEYPOT_LAB_E2E`, `DGW_HONEYPOT_TIER_GATE`, and `DGW_HONEYPOT_INTEROP_*` set.
- Add a sanctioned non-test manual-headed runtime writer that emits digest-bound artifacts under `target/row706/runs/<run_id>/manual_headed/`.
- Reuse GStreamer for row `716` once that runtime writer exists and the video metadata can be bound to the same verified Tiny11 run.
