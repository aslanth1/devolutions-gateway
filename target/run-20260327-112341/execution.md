# What Was Done

1. Ran host preflight checks for `cargo`, `jq`, `qemu-system-x86_64`, `xfreerdp`, `google-chrome`, `sha256sum`, `gdbus`, `dbus-send`, `gst-launch-1.0`, `gst-discoverer-1.0`, `DISPLAY`, and `/dev/kvm`.
2. Searched `/srv/honeypot/images` and `/home/jf/research/ned/labs/windows/kvm-win11` for manifest-backed Tiny11 attestation records and found none.
3. Captured the existing `target/row706/runs/*` baseline into `/tmp/row706-before.txt`.
4. Tried `cargo test -p testsuite --test honeypot_control_plane -- --nocapture --test-threads=1`.
5. Adjusted after discovering that `testsuite` exposes only the shared `integration_tests` target, not a standalone `honeypot_control_plane` test target.
6. Ran the actual authoritative attempt with `RUST_TEST_THREADS=1 cargo test -p testsuite --test integration_tests 'honeypot_control_plane::control_plane_' -- --nocapture --test-threads=1`.
7. Captured the new run id by diffing `/tmp/row706-before.txt` against `/tmp/row706-after.txt`.
8. Inspected `manifest.json`, `gold_image_acceptance.json`, `gold_image_repeatability.json`, `external_client_interop.json`, and `digest_mismatch_negative_control.json` for the new run.
9. Probed host desktop capture with GStreamer:
   - one PNG screenshot via `ximagesrc ... ! pngenc`
   - one short WebM via `ximagesrc ... ! vp8enc ! webmmux`
10. Moved the capture outputs into `target/run-20260327-112341/artifacts/`.
11. Recorded artifact hashes with `sha256sum` and duration metadata with `gst-discoverer-1.0`.
12. Re-checked the repo for a non-test manual-headed runtime writer path and found only helper and test surfaces under `testsuite/src/` and `testsuite/tests/`.

# Commands / Actions Taken

- `printf 'DATE_UTC=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" ...`
- `find /srv/honeypot/images /home/jf/research/ned/labs/windows/kvm-win11 -type f -name '*.json'`
- `rg -n '"attestation_ref"|"base_image_path"|"source_iso"|"transformation"|"approval"' /srv/honeypot/images /home/jf/research/ned/labs/windows/kvm-win11`
- `find target/row706/runs ... > /tmp/row706-before.txt`
- `cargo test -p testsuite --test honeypot_control_plane -- --nocapture --test-threads=1`
- `cargo test -p testsuite --test integration_tests -- --list | rg 'control_plane_(gold_image|external_client|reports_host_unavailable).*|row706'`
- `RUST_TEST_THREADS=1 cargo test -p testsuite --test integration_tests 'honeypot_control_plane::control_plane_' -- --nocapture --test-threads=1`
- `find target/row706/runs ... > /tmp/row706-after.txt`
- `comm -13 /tmp/row706-before.txt /tmp/row706-after.txt`
- `sed -n '1,180p' target/row706/runs/<run_id>/*.json`
- `gst-launch-1.0 -e ximagesrc display-name=:0 use-damage=0 num-buffers=1 ! videoconvert ! pngenc ! filesink location=/tmp/manual-headed-snapshot.png`
- `gst-launch-1.0 -e ximagesrc display-name=:0 use-damage=0 num-buffers=90 ! videoconvert ! vp8enc deadline=1 ! webmmux ! filesink location=/tmp/manual-headed-video.webm`
- `gst-discoverer-1.0 target/run-20260327-112341/artifacts/host-gstreamer-video.webm`
- `sha256sum target/run-20260327-112341/artifacts/host-gstreamer-snapshot.png target/run-20260327-112341/artifacts/host-gstreamer-video.webm`
- `rg -n 'manual_headed_begin_run|write_manual_headed_anchor_result|verify_manual_headed_evidence_envelope' -g '!target/**' .`

# Deviations From Plan

- The first runtime command targeted a nonexistent standalone test target.
  I corrected course by listing the real `integration_tests` entries and rerunning the row-706 attempt inside that shared harness.
- No attested Tiny11 interop store existed on host, so the execution intentionally stopped at the fail-closed blocked-prereq lane instead of trying to fabricate provenance.
- The video probe succeeded with GStreamer, so the video tooling question was partially resolved even though the checklist itself remained blocked.
