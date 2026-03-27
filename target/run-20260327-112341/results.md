# Success / Failure

- Partial success.
- The host capability portion succeeded:
  required binaries were present, `/dev/kvm` was present, and GStreamer produced a reviewable screenshot and WebM capture.
- The checklist closure failed honestly:
  there was no manifest-backed Tiny11 interop store on host, and the authoritative row-706 runtime attempt produced skipped positive anchors instead of live Tiny11 proof.

# Observable Signals

- Host preflight:
  `DISPLAY=:0`
  `KVM_OK`
  `cargo`, `jq`, `qemu-system-x86_64`, `xfreerdp`, `google-chrome`, `gdbus`, `dbus-send`, `gst-launch-1.0`, and `gst-discoverer-1.0` all resolved on `PATH`.
- Provenance search:
  no JSON manifests were found under `/srv/honeypot/images` or `/home/jf/research/ned/labs/windows/kvm-win11`.
- New authoritative row-706 run:
  `target/row706/runs/6ed7055a-c844-47c0-b2e1-962e63ff354a/`
- Run manifest:
  `status: "complete"`
- Positive anchors in that run:
  `gold_image_acceptance`, `gold_image_repeatability`, and `external_client_interop` all recorded `executed: false` and `status: "skipped"` with `lab-e2e tier requested, but active tier is contract`.
- Negative control in that run:
  `digest_mismatch_negative_control` recorded `executed: true` and `status: "passed"`.
- Host video probe artifacts:
  `target/run-20260327-112341/artifacts/host-gstreamer-snapshot.png`
  `target/run-20260327-112341/artifacts/host-gstreamer-video.webm`
- Video metadata:
  duration `0:00:03.646411006`
  hash `cc4402630e3d14927f3e0bd7bfcd9d2f7e77abdb791d2bb08557310194dc715c`

# Unexpected Behavior

- `testsuite` does not expose a standalone `honeypot_control_plane` test target even though the module name suggested it might.
- The video fallback was better than expected:
  `ffmpeg` was absent, but GStreamer screen capture worked immediately under the active GNOME and Xwayland session.
- The remaining blocker is narrower than “no video tooling”:
  the real blocker for row `716` is the absence of a non-test manual-headed runtime writer bound to the same `run_id`, `session_id`, and `vm_lease_id` as a verified Tiny11 row-706 run.
