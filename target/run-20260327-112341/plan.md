# Hypothesis

If this workstation already has a manifest-backed Tiny11-derived interop store and the explicit `DGW_HONEYPOT_LAB_E2E` and `DGW_HONEYPOT_INTEROP_*` inputs, then one single-process row-706 runtime attempt should produce an authoritative run envelope under `target/row706/runs/<run_id>/`.

If those prerequisites are missing, the honest outcome should be a fail-closed blocked-prereq style run with skipped positive anchors instead of false checklist closure.

The manual-headed video lane may still be testable independently as a host capability probe via GStreamer even if the full checklist remains blocked.

# Steps

1. Record host preflight facts for `DISPLAY`, `/dev/kvm`, required binaries, and current `DGW_HONEYPOT_*` env state.
2. Search the obvious runtime locations for a manifest-backed Tiny11 attestation set.
3. If no attested Tiny11 store is found, run one authoritative row-706 attempt through the shared `integration_tests` binary with single-threaded execution and no lab env overrides.
4. Identify the new row-706 run directory and inspect the manifest plus four anchor fragments.
5. Probe the winning-plan video fallback with GStreamer screen capture and record digest and duration metadata.
6. Review whether a non-test manual-headed runtime writer exists before claiming any Milestone 6a runtime row.

# Assumptions

- The canonical row-706 authority is `target/row706/runs/<run_id>/`.
- The `integration_tests` binary keeps one process-scoped `row706` run id for the live anchor writers.
- Generic `/home/jf/research/ned/labs/windows/kvm-win11` assets do not count as Tiny11 evidence unless first imported into an attested store through the documented consume path.
- A host video capture probe is useful evidence about tooling availability, but it is not sufficient by itself to close row `716`.
