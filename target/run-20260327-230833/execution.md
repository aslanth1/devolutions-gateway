# What Was Actually Done

- Re-read the latest relevant `target/*/insights.md` artifacts and summarized the durable lessons before the council started:
  - what worked: explicit run-scoped row-706 verification, canonical sealed Tiny11 lineage, startup-loaded trusted-image validation, and focused acceptance lanes,
  - what failed: fragmented reruns, newest-directory heuristics, overlapping shell harnesses, and repeated request-path hashing,
  - dead ends to avoid: reopening implementation work without invalidating evidence and adding duplicate verifier logic,
  - promising reuse: centralized Rust verification surfaces with explicit `run_id`.
- Confirmed the git working tree was clean and that `AGENTS.md` had zero unchecked rows.
- Spawned three `gpt-5.3-codex` sub-agents at `high` reasoning and ran all six council phases.
- The council voted `2-1` for a two-tier closure gate:
  - static explicit row-706 verification,
  - plus one real focused runtime acceptance lane,
  - with escalation only if the live lane failed.
- Terminated all three sub-agents after the vote.
- Ran the static gate successfully with the explicit canonical row-706 verifier command.
- Tried the focused acceptance lane once at the default contract tier and observed an immediate skip, which was not counted as runtime proof.
- Inspected the tier gate and interop env contract, then reran the same focused acceptance lane under the sanctioned `lab-e2e` env with:
  - absolute `DGW_HONEYPOT_TIER_GATE`,
  - sealed imported Tiny11 store,
  - manifest dir,
  - `jf / ChangeMe123!`,
  - `/usr/bin/qemu-system-x86_64`,
  - `/dev/kvm`,
  - `/usr/bin/xfreerdp`,
  - `DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS=180`.
- Waited through the full multi-minute live run until it exited `0`.
- Identified and removed the two fresh partial row-706 stubs created during this pass:
  - `1f9b5180-9d6c-4f11-ae9f-8fdc85355a20` from the initial contract-tier skip,
  - `2385feed-892b-4fdb-b66e-1baadfa6aa80` from the focused live rerun,
  so the canonical explicit run id stayed authoritative.

# Commands / Actions Taken

- `git status --short`
- `rg -n '^- \\[ \\]' AGENTS.md`
- `ls -1d target/run-* | sort | tail -n 8`
- `for f in $(ls -1d target/run-* | sort | tail -n 8); do ... sed -n '1,120p' \"$f/insights.md\"; done`
- Council sub-agent spawn, critique, refinement, detailed-plan, vote, and close operations
- `/usr/bin/time -f 'elapsed=%e' cargo run -p testsuite --bin honeypot-manual-headed-writer -- verify-row706 --run-id 5c6c2ece-0c30-4694-a569-353ee88ffae9`
- `/usr/bin/time -f 'elapsed=%e' cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly -- --nocapture`
- `rg -n "DGW_HONEYPOT_HOST_SMOKE|DGW_HONEYPOT_LAB_E2E|lab-e2e gold-image acceptance test|active tier is contract" testsuite -S`
- `sed -n '1,220p' testsuite/src/honeypot_tiers.rs`
- `sed -n '2680,2765p' testsuite/tests/honeypot_control_plane.rs`
- `cat target/run-20260327-173919/artifacts/live-proof/import/honeypot-tier-gate.json`
- `sed -n '1,80p' target/run-20260327-210402/execution.md`
- `/usr/bin/time -f 'elapsed=%e' env DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE=/home/jf/src/devolutions-gateway/target/run-20260327-173919/artifacts/live-proof/import/honeypot-tier-gate.json DGW_HONEYPOT_INTEROP_IMAGE_STORE=/home/jf/src/devolutions-gateway/target/run-20260327-173919/artifacts/live-proof/import/images DGW_HONEYPOT_INTEROP_MANIFEST_DIR=/home/jf/src/devolutions-gateway/target/run-20260327-173919/artifacts/live-proof/import/images/manifests DGW_HONEYPOT_INTEROP_QEMU_BINARY=/usr/bin/qemu-system-x86_64 DGW_HONEYPOT_INTEROP_KVM_PATH=/dev/kvm DGW_HONEYPOT_INTEROP_RDP_USERNAME=jf DGW_HONEYPOT_INTEROP_RDP_PASSWORD=ChangeMe123! DGW_HONEYPOT_INTEROP_XFREERDP_PATH=/usr/bin/xfreerdp DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS=180 cargo test -p testsuite --test integration_tests control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly -- --nocapture --test-threads=1`
- `ps -eo pid,etime,cmd | rg 'integration_tests|control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly|qemu-system-x86_64|xfreerdp'`
- `find target/row706/runs -maxdepth 1 -mindepth 1 -type d -printf '%TY-%Tm-%Td %TH:%TM:%TS %f\\n' | sort | tail -n 8`
- `rm -rf target/row706/runs/1f9b5180-9d6c-4f11-ae9f-8fdc85355a20 target/row706/runs/2385feed-892b-4fdb-b66e-1baadfa6aa80`

# Deviations From Plan

- The first focused acceptance invocation ran at the default contract tier and skipped immediately.
  That was treated as a misconfigured execution attempt, not as runtime evidence.
- The detailed-plan draft mentioned possible repeatability probing, but the winning-plan summary and vote rationale centered on one real focused runtime lane.
  After the real `lab-e2e` pass succeeded, I kept the run bounded and did not add repeated live reruns.
