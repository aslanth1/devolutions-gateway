# Honeypot Operator Runbook

## Purpose

This document is the canonical operator procedure for local honeypot bring-up, session control, emergency stop, VM recycle, evidence capture, and recovery.
It works with [deployment.md](deployment.md), [contracts.md](contracts.md), [risk.md](risk.md), [testing.md](testing.md), and [operator-content-policy.md](operator-content-policy.md).
It does not by itself approve public deployment or exposure to untrusted traffic.

## Preconditions

- Obtain written authorization for the target environment, network, credentials, storage, and attacker-content handling scope before exposing any listener.
- Use a prepared Linux host with Docker, `/dev/kvm`, and the documented host paths under `/srv/honeypot/`.
- Keep `control-plane`, `proxy`, and `frontend` as the only runtime services.
- Do not expose the checked-in compose stack to the public internet until the Windows image pipeline, host resource controls, and gold-image acceptance rows are complete.
- Treat the checked-in compose and frontend config as local-lab defaults only, because the checked-in frontend config disables operator token validation for local bring-up.

## Public Deployment Gate

- Treat public-internet exposure as a separate deployment profile from the checked-in local compose stack.
- Before exposing attacker traffic to the public internet, set `Honeypot.Exposure.PublicInternetEnabled = true` in the proxy config and confirm the gateway still starts cleanly.
- Confirm `Honeypot.Exposure.AllowCidrs` is non-empty and `Honeypot.Exposure.IntakeLimitRate` is positive.
- If `Honeypot.Exposure.DenyCidrs` is used, confirm it only narrows the required allowlist and does not replace it.
- Confirm `Honeypot.KillSwitch.EnableSessionKill = true`, `Honeypot.KillSwitch.EnableSystemKill = true`, and `Honeypot.KillSwitch.HaltNewSessionsOnSystemKill = true` before enabling public intake.
- Keep `frontend` behind loopback or an operator-scoped ingress path even when public attacker intake is enabled for `proxy`.

## Required Inputs

- Non-secret env files live at `honeypot/docker/env/control-plane.env`, `honeypot/docker/env/proxy.env`, and `honeypot/docker/env/frontend.env`.
- Runtime config mounts live at `honeypot/docker/config/control-plane/config.toml`, `honeypot/docker/config/proxy/gateway.json`, and `honeypot/docker/config/frontend/config.toml`.
- Secret mounts live at `honeypot/docker/secrets/control-plane/`, `honeypot/docker/secrets/proxy/`, and `honeypot/docker/secrets/frontend/`.
- The control-plane host image store is `/srv/honeypot/images`.
- The control-plane host lease and overlay store is `/srv/honeypot/leases`.
- The control-plane quarantine store is `/srv/honeypot/quarantine`.
- The control-plane QMP socket store is `/srv/honeypot/run/qmp`.
- The optional control-plane QGA socket store is `/srv/honeypot/run/qga`.

## Baseline Verification

Run the baseline Rust path before changing runtime state.

```bash
cargo +nightly fmt --all
cargo +nightly fmt --all --check
cargo clippy --workspace --tests -- -D warnings
cargo test -p testsuite --test integration_tests
```

- Run `host-smoke` work only when `DGW_HONEYPOT_HOST_SMOKE=1` is set.
- Run `lab-e2e` work only when `DGW_HONEYPOT_LAB_E2E=1` is set.
- `lab-e2e` also requires `DGW_HONEYPOT_TIER_GATE` to point at a gate manifest whose `contract_passed` and `host_smoke_passed` fields are both `true`.
- The external-client interoperability lane additionally requires the documented `DGW_HONEYPOT_INTEROP_*` variables from [testing.md](testing.md).
- Relevant Tiny11-backed `lab-e2e` lanes now execute one canonical availability and readiness gate before lease work begins.
- That gate resolves the interop store from `DGW_HONEYPOT_INTEROP_IMAGE_STORE` when set or from `/srv/honeypot/images` otherwise, reuses manifest-backed provenance validation, rejects stale `.importing` markers, and refuses to proceed when the required RDP credentials, QEMU path, KVM path, or `xfreerdp` path are absent.
- If the canonical store is absent or fails provenance checks, repopulate it only through `honeypot-control-plane consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>`.
- The repo root `Makefile` now provides the sanctioned tier shortcuts:
  `make test-host-smoke`,
  and `make test-lab-e2e`.
- `make test-host-smoke` is the non-mutating prepared-host shortcut.
- It only sets `DGW_HONEYPOT_HOST_SMOKE=1` before launching the existing `cargo test -p testsuite --test integration_tests` path.
- `make test-lab-e2e` is the artifact-aware QEMU-host shortcut.
- It writes `target/honeypot/lab-e2e-gate.json`, runs `make manual-lab-ensure-artifacts` by default, and then launches the existing `cargo test -p testsuite --test integration_tests` path with `DGW_HONEYPOT_LAB_E2E=1` plus `DGW_HONEYPOT_TIER_GATE`.
- On a non-root workstation, use `MANUAL_LAB_PROFILE=local make test-lab-e2e` so the artifact precheck stays on the repo-local interop store instead of canonical `/srv`.
- Set `LAB_E2E_PRECHECK=0` when you intentionally need the older raw `lab-e2e` launch order without the automatic artifact ensure step.
- Use `HOST_SMOKE_TEST_ARGS='<filter or extra cargo args>'` or `LAB_E2E_TEST_ARGS='<filter or extra cargo args>'` to pass through test filters or trailing harness flags such as `-- --nocapture`.

## Local Bring-Up

1. Confirm the required host paths exist and are writable only by the operator or service account that owns the lab host.
2. Confirm the secret directories contain the expected proxy verifier key, service bearer token, and backend credential store before starting the stack.
3. Start the three-service stack from the checked-in compose file.

```bash
docker compose -f honeypot/docker/compose.yaml up -d --build control-plane proxy frontend
docker compose -f honeypot/docker/compose.yaml ps
```

4. Wait until `control-plane`, `proxy`, and `frontend` all report `healthy` in `docker compose ps`.
5. Verify the operator entrypoint responds on loopback.

```bash
curl -fsS http://127.0.0.1:8080/health
docker compose -f honeypot/docker/compose.yaml exec proxy curl -fsS http://127.0.0.1:8080/jet/health
```

6. Treat the compose health state as the canonical readiness signal for `control-plane`, because its healthcheck already applies the internal service token requirement for `GET /api/v1/health`.
7. Open the operator frontend at `http://127.0.0.1:8080/`.
8. Do not allow attacker traffic until the stack is healthy end to end and the operator can load the dashboard without bootstrap errors.

## Milestone 6a Manual-Headed Checklist

- Use one `run_id` for the entire headed walkthrough and store every manual-headed artifact under `target/row706/runs/<run_id>/`.
- Treat manual-headed evidence as a profile in the existing row-`706` run envelope, not as a separate checklist store or second authority.
- Do not start a manual-headed run unless the explicit manual-lab gate is recorded, headed display is available, Chrome is present, the run records either `WINDOWS11-LICENSE.md` or a non-git secret path for Windows key material, and the attested Tiny11 image-store or interop root is named before startup begins.
- Keep live product keys, RDP credentials, and equivalent secrets only in mounted secret paths or other non-git operator storage.
- The tracked `WINDOWS11-LICENSE.md` file is the one allowed repo-local Windows provisioning key file for local Win11 host creation.
- Do not copy that key into manual-headed evidence, screenshots, exports, secondary docs, or any other tracked artifact.
- Record `session_id` and `vm_lease_id` on every runtime manual-headed artifact whenever those identifiers exist.
- Treat startup/shutdown service-state capture, Tiny11 plus RDP-ready proof, headed QEMU plus Chrome correlation, bounded interaction, video evidence, and heavy-artifact retrieval as `runtime_required`.
- For the startup or shutdown capture, write one machine-readable JSON artifact that records ordered startup and teardown timestamps, exactly three service entries named `control-plane`, `proxy`, and `frontend`, and one teardown disposition of `clean_shutdown` or `explicit_failure`.
- Each recorded service entry must state whether the evidence came from `health` or `bootstrap` plus a startup status of `healthy`, `ready`, or `reachable`.
- If teardown ends in `explicit_failure`, record both a non-empty failure code and a non-empty failure reason before the run may be finalized.
- For Tiny11 plus RDP-ready proof, write one machine-readable JSON artifact that records `probe`, `identity`, `provenance`, and `key_source`.
- Keep `probe.method`, `probe.endpoint`, and `probe.evidence_ref` non-empty, keep `probe.captured_at_unix_secs` positive, and keep `probe.ready` set to `true`.
- Keep `identity.vm_lease_id` aligned with the runtime anchor invocation, and keep `identity.session_id` aligned too whenever the artifact records one.
- Keep `provenance.row706_run_id`, `provenance.attestation_ref`, and `provenance.interop_store_root` aligned with the verified row-`706` envelope so the Tiny11 lineage stays bound to the same run.
- Keep `key_source.class` to `repo_allowlisted_windows_license` or `non_git_secret_alias`, keep `key_source.alias` free of raw product-key material and absolute or host-specific paths, and use `WINDOWS11-LICENSE.md` only for the allowlisted repo-local case.
- For video evidence, write one machine-readable JSON artifact that records `video_sha256`, `duration_floor_secs`, `timestamp_window`, `storage_uri`, and `retention_window`.
- Keep the timestamp window ordered, keep the retention policy and expiry explicit, and ensure the stored `session_id` and `vm_lease_id` match the runtime anchor invocation whenever those identifiers exist.
- For headed QEMU plus Chrome observation, write one machine-readable JSON artifact that records `qemu_display_mode`, `qemu_launch_reference`, `browser_family`, `frontend_access_path`, and `correlation_snapshot`.
- Keep `qemu_display_mode` set to `headed`, keep `browser_family` set to `chrome`, and ensure the correlation snapshot ties the observed tile or session back to the exact `session_id` and `vm_lease_id` for the run.
- The headed-observation artifact must also agree on `vm_lease_id` with the Tiny11 RDP-ready anchor so the observed frontend tile cannot drift from the active lease identity.
- For bounded interaction, write one machine-readable JSON artifact that records `interaction_window`, `session_id`, `vm_lease_id`, and `modalities`.
- Keep `interaction_window` ordered and bounded, keep it inside the recorded video `timestamp_window`, and keep its `session_id` plus `vm_lease_id` aligned with the headed-observation anchor.
- `modalities.mouse`, `modalities.keyboard`, and `modalities.browsing` must each provide `event_count > 0` and at least one non-empty `evidence_refs` entry so no modality is satisfied by a no-op claim.
- Treat prerequisite gating, run identity setup, redaction hygiene, and artifact-storage contract setup as `preflight_only`.
- A `preflight_only` run may end in `blocked_prereq`, but it must not be cited as completion evidence for row `735`.
- Any artifact referenced by a manual-headed run must remain retrievable through the approved storage backend and must match the recorded digest when re-read.

## Three-Host Manual Observation Deck

- Use the Rust launcher when you want a real operator deck with three live Tiny11-backed sessions and a browser view you can click through.
- The sanctioned command surface is `cargo run -p testsuite --bin honeypot-manual-lab -- preflight`, `ensure-artifacts`, `remember-source-manifest`, `bootstrap-store`, `up`, `status`, and `down`.
- The repo root `Makefile` also provides thin convenience wrappers `make manual-lab-preflight`, `make manual-lab-ensure-artifacts`, `make manual-lab-remember-source-manifest`, `make manual-lab-bootstrap-store`, `make manual-lab-bootstrap-store-exec`, `make manual-lab-up`, `make manual-lab-status`, and `make manual-lab-down`.
- For manual operator self-test on a non-root host, prefer `make manual-lab-selftest` for the normal browser-backed path or `make manual-lab-selftest-no-browser` when you want the deck live without opening Chrome.
- The granular local aliases `make manual-lab-selftest-preflight`, `make manual-lab-selftest-ensure-artifacts`, `make manual-lab-selftest-bootstrap-store`, `make manual-lab-selftest-bootstrap-store-exec`, `make manual-lab-selftest-up`, `make manual-lab-selftest-status`, and `make manual-lab-selftest-down` still exist for debugging or stepwise recovery.
- `make manual-lab-show-profile` is the read-only visibility helper for the effective profile, config path, store root, manifest dir, and masked guest-auth state.
- The related prepared-host tier shortcuts are `make test-host-smoke` and `make test-lab-e2e`.
- `make test-host-smoke` keeps the existing `host-smoke` tier non-mutating by default.
- `make test-lab-e2e` reuses `make manual-lab-ensure-artifacts` as its default fast precheck before setting `DGW_HONEYPOT_LAB_E2E=1` and the test tier gate.
- On non-root hosts, prefer `MANUAL_LAB_PROFILE=local make test-lab-e2e` so the lab-e2e precheck stays on repo-local state instead of canonical `/srv`.
- Set `LAB_E2E_PRECHECK=0` when a scripted caller intentionally wants the raw `lab-e2e` launch order without the automatic artifact ensure step.
- Use `HOST_SMOKE_TEST_ARGS` or `LAB_E2E_TEST_ARGS` to pass through a test filter or trailing harness flags.
- Those wrappers still call the same Rust launcher and only pre-create a local lab-e2e gate file plus set `DGW_HONEYPOT_LAB_E2E=1` and `DGW_HONEYPOT_TIER_GATE` for `preflight`, `ensure-artifacts`, `bootstrap-store`, and `up`.
- For `manual-lab-preflight`, `manual-lab-preflight-no-browser`, `manual-lab-ensure-artifacts`, `manual-lab-bootstrap-store`, `manual-lab-bootstrap-store-exec`, `manual-lab-up`, and `manual-lab-up-no-browser`, the Makefile also injects default guest-auth values `DGW_HONEYPOT_INTEROP_RDP_USERNAME=operator` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD=password`.
- Override those wrapper defaults with `MANUAL_LAB_INTEROP_RDP_USERNAME=<value>`, `MANUAL_LAB_INTEROP_RDP_PASSWORD=<value>`, or raw exported `DGW_HONEYPOT_INTEROP_RDP_USERNAME` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD` when an imported image uses a different guest account.
- `MANUAL_LAB_PROFILE=canonical|local` selects the sanctioned host-state lane for those Make wrappers.
- `canonical` is the default and keeps the checked-in `/srv/honeypot/...` paths.
- `local` is the explicit non-root operator lane and switches the wrappers to repo-local state under `target/manual-lab/state/`.
- `make manual-lab-selftest` and the `manual-lab-selftest-*` aliases always select that explicit `local` lane for convenience, but they do not change the canonical `manual-lab-*` defaults.
- By default, `make manual-lab-selftest-up` and `make manual-lab-selftest-up-no-browser` run `make manual-lab-selftest-ensure-artifacts` first so warmed local stores skip repeat import work before launch.
- Set `MANUAL_LAB_SELFTEST_UP_PRECHECK=0` when a scripted caller intentionally needs the older raw local `manual-lab-up*` launch shape and failure ordering.
- `ensure-artifacts` is the fast explicit prewarm lane for QEMU-backed runs.
- It first runs the same manual-lab readiness check with `preflight --no-browser`.
- If the selected interop store is already ready, it returns immediately and skips `bootstrap-store`.
- It only provisions through the sanctioned `consume-image` path when store readiness is the blocker and the source manifest is explicit or unambiguous under the existing discovery rules.
- Repeated local self-test bootstrap is idempotent.
- If the requested trusted image is already present and valid in the selected store, `bootstrap-store --execute` returns `already_present` before attempting to create a matching import lock.
- Dead-pid import locks are reclaimed automatically.
- A first import or a cache miss still reports `validation_mode=hashed`.
- A repeated unchanged import may report `validation_mode=cached`.
- Any missing, corrupt, or stale digest stamp falls back to a full hash before trust is granted.
- A live `import_lock_held` blocker means a real `honeypot-control-plane consume-image` process still owns the matching lock; wait for that process or stop the reported pid if it is unexpected, then rerun `make manual-lab-selftest`.
- Use the artifact-first sequence for repeated manual operator work:
  `make manual-lab-ensure-artifacts`,
  if ensure-artifacts reports multiple admissible manifests, rerun `make manual-lab-remember-source-manifest MANUAL_LAB_SOURCE_MANIFEST=<path>`,
  then rerun `make manual-lab-ensure-artifacts`,
  rerun `make manual-lab-preflight`,
  then launch with `make manual-lab-up`.
- `up` is `lab-e2e` gated and refuses to start unless `DGW_HONEYPOT_LAB_E2E=1` is set and `DGW_HONEYPOT_TIER_GATE` points at a gate file whose `contract_passed` and `host_smoke_passed` fields are both `true`.
- The live manual deck also requires the same canonical Tiny11 interop inputs as the external-client proof path:
  `DGW_HONEYPOT_INTEROP_RDP_USERNAME`,
  `DGW_HONEYPOT_INTEROP_RDP_PASSWORD`,
  `DGW_HONEYPOT_INTEROP_IMAGE_STORE`,
  `DGW_HONEYPOT_INTEROP_MANIFEST_DIR`,
  `DGW_HONEYPOT_INTEROP_QEMU_BINARY`,
  `DGW_HONEYPOT_INTEROP_KVM_PATH`,
  and `DGW_HONEYPOT_INTEROP_XFREERDP_PATH`.
- `DGW_HONEYPOT_INTEROP_IMAGE_STORE` and `DGW_HONEYPOT_INTEROP_MANIFEST_DIR` are optional if the canonical sealed store under `/srv/honeypot/images` is already present and trusted.
- `DGW_HONEYPOT_INTEROP_RDP_DOMAIN`, `DGW_HONEYPOT_INTEROP_RDP_SECURITY`, and `DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS` remain optional overrides for unusual lab hosts.
- `preflight` remains read-only.
- `remember-source-manifest` stores only a local git-ignored hint under `target/manual-lab/selected-source-manifest.json`; it never mutates the interop store.
- `ensure-artifacts` stays explicit and may mutate the selected interop store, but it only does so when preflight is blocked by store readiness and the source manifest selection is explicit or unique.
- When `preflight` is already ready, `ensure-artifacts` stops there and avoids a repeat `consume-image` run entirely.
- `bootstrap-store` is the sanctioned mutating remediation lane, and it is dry-run by default until `--execute` or `make manual-lab-bootstrap-store-exec` is used.
- `bootstrap-store` checks the same manual-lab interop root that `preflight` will later validate.
- If more than one admissible local bundle manifest is present under the sanctioned `target/run-*/artifacts/.../bundle-manifest.json` lanes, `bootstrap-store` refuses to guess until the operator either remembers one with `MANUAL_LAB_SOURCE_MANIFEST=<path>` or passes `--source-manifest <path>` explicitly.
- Explicit `MANUAL_LAB_SOURCE_MANIFEST=<path>` or `--source-manifest <path>` still wins over any remembered hint.
- remove `target/manual-lab/selected-source-manifest.json` to clear the local hint.
- `MANUAL_LAB_CONTROL_PLANE_CONFIG=<path>` or `--config <path>` is available when the import config must differ from the repo default `honeypot/docker/config/control-plane/manual-lab-bootstrap.toml`.
- If the canonical `/srv` lane is blocked by store-root permissions on a non-root host, switch to the explicit local profile:
  `make manual-lab-preflight MANUAL_LAB_PROFILE=local`,
  `make manual-lab-ensure-artifacts MANUAL_LAB_PROFILE=local`,
  `make manual-lab-preflight MANUAL_LAB_PROFILE=local`,
  then `make manual-lab-up MANUAL_LAB_PROFILE=local`.
- The live canonical `missing_store_root` blocker now points non-root operators at the self-test quick path first:
  `make manual-lab-selftest`.
- That same blocker still keeps canonical `/srv` proof separate:
  `make manual-lab-ensure-artifacts`,
  then `make manual-lab-preflight`.
- If you want to inspect the lane first without mutating anything, run `make manual-lab-show-profile`.
- The shorter manual self-test quick path on this host is:
  `make manual-lab-selftest`,
  then `make manual-lab-selftest-status` and `make manual-lab-selftest-down`.
- The granular local launch aliases now use the same warmup step by default:
  `make manual-lab-selftest-up`,
  `make manual-lab-selftest-up-no-browser`.
- Those aliases still share one local writable state root, so disable the precheck or serialize runs if you intentionally script parallel local launch attempts.
- The local profile is for operator self-test and uses repo-local writable state only.
- It does not replace the canonical `/srv` lane for production-like host readiness proof.
- If `preflight` or `up` reports `missing_store_root`, run `make manual-lab-ensure-artifacts` first instead of editing a placeholder `consume-image` command by hand.
- The expected post-import state is a trusted-image store under `/srv/honeypot/images`, a manifest set under `/srv/honeypot/images/manifests`, and a `preflight` result of `ready` before the operator launches `up`.
- Treat a blocked `preflight` result as `blocked_prereq` only.
- It is a prerequisite signal, not runtime proof and not Milestone 6b completion evidence by itself.
- `up` opens Chrome by default after the frontend reports three ready tiles.
- Set `DGW_HONEYPOT_MANUAL_LAB_CHROME` if Chrome is not on `PATH`.
- Pass `--no-browser` when you want the deck live without opening a window.
- The hidden `xfreerdp` drivers prefer `Xvfb` when available.
- Set `DGW_HONEYPOT_MANUAL_LAB_XVFB` if `Xvfb` is installed outside `PATH`.
- If `Xvfb` is unavailable, the launcher requires a live `DISPLAY` and the helper `xfreerdp` sessions will render on that active desktop.
- The launcher writes its active state to `target/manual-lab/active.json` and stores run logs plus runtime files under `target/manual-lab/manual-lab-<uuid>/`.
- Use `status` to print the current run root, dashboard URL, process ids, health snapshots, and known `session_id`, `vm_lease_id`, and `stream_id` values.
- Use `down` to terminate the helper `xfreerdp` clients, request proxy session terminate, request control-plane release plus recycle for known leases, stop `control-plane`, `proxy`, and `frontend`, and clear the active state file.
- This manual deck intentionally runs the three honeypot services as host processes rather than through `docker compose`.
- The reason is that live Tiny11 leases currently expose guest RDP through host-loopback forwards such as `127.0.0.1:<guest_rdp_port>`, and a separate proxy container cannot reliably consume those loopback-scoped ports.
- Keep the checked-in compose flow as the validated readiness, dependency-order, and rollback topology.
- Use the host-process manual deck only for the live three-host observation workflow.
- Treat isolated helper-display support such as `Xvfb` as the preferred operator-host shape for a real live-proof run so the three helper RDP clients do not steal focus on the operator desktop.

## Routine Observation

- The frontend dashboard is the preferred operator surface for live sessions.
- The frontend health route is `GET /health`.
- The proxy bootstrap route is `GET /jet/honeypot/bootstrap`.
- The proxy replay and live update route is `GET /jet/honeypot/events`.
- The proxy session list route is `GET /jet/sessions`.
- The canonical correlation keys for logs, events, and evidence are `session_id`, `vm_lease_id`, `stream_id`, `event_id`, and `correlation_id`.
- The current audit surface is the existing typed control-plane request and response envelopes plus the honeypot lifecycle events, not a second browser-facing audit API.

## Session Kill Procedure

- Use the frontend `POST /session/{id}/kill` action for normal operator termination.
- That frontend action proxies to the stable proxy route `POST /jet/session/{id}/terminate`.
- The required operator scope is `gateway.honeypot.session.kill`, and `gateway.honeypot.system.kill` may also satisfy the route.
- Prefer a normal kill when the attacker session should end and the guest may be returned to the reusable pool after a clean recycle.
- Expected lifecycle after a successful kill is `session.killed`, then `session.recycle.requested`, then `host.recycled`.
- Confirm the session disappears from `/jet/sessions` and from the bootstrap payload after the recycle path completes.
- Confirm session-bound stream tokens and provisioned credentials are no longer usable after the kill completes.

## Quarantine Procedure

- Use the frontend `POST /session/{id}/quarantine` action when guest behavior, recycle behavior, image provenance, or host integrity looks suspicious.
- That frontend action proxies to the stable proxy route `POST /jet/session/{id}/quarantine`.
- The required operator scope is `gateway.honeypot.session.kill`, and `gateway.honeypot.system.kill` may also satisfy the route.
- Quarantine is the preferred action when you need to preserve the affected lease or image chain for review instead of returning it to the ready pool.
- Expected lifecycle after quarantine is `session.killed` with `kill_reason = operator_quarantine`, then `session.recycle.requested`, then `host.recycled` with `quarantined = true`.
- Do not manually reopen quarantined artifacts to `proxy` or `frontend`.

## Global Emergency Stop

- Use the frontend `POST /system/kill` action for the operator-facing global kill.
- That frontend action proxies to the stable proxy route `POST /jet/session/system/terminate`.
- The required operator scope is `gateway.honeypot.system.kill`.
- A successful global kill must set `system_kill_active = true`, report whether new sessions are halted, kill every live session, revoke live stream and credential material, and request recycle for every assigned lease.
- Verify that `/jet/sessions` drains to empty and that the frontend dashboard no longer shows live tiles.
- Verify that no new attacker intake resumes until the operator intentionally restores service.
- If the proxy cannot execute the global kill path, stop attacker ingress first by stopping the `proxy` service, then continue with evidence capture and recovery.

## VM Recycle Procedure

- Normal recycle is automatic after disconnect, kill, no-lease cleanup, boot timeout, and global kill handling.
- Treat `session.recycle.requested` followed by `host.recycled` as the authoritative proof that the lease completed the recycle state machine.
- Use normal kill when you want the guest returned to service if recycle succeeds.
- Use quarantine when you want recycle failure or suspicious guest state to preserve artifacts for review.
- There is no anonymous browser-side recycle button in the MVP.
- Direct `recycle_vm` calls remain an internal control-plane API for service or admin workflows on the private honeypot network.

## Evidence Collection

1. Record the UTC time, operator identity, reason for intervention, and the known `session_id`, `vm_lease_id`, `stream_id`, `event_id`, and `correlation_id` values.
2. Capture the current service state.

```bash
docker compose -f honeypot/docker/compose.yaml ps
docker compose -f honeypot/docker/compose.yaml logs --timestamps control-plane proxy frontend
```

3. Capture the operator-visible session state from the frontend or from the proxy bootstrap and event replay routes.
4. Preserve the matching quarantine subtree under `/srv/honeypot/quarantine` when the incident moved a lease or image out of the reusable pool.
5. Preserve the matching attestation manifest and image reference under `/srv/honeypot/images` when image integrity or provenance is part of the incident.
6. If live media proof is required, use the existing proxy-owned stream bridge and JREC player flow rather than exposing raw QEMU display channels.
7. Never copy secret mounts into an evidence bundle.
8. Redact guest credentials, service tokens, private keys, and personally identifying information from exported material unless explicit authorization requires otherwise.
9. Keep evidence on access-controlled storage and preserve enough audit context to explain every operator action.
10. Apply the role and sharing limits in [operator-content-policy.md](operator-content-policy.md) before viewing, exporting, or escalating attacker content.

## Retention And Case Hygiene

- Apply the canonical retention windows from [risk.md](risk.md) to every case bundle, quarantine subtree, and exported note set.
- Treat live stream and recording scratch output as zero-retention runtime material.
  If it is not intentionally captured into a named case, it must disappear through normal disconnect, recycle, compose teardown, or orphan cleanup.
- Close or reclassify quarantined overlays, runtime directories, pid files, QMP or QGA sockets, attestation copies, and related logs within `14` days of incident closure unless a written hold extends the case.
- Delete intentionally exported screenshots, recordings, and evidence bundles within `30` days of case closure unless a written hold extends the case.
- Delete operator action summaries, incident notes, and similar case metadata within `90` days of case closure unless a written hold extends the case.
- Preserve the matching control-plane envelopes plus `session.killed`, `session.recycle.requested`, and `host.recycled` records for kill, quarantine, and system-kill incidents before deleting the surrounding case bundle on schedule.
- Do not retain vote transcripts or vote history because `propose` and `approve` remain disabled in MVP.
- Never copy secret mounts, backend credentials, bearer tokens, private keys, or raw credential mappings into case storage.

## Recovery Playbooks

### Failed Recycle

1. Stop new intake with the global emergency stop if attacker traffic is still arriving.
2. Quarantine the affected session or lease if that has not already happened automatically.
3. Preserve compose logs, the relevant `session_id` and `vm_lease_id`, and the matching overlay, runtime metadata, and socket state under the quarantine store.
4. Confirm the affected lease is no longer considered reusable by checking that the session has left `/jet/sessions` and that the control-plane health state is either `degraded` or `unsafe` until review completes.
5. Do not delete quarantined artifacts until the evidence package and operator audit trail are complete.
6. Return the host to service only after the control-plane health state is `ready`, the affected lease artifacts are either discarded or approved, and the base-image chain revalidates successfully.

### Image Corruption Or Provenance Failure

1. Treat checksum mismatch, missing attestation, or corrupted base-image state as a hard stop for leasing.
2. Trigger the global emergency stop before attempting image replacement.
3. Preserve the relevant attestation manifest, image digest, compose logs, and control-plane degraded reasons for the incident record.
4. Keep the affected image or manifest out of the trusted image set and move any dependent lease artifacts into quarantine.
5. Replace the bad image chain only from a known-good promoted input that matches `honeypot/docker/images.lock`.
6. Re-run the baseline verification plus the appropriate `host-smoke` or `lab-e2e` lane before resuming attacker traffic.

### Stuck Lease Or Orphaned Runtime Artifacts

1. Start with a normal kill or quarantine for the affected session.
2. Confirm whether the session left `/jet/sessions` while lease artifacts remain under `/srv/honeypot/leases`, `/srv/honeypot/run/qmp`, or `/srv/honeypot/run/qga`.
3. Preserve the overlay, pid file, QMP socket, QGA socket, and compose logs before manual cleanup.
4. Restart `control-plane` only after the evidence above is captured so the built-in orphan cleanup path can reclaim stale processes, sockets, overlays, and lease metadata.
5. If the runtime artifacts still do not clear, keep the lease out of the pool and move the stale subtree into quarantine rather than deleting it in place.
6. Resume service only after `control-plane` reports `ready`, the stale lease no longer appears active, and the remaining host artifacts match the documented clean-state paths.

## Normal Teardown

- Use a normal compose shutdown when the lab is ending without an incident.

```bash
docker compose -f honeypot/docker/compose.yaml down
docker compose -f honeypot/docker/compose.yaml ps
```

- Confirm that the three services are stopped and that no new operator dashboard session can load.
- Review `/srv/honeypot/quarantine` for any leftover artifacts that still require operator follow-up before reusing the host.
