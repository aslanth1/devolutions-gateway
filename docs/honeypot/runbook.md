# Honeypot Operator Runbook

## Purpose

This document is the canonical operator procedure for local honeypot bring-up, session control, emergency stop, VM recycle, evidence capture, and recovery.
It works with [deployment.md](deployment.md), [contracts.md](contracts.md), [risk.md](risk.md), [testing.md](testing.md), and [operator-content-policy.md](operator-content-policy.md).
It does not by itself approve public deployment or exposure to untrusted traffic.

## Preconditions

- Obtain written authorization for the target environment, network, credentials, storage, and attacker-content handling scope before exposing any listener.
- Use a prepared Linux host with Docker, `/dev/kvm`, and the documented host paths under `/srv/honeypot/`.
- Keep `control-plane`, `proxy`, and `frontend` as the only runtime services.
- Do not expose the checked-in compose stack to the public internet until the remaining exposure, retention, audit, and content-handling hardening rows are complete.
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

## Routine Observation

- The frontend dashboard is the preferred operator surface for live sessions.
- The frontend health route is `GET /health`.
- The proxy bootstrap route is `GET /jet/honeypot/bootstrap`.
- The proxy replay and live update route is `GET /jet/honeypot/events`.
- The proxy session list route is `GET /jet/sessions`.
- The canonical correlation keys for logs, events, and evidence are `session_id`, `vm_lease_id`, `stream_id`, `event_id`, and `correlation_id`.

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
