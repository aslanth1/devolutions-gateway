# Honeypot Architecture

## Purpose

This document fixes the service boundaries and reuse seams for the honeypot fork.
It is the architecture companion to the `DF-*` and `OM-*` rows in `AGENTS.md`.
Detailed contract fields belong in `docs/honeypot/contracts.md`.
Detailed frozen choices belong in `docs/honeypot/decisions.md`.
Later milestone work must cite the relevant `DF-*` or `OM-*` rows instead of redefining owners or policy locally.
This document must not be read as permission to introduce a fourth runtime service or a parallel session or stream control stack.

## Runtime Domains

- `proxy` remains the public trust boundary and stays rooted in the current `devolutions-gateway` binary.
- `control-plane` is a new Rust service that owns QEMU, leases, reset, recycle, and host safety.
- `frontend` is a new HTMX service that renders live sessions and approved operator actions.
- Shared crates under `honeypot/` may carry versioned contracts, but they do not run as a fourth service.

## Trust Boundaries

- Attacker traffic enters only through `proxy`.
- `control-plane` is an internal service and never accepts attacker traffic or browser traffic directly.
- `frontend` is operator-facing and never talks to guest VMs or QEMU directly.
- Backend guest credentials, VM lease state, and emergency-stop authority cross the internal boundary only through versioned proxy-to-control-plane contracts.
- Stream tokens and operator auth cross the browser boundary only through `proxy`-owned auth and API surfaces.
- Host resources such as `/dev/kvm`, qcow2 storage, QMP sockets, and optional QGA endpoints stay behind the control-plane boundary.

## Ownership Summary

- `proxy` owns attacker sessions, credential substitution, stream metadata, session APIs, and frontend event emission.
- `control-plane` owns VM inventory, lease lifecycle, image provenance, recycle, quarantine, and host cleanup.
- `frontend` owns presentation, bootstrap, fullscreen viewing, and policy-gated interaction stubs.
- Session, event, and stream ownership must follow `OM-01` through `OM-05` in `AGENTS.md`.

## Reuse Guardrails

- `OM-02` and `OM-03` are authoritative for attacker session lifecycle, credential substitution, session discovery, replay bootstrap, and stream-token ownership.
- The honeypot proxy must extend `devolutions-gateway/src/rdp_proxy.rs` for the RDP MiTM data plane instead of introducing a parallel RDP stack.
- Session state and lifecycle fan-out must extend `devolutions-gateway/src/session.rs` and `devolutions-gateway/src/subscriber.rs` instead of creating a second session or subscriber bus.
- Short-lived backend credential mapping must stay on `devolutions-gateway/src/api/preflight.rs` through `provision-credentials` instead of introducing a second credential API.
- Operator bootstrap and kill workflows must stay rooted in `devolutions-gateway/src/api/sessions.rs` and `devolutions-gateway/src/api/session.rs` instead of introducing a second session-management API family.
- Browser stream delivery must start from the existing `devolutions-gateway/src/recording.rs`, `devolutions-gateway/src/streaming.rs`, `devolutions-gateway/src/ws.rs`, `crates/video-streamer`, and `crates/terminal-streamer` seams instead of creating a parallel stream service.
- If a future milestone replaces any of those seams, the replacement and the reason reuse failed must be recorded first under `DF-03` or `DF-04` in [decisions.md](decisions.md).

## Gold Image And Lease Boundary

- `control-plane` may lease only base images that pair an official Microsoft Windows 11 Pro x64 ISO record with a Tiny11-derived transformation manifest and a verified base-image digest.
- Each lease is created from a reusable attested base image plus a per-lease qcow2 overlay, a dedicated runtime directory, and a lease-scoped QMP socket.
- Optional guest-agent support stays behind a lease-scoped QGA socket and may be disabled without changing the three-service boundary.
- A lease returns to the reusable pool only after the guest is stopped, the overlay and lease-scoped runtime artifacts are removed, and the base image still passes integrity and provenance checks.
- Any provenance, launch, reset, cleanup, or integrity failure moves the lease or image chain into quarantine instead of the reusable pool.

## End-To-End Flow

1. An attacker connection hits the existing public listener in the `proxy` service.
2. The `proxy` reuses the current Gateway path to authenticate the incoming request, negotiate the RDP path, and register session state through `devolutions-gateway/src/rdp_proxy.rs` and `devolutions-gateway/src/session.rs`.
3. The `proxy` acquires a VM lease from `control-plane`, which validates the attested base image, creates a fresh per-session overlay and runtime artifacts, and binds the session to a single `vm_lease_id`.
4. The `proxy` provisions short-lived backend credentials through the existing `/jet/preflight` `provision-credentials` seam instead of inventing a second credential API.
5. The `proxy` completes the attacker-to-guest RDP path by swapping attacker-facing credentials for the backend guest credentials before traffic reaches the Windows VM.
6. The `proxy` publishes session state and frontend events through `devolutions-gateway/src/subscriber.rs`, `devolutions-gateway/src/api/sessions.rs`, and future honeypot extensions to the same seam family.
7. The `frontend` bootstraps running sessions, subscribes to live updates, and opens stream views only after the `proxy` proves a live recording producer and issues short-lived stream tokens.
8. When the attacker disconnects or an operator kills the session, the `proxy` revokes session-bound credentials, marks the session terminal outcome, and asks `control-plane` to recycle or quarantine the lease.
9. The `control-plane` stops the guest, removes lease-scoped overlays and sockets, revalidates the base image before reuse, or quarantines the affected artifacts on failure, and the `frontend` removes or updates the tile from the resulting terminal event.

## Diagram

```text
[Attacker RDP client]
        |
        v
     [proxy]
        |
        +--> session.rs registration
        +--> /jet/preflight credential mapping
        +--> control-plane acquire_vm / recycle_vm
        +--> session + event replay for frontend
        +--> stream token + metadata
        |
        v
[Windows 11 VM lease]

[frontend] <-- bootstrap + live events + stream tokens -- [proxy]

disconnect / kill / timeout
        |
        v
     [proxy]
        |
        +--> credential revoke
        +--> terminal event
        +--> recycle or quarantine request
        |
        v
[control-plane cleanup]
```

## Credential Flow

- The attacker presents credentials to `proxy`, but the guest VM must receive only the backend credential mapping chosen for the assigned lease.
- The existing `devolutions-gateway/src/api/preflight.rs` `provision-credentials` operation is the reuse-first mapping seam.
- The mapping lives in the Gateway credential store and is time-bounded.
- The mapping must be bound to `session_id` and `vm_lease_id`, and it must be revoked on disconnect, kill, recycle, or orphan cleanup.
- `control-plane` may supply or reference backend credentials through its own secret injection contract, but it must not invent a browser-facing credential API.
- `frontend` never handles raw guest credentials.

## Event And Session Flow

- The existing session manager in `devolutions-gateway/src/session.rs` remains the source of truth for live session identity.
- The existing subscriber path in `devolutions-gateway/src/subscriber.rs` remains the base event fan-out seam.
- The existing `/jet/sessions` and `/jet/session/{id}/terminate` routes in `devolutions-gateway/src/api/sessions.rs` and `devolutions-gateway/src/api/session.rs` remain the starting point for bootstrap and kill actions.
- Honeypot-specific fields should extend `SessionInfo` and subscriber payloads rather than creating a second session registry.
- The event schema must eventually cover `session.started`, `session.assigned`, `session.stream.ready`, `session.ended`, `session.killed`, `session.recycle.requested`, and `host.recycled`.

## Stream Flow

- Browser-visible stream discovery belongs to `proxy`, even if the underlying capture source is frozen later by `DF-04`.
- The MVP stream path must evaluate reuse of `devolutions-gateway/src/recording.rs`, `devolutions-gateway/src/streaming.rs`, `crates/video-streamer`, `crates/terminal-streamer`, and `devolutions-gateway/src/ws.rs` before any alternate capture or transport stack is introduced.
- The chosen MVP media path reuses `devolutions-gateway/src/api/jrec.rs` for `/jet/jrec/play` and `/jet/jrec/shadow/{session_id}`, with `streaming.rs`, `ws.rs`, `video-streamer`, and `terminal-streamer` as the live-delivery seam behind that player route.
- The `frontend` bootstraps already-running sessions first and then consumes live updates through an HTMX-compatible transport chosen by `DF-04`.
- Every browser stream must be bound to `session_id`, `vm_lease_id`, and a short-lived token.
- `frontend` never reaches into host files, QMP, or guest display sockets directly.
- The stream source of truth is a design-freeze decision, but the browser control plane is not.
- The frontend focus view uses a proxy-owned bridge such as `/jet/honeypot/session/{session_id}/stream?stream_id={stream_id}`, and that bridge redirects into `/jet/jrec/play/?isActive=true` only when the proxy has proven an active recording producer so live refresh reconnects near the active tail through the existing shadow websocket path.

## Kill Switch And Recycle

- A single-session kill starts from the `proxy` operator surface and fans into the existing `kill_session` path exposed by `devolutions-gateway/src/api/session.rs`.
- A global kill starts from the `proxy` control surface and iterates across all live sessions rather than bypassing session state.
- The `proxy` owns credential revocation, terminal event emission, and the request for `control-plane` recycle or quarantine.
- The `control-plane` owns VM stop, reset, overlay discard or snapshot restore, and host-side cleanup after the kill or disconnect.
- Recycle is a full lease teardown path rather than a best-effort reboot, and it completes only after QEMU exit, socket cleanup, overlay discard, and base-image revalidation succeed together.
- The `frontend` reflects kill and recycle outcomes, but it does not directly terminate VMs or manipulate guest credentials.
- Recycle failure must surface as a quarantined host or guest outcome rather than as a silent disconnect.

## Current Gateway Integration Seams

- `devolutions-gateway/src/lib.rs` exposes `DgwState`, so honeypot state should plug into the current binary state instead of creating a parallel process-local registry.
- `devolutions-gateway/src/service.rs` is where background tasks, managers, credential store, and listener wiring are assembled, so honeypot startup work should register there or in a thin wrapper that still reuses the same library core.
- `devolutions-gateway/src/api/mod.rs` is the current HTTP composition point for `/jet/*` routes, so honeypot routes should be nested here or alongside it under the chosen proxy packaging model from `DF-01`.
- `devolutions-gateway/src/api/webapp.rs` is a token-signing and auth-pattern reference only, so the honeypot frontend may reuse compatible token and auth ideas but must keep its own UI routes and assets instead of inheriting the legacy webapp surface.
- `devolutions-gateway/src/extract.rs` contains token- and scope-based request extractors, so honeypot scopes should extend this pattern instead of layering a second authorization parser.
- `devolutions-gateway/src/middleware/auth.rs` is the current auth gate and exception list, so operator and stream auth should reuse this style of token validation and route scoping where it fits.
- `devolutions-gateway/src/rdp_proxy.rs` is the current RDP MITM and credential injection path, so the honeypot proxy must extend or wrap it instead of reimplementing CredSSP and RDP forwarding.
- `devolutions-gateway/src/session.rs` and `devolutions-gateway/src/subscriber.rs` are the current session and event backbone, so honeypot lifecycle fields should extend them.
- `devolutions-gateway/src/api/preflight.rs` is the current short-lived provisioning seam, so session-bound credential mapping must reuse it.
- `devolutions-gateway/src/api/sessions.rs` and `devolutions-gateway/src/api/session.rs` are the current read and terminate surfaces, so the frontend bootstrap and operator kill path should start there.
- `devolutions-gateway/src/recording.rs` and `devolutions-gateway/src/streaming.rs` are the current recording and stream delivery seams, so the honeypot MVP should reuse or explicitly reject them in `DF-04`.
- `devolutions-gateway/src/config.rs` and `config_schema.json` are the current config surface, so honeypot mode and control-plane endpoints should extend them rather than introducing handwritten sidecar config.
- `testsuite/src/dgw_config.rs` is the current test bootstrap helper, so honeypot integration tests should extend it before inventing a second harness.

## Architectural Constraints

- This architecture keeps exactly three runtime services.
- This architecture assumes `proxy` remains the only public listener.
- This architecture assumes `frontend` is a separate HTMX application and not a reuse of `webapp/`.
- This architecture assumes no new session bus, stream bus, credential API, or browser-stream service unless `DF-03` or `DF-04` explicitly records the replacement and why reuse failed.

## Implementation Sequence

1. Freeze `DF-01` through `DF-09` in `docs/honeypot/decisions.md`.
2. Write `docs/honeypot/contracts.md` so the control-plane API, session events, stream metadata, and auth model match this boundary map.
3. Extend `config.rs`, `config_schema.json`, and `testsuite/src/dgw_config.rs` with honeypot mode and control-plane settings.
4. Add the `honeypot/` workspace and the three service entrypoints without changing default non-honeypot behavior.
5. Implement control-plane, proxy extensions, frontend bootstrap, and stream delivery only after the above boundaries are frozen.
