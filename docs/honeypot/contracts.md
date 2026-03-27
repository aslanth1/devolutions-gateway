# Honeypot Contracts

## Purpose

This document is the single source of truth for honeypot control-plane, proxy, stream, and frontend payloads.
It carries the contract details required by `DF-02`, `DF-03`, `DF-04`, `DF-07`, `DF-08`, and `DF-09` in [decisions.md](decisions.md).
It works with [architecture.md](architecture.md) and [risk.md](risk.md).
It must not be read as permission to add a fourth runtime service or a parallel session or stream control stack.

## Shared Crate

- The canonical Rust contract crate path is `honeypot/contracts`.
- `honeypot/contracts` owns the typed definitions for control-plane RPC payloads, event envelopes, stream metadata, operator auth scopes, and frontend bootstrap payloads.
- No honeypot runtime service may carry a hand-written duplicate of a JSON contract that already belongs in `honeypot/contracts`.
- The crate may expose modules named `auth`, `control_plane`, `events`, `frontend`, and `stream`, but it does not become a runtime service.

## No-Parallel-Surface Rule

- The contract families in this document extend the existing Gateway seam owners from `OM-02` and `OM-03` instead of authorizing a second session bus, subscriber bus, credential API, or stream API.
- Session lifecycle and replay contracts are layered onto `session.rs`, `subscriber.rs`, `api/sessions.rs`, and `api/session.rs`.
- Credential-substitution contracts are layered onto `api/preflight.rs` and its `provision-credentials` flow.
- Stream bootstrap, token, and replay contracts are layered onto the existing recording and streaming seam family described in [architecture.md](architecture.md).
- Any future contract family that replaces one of those seams must first record the replaced seam and the reason reuse failed under `DF-03` or `DF-04` in [decisions.md](decisions.md).

## Versioning Rules

- Every contract payload carries `schema_version`.
- `schema_version` starts at `1` for the MVP contract families in this document.
- Every event carries `event_id`, `schema_version`, `event_kind`, and ordering fields.
- Additive optional fields are allowed within the same major `schema_version`.
- Removing a field, changing a field meaning, or changing ordering semantics requires a new major `schema_version`.
- Producers must ignore unknown optional fields from newer peers.
- Consumers must reject unknown required fields from newer peers as an unsupported-version failure.

## Compatibility Rules

- `frontend current` supports `proxy current` and `proxy previous` for bootstrap, event replay, and stream-token contracts when the major `schema_version` is the same.
- `frontend previous` supports `proxy current` for one adjacent release if the major `schema_version` is unchanged and new fields are additive.
- `proxy current` supports `control-plane current` and `control-plane previous` for internal control-plane RPC when the major `schema_version` is the same.
- `proxy previous` supports `control-plane current` for one adjacent release if the major `schema_version` is unchanged and required request fields are unchanged.
- `frontend` never talks directly to `control-plane`, so there is no supported `frontend` to `control-plane` compatibility matrix.
- Rolling upgrades and rollbacks may mix only `current` and `previous` images recorded in `honeypot/docker/images.lock`.
- Any contract change that breaks `current -> previous` or `previous -> current` behavior for adjacent releases blocks promotion until all affected services are updated together.

## Auth Model

- `proxy` is the only public trust boundary.
- `control-plane` accepts requests only from `proxy` over the internal service network.
- `frontend` authenticates only to `proxy`.
- `proxy` signs short-lived service and operator tokens with a mounted private signing key.
- `proxy` and `control-plane` validate tokens against a mounted verification key set that carries stable key IDs.
- Trust material comes from read-only secret mounts defined by the deployment contract and never from image layers or browser assets.
- Rotation uses overlapping key sets so `current` and `next` verification keys coexist for at least the maximum issued token lifetime plus clock skew.
- Service tokens use the scope `gateway.honeypot.control-plane`.
- Operator tokens use the scopes `gateway.honeypot.watch`, `gateway.honeypot.stream.read`, `gateway.honeypot.session.kill`, and `gateway.honeypot.system.kill`.
- The frozen command scopes are `gateway.honeypot.command.propose` and `gateway.honeypot.command.approve`.
- `gateway.honeypot.command.propose` may reach only the non-executing deferred proposal placeholder in MVP.
- `gateway.honeypot.command.approve` may reach only the non-executing deferred voting placeholder in MVP.
- `proxy` may continue to reuse existing Gateway token-validation and web-app token patterns internally while exposing the honeypot scope names above as the external contract.
- Missing or invalid tokens fail with `401 unauthorized`.
- Valid tokens without the required scope or role fail with `403 forbidden`.
- Inter-service auth failure must not trigger guest credential delivery, lease mutation, or stream issuance.
- Every auth failure emits an audit record with `correlation_id`, `actor_type`, `actor_id` when present, `scope`, `result`, and `reason_code`.

## Operator Identity And Roles

- Operator identity is established by a proxy-local authentication flow that follows the current web-app token pattern.
- The proxy issues a long-lived operator app token after successful login and then exchanges it for short-lived scoped access tokens.
- The `watch` role maps to `gateway.honeypot.watch` and may read bootstrap state, consume events, and request stream tokens when paired with `gateway.honeypot.stream.read`.
- The `kill` role maps to `gateway.honeypot.session.kill` for single-session kills or quarantines and `gateway.honeypot.system.kill` for global kill.
- The `propose` role maps to `gateway.honeypot.command.propose` and may record only deferred or rejected placeholder commands in MVP.
- The `approve` role maps to `gateway.honeypot.command.approve` and may record only deferred or rejected placeholder votes in MVP.
- The operator workflow and sensitive-content rules for those roles live in [operator-content-policy.md](operator-content-policy.md).
- Every operator-visible action must carry `operator_id`, `role`, `session_id` when present, `vm_lease_id` when present, `event_id` when present, and `correlation_id`.

## Error Envelope

- Every RPC or browser-facing JSON failure uses `schema_version`, `correlation_id`, `error_code`, `message`, and `retryable`.
- `error_code` is machine-readable and stable across adjacent releases.
- `message` is operator-readable and may change without a schema bump.
- `retryable` tells the caller whether the exact request may be retried without a state change.

## Control-Plane Transport

- The control-plane API is internal JSON over HTTPS on the private honeypot network.
- `frontend` never calls the control-plane API.
- `proxy` authenticates every control-plane call with a bearer service token carrying `gateway.honeypot.control-plane`.
- Every request includes `schema_version` and `request_id`.
- Every success response includes `schema_version` and `correlation_id`.

## Control-Plane API

### `acquire_vm`

- Method and path: `POST /api/v1/vm/acquire`.
- Request fields: `schema_version`, `request_id`, `session_id`, `requested_pool`, `requested_ready_timeout_secs`, `stream_policy`, `backend_credential_ref`, and `attacker_protocol`.
- Success fields: `schema_version`, `correlation_id`, `vm_lease_id`, `vm_name`, `guest_rdp_addr`, `guest_rdp_port`, `lease_state`, `lease_expires_at`, `backend_credential_ref`, and `attestation_ref`.
- Failure codes: `auth_failed`, `invalid_request`, `no_capacity`, `image_untrusted`, `host_unavailable`, `boot_timeout`, and `lease_conflict`.
- `backend_credential_ref` must resolve through the control-plane backend credential store rooted in the documented secret mount before a lease is assigned.
- `boot_timeout` means the lease was reserved but the guest did not reach ready state before the requested timeout.
- `no_capacity` is retryable only after the proxy has emitted the matching frontend-visible terminal state.

### `release_vm`

- Method and path: `POST /api/v1/vm/{vm_lease_id}/release`.
- Request fields: `schema_version`, `request_id`, `session_id`, `release_reason`, and `terminal_outcome`.
- Success fields: `schema_version`, `correlation_id`, `vm_lease_id`, `release_state`, and `recycle_required`.
- Failure codes: `auth_failed`, `invalid_request`, `lease_not_found`, `lease_state_conflict`, and `host_unavailable`.
- `release_vm` ends the session-to-lease assignment and moves the lease into the recycle state machine.

### `reset_vm`

- Method and path: `POST /api/v1/vm/{vm_lease_id}/reset`.
- Request fields: `schema_version`, `request_id`, `session_id`, `reset_reason`, and `force`.
- Success fields: `schema_version`, `correlation_id`, `vm_lease_id`, `reset_state`, and `quarantine_required`.
- Failure codes: `auth_failed`, `invalid_request`, `lease_not_found`, `lease_state_conflict`, `reset_failed`, and `host_unavailable`.
- `reset_vm` is for an explicit forced guest reset and does not by itself return the lease to the ready pool.

### `recycle_vm`

- Method and path: `POST /api/v1/vm/{vm_lease_id}/recycle`.
- Request fields: `schema_version`, `request_id`, `session_id`, `recycle_reason`, `quarantine_on_failure`, and `force_quarantine`.
- Success fields: `schema_version`, `correlation_id`, `vm_lease_id`, `recycle_state`, `pool_state`, and `quarantined`.
- Failure codes: `auth_failed`, `invalid_request`, `lease_not_found`, `recycle_failed`, `quarantined`, and `host_unavailable`.
- `recycle_vm` discards the overlay or restores the clean snapshot and either returns the lease to the ready pool or moves it to quarantine.

### `health`

- Method and path: `GET /api/v1/health`.
- Request fields: `schema_version` and `request_id`.
- Success fields: `schema_version`, `correlation_id`, `service_state`, `kvm_available`, `trusted_image_count`, `active_lease_count`, `quarantined_lease_count`, and `degraded_reasons`.
- Failure codes: `auth_failed` and `host_unavailable`.
- `service_state` is one of `ready`, `degraded`, or `unsafe`.

### `stream_endpoint`

- Method and path: `GET /api/v1/vm/{vm_lease_id}/stream`.
- Request fields: `schema_version`, `request_id`, `session_id`, and `preferred_transport`.
- Success fields: `schema_version`, `correlation_id`, `vm_lease_id`, `capture_source_kind`, `capture_source_ref`, `source_ready`, and `expires_at`.
- Failure codes: `auth_failed`, `lease_not_found`, `stream_unavailable`, `lease_state_conflict`, and `host_unavailable`.
- `capture_source_kind` is `gateway-recording` for the MVP source-of-truth path.
- The control-plane response never exposes a browser-direct endpoint.

## Event Envelope

- Proxy lifecycle events are the source of truth for frontend session state.
- Every event carries `event_id`, `schema_version`, `event_kind`, `correlation_id`, `emitted_at`, `session_id`, `vm_lease_id` when assigned, `stream_id` when assigned, `global_cursor`, and `session_seq`.
- `global_cursor` is an opaque monotonic replay cursor for the whole event stream.
- `session_seq` starts at `1` for each `session_id` and increases by exactly `1` for each subsequent event for that session.
- Frontend consumers deduplicate by `event_id`.
- Frontend consumers order events for a session by `session_seq`.
- If a consumer detects a gap in `session_seq`, it must re-run bootstrap and resume from the new replay cursor.

## Required Event Kinds

- `session.started` fields: `attacker_addr`, `listener_id`, `started_at`, and `session_state = waiting_for_lease`.
- `session.assigned` fields: `assigned_at`, `vm_lease_id`, `vm_name`, `guest_rdp_addr`, and `attestation_ref`.
- `session.stream.ready` fields: `ready_at`, `stream_id`, `transport`, `stream_endpoint`, `token_expires_at`, and `stream_state = ready`.
- `session.ended` fields: `ended_at`, `terminal_outcome`, `disconnect_reason`, and `recycle_expected`.
- `session.killed` fields: `killed_at`, `kill_scope`, `killed_by_operator_id`, and `kill_reason`.
- `session.recycle.requested` fields: `requested_at`, `recycle_reason`, and `requested_by`.
- `host.recycled` fields: `completed_at`, `recycle_state`, `quarantined`, and `quarantine_reason` when present.

## Optional Event Kinds

- `session.stream.failed` fields: `failed_at`, `failure_code`, `retryable`, and `stream_state = failed`.
- `proxy.status.degraded` fields: `degraded_at`, `reason_code`, and `affected_session_ids`.

## Frontend Bootstrap And Replay

- The frontend bootstrap path is `GET /jet/honeypot/bootstrap`.
- Bootstrap requires `gateway.honeypot.watch`.
- The bootstrap response carries `schema_version`, `correlation_id`, `generated_at`, `replay_cursor`, and `sessions`.
- Each bootstrap session item carries `session_id`, `vm_lease_id` when present, `state`, `last_event_id`, `last_session_seq`, `stream_state`, and `stream_preview` when ready.
- The live update path is `GET /jet/honeypot/events`.
- The update transport is SSE with `text/event-stream` because it is the simplest HTMX-compatible delivery mechanism and avoids a second general-purpose websocket control plane.
- The SSE request carries the last known `replay_cursor`.
- The proxy must replay events newer than that cursor before switching to live delivery.
- If the cursor is missing, expired, or invalid, the proxy returns `409 cursor_expired` and the frontend must re-run bootstrap.
- The frontend must be able to render already-running sessions entirely from bootstrap without waiting for a new attacker connect.

## Deferred Command Proposal Placeholder

- The placeholder proposal path is `POST /jet/session/{session_id}/propose` on `proxy` and `POST /session/{session_id}/propose` on `frontend`.
- The frontend route is HTMX-friendly form submission that relays to the proxy placeholder.
- The request fields are `schema_version`, `request_id`, and `command_text`.
- The success fields are `schema_version`, `correlation_id`, `proposal_id`, `recorded_at`, `session_id`, `command_text`, `proposal_state`, `decision_reason`, and `executed`.
- `proposal_state` is `deferred` for a non-empty command and `rejected` for an empty or whitespace-only command.
- `executed` is always `false` in MVP.
- The placeholder must record a proposal identifier and return a typed response, but it must not execute a guest command, persist vote state, or mutate the VM.
- The placeholder requires `gateway.honeypot.command.propose`.

## Deferred Command Voting Placeholder

- The placeholder vote path is `POST /jet/session/{session_id}/vote` on `proxy` and `POST /session/{session_id}/vote` on `frontend`.
- The frontend route is HTMX-friendly form submission that relays to the proxy placeholder.
- The request fields are `schema_version`, `request_id`, `proposal_id`, and `vote`.
- `vote` is one of `approve` or `reject`.
- The success fields are `schema_version`, `correlation_id`, `vote_id`, `recorded_at`, `session_id`, `proposal_id`, `vote`, `vote_state`, `decision_reason`, and `executed`.
- `vote_state` is `deferred` for an `approve` placeholder vote and `rejected` for a `reject` placeholder vote.
- `executed` is always `false` in MVP.
- The placeholder must record a vote identifier and return a typed response, but it must not execute a guest command, persist vote history, or mutate the VM.
- The placeholder requires `gateway.honeypot.command.approve`.

## Stream Token And Metadata Contract

- The proxy is the only service that issues browser stream tokens.
- A stream token is requested through `POST /jet/honeypot/session/{session_id}/stream-token`.
- Stream-token requests require both `gateway.honeypot.watch` and `gateway.honeypot.stream.read`.
- The request fields are `schema_version`, `request_id`, and `session_id`.
- The success fields are `schema_version`, `correlation_id`, `session_id`, `vm_lease_id`, `stream_id`, `stream_endpoint`, `transport`, `issued_at`, and `expires_at`.
- Every stream token is bound to exactly one `session_id`, one `vm_lease_id`, one `stream_id`, and one concrete `stream_endpoint`.
- Stream tokens are short-lived and must not exceed `60` seconds.
- The frontend may renew a stream token while the session is live without reconnecting the attacker.
- The MVP stream source of truth is Gateway recording and streaming reuse because it preserves the existing streamer seam and avoids introducing a fourth runtime service.
- The proxy-owned `stream_endpoint` is a browser-facing route such as `/jet/honeypot/session/{session_id}/stream?stream_id={stream_id}` rather than a raw capture-source reference.
- That route must mint a just-in-time JREC pull token and redirect into `/jet/jrec/play?isActive=true`, which then connects to `/jet/jrec/shadow/{session_id}` for live observation.
- For the Gateway recording-backed MVP, `transport = websocket` because the JREC player reaches live media through the existing shadow websocket seam while SSE remains only the session-state update transport.
- Opening or refreshing the frontend focus view while the attacker session is still active should reconnect near the live tail rather than replaying the full recording from the beginning.
- The tradeoff is higher latency and less capture flexibility than direct QEMU display capture, which is acceptable for the MVP freeze.

## `/jet/preflight` Credential Mapping Contract

- The proxy remains the only caller that uses `/jet/preflight` for honeypot guest credential provisioning.
- The proxy uses `provision-credentials` with the existing `gateway.preflight` authorization pattern.
- Each credential mapping is bound in proxy state to `session_id`, `vm_lease_id`, `credential_mapping_id`, and the backend credential reference returned by the control plane.
- The effective credential TTL defaults to `900` seconds and must not exceed `7200` seconds.
- The effective credential TTL must also not exceed the remaining lifetime of the session assignment.
- Credential mappings are revoked on normal disconnect, single-session kill, global kill, recycle request, and orphan cleanup.
- Orphan cleanup must revoke any mapping whose `session_id` no longer exists or whose lease has already entered recycle or quarantine.
- The frontend never receives raw guest credentials or credential mapping material.

## Failure Semantics

- No-lease handling emits `session.started` followed by `session.ended` with `terminal_outcome = no_lease`.
- No-lease handling must not emit `session.assigned`.
- No-lease handling presents an operator-visible capacity or availability error and triggers local session cleanup without a guest assignment.
- Boot-timeout handling emits `session.started`, `session.assigned`, `session.recycle.requested`, and `session.ended` with `terminal_outcome = boot_timeout`.
- Boot-timeout handling allows recycle but does not silently retry the attacker connection onto a second guest in the same session.
- Recycle-failure handling emits `session.recycle.requested` followed by `host.recycled` with `quarantined = true`.
- Recycle-failure handling must let operators distinguish a quarantined guest or image from an ordinary disconnect by `recycle_state` and `quarantine_reason`.
- Explicit quarantine handling emits `session.killed` with `kill_reason = operator_quarantine`, then requests `recycle_vm` with `force_quarantine = true`, and must end with `host.recycled` marked `quarantined = true`.
- Proxy or control-plane partition before lease assignment behaves like `no_lease` with an operator-visible degraded reason.
- Proxy or control-plane partition after lease assignment leaves the attacker session in its current state when possible, marks the operator surface degraded, and queues recycle or kill work until connectivity returns or a timeout forces quarantine.
- Stream-start failure does not disconnect the attacker session.
- Stream-start failure emits `session.stream.failed`, keeps the session visible in bootstrap, and allows stream recovery by requesting a fresh stream token without reconnecting the attacker.
- Single-session kill or quarantine emits `session.killed`, revokes session-bound credentials, tears down active stream tokens, and requests `recycle_vm`.
- Global kill first halts new intake, then emits `session.killed` for each live session, revokes all live stream and credential material, and requests recycle for every assigned lease.

## Observability Contract

- Every control-plane request, frontend bootstrap response, stream-token issuance, and lifecycle event carries `correlation_id`.
- `session_id`, `vm_lease_id`, and `stream_id` are the canonical identifiers for logs, metrics, and audit events.
- The current stable audit record surface is the existing typed control-plane request and response envelopes together with the honeypot lifecycle event envelopes, not a second browser-facing audit API.
- Control-plane actions are auditable by stable `request_id`, `correlation_id`, and `vm_lease_id` fields across `acquire_vm`, `reset_vm`, `release_vm`, `recycle_vm`, and `stream_endpoint`.
- Single-session kill and quarantine actions are auditable by the ordered `session.killed`, `session.recycle.requested`, and `host.recycled` event sequence bound to `operator_id`, `session_id`, `vm_lease_id`, and `correlation_id`.
- Global emergency stop is auditable by the `POST /jet/session/system/terminate` response plus the same per-session lifecycle sequence for every affected session.
- Frontend proposal and vote placeholders are auditable by their typed `proposal_id` or `vote_id`, `correlation_id`, `session_id`, and `decision_reason` fields, but they must remain non-executing and non-persistent in MVP.
- Metrics must distinguish `session_started_total`, `session_ended_total`, `session_killed_total`, `lease_acquire_fail_total`, `lease_quarantine_total`, and `stream_start_fail_total`.
- Audit events must capture `operator_id`, `actor_type`, `action`, `result`, `session_id` when present, `vm_lease_id` when present, `stream_id` when present, and `correlation_id`.
- Logs must never include raw guest credentials, stream tokens, or private key material.
