# Honeypot Fork AGENTS

## Mission

This fork turns `devolutions-gateway` into an art-piece honeypot with three runtime service domains: `control-plane`, `proxy`, and `frontend`.
The winning direction is to extend the current Gateway data plane as the proxy core, add a Rust control plane for Linux-hosted QEMU Windows 11 VMs, and add a fresh HTMX frontend around versioned contracts.

## Non-Negotiables

- Keep exactly three runtime service domains: `control-plane`, `proxy`, and `frontend`.
- Package each runtime service as its own Docker image with its own build context.
- Shared crates and docs under `honeypot/` are allowed, but they do not become extra runtime services.
- Keep the honeypot frontend separate from the existing `webapp/` codebase.
- Do not introduce Python or Bash for implementation, orchestration, image prep, or tests.
- Keep end-to-end and lab automation in Rust.
- Use Tiny11-derived Windows 11 gold images under QEMU with RDP enabled.
- Pin a Windows 11 edition that can act as an RDP host.
- Prefer extending the current Gateway primitives over rewriting RDP and CredSSP handling from scratch.
- Default non-honeypot Gateway behavior must remain unchanged unless honeypot mode is explicitly enabled.
- Keep a Docker-based bring-up path for the three honeypot services so current and previous versions can be swapped quickly during testing.
- Keyboard capture, clipboard capture, and voted command execution stay deferred or policy-gated until explicitly approved.

## Working Rules

- Keep this file task-oriented, but preserve enough repo guidance that an implementation agent can execute and verify work without hunting through old docs.
- Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests` as the baseline Rust verification path for honeypot work.
- Put new end-to-end tests in `testsuite/tests/` and new test helpers in `testsuite/src/` unless a written reason for a different harness exists.
- Follow `STYLE.md` and the IronRDP style guide for Rust style, structured logging, lowercase error messages, and one sentence per line in Markdown prose.
- Keep Docker build, bring-up, and rollback flows declarative and Rust-testable rather than hidden behind Bash or Python wrappers.
- Treat `webapp/`, PowerShell modules, and C# agent code as legacy or reference surfaces for this fork unless a task explicitly calls for compatibility validation.

## Execution Order

- [x] Treat Milestone 0 as the baseline gate before any honeypot implementation starts.
Pass when: the baseline test path is green, the workspace boundaries are documented, and the initial honeypot docs are created.

- [x] Treat Milestone 0.5 as a hard design freeze before Milestone 1 through Milestone 6 implementation starts.
Pass when: every `DF-*` row below is resolved in `docs/honeypot/decisions.md` and the owning docs it names before Milestone 1 through Milestone 6 work starts.

- [x] Keep the `Decision Freeze Matrix` and `Ownership Matrix` authoritative.
Pass when: later milestones reference `DF-*` and `OM-*` rows instead of restating the same policy or inventing a second owner for the same seam.

- [x] Do not introduce a parallel honeypot session bus, subscriber bus, credential API, or stream API unless the replaced Gateway seam and the reason reuse is insufficient are documented first.
Pass when: every new surface explicitly extends or replaces an existing seam in `rdp_proxy.rs`, `api/preflight.rs`, `session.rs`, `subscriber.rs`, `api/sessions.rs`, `api/session.rs`, or the current streaming path.

## Decision Freeze Matrix

This matrix is the canonical Milestone 0.5 design-freeze ledger.
`docs/honeypot/decisions.md` records the winner, rejected alternatives, and upgrade path for each row.
Later milestones may reference `DF-*` rows, but they must not restate policy owned here.

- `DF-01` Proxy packaging and process boundary.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/architecture.md`, and `docs/honeypot/deployment.md`.
Blocks: proxy image packaging, binary entrypoints, and Gateway integration wiring.

- `DF-02` Service-to-service authentication, operator identity, and audit envelope.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/contracts.md`, and `docs/honeypot/risk.md`.
Blocks: control-plane client auth, frontend auth, token issuance, and operator-visible actions.

- `DF-03` Session, event, and stream seam ownership.
Source of truth: this matrix, the Ownership Matrix below, `docs/honeypot/architecture.md`, and `docs/honeypot/contracts.md`.
Blocks: any new session bus, stream bus, or replacement API surface.

- `DF-04` Stream source of truth, browser update transport, and ordering model.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/contracts.md`, and `docs/honeypot/architecture.md`.
Blocks: stream token issuance, HTMX delivery, replay handling, and frontend tile behavior.

- `DF-05` Windows SKU, Microsoft ISO input, Tiny11 transformation, and gold-image attestation.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/risk.md`, and `docs/honeypot/research.md`.
Blocks: image build flow, lease integrity checks, and control-plane readiness gates.

- `DF-06` QEMU control surfaces, container runtime contract, and VM recycle semantics.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/deployment.md`, and `docs/honeypot/architecture.md`.
Blocks: control-plane lifecycle adapters, host mounts, sockets, and cleanup behavior.

- `DF-07` Registry namespace, tag policy, promotion manifest, and `honeypot/docker/images.lock` contract.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/release.md`, and `honeypot/docker/images.lock`.
Blocks: compose pinning, rollback drills, mixed-version checks, and release validation.

- `DF-08` Runtime config mounts, secret mounts, retention and redaction, emergency stop, and quarantine policy.
Source of truth: `docs/honeypot/decisions.md`, `docs/honeypot/deployment.md`, and `docs/honeypot/risk.md`.
Blocks: service startup contracts, kill switches, evidence handling, and host compromise response.

- `DF-09` Test tier boundary and explicit lab gate.
Source of truth: `docs/honeypot/decisions.md` and `testsuite`.
Blocks: `contract`, `host-smoke`, and `lab-e2e` scheduling plus CI-safe coverage.

## Service Boundaries

### Control Plane

The control plane owns QEMU lifecycle, image preparation, image provenance, VM pool management, session-to-VM assignment, reset, recycle, host-side safety controls, and lease cleanup.

### Proxy

The proxy owns the public listener, the full connection state machine, attacker-to-backend credential replacement, session lifecycle, control-plane coordination, and frontend-facing event emission.
The proxy stays rooted in the existing Gateway code path instead of replacing `rdp_proxy.rs`.

### Frontend

The frontend is a fresh HTMX application that shows live attacker sessions as tiled streams, removes tiles on disconnect, bootstraps already-running sessions, and expands a tile to fullscreen on click.
Future interactive features such as keyboard capture, clipboard capture, and voted command execution remain gated behind policy and audit controls.

## Ownership Matrix

This matrix is the canonical seam ownership map for the three runtime services.
Any new API, event loop, or background worker must extend one row below or document a replacement in `docs/honeypot/architecture.md` and `docs/honeypot/decisions.md` first.

- `OM-01` VM lifecycle, lease state, host emergency stop, and guest quarantine belong to `control-plane`.
Source of truth: `honeypot/control-plane/`, `docs/honeypot/architecture.md`, and `docs/honeypot/contracts.md`.
Reuse anchor: extend the typed control-plane API instead of inventing a second lease controller.

- `OM-02` Attacker session lifecycle, credential substitution, and terminal outcomes belong to `proxy`.
Source of truth: `devolutions-gateway/src/rdp_proxy.rs`, `devolutions-gateway/src/session.rs`, `devolutions-gateway/src/subscriber.rs`, and `docs/honeypot/contracts.md`.
Reuse anchor: extend `rdp_proxy.rs`, `api/preflight.rs`, `session.rs`, and `subscriber.rs`.

- `OM-03` Session discovery, replay bootstrap, stream tokens, and frontend event emission belong to `proxy`.
Source of truth: `devolutions-gateway/src/api/sessions.rs`, `devolutions-gateway/src/api/session.rs`, and `docs/honeypot/contracts.md`.
Reuse anchor: reuse `/jet/sessions`, `/jet/session/{id}/terminate`, and the existing streaming path unless `DF-03` documents a replacement.

- `OM-04` Browser presentation, operator workflows, and policy-gated future interaction surfaces belong to `frontend`.
Source of truth: `honeypot/frontend/`, `docs/honeypot/contracts.md`, and `docs/honeypot/risk.md`.
Reuse anchor: keep the honeypot UI separate from `webapp/` and consume versioned contracts from `proxy`.

- `OM-05` Cross-service authn and authz material plus audit correlation belong to `proxy` as the public trust boundary, with contract shapes shared in `honeypot/contracts/`.
Source of truth: `docs/honeypot/contracts.md`, `docs/honeypot/risk.md`, and `devolutions-gateway/src/middleware/auth.rs`.
Reuse anchor: reuse Gateway auth patterns where they fit, but keep the owning contract in the honeypot docs.

## Reuse-First Map

- [x] Keep `devolutions-gateway/src/rdp_proxy.rs` as the primary RDP MiTM data-plane foundation.
Pass when: the proxy design doc says "extend" or "wrap" this path rather than "replace".

- [x] Do not create a parallel session, subscriber, credential-mapping, or stream control stack unless `docs/honeypot/architecture.md` names the replaced Gateway seam and why reuse is insufficient.
Pass when: any new surface explicitly extends or replaces `session.rs`, `subscriber.rs`, `api/preflight.rs`, `api/sessions.rs`, `api/session.rs`, or the existing streaming path.

- [x] Reuse `devolutions-gateway/src/api/preflight.rs` for short-lived credential mapping instead of inventing a second credential provisioning API.
Pass when: the control-plane and proxy contracts explicitly reference `provision-credentials`.

- [x] Extend `devolutions-gateway/src/session.rs` and `devolutions-gateway/src/subscriber.rs` to publish honeypot session state and frontend event payloads.
Pass when: the event schema covers start, assignment, stream ready, disconnect, kill, recycle requested, and recycled outcomes.

- [x] Review `devolutions-gateway/src/api/sessions.rs` and `devolutions-gateway/src/api/session.rs` before inventing new session-management APIs.
Pass when: the plan either reuses `/jet/sessions` and `/jet/session/{id}/terminate` or documents replacement endpoints and why they are necessary.

- [x] Review `devolutions-gateway/src/recording.rs`, `devolutions-gateway/src/streaming.rs`, `devolutions-gateway/src/ws.rs`, `crates/transport/src/ws.rs`, `crates/video-streamer`, and `crates/terminal-streamer` before building new browser-stream code.
Pass when: the stream plan names the reuse points or explains why they are insufficient.

- [x] Review `devolutions-gateway/src/api/webapp.rs` for token issuance and auth ideas only.
Pass when: the honeypot frontend keeps its own UI code while reusing only the auth and token patterns that still fit.

- [x] Review and document the existing Gateway integration seams in `devolutions-gateway/src/lib.rs`, `devolutions-gateway/src/service.rs`, `devolutions-gateway/src/api/mod.rs`, `devolutions-gateway/src/extract.rs`, and `devolutions-gateway/src/middleware/auth.rs`.
Pass when: `docs/honeypot/architecture.md` states exactly where honeypot state, routes, scopes, and background tasks plug into the current binary.

- [x] Review `testsuite/src/dgw_config.rs` before inventing a second test bootstrap path.
Pass when: the honeypot test plan either extends this helper or documents why it cannot.

- [x] Write `docs/honeypot/research.md` evaluation notes for `devolutions-session`, `devolutions-agent`, `jetsocat`, `crates/transport`, `testsuite`, `video-streamer`, and `terminal-streamer`.
Pass when: each candidate is labeled `reuse`, `adapt`, or `do not use` with a one-sentence rationale.

- [x] Review `devolutions-agent` and `devolutions-session` for patterns only, and explicitly record whether they are out of scope for the Linux-hosted control plane.
Pass when: `docs/honeypot/research.md` says what was learned and why they are or are not reused.

- [x] Record external repo evaluation notes for `Devolutions/IronRDP`, `Devolutions/sspi-rs`, `FreeRDP/FreeRDP`, `Devolutions/MsRdpEx`, `Devolutions/picky-rs`, `Devolutions/DevoSamples-ps`, and `Devolutions/RdpCredProv`.
Pass when: each repo is mapped to a concrete use, validation role, or explicit non-use decision, and `RdpCredProv` is marked validation-only or non-use for NLA-based credential substitution.

- [x] Record how the in-tree `cadeau` dependency and `devolutions-labs` affect the honeypot plan.
Pass when: `docs/honeypot/research.md` labels `cadeau` as a reuse or validation input and marks `devolutions-labs` as optional, validation-only, or non-use unless a concrete lab role is documented.

- [x] Keep `package/Linux/Dockerfile` and the legacy gateway container packaging path as reference-only unless a honeypot service explicitly reuses a safe fragment.
Pass when: the honeypot `proxy` and `frontend` images do not inherit the current gateway or webapp container bundle by accident.

## Cross-Service Contracts

- [x] Add `honeypot/contracts/Cargo.toml` and `honeypot/contracts/src/lib.rs` as the shared versioned contracts crate used by `control-plane`, `proxy`, and `frontend`.
Pass when: the workspace has one canonical contracts crate path and no duplicated JSON shape definitions across services.

- [x] Add `docs/honeypot/contracts.md` as the single source of truth for control-plane, proxy, stream, and frontend payloads.
Pass when: APIs, events, stream metadata, auth scopes, and failure semantics are versioned in one place.

- [x] Define the service-to-service authentication and authorization contract.
Pass when: `docs/honeypot/contracts.md` names how `proxy` authenticates to `control-plane`, how `frontend` authenticates to `proxy`, where trust material comes from, how it rotates, and what happens on auth failure.

- [x] Define the control-plane API for `acquire_vm`, `release_vm`, `reset_vm`, `recycle_vm`, `health`, and `stream_endpoint`.
Pass when: every call has request and response shapes plus failure semantics.

- [x] Define the proxy event schema as the source of truth for session lifecycle.
Pass when: the schema includes `session.started`, `session.assigned`, `session.stream.ready`, `session.ended`, `session.killed`, `session.recycle.requested`, and `host.recycled`.

- [x] Version every honeypot event with `event_id`, `schema_version`, and ordering semantics.
Pass when: producers and consumers document replay, deduplication, and out-of-order handling.

- [x] Define backward-compatibility rules for mixed-version service peers.
Pass when: `docs/honeypot/contracts.md` says which `current` and `previous` image combinations are supported for `control-plane`, `proxy`, and `frontend`, and whether both `current -> previous` and `previous -> current` rejoin are supported for each contract family.

- [x] Define a frontend bootstrap API plus event replay model for live sessions.
Pass when: a newly opened frontend can render already-running sessions without waiting for a fresh connect event.

- [x] Define how `/jet/preflight` credential mappings are bound to a session, expire, and revoke early.
Pass when: the TTL, disconnect cleanup path, kill path, recycle path, and orphan cleanup guarantees are documented.

- [x] Define the stream token and metadata contract.
Pass when: every stream is bound to `session_id`, `vm_lease_id`, a short-lived token, and a concrete stream endpoint.

- [x] Define the frontend update transport with a bias toward simple HTMX-compatible delivery.
Pass when: the design chooses SSE, long-polling, or a minimal websocket bridge and documents why.

- [x] Define the source of truth for live video streaming.
Pass when: the design chooses between Gateway recording/streaming reuse, QEMU display capture, or another capture path and names the tradeoff.

- [x] Define frontend operator authentication and voting authorization.
Pass when: the plan states the identity source, the authentication flow, who may watch, who may propose commands, who may approve execution, who may kill sessions, and which audit fields bind actions to operator identity.

- [x] Define no-lease failure handling across control plane, proxy, and frontend.
Pass when: `docs/honeypot/contracts.md` says what operators and the frontend see when no VM lease is available, which events are emitted, and how cleanup is triggered.

- [x] Define boot-timeout failure handling across control plane, proxy, and frontend.
Pass when: `docs/honeypot/contracts.md` says what happens when a guest fails to reach ready state in time, which events are emitted, and whether retry, kill, or recycle is allowed.

- [x] Define recycle-failure handling across control plane, proxy, and frontend.
Pass when: `docs/honeypot/contracts.md` says how a failed reset or recycle is surfaced, how the guest is quarantined, and how operators distinguish it from ordinary disconnects.

- [x] Define proxy or control-plane partition handling.
Pass when: `docs/honeypot/contracts.md` says what happens when the proxy cannot reach the control plane, how sessions degrade, and which operator-visible status is emitted.

- [x] Define stream-start failure handling.
Pass when: `docs/honeypot/contracts.md` says how stream bootstrap failure is reported, how the frontend behaves, and whether session observation can recover without reconnecting the attacker.

- [x] Define kill-switch handling.
Pass when: `docs/honeypot/contracts.md` says how single-session and global kill actions terminate sessions, revoke credentials, tear down streams, and request recycle.

- [x] Define the observability contract.
Pass when: logs, metrics, audit events, and correlation IDs are named for `session_id`, `vm_lease_id`, and `stream_id`.

## Container Delivery And Rollback

This section is the single source of truth for Docker topology, image naming, registry and digest policy, rollout flow, and rollback behavior.
Rows `DF-07` and `DF-08` freeze the policy here.
Milestones below should consume these decisions rather than restate them.

- [x] Add `honeypot/docker/control-plane/Dockerfile`, `honeypot/docker/proxy/Dockerfile`, and `honeypot/docker/frontend/Dockerfile`.
Pass when: each runtime service has its own explicit Dockerfile path, build context, and image target, and no image merges multiple runtime responsibilities.

- [x] Add `honeypot/docker/compose.yaml` for the three-service stack.
Pass when: the compose file defines the three services, their networks, volumes, healthchecks, and startup order without introducing extra runtime services.

- [x] Add `docs/honeypot/deployment.md` as the source of truth for Docker topology, networks, volumes, healthchecks, startup order, and rollback flow.
Pass when: a reader can bring up, downgrade, and restore the three-service stack from repo docs alone, with compose service IDs `control-plane`, `proxy`, and `frontend`, one fixed compose project naming rule, and exact runtime env-file paths recorded under `honeypot/docker/`.

- [x] Add `docs/honeypot/release.md` as the source of truth for registry namespaces, tag scheme, digest promotion, and rollback policy.
Pass when: a reader can tell where images are published, which commit-SHA and release-tag variants exist, which validation paths reject floating tags, and how a prior version is restored without rebuilding.

- [x] Define the promotion manifest that alone may update `honeypot/docker/images.lock`.
Pass when: `release.md` names the immutable or attested input, the fields it carries, and the validation path that rejects stale, unsigned, or mismatched updates.

- [x] Add `honeypot/docker/images.lock` for `control-plane`, `proxy`, and `frontend`.
Pass when: compose and Rust tests can read the exact `current` and `previous` digests for each service from this one file.

- [x] Define the `honeypot/docker/images.lock` schema.
Pass when: the file contains top-level `control-plane`, `proxy`, and `frontend` entries, and each service entry records `image`, `registry`, `current.tag`, `current.digest`, `current.source_ref`, `previous.tag`, `previous.digest`, and `previous.source_ref`.

- [x] Define service image naming and registry namespaces.
Pass when: `control-plane`, `proxy`, and `frontend` each have one canonical image name and registry namespace recorded in `release.md`.

- [x] Define semver-tag and commit-SHA tag policy.
Pass when: `release.md` says which tag variants are emitted for each service, which variant compose may use for human-readable inspection, and that validation still resolves digests from `honeypot/docker/images.lock`.

- [x] Define previous-version retention and promotion-by-digest policy.
Pass when: each service can be pinned to a current and prior image without rebuilding, without relying on `latest`, and with a documented promotion path by digest.

- [x] Define service-specific env-file and mounted-config contracts for containerized runtime.
Pass when: `control-plane`, `proxy`, and `frontend` each have documented env-file paths, mounted config paths, and restart-safe config behavior.

- [x] Define service-specific secret-mount contracts for containerized runtime.
Pass when: `control-plane`, `proxy`, and `frontend` each have documented secret mount paths, ownership expectations, and reload or restart semantics without baking secrets into images.

- [x] Define the control-plane container least-privilege contract for `/dev/kvm`, host mounts, qcow2 storage, QMP or QGA sockets, and networking.
Pass when: allowed devices, mounts, ownership, capabilities, network mode, and forbidden defaults are explicitly documented.

- [x] Define a `docker compose`-style local bring-up and rollback flow for the three services only.
Pass when: `honeypot/docker/compose.yaml` consumes `honeypot/docker/images.lock`, resolves each service by pinned digest rather than floating tag, the stack starts in dependency order, reports health, and can revert one service to the previously pinned image while the other two remain current.

## Milestone 0: Baseline, Safety, and Repo Boundaries

- [x] Add a `honeypot/` workspace area for the new service code and shared contracts.
Pass when: the root workspace and directory layout make the new surfaces obvious without introducing extra runtime services.

- [x] Add concrete crate and entrypoint anchors for the new honeypot workspaces.
Pass when: `honeypot/contracts/Cargo.toml`, `honeypot/contracts/src/lib.rs`, `honeypot/control-plane/Cargo.toml`, `honeypot/control-plane/src/main.rs`, `honeypot/frontend/Cargo.toml`, and `honeypot/frontend/src/main.rs` exist, or the repo pins a documented alternative entrypoint before implementation starts.

- [x] Add the initial honeypot container layout under `honeypot/docker/`.
Pass when: the repo contains `honeypot/docker/control-plane/Dockerfile`, `honeypot/docker/proxy/Dockerfile`, `honeypot/docker/frontend/Dockerfile`, `honeypot/docker/compose.yaml`, and `honeypot/docker/images.lock` before service implementation starts.

- [x] Add `docs/honeypot/architecture.md` with trust boundaries, event flow, credential flow, stream flow, and kill-switch behavior.
Pass when: a reviewer can trace attacker traffic from the public listener to VM recycle in one diagram.

- [x] Add `docs/honeypot/risk.md` covering legal scope, authorization requirements, exposure limits, Tiny11 artifact provenance, operator-content handling, and teardown policy.
Pass when: the repo states that this is for authorized defensive research only and names the major operational risks.

- [x] Add `docs/honeypot/research.md` summarizing local reuse points and useful external repos.
Pass when: the file names the local reuse anchors and the external repos to consult before implementation.

- [x] Add `docs/honeypot/deployment.md` for the Dockerized three-service stack.
Pass when: the doc names compose service IDs, service images, project naming, env-file paths, networks, volumes, healthchecks, runtime config injection, and rollback expectations.

- [x] Add `docs/honeypot/release.md` for service image publication and rollback policy.
Pass when: the doc names registry namespaces, tag and digest policy, image promotion flow, and current or previous version retention.

- [x] Freeze the current non-honeypot behavior before starting fork work.
Pass when: `cargo test -p testsuite --test integration_tests` is a known baseline and the existing routes still behave as before.

- [x] Add the honeypot config surface to `devolutions-gateway/src/config.rs` and `config_schema.json`.
Pass when: honeypot mode, control-plane endpoint, stream policy, operator auth, kill-switch settings, and frontend settings are represented in code and schema.

- [x] Extend `testsuite/src/dgw_config.rs` for honeypot mode, control-plane endpoint, operator auth, and stream settings.
Pass when: Rust integration tests can boot honeypot-mode Gateway config without handwritten JSON blobs.

- [x] Define the test tiers and lab gating strategy.
Pass when: the repo states the `contract`, `host-smoke`, and `lab-e2e` tiers, which tests may touch QEMU, and how the lab tier is explicitly gated.

## Milestone 0.5: Research and Design Freeze

### Milestone 0.5a: Decision Ledger And Release Freeze

- [x] Add `docs/honeypot/decisions.md` for blocking architectural choices.
Pass when: each `DF-*` row records the winner, rejected alternatives, upgrade path, and links to the owning docs.

- [x] Resolve `DF-01`, `DF-07`, and `DF-09` before service implementation starts.
Pass when: proxy packaging, release namespace and tagging, promotion policy, `images.lock`, and the `contract`, `host-smoke`, and `lab-e2e` gate are frozen in the owning docs, and later milestones reference those rows instead of redefining them.

### Milestone 0.5b: Host, Image, And Runtime Freeze

- [x] Resolve `DF-05` and `DF-06` before the control plane is implemented.
Pass when: Windows SKU, ISO inputs, Tiny11 provenance, sealing steps, QEMU controls, runtime contract, and recycle semantics are captured in the owning docs named by those rows.

### Milestone 0.5c: Proxy, Stream, And Ownership Freeze

- [x] Resolve `DF-03` and `DF-04` before proxy or frontend implementation starts.
Pass when: the stream source, browser transport, ordering model, and seam ownership map are frozen in the owning docs, and no later milestone creates a second session or stream control stack without an explicit replacement note.

### Milestone 0.5d: Frontend, Operator, And Trust Decisions

- [x] Record the MVP status of keyboard capture, clipboard capture, and voted command execution under `DF-02` and `DF-08`.
Pass when: each feature is marked `deferred`, `stubbed`, or `approved for MVP`, and any approved surface names an authz and audit owner.

- [x] Resolve `DF-02` before any operator-facing surface is implemented.
Pass when: the plan names the service-to-service auth model, the operator identity source, the watch, propose, approve, and kill roles, and the audit fields that bind every action to an operator identity.

- [x] Resolve `DF-08` before the first live-stream or evidence surface is implemented.
Pass when: the plan states who can halt the whole stack, how a broken host or image is quarantined, how live sessions, leases, tokens, and backend credentials are revoked, what is stored, how secrets and PII are redacted, how long artifacts live, and how operators export evidence safely.

- [x] Resolve the provenance and promotion checks in `DF-05` and `DF-07` before the control plane is implemented.
Pass when: the docs name the source ISO, checksums, transformation steps, and the immutable or attested promotion input that both `images.lock` and the control plane consume.

- [x] Freeze implementation only after the design set is complete.
Pass when: every `DF-*` row is resolved, `docs/honeypot/decisions.md` links to the owning docs for each row, and no Milestone 1 through Milestone 6 implementation work has started early.

## Milestone 1: Gold Image and Control Plane Foundations

- [x] Create the Rust control-plane service under `honeypot/control-plane/`.
Pass when: the service exposes a stable API skeleton and a health endpoint.

- [x] Wire the `control-plane` binary into the established image target.
Pass when: the service starts from the chosen `honeypot/docker/control-plane/` image target directly without Bash or Python entrypoint glue.

- [x] Add a typed Gateway-side control-plane client and wire it through Gateway state.
Pass when: the proxy can acquire, release, reset, and recycle VMs through typed Rust calls rather than ad hoc requests.

- [x] Wire control-plane runtime config injection.
Pass when: the service receives QEMU settings and image paths through documented env or mounted files.

- [x] Wire control-plane secret injection.
Pass when: backend credentials and similar sensitive inputs arrive through the documented runtime contract without being baked into the image.

- [x] Wire control-plane host mounts and socket paths.
Pass when: the service consumes only the documented host mount paths and socket paths from `deployment.md`.

- [x] Wire control-plane device access and startup contract.
Pass when: the service consumes only the documented `/dev/kvm` and related startup contract from `deployment.md`.

- [x] Add QEMU command building and config validation in Rust.
Pass when: VM launch parameters, sockets, disks, CPU, memory, and network settings are derived from typed config rather than shell snippets.

- [x] Add control-plane container health and readiness checks.
Pass when: compose and Rust tests can distinguish startup, healthy, degraded, and unsafe host-integration states.

- [x] Implement VM lifecycle adapters for create, start, stop, and reset.
Pass when: the control plane can drive a named VM through the active runtime lifecycle and surface actionable errors.

- [x] Implement VM lifecycle adapters for destroy and recycle.
Pass when: the control plane can retire, reset, or recycle a named VM back to the chosen clean state and surface actionable errors.

- [x] Build or consume the Tiny11-derived Windows 11 gold image flow without Bash or Python wrappers.
Pass when: the image process is reproducible, documented, records provenance inputs, and produces a version-pinned base artifact.

- [x] Add a canonical Tiny11 availability and readiness gate for lab-backed runs.
Pass when: if the documented canonical Tiny11-derived image or trusted interop store is absent, the repo has one sanctioned path to create or import it for use, and if it already exists, every relevant test run executes heuristics that confirm provenance binding, expected clean-state, and required readiness before the run may proceed.

- [x] Clone the working `kvm-win11` gold image into a dedicated Tiny11-prep workspace before any transformation.
Pass when: the prep flow records the source `kvm-win11` image and firmware state it cloned from, uses a distinct target path that does not mutate the working gold image in place, and leaves the original `kvm-win11` lab bootable for fallback use.

- [x] Boot the cloned `kvm-win11` prep image and confirm it reaches a known pre-transformation ready state under QEMU.
Pass when: the cloned VM can be started intentionally, the prep notes record the boot path and guest identity used for the session, and the clone is ready for Tiny11 modification without relying on the original gold image staying powered on.

- [x] Apply the approved Tiny11 transformation scripts to the cloned `kvm-win11` prep image and capture the resulting provenance inputs.
Pass when: the transformation runs against the clone rather than the original working image, the script references and digests needed for later manifest attestation are recorded, and the transformed output is ready for post-transform RDP verification plus sanctioned `consume-image` import into the canonical interop store.

- [x] Enable and verify RDP in the gold image.
Pass when: a fresh VM from the gold image reaches a known-ready signal and accepts RDP on TCP 3389 in the lab.

- [x] Close the authentication gap between the manually verified Tiny11 image and the control-plane-launched imported Tiny11 lease path.
Pass when: the same approved RDP credentials that succeed against the manually verified Tiny11 boot also succeed through the sanctioned `consume-image` plus control-plane lease path, and the repo records whether the remaining difference was guest policy, runtime launch shape, or another control-plane assumption.

- [x] Prove whether the trusted-image contract needs boot-critical firmware or NVRAM state in addition to the imported qcow2 artifact.
Pass when: the repo either demonstrates that qcow2-only import preserves the boot and auth state needed for the control-plane RDP acceptance lane, or it extends the trusted-image contract and runtime launch path to carry the additional sealed firmware inputs required for that proof.

- [x] Seal the manually verified Tiny11 boot profile into the trusted-image contract instead of treating the imported qcow2 as self-contained.
Pass when: the sanctioned import path records and validates the firmware code input, writable vars input, disk interface, NIC model, and any other boot-critical launch-shape inputs that were required for the manually verified Tiny11 auth success.

- [x] Replay the sealed Tiny11 boot profile through a control-plane launch and prove it preserves the manually verified auth behavior.
Pass when: a control-plane-launched imported Tiny11 lease using the sealed boot profile accepts the same approved RDP credentials that succeeded in the manual-good verification lane, and the repo records which launch-shape inputs were actually required.

- [x] Bound trusted-image validation latency so authenticated health and acquire can reach QEMU launch for large imported Tiny11 images.
Pass when: authenticated `/api/v1/health` and `/api/v1/vm/acquire` stop synchronously rehashing multi-gigabyte imported qcow2 artifacts on every request, and a sealed-profile imported Tiny11 store can reach VM launch within the documented lab-e2e readiness window.

- [x] Decide whether startup-time full attestation of large imported trusted images should remain on the control-plane boot path.
Pass when: the repo either accepts the measured startup-time full-hash cost for large imported Tiny11 stores as part of the documented readiness budget, or it adds a narrower preload or refresh contract that preserves fail-closed behavior without reintroducing request-path qcow2 hashing.

- [x] Add image integrity checks before lease.
Pass when: the control plane verifies qcow2 chain health and refuses to lease dirty or corrupt images.

- [x] Implement a VM pool with deterministic naming, lease tracking, and recycle-on-release behavior.
Pass when: one session maps to one VM lease and a released VM returns to the chosen clean state.

- [x] Add orphaned QEMU, socket, overlay, and lease cleanup.
Pass when: stale QEMU processes, QMP or QGA sockets, overlays, tempdirs, and lease artifacts are reclaimed deterministically after crashes or abandoned sessions.

- [x] Add host-side resource and network controls.
Pass when: CPU, memory, disk, outbound routing, control sockets, and emergency stop limits are enforced per VM.

- [x] Add secret storage for backend credentials with a replaceable adapter.
Pass when: credentials are never printed to logs and the adapter boundary is testable.

- [x] Add a gold-image acceptance test.
Pass when: a newly produced image boots, reaches a known-ready signal, accepts RDP, exposes any required control channels, and tears down without leaked host artifacts.

## Milestone 2: Proxy Honeypot Mode

- [x] Add an explicit honeypot proxy mode instead of mutating the default Gateway path silently.
Pass when: non-honeypot behavior stays unchanged unless honeypot mode is enabled.

- [x] Wire the `proxy` binary into the established image target.
Pass when: the service starts from the chosen `honeypot/docker/proxy/` image target and does not inherit the legacy gateway or webapp container bundle by accident.

- [x] Wire proxy listener and control-plane endpoint config.
Pass when: public listener config and control-plane endpoint flow through documented env or mounted files.

- [x] Wire proxy frontend event delivery config.
Pass when: the frontend event delivery path flows through documented env or mounted files.

- [x] Wire proxy backend credential material injection.
Pass when: backend credential material is injected through the documented runtime contract without being baked into the image.

- [x] Wire proxy token-secret injection.
Pass when: token-related secrets are injected through the documented runtime contract without being baked into the image.

- [x] Bind attacker-facing credentials to backend credentials through `/jet/preflight`.
Pass when: the attacker can authenticate through the proxy while the VM only receives the stored backend credentials.

- [x] Add immediate session-bound credential revocation on disconnect, kill, and recycle in addition to TTL cleanup.
Pass when: `/jet/preflight` mappings are removed deterministically before the periodic credential-store cleanup window.

- [x] Extend `devolutions-gateway/src/session.rs` with honeypot metadata for attacker source, assigned VM, stream metadata, and terminal outcome.
Pass when: the proxy-visible session model can distinguish disconnect, kill, recycle, assignment, and stream readiness without scraping logs.

- [x] Extend the session state machine to include honeypot-specific lifecycle states.
Pass when: the proxy can emit connected, assigned, ready, disconnected, killed, recycle requested, and recycled outcomes.

- [x] Extend subscriber and traffic signals so the frontend can track tiles without scraping logs.
Pass when: the frontend can discover live sessions and terminal states through structured events and APIs.

- [x] Reuse `/jet/sessions` and `/jet/session/{id}/terminate` where possible.
Pass when: the plan either reuses these surfaces or documents replacement endpoints and why they are needed.

- [x] Add stream token issuance and stream metadata to the proxy-visible model.
Pass when: a session event includes enough data for the frontend to open, replay, and close a tile deterministically.

- [x] Add explicit guest assignment and recycle markers to session events.
Pass when: the frontend can tell the difference between attacker disconnect, operator kill, no-lease failure, and VM recycle.

- [x] Add quarantine controls.
Pass when: the operator can quarantine a broken or suspicious session or guest without leaving live credential mappings behind.

- [x] Add kill-switch controls.
Pass when: the operator can revoke one session or all active sessions and the proxy tears down credential mappings and VM leases cleanly.

- [x] Add partition and timeout handling between proxy and control plane.
Pass when: no-lease, boot-timeout, recycle-failure, and control-plane-unavailable states are visible and recoverable.

- [x] Add proxy container health and readiness checks.
Pass when: compose and Rust tests can distinguish healthy listener startup from dependency failures in the control plane or stream path.

## Milestone 3: Frontend MVP

- [x] Create a fresh HTMX frontend under `honeypot/frontend/`.
Pass when: the implementation does not import or depend on the current `webapp/` application code.

- [x] Wire the `frontend` application into the established image target.
Pass when: the service starts from the chosen `honeypot/docker/frontend/` image target and does not package the existing `webapp/` application.

- [x] Wire frontend proxy event endpoint settings.
Pass when: the service consumes only documented env or mounted config for proxy event endpoints.

- [x] Wire frontend stream endpoint settings.
Pass when: the service consumes only documented env or mounted config for stream endpoints.

- [x] Wire frontend operator auth config.
Pass when: the service consumes only documented env or mounted config for operator auth.

- [x] Wire frontend session bootstrap and runtime toggles.
Pass when: the service consumes only documented env or mounted config for session bootstrap behavior and runtime toggles.

- [x] Implement operator authentication and watch authorization for the frontend.
Pass when: anonymous access is either forbidden or explicitly documented as lab-only mode.

- [x] Implement a bootstrap view for already-running sessions.
Pass when: opening the frontend renders live sessions immediately instead of waiting for a new event.

- [x] Implement the tiled live-session dashboard.
Pass when: active sessions render as tiles with status, origin, target VM, session age, and stream readiness.

- [x] Implement fullscreen stream mode on tile click.
Pass when: clicking a tile expands the session stream and closing it returns to the grid.

- [x] Implement disconnect-driven tile removal.
Pass when: `session.ended`, `session.killed`, and recycle terminal events remove or update tiles without a manual refresh.

- [x] Add a command proposal skeleton for future state-messing features.
Pass when: a command can be proposed, recorded, and rejected or deferred without execution.

- [x] Add a command voting skeleton for future state-messing features.
Pass when: proposed commands can be voted on, but execution stays policy-gated.

- [x] Add a keyboard capture placeholder behind explicit policy checks.
Pass when: the endpoint exists as a stub and returns a structured `disabled_by_policy` response until intentionally enabled.

- [x] Add a clipboard capture placeholder behind explicit policy checks.
Pass when: the endpoint exists as a stub and returns a structured `disabled_by_policy` response until intentionally enabled.

- [x] Add frontend container health and readiness checks.
Pass when: compose and Rust tests can detect successful startup, bootstrap API reachability, and stream-tile readiness.

## Milestone 4: Stream Delivery Path

- Live-stream note: the MVP media path reuses the existing Gateway JREC player and shadow websocket seam rather than WebRTC.
Pass when: active observation uses `/jet/jrec/play?isActive=true` plus `/jet/jrec/shadow/{session_id}`, browser refresh during an active session reconnects near the live tail instead of replaying the full recording from the beginning, and only the post-disconnect fallback may return to static playback from the start.

- [x] Implement the chosen live-stream source adapter for the frontend.
Pass when: the MVP stream source is wired into the stack without inventing an unreviewed second capture path.

- [x] Implement the chosen frontend stream transport adapter.
Pass when: the MVP browser delivery path is wired end to end without inventing an unreviewed second browser-transport stack.

- [x] Bind every live stream to `session_id`, `vm_lease_id`, and a short-lived stream token.
Pass when: the frontend cannot confuse one attacker tile with another after reconnects or rapid lease churn.

- [x] Validate stream startup and replay behavior.
Pass when: tiles can open from bootstrap state and survive expected update ordering.

- [x] Validate stream shutdown behavior.
Pass when: tiles close cleanly on disconnect or recycle.

- [x] Reuse or explicitly reject existing Gateway streaming and media code.
Pass when: the implementation names the reuse points in `recording.rs`, `streaming.rs`, `ws.rs`, `crates/transport`, `video-streamer`, and `terminal-streamer`, or explains why they are insufficient.

- [x] Add stream provenance and isolation tests.
Pass when: the lab proves where video comes from, how it is authenticated, and that one session cannot read another session's stream.

## Milestone 5: Rust E2E and Lab Validation

### Milestone 5a: Container Smoke And Pinning

- [x] Implement the `contract`, `host-smoke`, and `lab-e2e` test tiers in Rust.
Pass when: each new honeypot test fits one named tier, CI-safe checks do not require QEMU, and the lab tier only runs when explicitly enabled.

- [x] Add a Rust-native tier gate that blocks `lab-e2e` until `contract` and `host-smoke` pass.
Pass when: lab selection is enforced by Rust test selection or a repo-local Rust-readable manifest rather than Bash or Python wrappers.

- [x] Pin `current` and `previous` image digests before deeper lab work starts.
Pass when: the Docker smoke and compose tiers read the exact `current` and `previous` digests for each service from `honeypot/docker/images.lock` before rollback or lab tests run.

- [x] Add a Rust lockfile-schema validation test for `honeypot/docker/images.lock`.
Pass when: tests fail if `control-plane`, `proxy`, or `frontend` is missing, if `current` or `previous` digest fields are missing, or if validation paths try to use a floating tag.

- [x] Add a Rust Docker smoke-test tier for the three service images.
Pass when: Rust tests can build or pull `control-plane`, `proxy`, and `frontend`, start them in dependency order, and verify their health endpoints without the full QEMU lab.

- [x] Add a Rust pull-by-digest smoke test for the three service images.
Pass when: Rust tests can pull or resolve each service by pinned digest rather than floating tag, and fail if compose or release inputs bypass `honeypot/docker/images.lock` before bring-up or rollback verification.

### Milestone 5b: Compose Bring-Up And Mixed-Version Checks

- [x] Add a Rust compose bring-up test for the three-service stack.
Pass when: the test boots the Dockerized stack with documented networks and volumes, resolves service images from `honeypot/docker/images.lock`, verifies inter-service wiring, and tears it down cleanly.

- [x] Add a compose lockfile-conformance test.
Pass when: the three-service stack refuses validation if a service image reference bypasses `honeypot/docker/images.lock` or resolves a floating tag.

- [x] Add a downgraded `control-plane` compose compatibility test.
Pass when: the test boots `previous/current/current` and verifies the downgraded `control-plane` can rejoin two current peers safely.

- [x] Add a downgraded `proxy` compose compatibility test.
Pass when: the test boots `current/previous/current` and verifies the downgraded `proxy` can rejoin two current peers safely.

- [x] Add a downgraded `frontend` compose compatibility test.
Pass when: the test boots `current/current/previous` and verifies the downgraded `frontend` can rejoin two current peers safely.

### Milestone 5c: Contract And Lab Harness Validation

- [x] Keep honeypot e2e coverage inside `testsuite/tests/` and the existing `integration_tests` harness unless a split is justified.
Pass when: the test layout remains discoverable and any new harness has a written reason.

- [x] Add contract tests for config parsing, schema versioning, and event payloads.
Pass when: honeypot config and event contracts fail fast on incompatible changes without requiring the QEMU lab.

- [x] Add a Rust-driven lab harness startup and readiness test for QEMU lifecycle on a POSIX host.
Pass when: tests can start the lab and wait for RDP readiness without manual intervention.

- [x] Add a Rust-driven lab harness teardown cleanliness test.
Pass when: the lab tears down without orphaned QEMU processes, sockets, overlays, tempdirs, containers, networks, or volumes.

### Milestone 5d: Control-Plane And Proxy End-To-End Flows

- [x] Add an end-to-end credential replacement test.
Pass when: the test provisions a VM, posts a credential mapping, opens an attacker-facing RDP connection, and proves the VM received the backend credentials instead of the attacker credentials.

- [x] Add a session visibility and replay test.
Pass when: the test sees the session in `/jet/sessions`, receives the frontend bootstrap and event payloads, and observes stream metadata.

### Milestone 5e: Frontend And Session Stream End-To-End Flows

- [x] Add a frontend stream lifecycle test.
Pass when: the backend announces a stream, the frontend opens a tile, fullscreen works, and disconnect or recycle removes the tile.

- [x] Add a recycle-and-cleanup test.
Pass when: terminating a session removes the live session, expires the credential mapping, and returns the VM to a clean snapshot or overlay state.

### Milestone 5f: Rollback And Rejoin Verification

- [x] Add a `control-plane` rollback drill test.
Pass when: Rust tests can swap `control-plane` from `current` to `previous`, confirm the stack still starts and serves traffic, then restore `previous` back to `current` using `honeypot/docker/images.lock`.

- [x] Add a `proxy` rollback drill test.
Pass when: Rust tests can swap `proxy` from `current` to `previous`, confirm the stack still starts and serves traffic, then restore `previous` back to `current` using `honeypot/docker/images.lock`.

- [x] Add a `frontend` rollback drill test.
Pass when: Rust tests can swap `frontend` from `current` to `previous`, confirm the stack still starts and serves traffic, then restore `previous` back to `current` using `honeypot/docker/images.lock`.

- [x] Add a downgraded-service rejoin health-recovery test.
Pass when: a service rolled from `current` to `previous` can rejoin two current peers and recover its health without manual data repair.

- [x] Add a downgraded-service contract-compatibility test.
Pass when: a service rolled from `current` to `previous` can continue exchanging versioned contracts with two current peers without manual data repair.

- [x] Add a restored-service rejoin health-recovery test.
Pass when: a service restored from `previous` back to `current` can rejoin its peers and recover its health without manual data repair.

- [x] Add a restored-service contract-compatibility test.
Pass when: a service restored from `previous` back to `current` can continue exchanging versioned contracts with its peers without manual data repair.

### Milestone 5g: Negative, Cleanup, And Host Isolation Checks

- [x] Add POSIX host artifact checks.
Pass when: the tests verify image artifacts, control sockets, logs, stream outputs, and Docker runtime artifacts on the host filesystem with correct ownership, isolation, and redaction.

- [x] Add a log-redaction negative test.
Pass when: secrets stay redacted in service logs, host logs, and lab artifacts during both success and failure paths.

- [x] Add a credential TTL-expiry test.
Pass when: expired mappings are removed deterministically and do not survive disconnect, kill, or recycle paths.

- [x] Add a no-lease handling test.
Pass when: the proxy and frontend surface the no-lease outcome clearly and do not leave behind partial session or VM state.

- [x] Add a kill-switch action test.
Pass when: single-session and global kill actions tear down sessions and revoke credentials deterministically.

- [x] Add an orphan-cleanup test.
Pass when: abandoned VM and container artifacts are reclaimed deterministically after interrupted or failed sessions.

- [x] Add a control-plane outage degradation test.
Pass when: the proxy and frontend expose control-plane-unavailable state cleanly and recover without manual data repair when connectivity returns.

- [x] Add a snapshot-corruption detection test.
Pass when: the lab detects qcow2 corruption and stale backing chains without silently reusing a dirty VM.

- [x] Add a rollback-failure handling test.
Pass when: failed recycle or rollback attempts are surfaced clearly and do not silently return a dirty VM to service.

- [x] Add host-side control-socket isolation checks.
Pass when: QMP, QGA, VNC, and similar control channels are not exposed to untrusted networks or weak filesystem permissions.

- [x] Add an external-client interoperability smoke test.
Pass when: the lab proves the guest accepts a non-project RDP client path as an independent compatibility check.

## Milestone 6: Hardening and Operational Readiness

- [x] Add an operator runbook for lab startup, emergency stop, VM recycle, evidence collection, and session kill procedures.
Pass when: another engineer can operate the lab without tribal knowledge and the documented steps match the Rust-validated lifecycle.

- [x] Add exposure guards for public-internet deployment.
Pass when: public listeners require explicit allowlists, rate controls, and a documented kill switch.

- [x] Add retention and forensic boundaries for recordings, streams, operator actions, and vote history.
Pass when: retention windows and cleanup behavior are documented and enforced.

- [x] Add audit logging for control-plane actions, session kills, and frontend vote actions.
Pass when: every operator-visible action has a stable audit record with session and VM correlation IDs.

- [x] Add operator content-handling policy.
Pass when: the repo states who may watch, who may propose commands, who may approve execution, and how sensitive attacker content is handled.

- [x] Add recovery playbooks for failed recycle, image corruption, and stuck leases.
Pass when: the runbook describes how to quarantine bad images or hosts without losing auditability.

### Milestone 6a: Manual Headed Tiny11 Walkthrough Contract (Gated)

- [x] Add a gated manual-headed lab prerequisite checklist.
Pass when: the run requires an explicit manual-lab gate, confirms headed-display and Chrome availability, records either the approved repo-local Windows provisioning key file or a non-git secret path for key material, and names the attested Tiny11 image-store or interop root before startup begins.

- [x] Add a manual-headed run-identity binding checklist.
Pass when: one `run_id` is created and every committed log, manifest, frontend snapshot, video reference, and service-state capture binds to that same `run_id`, `session_id`, and `vm_lease_id` whenever those identifiers exist.

- [x] Add a manual full-stack startup and shutdown proof checklist for `control-plane`, `proxy`, and `frontend`.
Pass when: the manual lane records health or bootstrap evidence for all three services under the same run envelope before interaction starts and records clean teardown or explicit failure disposition at the end.

- [x] Add a Tiny11 host provisioning checklist that includes key-based setup and RDP enablement.
Pass when: the runbook names where key material is loaded from without committing it, records the Tiny11 lineage used for the run, and captures non-skipped RDP-ready evidence for the same guest identity that the headed walkthrough uses.

- [x] Add a headed QEMU and Chrome frontend observation checklist.
Pass when: the run records the non-headless QEMU launch path, the Chrome frontend access path, and a correlation snapshot proving the observed tile or session matches the active Tiny11 lease.

- [x] Add a bounded manual interaction checklist.
Pass when: the run records a bounded mouse, keyboard, and guest-browsing interaction window whose timestamps are tied to the same `run_id`, `session_id`, and `vm_lease_id`.

- [x] Add a video-evidence checklist for manual-headed runs.
Pass when: a reviewable video artifact is saved through the approved artifact path and the committed evidence index records its digest, duration floor, timestamp window, storage URI, and retention window.

- [x] Add a redaction and credential-handling checklist for manual-headed runs.
Pass when: plaintext RDP credentials, session tokens, and similar secrets are forbidden from git-tracked artifacts, the single repo-local Windows provisioning key file is explicitly allowlisted for local Win11 host creation only, redacted evidence remains reviewable, and live credentials follow the documented secret-handling path without copying the key into run evidence or exports.

- [x] Add a VM artifact storage and retrieval checklist for manual-headed runs.
Pass when: raw `.qcow2`, overlay, memory-dump, and equivalent heavy or sensitive VM state are forbidden from normal git history, the approved storage backend is recorded, and the checklist fails if the referenced artifact cannot be retrieved or its digest mismatches.

### Milestone 6b: Three-Host Manual Observation Deck

- [x] Add a Rust-native three-host manual observation deck launcher with `up`, `status`, and `down`.
Pass when: `honeypot-manual-lab` exists as a Rust testsuite binary, `help`, `status`, and `down` behave deterministically without lab dependencies, and `up` is wired to the documented host-process topology plus the sanctioned Tiny11 lab gate instead of Bash or Python wrappers.

- [x] Add a three-host Tiny11 trusted-image fan-out path for the manual deck.
Pass when: one attested Tiny11 manifest lineage can be cloned into three trusted-image identities with unique `vm_name` and guest RDP ports for one run without copying the base qcow2 artifact, and focused tests lock that transform.

- [x] Add real proxy-backed session priming for the manual deck.
Pass when: the launcher code creates proxy-backed RDP session attempts, resolves `session_id` to `vm_lease_id`, requests stream tokens, and refuses success until the frontend reports three ready tiles.

- [x] Add idempotent active-state tracking and teardown for the manual deck.
Pass when: the launcher records one active state file for the current run, `status` and `down` report the inactive case cleanly, and the teardown path best-effort terminates helper clients and sessions, requests release plus recycle for known leases, stops service processes, and removes the active state file after partial startup failures.

- [x] Add operator docs for the manual three-host observation deck and document the host-process topology choice.
Pass when: the runbook and testing docs explain the required `DGW_HONEYPOT_INTEROP_*` inputs, the `cargo run -p testsuite --bin honeypot-manual-lab -- up|status|down` commands, the Chrome and `Xvfb` assumptions, and why the live deck uses host processes while compose remains the validated readiness and rollback path.

- [x] Add a live operator proof run for the three-host manual deck.
Pass when: on a host with isolated helper-display support such as `Xvfb`, one sanctioned `honeypot-manual-lab up` run creates three distinct Tiny11-backed live sessions, the frontend reaches three ready tiles, and `honeypot-manual-lab down` drains the active lease count back to zero without orphaned helper processes.

### Milestone 6c: Manual Deck Preflight And Interop-Store Readiness

- [x] Add a Rust-native `honeypot-manual-lab preflight` command.
Pass when: it evaluates manual-deck prerequisites without starting services, and it reports `ready` or one canonical blocker before the operator attempts `up`.

- [x] Make manual preflight and manual up share one gate authority.
Pass when: `preflight` and `up` both call the same Rust readiness evaluator over the tier gate, Tiny11 gate, active-state check, and browser-launch prerequisites, and `up` reruns that evaluator immediately before side effects.

- [x] Add a structured manual-deck gate report contract.
Pass when: the preflight output can render both text and JSON with stable top-level keys for `status`, `blocker`, `image_store_root`, `manifest_dir`, `detail`, and `remediation`, while keeping human detail text flexible.

- [x] Add parity tests proving `preflight` and `up` share one authority.
Pass when: fixture-driven tests prove `preflight` and `up` emit the same blocker class and remediation anchor for the same blocked inputs, and `preflight` leaves no active-state file behind.

- [x] Add thin operator wrappers and docs for the preflight-first manual flow.
Pass when: the repo root `Makefile` exposes `manual-lab-preflight`, `manual-lab-up` runs preflight before launch, and the runbook plus testing docs require `preflight -> remediate -> preflight -> up` instead of trial-and-error `up`.

- [x] Add a sanctioned Tiny11 interop-store bootstrap checklist for manual operators.
Pass when: the docs codify the exact `honeypot-control-plane consume-image` bootstrap inputs, the expected post-import store layout, and the explicit `preflight` signals that prove the manual deck is ready to launch.

### Milestone 6d: Manual Deck Bootstrap Resolution

- [x] Keep `honeypot-manual-lab preflight` non-mutating while surfacing bootstrap diagnostics.
Pass when: `preflight` still performs no host mutation, but `missing_store_root` and `invalid_provenance` reports name the sanctioned `bootstrap-store` lane, include local source-manifest candidate diagnostics, and keep the blocker fail-closed.

- [x] Add a Rust-native `honeypot-manual-lab bootstrap-store` command for manual operators.
Pass when: the command supports dry-run by default, `--execute` for mutation, `--source-manifest <path>` for explicit operator choice, `--config <path>` for config drift, and reuses the control-plane consume-image authority instead of inventing a parallel import path.

- [x] Add ambiguity-safe source-manifest discovery for local manual-lab remediation.
Pass when: discovery searches only sanctioned local bundle-manifest lanes, rejects malformed or incomplete bundles, proceeds automatically only when exactly one admissible candidate exists, and refuses to guess when multiple admissible candidates exist.

- [x] Add thin Makefile wrappers for the bootstrap-store flow.
Pass when: the repo root `Makefile` exposes `manual-lab-bootstrap-store` as dry-run and `manual-lab-bootstrap-store-exec` as the explicit mutating path, with optional `MANUAL_LAB_SOURCE_MANIFEST` and `MANUAL_LAB_CONTROL_PLANE_CONFIG` overrides while keeping all selection logic in Rust.

- [x] Add post-import proof and docs for the bootstrap-store operator lane.
Pass when: `bootstrap-store --execute` reruns read-only preflight after import, docs require `preflight -> bootstrap-store -> bootstrap-store-exec -> preflight -> up`, and tests cover zero or one or multiple candidate behavior, explicit-manifest failure clarity, and non-mutating dry-run behavior.

### Milestone 6e: Manual Deck Remembered Source Manifest

- [x] Add an optional remembered source-manifest helper for repeated manual bootstrap runs.
Pass when: `honeypot-manual-lab remember-source-manifest --source-manifest <path>` writes only a local git-ignored hint under `target/manual-lab/`, never mutates the interop store, and succeeds only for an admissible bundle manifest.

- [x] Keep explicit bootstrap overrides authoritative over any remembered source-manifest hint.
Pass when: `MANUAL_LAB_SOURCE_MANIFEST=<path>` or `--source-manifest <path>` always overrides the remembered hint, and `bootstrap-store` consults the hint only when no explicit source-manifest is provided.

- [x] Revalidate the remembered source-manifest hint on every bootstrap run and fail closed on drift.
Pass when: `bootstrap-store` reruns the full admissibility checks against the remembered hint, rejects missing or stale or digest-mismatched hints with a typed blocker, and never falls back to another candidate automatically.

- [x] Add thin Make and docs support for the remembered source-manifest lane.
Pass when: the repo root `Makefile` exposes `manual-lab-remember-source-manifest`, docs show `remember-source-manifest -> bootstrap-store-exec -> preflight -> up`, and they state that removing `target/manual-lab/selected-source-manifest.json` clears the local hint.

### Milestone 6f: Manual Deck Rootless Host-State Profile

- [x] Add an explicit local-state manual-lab profile for non-root hosts.
Pass when: `MANUAL_LAB_PROFILE=local` switches the manual-lab Make wrappers and the aligned control-plane bootstrap config to a repo-local writable state root under `target/manual-lab/state/` without changing the canonical default profile.

- [x] Keep canonical `/srv` paths authoritative by default.
Pass when: the default manual-lab profile remains the checked-in canonical `/srv/honeypot/...` lane, and operators must opt into the local profile explicitly instead of auto-falling back.

- [x] Add typed remediation for non-writable manual-lab store roots.
Pass when: `bootstrap-store --execute` reports a distinct blocker for store-root permission failures and tells non-root operators to retry with `MANUAL_LAB_PROFILE=local` or fix host ownership intentionally.

- [x] Add Make, docs, and tests for profile parity across `preflight`, `bootstrap-store`, and `up`.
Pass when: the repo root `Makefile` threads `MANUAL_LAB_PROFILE=canonical|local` consistently, docs show the local-profile manual sequence, and tests prove the blocker or remediation and docs parity without weakening the single Rust authority.

### Milestone 6g: Manual Deck Makefile Runtime Env Defaults

- [x] Add Make-managed guest-auth env defaults for readiness and launch verbs.
Pass when: the repo root `Makefile` injects default `DGW_HONEYPOT_INTEROP_RDP_USERNAME=operator` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD=password` for `manual-lab-preflight`, `manual-lab-preflight-no-browser`, `manual-lab-bootstrap-store`, `manual-lab-bootstrap-store-exec`, `manual-lab-up`, and `manual-lab-up-no-browser`, while `status` and `down` keep their current no-extra-env behavior.

- [x] Keep explicit operator overrides authoritative over the Make-managed defaults.
Pass when: `MANUAL_LAB_INTEROP_RDP_USERNAME=<value>`, `MANUAL_LAB_INTEROP_RDP_PASSWORD=<value>`, or raw exported `DGW_HONEYPOT_INTEROP_RDP_USERNAME` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD` still override the default guest-auth pair without changing the Rust readiness authority.

- [x] Add docs and tests for the Make-managed runtime env contract.
Pass when: the runbook and testing docs name the `operator/password` wrapper defaults, explain the override knobs, state which verbs consume those defaults, and docs-parity tests cover the new contract.

### Milestone 6h: Manual Deck Self-Test Alias Lane

- [x] Add explicit local-profile self-test aliases for manual operators.
Pass when: the repo root `Makefile` exposes `manual-lab-selftest-preflight`, `manual-lab-selftest-preflight-no-browser`, `manual-lab-selftest-bootstrap-store`, `manual-lab-selftest-bootstrap-store-exec`, `manual-lab-selftest-up`, `manual-lab-selftest-up-no-browser`, `manual-lab-selftest-status`, and `manual-lab-selftest-down`, and each readiness or launch alias delegates to the existing wrapper with `MANUAL_LAB_PROFILE=local` while keeping canonical `manual-lab-*` defaults unchanged.

- [x] Add a read-only manual-lab profile inspector.
Pass when: `make manual-lab-show-profile` prints the effective profile, control-plane config path, image-store root, manifest dir, and masked guest-auth state without mutating the host or bypassing Rust readiness checks.

- [x] Add docs and parity tests for the self-test alias lane.
Pass when: the runbook and testing docs name the self-test aliases as the manual operator quick path, explain that the local self-test lane is not canonical `/srv` readiness proof, and docs-parity tests cover the new command surface.

### Milestone 6i: Manual Deck Wrong-Lane Remediation Bridge

- [x] Update Rust blocker remediation to prefer the self-test quick path on non-root hosts.
Pass when: the `missing_store_root` and store-root permission remediation emitted by `testsuite::honeypot_manual_lab` points operators first to `make manual-lab-show-profile`, `make manual-lab-selftest-bootstrap-store-exec`, `make manual-lab-selftest-preflight`, and `make manual-lab-selftest-up`, while still keeping canonical `/srv` proof guidance distinct.

- [x] Keep canonical proof guidance explicit inside the same remediation contract.
Pass when: the blocker text still explains that `make manual-lab-bootstrap-store-exec` plus `make manual-lab-preflight` is the canonical `/srv` proof lane and does not imply any automatic fallback.

- [x] Add docs and tests for the remediation bridge.
Pass when: the runbook and testing docs explain that canonical `missing_store_root` guidance now points to the self-test lane first on non-root hosts, and tests cover the new remediation strings so command names do not drift.

## Verification Matrix

- [x] Standard repo verification remains green with `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests`.
- [x] Milestone 0 and Milestone 0.5 are complete before Milestone 1 through Milestone 6 implementation starts.
- [x] The design-freeze docs exist before implementation starts.
- [x] The three honeypot services each have their own Docker image, build context, healthcheck, and runtime config contract.
- [x] Current and previous image digests are pinned for `control-plane`, `proxy`, and `frontend`, and rollback does not require rebuilding.
- [x] `honeypot/docker/images.lock` has a documented schema for `control-plane`, `proxy`, and `frontend`, and release or test paths reject floating tags.
- [x] Mixed-version `current` or `previous` service combinations are documented and validated before rollback is considered safe.
- [x] The test plan is split into `contract`, `host-smoke`, and `lab-e2e` tiers.
- [x] The control plane can produce and recycle at least one Tiny11-derived Windows 11 VM with RDP enabled and host-side cleanup verified.
- [x] The proxy can replace attacker credentials with backend credentials without leaking secrets to logs.
- [x] The frontend can bootstrap, create, update, fullscreen, and remove tiles from live session events.
- [x] The stream path is bound to session identity and survives disconnect and recycle correctly.
- [x] The Rust e2e path validates both guest behavior and POSIX host artifacts.
- [x] Normal and failure-path teardown leave no orphaned QEMU processes, exposed control sockets, leaked overlays, stale containers, stale networks, stale volumes, or unredacted sensitive logs.
