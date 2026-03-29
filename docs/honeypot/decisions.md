# Honeypot Decision Ledger

## Purpose

This document is the canonical Milestone 0.5 decision ledger for the honeypot fork.
It resolves `DF-01` through `DF-09` from [AGENTS.md](../../AGENTS.md).
Later honeypot docs and milestones must consume these rows instead of restating policy.
Detailed schemas, Docker topology, and release mechanics belong in the owning docs named under each row.

## Freeze Status

- These decisions are frozen for Milestone 0.5 and block Milestone 1 through Milestone 6 implementation.
- The `Decision Freeze Matrix` and `Ownership Matrix` in `AGENTS.md` remain authoritative, so later milestone docs must cite the relevant `DF-*` or `OM-*` rows instead of inventing a second owner or restating frozen policy.
- This ledger must not be read as permission to introduce a fourth runtime service, a parallel session bus, or a parallel stream service.
- If a later milestone needs to replace one of these choices, it must update this file first and then update the owning docs.

## DF-01 Proxy Packaging And Process Boundary

- Winner: `proxy` remains a single public runtime service rooted in the current `devolutions-gateway` binary and is packaged as its own honeypot image rather than split into multiple honeypot-side processes.
- Rejected alternative: reuse the legacy `package/Linux/Dockerfile` bundle as the honeypot proxy container.
- Rejected alternative: split the proxy into separate listener, stream, or credential sidecars that would create extra runtime services.
- Rejected alternative: replace `rdp_proxy.rs` with a fresh standalone RDP proxy implementation.
- Upgrade path: the fork may later move the proxy entrypoint into a dedicated honeypot crate or binary if it preserves the same external contracts and the same three-service runtime boundary.
- Owning docs: this file, [architecture.md](architecture.md), and [deployment.md](deployment.md).

## DF-02 Service-To-Service Authentication, Operator Identity, And Audit Envelope

- Winner: `proxy` remains the public trust boundary, `control-plane` accepts only short-lived proxy-issued service tokens on the internal network, and operators authenticate to `proxy` through a proxy-local auth flow that follows the current web-app token pattern before the proxy issues scoped operator and stream tokens.
- Winner detail: operator roles are frozen as `watch`, `propose`, `approve`, and `kill`, and every operator-visible action must log `operator_id`, `role`, `session_id`, `vm_lease_id`, `event_id`, and `correlation_id` when those fields exist.
- Rejected alternative: anonymous or shared-credential access to the frontend or operator actions.
- Rejected alternative: direct browser or operator access to `control-plane`.
- Rejected alternative: browser-held guest credentials or long-lived static inter-service secrets as the normal operating model.
- Upgrade path: a later milestone may replace the proxy-local operator login bootstrap with an external identity provider or stronger service-auth mechanism if it preserves the same scoped token model and audit envelope.
- Owning docs: this file, [contracts.md](contracts.md), and [risk.md](risk.md).

## DF-03 Session, Event, And Stream Seam Ownership

- Winner: `proxy` owns attacker session state, event emission, replay bootstrap, and stream token issuance, while `control-plane` owns only VM lease lifecycle and `frontend` remains a contract consumer.
- Winner detail: honeypot session and event fields must extend `session.rs`, `subscriber.rs`, `api/sessions.rs`, and `api/session.rs` instead of introducing a second source of truth.
- Rejected alternative: a parallel honeypot session database or subscriber bus.
- Rejected alternative: `control-plane` ownership of browser-visible session or stream state.
- Rejected alternative: `frontend` polling or reading host-side state directly from QEMU, storage, or control sockets.
- Upgrade path: the proxy may later add a durable replay log behind the same proxy-owned contract if scale requires it, but ownership must stay with `proxy` unless this row is revised first.
- Owning docs: this file, [architecture.md](architecture.md), and [contracts.md](contracts.md).

## DF-04 Stream Source Of Truth, Browser Update Transport, And Ordering Model

- Winner: honeypot session and operator updates use proxy-owned SSE for HTMX-friendly delivery, while browser media reuse stays on the existing Gateway recording and streaming seam until a later revision proves that another capture path is necessary.
- Winner detail: stream metadata and stream tokens are bound to `session_id` and `vm_lease_id`, and proxy-emitted session events use per-session ordering fields so replay, deduplication, and out-of-order handling are explicit.
- Rejected alternative: direct QEMU or VNC display capture as the MVP stream source of truth.
- Rejected alternative: a separate websocket event bus for ordinary frontend state updates.
- Rejected alternative: unordered best-effort event fan-out with no replay or deduplication contract.
- Upgrade path: a later milestone may swap in an alternate capture backend or a minimal media websocket bridge if it preserves the same proxy-owned stream metadata and event-ordering contract.
- Owning docs: this file, [contracts.md](contracts.md), and [architecture.md](architecture.md).

### BS-39 Proxy Capture Fallback Gate

- `seam_ownership`: `devolutions-gateway/src/rdp_proxy.rs` plus `devolutions-gateway/src/session.rs` plus `devolutions-gateway/src/recording.rs` plus `devolutions-gateway/src/api/jrec.rs`, with `/jet/jrec/push/{session_id}` kept as the canonical producer contract.
- `rejection_reason`: no explicit proxy-seam insufficiency has been recorded yet, so control-plane-assisted capture fallback cannot open.
- `exhausted_lanes`: `instrumentation-first`, `non-RDPGFX`.
- `fallback_status`: `blocked` until this same canonical row is updated with the exact blocker that proves `/jet/jrec/push/{session_id}` remained insufficient after those lanes were exhausted.

## DF-05 Windows SKU, ISO Input, Tiny11 Transformation, And Gold-Image Attestation

- Winner: the gold image is based on an official Microsoft Windows 11 Pro x64 ISO, pinned to one approved language variant, with a recorded acquisition channel, acquisition date, filename, size, and SHA-256 before any derived image may enter the reusable pool.
- Winner detail: the MVP guest SKU is Windows 11 Pro x64 because it can act as an RDP host, and Windows 11 Home is not allowed.
- Winner detail: every reusable base image must ship with an attestation manifest that records the source ISO identity, Tiny11-derived transformation input refs and checksums, transformation timestamp, resulting base-image digest, and the operator or automation identity that approved the artifact for lease use.
- Winner detail: `control-plane` must fail closed on startup or lease acquisition if the configured image lacks a complete manifest, if the digest chain does not match, or if the transformed output cannot be traced back to the approved Microsoft ISO record.
- Rejected alternative: community-repacked ISOs, unrecorded download sources, or mutable hand-built gold images with no checksum chain.
- Rejected alternative: silently changing the Windows edition, language, or update baseline without updating the attestation manifest and decision record first.
- Rejected alternative: accepting provenance notes such as `WINDOWS11-LICENSE.md` as an approval or attestation record.
- Upgrade path: a later milestone may move to another host-capable Windows 11 SKU if the source ISO, transformation inputs, and resulting attestation manifest are updated under the same provenance contract.
- Acceptance checklist: Milestone 1 may assume one approved Windows 11 Pro x64 source ISO lineage, one attested Tiny11-derived transformation lineage, and no lease path that bypasses manifest validation.
- Owning docs: this file, [risk.md](risk.md), and [research.md](research.md).

## DF-06 QEMU Control Surfaces, Container Runtime Contract, And VM Recycle Semantics

- Winner: `control-plane` drives `qemu-system-x86_64` directly from Rust by using `/dev/kvm`, Unix-domain QMP sockets, optional guest-agent support through Unix-domain QGA sockets, and per-lease qcow2 overlays rooted in the documented host mounts.
- Winner detail: the documented runtime contract is limited to the attested image store, the lease and overlay store, the quarantine store, the QMP socket directory, the optional QGA socket directory, and no extra runtime controller such as libvirt.
- Winner detail: recycle means `control-plane` stops the guest, confirms QEMU exit, removes lease-scoped sockets and tempdirs, discards the per-lease overlay, and revalidates the base-image provenance and integrity before the lease returns to the reusable pool.
- Winner detail: any launch, reset, cleanup, integrity, or provenance failure moves the affected lease or image chain into quarantine instead of back into the reusable pool, and the health surface must expose that degraded or unsafe state.
- Rejected alternative: Bash or Python wrappers for VM launch, reset, or image handling.
- Rejected alternative: making libvirt or another orchestration layer a required extra runtime service for the MVP.
- Rejected alternative: in-place guest reset with no overlay discard or quarantine boundary.
- Upgrade path: a later milestone may add an alternate runtime adapter behind the same typed lifecycle API if the same lease, cleanup, and quarantine contract is preserved.
- Acceptance checklist: Milestone 1 may assume one direct Rust-to-QEMU adapter, one least-privilege `/dev/kvm` contract, lease-scoped overlays and sockets, and fail-closed quarantine on any non-clean recycle path.
- Owning docs: this file, [deployment.md](deployment.md), and [architecture.md](architecture.md).

## DF-07 Registry Namespace, Tag Policy, Promotion Manifest, And `images.lock` Contract

- Winner: the canonical image family lives under `ghcr.io/<fork-owner>/devolutions-gateway-honeypot/{control-plane,proxy,frontend}`, each service publishes semver and commit-SHA tags, and compose or tests consume only immutable digests recorded in `honeypot/docker/images.lock`.
- Winner detail: a signed promotion manifest is the only allowed input that may update `honeypot/docker/images.lock`, and that manifest must carry the service name, canonical image reference, promoted tag, digest, source ref, and provenance timestamp needed for current and previous rollbacks.
- Rejected alternative: floating tags such as `latest` as the source of truth for rollout or rollback.
- Rejected alternative: ad hoc manual edits to `honeypot/docker/images.lock`.
- Rejected alternative: different registry rules or naming schemes for each service.
- Upgrade path: a later milestone may extend the promotion manifest with attestations, SBOM references, or policy signatures if the same single-manifest and digest-promotion rule is preserved.
- Owning docs: this file, [release.md](release.md), and `honeypot/docker/images.lock`.

## DF-08 Runtime Config Mounts, Secret Mounts, Retention And Redaction, Emergency Stop, And Quarantine Policy

- Winner: each honeypot service uses explicit env files plus read-only config mounts and read-only secret mounts, `proxy` owns the emergency stop that halts intake and kills live sessions, and `control-plane` owns lease or image quarantine.
- Winner detail: runtime config is mounted separately from secrets, exported evidence is redacted for secrets and PII by default, and stored attacker content is kept only for the minimum retention window required by the authorized research objective.
- Rejected alternative: baking secrets into images, environment variables, or browser-delivered payloads as the primary secret transport.
- Rejected alternative: indefinite raw evidence retention or unredacted export by default.
- Rejected alternative: best-effort cleanup with no explicit quarantine or no global kill path.
- Upgrade path: a later milestone may move secret delivery or evidence storage onto dedicated infrastructure if the same mount contract, kill semantics, and quarantine ownership are preserved.
- Owning docs: this file, [deployment.md](deployment.md), and [risk.md](risk.md).

## DF-09 Test Tier Boundary And Explicit Lab Gate

- Winner: honeypot verification is split into `contract`, `host-smoke`, and `lab-e2e`, where `contract` is CI-safe and cannot require QEMU, `host-smoke` is explicit opt-in on a prepared Linux KVM host, and `lab-e2e` is a separately gated isolated lab tier.
- Winner detail: no default CI path may require `/dev/kvm`, mutable Windows images, or exposure to untrusted traffic.
- Rejected alternative: always-on QEMU or Windows image bring-up in the default integration-test path.
- Rejected alternative: undocumented manual validation as the only evidence for Milestone 1 through Milestone 6 work.
- Rejected alternative: mixing host-only or lab-only tests into the baseline suite with no explicit gate.
- Upgrade path: a later milestone may automate `host-smoke` or `lab-e2e` on dedicated runners if the same tier split and explicit gate remain visible in repo docs and test wiring.
- Owning docs: this file and [testsuite](../../testsuite).
