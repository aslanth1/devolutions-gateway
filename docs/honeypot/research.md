# Honeypot Research Notes

## Purpose

This document records the reuse-first research inputs for the honeypot fork.
It supports `docs/honeypot/architecture.md`, `docs/honeypot/risk.md`, and the `DF-*` rows in `AGENTS.md`.
It does not freeze protocol, image, or release decisions by itself.
It must not be read as permission to introduce a fourth runtime service, a parallel session bus, or a parallel stream stack.

## Decision Links

- `DF-03` owns any replacement of the current session, subscriber, or session-management seams.
- `DF-04` owns the stream source of truth, browser update transport, and ordering model.
- `DF-05` owns the Windows SKU, Microsoft ISO input, Tiny11 transformation, and gold-image attestation.
- `DF-06` owns the QEMU control surface, container runtime contract, and recycle semantics.
- `DF-07` owns image promotion, registry policy, and `honeypot/docker/images.lock`.
- `DF-09` owns the `contract`, `host-smoke`, and `lab-e2e` test tier boundary.

## Gateway Reuse Anchors

- `devolutions-gateway/src/rdp_proxy.rs`: `reuse`. It is the current RDP MiTM and credential-substitution core, so the honeypot proxy should extend it rather than replace it.
- `devolutions-gateway/src/session.rs`: `adapt`. It is the current live session registry and should gain honeypot session metadata instead of being shadowed by a second registry.
- `devolutions-gateway/src/subscriber.rs`: `adapt`. It already emits session lifecycle messages and is the correct base seam for honeypot event fan-out.
- `devolutions-gateway/src/api/preflight.rs`: `reuse`. It already exposes `provision-credentials`, which is the intended short-lived credential-mapping seam for backend guest credentials.
- `devolutions-gateway/src/api/sessions.rs`: `reuse`. It already exposes `/jet/sessions`, which is the right bootstrap surface for already-running sessions.
- `devolutions-gateway/src/api/session.rs`: `reuse`. It already exposes `/jet/session/{id}/terminate`, which is the right starting point for operator kill actions.
- `devolutions-gateway/src/recording.rs`: `adapt`. It already manages recording lifecycle and retention-sensitive artifacts, so it should inform honeypot capture handling without becoming a new service.
- `devolutions-gateway/src/streaming.rs`: `adapt`. It already bridges stored outputs into browser-facing streams, so it is the first stream seam to evaluate under `DF-04`.
- `devolutions-gateway/src/ws.rs`: `adapt`. It is the current websocket wrapper and should remain available only if `DF-04` keeps a minimal websocket bridge for stream delivery.
- `devolutions-gateway/src/service.rs`: `reuse`. It is the current startup and background-task composition point for the gateway binary and should remain the place where honeypot proxy state is wired in.
- `devolutions-gateway/src/api/mod.rs`: `reuse`. It is the current route composition seam and should host honeypot proxy route extensions instead of a parallel router tree.
- `devolutions-gateway/src/api/webapp.rs`: `adapt`. It is a token-issuance and auth-pattern reference only, and the honeypot frontend must keep its own UI, routes, and assets instead of reusing the legacy webapp surface.
- `devolutions-gateway/src/extract.rs`: `adapt`. It already provides scoped request extraction patterns and should be extended for honeypot scopes rather than bypassed.
- `devolutions-gateway/src/middleware/auth.rs`: `adapt`. It is the current auth gate and should remain the style reference for stream and operator auth enforcement.
- `devolutions-gateway/src/config.rs`: `adapt`. It is the right place to add honeypot mode, control-plane endpoint, stream, and operator settings.
- `testsuite/src/dgw_config.rs`: `adapt`. It is the right helper to extend for honeypot-mode integration tests before any second bootstrap path is considered.

## In-Tree Package Evaluation

- `devolutions-session`: `do not use`. It is the session host application for Devolutions Agent and its Windows and DVC focus puts it out of scope for the Linux-hosted control-plane runtime, although its lifecycle patterns may still be informative.
- `devolutions-agent`: `do not use`. It is the agent companion service for Devolutions Gateway and its Windows-centric agent model is out of scope for the three-service honeypot runtime, although its control and packaging patterns may still be reviewed.
- `jetsocat`: `adapt`. It is an in-tree Jet and WebSocket toolkit that can inform transport debugging and protocol experiments, but it must not become a fourth runtime service.
- `crates/transport`: `adapt`. It is the in-tree async transport foundation and is a safe low-level reuse point for proxy and frontend stream plumbing.
- `testsuite`: `reuse`. It is the existing Rust integration harness and should carry `contract` and non-lab honeypot coverage under `DF-09`.
- `video-streamer`: `adapt`. It is the strongest in-tree browser-stream reuse candidate because `devolutions-gateway/src/streaming.rs` already calls `webm_stream`, but `DF-04` still has to confirm that recording-derived WebM is the honeypot stream source of truth.
- `terminal-streamer`: `adapt`. It is already wired by `devolutions-gateway/src/streaming.rs`, but it should stay secondary to the RDP video path unless a text-oriented observation surface is explicitly approved.

## External Repository Evaluation

- `Devolutions/IronRDP`: `reuse`. The current gateway already depends on IronRDP crates, so this remains the primary protocol-level implementation family for RDP handshake and forwarding behavior.
- `Devolutions/sspi-rs`: `reuse`. It remains the best-fit SSPI implementation family for authentication and Windows security-provider interoperability around the proxy path.
- `FreeRDP/FreeRDP`: `do not use`. It is useful as an interoperability and behavior-validation reference, but it should not displace the current Rust and IronRDP-centered proxy plan.
- `Devolutions/MsRdpEx`: `do not use`. It may help validate Windows client or extension behavior, but it is not a fit for the Linux-hosted honeypot runtime.
- `Devolutions/picky-rs`: `reuse`. The current gateway already uses `picky` and `picky-krb`, so this repo remains the first PKI and token reference instead of importing a second identity stack.
- `Devolutions/DevoSamples-ps`: `do not use`. It is PowerShell sample material and is out of scope because implementation, orchestration, and tests must stay in Rust.
- `Devolutions/RdpCredProv`: `do not use`. It may serve as validation-only reference material for Windows credential-provider behavior, but NLA credential substitution must stay in the proxy through preflight-backed mapping rather than a guest credential-provider dependency.

## Related Inputs

- `cadeau`: `reuse`. It is already an in-tree dependency used by the current recording and video-streaming path, so it remains a direct reuse input for any recording-based stream plan chosen under `DF-04`.
- `devolutions-labs`: `do not use`. No in-tree dependency or concrete runtime role is documented today, so it stays optional validation-only context rather than a build, orchestration, or service dependency.
- `package/Linux/Dockerfile`: `do not use`. It remains reference-only packaging context and must not be inherited accidentally by the honeypot `proxy` or `frontend` images, and the release-input contract tests reject drift back toward that bundle.
- `WINDOWS11-LICENSE.md`: `do not use`. It may remain an operator scratch note, but it is not a provenance, attestation, or release input for `DF-05`.

## DF-05 And DF-06 Working Conclusions

- The reusable guest baseline should stay pinned to one official Microsoft Windows 11 Pro x64 ISO lineage because the guest must act as an RDP host and because provenance drift is more expensive than later SKU expansion.
- The Tiny11-derived image process must produce a machine-readable manifest that records the approved ISO record, transformation input refs, transformation timestamp, and resulting base-image digest before `control-plane` can lease the image.
- The Linux-hosted control plane should continue to treat `devolutions-session` and `devolutions-agent` as reference-only patterns rather than runtime dependencies.
- The runtime adapter should stay on direct `qemu-system-x86_64` control from Rust with `/dev/kvm`, QMP, optional QGA, and lease-scoped overlays rather than adding libvirt or unpublished host wrappers.
- Recycle should mean full lease teardown and overlay discard, while any reset, cleanup, or provenance failure should move the lease or image chain into quarantine instead of the reusable pool.

## Working Conclusions

- The proxy work should stay centered on `rdp_proxy.rs`, `session.rs`, `subscriber.rs`, `api/preflight.rs`, `api/sessions.rs`, and `api/session.rs`.
- The stream investigation should stay centered on `streaming.rs`, `recording.rs`, `video-streamer`, `terminal-streamer`, `ws.rs`, and `cadeau` until `DF-04` freezes a winner.
- The Linux-hosted control plane should not be built on `devolutions-agent` or `devolutions-session`, which remain reference-only pattern inputs.
- The external repositories above are reference, protocol, auth, and interoperability inputs, not permission to add new runtime services.
- `testsuite` and `testsuite/src/dgw_config.rs` remain the default verification path until `DF-09` records a written exception.
