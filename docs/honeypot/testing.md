# Honeypot Test Tiers

## Purpose

This document defines the honeypot verification tiers required by `DF-09`.
It works with [decisions.md](decisions.md), [contracts.md](contracts.md), [runbook.md](runbook.md), and `testsuite`.
It must keep the default test path CI-safe and must fail closed before any lab-only work runs.
The exact operator bring-up and recovery procedure lives in [runbook.md](runbook.md).

## Tier Summary

- `contract` is the default tier.
- `host-smoke` is explicit local validation on a prepared Linux KVM host.
- `lab-e2e` is isolated end-to-end validation that is never allowed to run by accident.

## Contract Tier

- `contract` must stay CI-safe.
- `contract` tests may parse config, validate schema shape, validate contract payloads, exercise pure Rust helpers, and run local process or network tests that do not require QEMU, `/dev/kvm`, Windows images, Docker host mutation, or untrusted traffic.
- The current `cargo test -p testsuite --test integration_tests` baseline remains a `contract` tier path.
- Any new honeypot test that can run without a prepared host or lab should stay in `contract`.

## Host-Smoke Tier

- `host-smoke` is for explicit local validation on a prepared Linux host with KVM available.
- `host-smoke` may touch `/dev/kvm`, local Docker bring-up, documented host mounts, qcow2 overlays, QMP sockets, QGA sockets, and cleanup checks on that prepared host.
- `host-smoke` must not require exposure to untrusted traffic or the full isolated attacker lab.
- `host-smoke` is opt-in and must not run unless `DGW_HONEYPOT_HOST_SMOKE=1` is set.
- `host-smoke` is also the right tier for real browser-surface wiring checks against the three-service compose stack when the proof stops at service readiness, dashboard bootstrap, and SSE handshake rather than live attacker traffic.

## Lab-E2E Tier

- `lab-e2e` is for the isolated end-to-end honeypot lab only.
- `lab-e2e` may use prepared Windows images, QEMU lifecycle, live stream validation, recycle behavior, and attacker-to-frontend flows that are out of scope for the default suite.
- `lab-e2e` must not run in ordinary CI or on an unprepared workstation.
- `lab-e2e` is opt-in and must not run unless `DGW_HONEYPOT_LAB_E2E=1` is set.
- The external-client interoperability smoke test additionally requires a prepared image store plus guest credentials through `DGW_HONEYPOT_INTEROP_IMAGE_STORE`, `DGW_HONEYPOT_INTEROP_RDP_USERNAME`, and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD`.
- Optional overrides for that smoke lane are `DGW_HONEYPOT_INTEROP_MANIFEST_DIR`, `DGW_HONEYPOT_INTEROP_QEMU_BINARY`, `DGW_HONEYPOT_INTEROP_KVM_PATH`, `DGW_HONEYPOT_INTEROP_POOL`, `DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS`, `DGW_HONEYPOT_INTEROP_RDP_DOMAIN`, `DGW_HONEYPOT_INTEROP_RDP_SECURITY`, and `DGW_HONEYPOT_INTEROP_XFREERDP_PATH`.

## Explicit Lab Gate

- `lab-e2e` also requires a Rust-readable gate manifest path in `DGW_HONEYPOT_TIER_GATE`.
- The gate manifest is JSON with `contract_passed` and `host_smoke_passed` booleans.
- `lab-e2e` must fail closed unless both booleans are `true`.
- The Rust gate implementation lives in `testsuite::honeypot_tiers`.
- Future `lab-e2e` tests must call `require_honeypot_tier(HoneypotTestTier::LabE2e)` before any lab setup work starts.

## Test Placement Rules

- Keep honeypot coverage inside `testsuite/tests/` and the existing `integration_tests` harness unless a later milestone records a justified split.
- Tests that only exercise config parsing, schema validation, event payloads, or other pure-Rust contract checks belong to `contract`.
- Tests that need a prepared KVM host but not the isolated attacker lab belong to `host-smoke`.
- Tests that need the isolated honeypot lab, attacker traffic, or the full multi-service runtime belong to `lab-e2e`.
- No `contract` test may touch QEMU, `/dev/kvm`, mutable Windows images, or host cleanup paths.

## Current Repo Mapping

- The current baseline `testsuite` integration suite is the `contract` tier.
- The `testsuite::honeypot_tiers` module is the current enforcement point for future `host-smoke` and `lab-e2e` additions.
- Later milestones may add more granular test modules, but they must keep the same tier names and fail-closed gate behavior.

## Reuse Guardrail Evidence

- `AGENTS.md` pass rows around no-parallel honeypot session, credential, and stream stacks are satisfied by the combined architecture and research crosswalks plus the current contract-tier evidence below.
- [architecture.md](architecture.md) and [research.md](research.md) now map each approved honeypot surface directly onto `rdp_proxy.rs`, `session.rs`, `subscriber.rs`, `api/preflight.rs`, `api/sessions.rs`, `api/session.rs`, `recording.rs`, `streaming.rs`, `ws.rs`, `video-streamer`, and `terminal-streamer`.
- `testsuite/tests/honeypot_visibility.rs` proves the proxy still owns session lifecycle, credential substitution, replay, and stream identity without a parallel session or credential API.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the operator control path still uses `/jet/sessions` and `/jet/session/{id}/terminate` rather than a second session-management surface.
- `testsuite/tests/honeypot_frontend.rs` proves the browser path still consumes proxy bootstrap, event, and stream-token routes rather than a separate stream-control service.

## Credential Replacement And Redaction Evidence

- `AGENTS.md` pass row `The proxy can replace attacker credentials with backend credentials without leaking secrets to logs.` is satisfied by the current `contract` tier.
- `testsuite/tests/honeypot_visibility.rs` proves the proxy replaces attacker-supplied preflight credentials with the mapped backend credentials during honeypot prepare, binds the backend credential reference to the session, and cleans the mapping up on abort.
- `testsuite/tests/cli/dgw/preflight.rs` proves the provisioned proxy and target passwords are redacted from gateway logs on the successful credential-provisioning path.
- `testsuite/tests/cli/dgw/preflight.rs` also proves the same passwords stay redacted when credential provisioning fails validation before session startup.

## Stream Identity And Recycle Evidence

- `AGENTS.md` pass row `The stream path is bound to session identity and survives disconnect and recycle correctly.` is satisfied by the current `contract` tier.
- `testsuite/tests/honeypot_visibility.rs` proves the proxy binds `session_id`, `vm_lease_id`, `stream_id`, bootstrap preview, and SSE replay to the same live stream identity.
- `testsuite/tests/honeypot_visibility.rs` also proves an active stream route redirects only while the session is live, then both the stream-token route and the stream route return `404` after terminate-triggered recycle removes the session.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the proxy rejects mismatched and unknown session IDs for both the stream-token route and the stream route.
- `testsuite/tests/honeypot_frontend.rs` proves the frontend only uses the requested session's stream binding, removes recycled tiles and focus routes after `host.recycled`, and filters disconnected and recycled sessions out of bootstrap-driven live views.

## Rust E2E Guest And POSIX Artifact Evidence

- `AGENTS.md` pass row `The Rust e2e path validates both guest behavior and POSIX host artifacts.` is satisfied by the existing Rust `lab-e2e` path, with `host-smoke` checks providing supporting depth.
- `testsuite/tests/honeypot_control_plane.rs` proves guest behavior in the Rust `lab-e2e` lane by acquiring a lease, waiting for forwarded RDP readiness, and recycling back to ready in `control_plane_lab_harness_startup_reaches_rdp_readiness_on_posix_host`.
- `testsuite/tests/honeypot_control_plane.rs` also proves POSIX host-artifact cleanup in the same Rust `lab-e2e` lane by asserting the active snapshot, runtime dir, overlay, pid file, QMP socket, QGA socket, and fake-QEMU process are all removed after recycle in `control_plane_lab_harness_teardown_cleans_runtime_artifacts_on_posix_host`.
- `testsuite/tests/honeypot_release.rs` adds supporting POSIX host depth by checking the three-service runtime artifact, permission, and redaction contract in `posix_host_artifact_checks_keep_runtime_artifacts_isolated_and_redacted`.
- `testsuite/tests/honeypot_control_plane.rs` includes `control_plane_external_client_interoperability_smoke_uses_xfreerdp` as an optional supplemental Rust `lab-e2e` lane when explicit external-client lab inputs are configured.

## Full-Stack Frontend Driver Evidence

- The current three-service compose harness also includes a full-stack frontend-driver smoke lane in `host-smoke`.
- `testsuite/tests/honeypot_release.rs` proves the checked-in `control-plane`, `proxy`, and `frontend` images can start together, render the `Observation Deck` dashboard through the real frontend-to-proxy bootstrap path, and complete the `/events` SSE header handshake in `compose_frontend_operator_path_renders_dashboard_and_proxies_event_stream_headers`.
- That lane deliberately uses a compose-network driver request from a peer service instead of assuming Docker-published localhost ports are reachable on every workstation namespace.
- That lane is intentionally narrower than `lab-e2e`: it proves operator-path frontend wiring for the full stack without claiming live attacker traffic, Tiny11 guest boot, or Chrome-driven session interaction.

## Gold Image Consumption Evidence

- `AGENTS.md` pass row `Build or consume the Tiny11-derived Windows 11 gold image flow without Bash or Python wrappers.` is satisfied by the Rust-native consume path in `honeypot-control-plane`.
- `honeypot/control-plane/src/image.rs` proves the consume flow rejects traversal, symlink escape, duplicate conflicting identities, and digest drift while producing a canonical digest-pinned trusted artifact and manifest that `trusted_images()` can load directly.
- `testsuite/tests/honeypot_control_plane.rs` proves the operator-facing `honeypot-control-plane consume-image` command imports a source bundle, starts the control plane with no manual manifest edits, reports one trusted image, and reaches acquire preconditions successfully in `control_plane_consume_image_command_imports_a_trusted_bundle_without_manual_manifest_edits`.
- This consume flow guarantees path confinement, digest binding, atomic visibility of imported artifacts, and compatibility with the existing lease path.
- This consume flow does not yet provide an external signer or PKI trust root beyond the recorded approval identity and manifest/digest checks.

## Gold Image Acceptance Evidence

- `AGENTS.md` pass row `Add a gold-image acceptance test.` is satisfied by the Rust `lab-e2e` acceptance lane in `testsuite/tests/honeypot_control_plane.rs`.
- `control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly` validates one attested Windows 11 Pro x64 image from the configured interop image store, acquires a lease, verifies live RDP readiness with `xfreerdp +auth-only`, confirms required runtime control-channel artifacts, and then proves recycle removes the active snapshot, runtime dir, overlay, pid file, and QMP socket.
- This acceptance lane is intentionally explicit and fail-closed behind the `lab-e2e` gate plus interop env prerequisites, so it does not run accidentally in the default contract-tier suite.

## Gold Image RDP Evidence

- `AGENTS.md` pass row `Enable and verify RDP in the gold image.` is satisfied by the Rust `lab-e2e` lane in `testsuite/tests/honeypot_control_plane.rs`.
- `control_plane_lab_harness_startup_accepts_rdp_on_tcp_3389_for_gold_image` proves a fresh lease from the attested manifest path reaches known-ready on the forwarded host RDP port and records a QEMU host-forward target of guest `tcp/3389` in the active launch snapshot.
- `control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly` remains the stronger interop anchor when the explicit `DGW_HONEYPOT_INTEROP_*` lab inputs are configured, because it verifies `xfreerdp +auth-only` against a prepared image store.

## Manual Headed Lab Contract

- `AGENTS.md` now carries a gated `Milestone 6a` contract for any future headed Tiny11 walkthrough that also touches Chrome or manual guest interaction.
- That contract is intentionally fail-closed: it requires explicit run identity binding, service-state capture, redacted credential handling, retrievable artifact references, and approved storage for heavy or sensitive VM assets instead of normal git history.
- The manual-headed lane remains supplemental to the canonical Rust `lab-e2e` proof and must not be used to bypass the existing Tiny11 lineage, RDP-ready, or cleanup evidence gates.
- The only approved evidence root for manual-headed work is the existing row-`706` run envelope under `target/row706/runs/<run_id>/`; Milestone `6a` is a profile inside that run root, not a second authority.
- Milestone `6a` anchors are now split into `preflight_only` and `runtime_required` classes.
- `preflight_only` anchors may validate headed-display, Chrome, run identity, the approved Windows key source, the attested Tiny11 image-store or interop root declaration, redaction policy, and artifact-storage contract inputs before any guest boots.
- `runtime_required` anchors must bind to machine-produced artifacts and a verified row-`706` runtime run before rows `704`, `707`, `710`, `713`, `716`, or the runtime portion of `722` may be treated as complete.
- A preflight-only manual-headed run may end in `blocked_prereq`, but that disposition is never sufficient to complete row `735`.
- The redaction lane still fails closed for tracked plaintext RDP credentials, session tokens, and similar secrets, but it now allows the single repo-local Windows provisioning key file documented in `WINDOWS11-LICENSE.md` for local Win11 host creation only.
- That allowlist does not extend to manual-headed evidence, exports, screenshots, or any second tracked artifact; the provisioning key must stay confined to that one documented file or an approved mounted secret path.

## Tiny11 Production And Recycle Evidence

- `AGENTS.md` row `The control plane can produce and recycle at least one Tiny11-derived Windows 11 VM with RDP enabled and host-side cleanup verified.` is stricter than a compile-only or skipped lane.
- That row is only complete after the Rust `lab-e2e` path runs without skip against a prepared Tiny11-derived interop image store and produces live evidence on the current workstation or lab host.
- The configured interop image store is now fail-closed by `testsuite::honeypot_control_plane::load_honeypot_interop_store_evidence`, which requires manifest-backed Windows 11 Pro x64 provenance fields, approval identity, relative in-store base-image paths, and attestation-to-base-image binding.
- The canonical row `706` evidence gate is now `testsuite::honeypot_control_plane::verify_row706_evidence_envelope`, which reads one explicit run-scoped manifest and fragment set under `target/row706/runs/<run_id>/` instead of auto-discovering mixed files from a shared directory.
- `testsuite::honeypot_control_plane::attempt_row706_evidence_run` now wraps one explicit row-`706` attempt around that same manifest-and-fragment contract and classifies the result as `verified`, `blocked_prereq`, or `failed_runtime` without inventing a second evidence authority.
- The positive-path proof anchor is `control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly`, which acquires one attested image-backed lease, verifies live RDP readiness with `xfreerdp +auth-only`, and proves recycle removes lease-scoped runtime artifacts.
- The repeatability proof anchor is `control_plane_gold_image_acceptance_repeats_boot_and_recycle_without_leaking_runtime_artifacts`, which runs that same acquire, RDP, recycle, and cleanup cycle twice against one control-plane instance and requires the pool to return to `Ready` after each cycle.
- The independent-client proof anchor is `control_plane_external_client_interoperability_smoke_uses_xfreerdp`, which exercises the same prepared image store through an external RDP client flow instead of relying only on control-plane-local readiness checks.
- All three positive anchors must bind to the same validated interop store root and manifest attestation identity at lease time, so a generic `win11` or `win11-canary` lab only counts if it was first imported into that attested Tiny11-derived store through the documented consume path.
- The fail-closed negative controls are `control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire` plus the contract-tier interop-store evidence checks, which prove tampered or escaped base-image paths are rejected before lease use.
- The verifier only accepts row `706` evidence when the selected run manifest is `complete`, all four fragments are present in that run, all required positive anchors are `executed=true` and `passed`, the negative control is `executed=true` and `passed`, and the positive anchors agree on `attestation_ref`, `base_image_path`, and `image_store_root`.
- Fragment writers now fail closed unless the run manifest already exists, and the run-scoped directory is canonicalized so symlinked or escaped paths cannot masquerade as legitimate row-`706` evidence.
- Skipped `lab-e2e` anchors now record explicit `executed=false` row-`706` fragments inside the active run, which means the verifier fails closed instead of letting old, partial, or cross-run artifacts masquerade as live Tiny11 proof.
- If the local machine does not have a prepared Tiny11-derived interop image store plus the explicit `DGW_HONEYPOT_INTEROP_*` inputs, this row must remain unchecked even when the gated tests compile and skip cleanly, and env presence alone is not enough without the validated store-binding checks above.

## Host Resource And Network Control Evidence

- `AGENTS.md` pass row `Add host-side resource and network controls.` is satisfied by the combined control-plane unit coverage and contract-tier integration coverage.
- `honeypot/control-plane/src/qemu.rs` proves the checked-in launch contract fails closed when QEMU CPU, memory, or stop-time settings exceed `runtime.limits`, keeps the guest on loopback-forwarded user-mode networking with `restrict=on`, and rejects TCP QMP or other exposed control-channel regressions.
- `testsuite/tests/honeypot_control_plane.rs` proves the service fails closed when the configured QEMU vCPU count exceeds the configured runtime ceiling in `control_plane_fails_closed_when_qemu_resource_limits_are_exceeded`.
- `testsuite/tests/honeypot_control_plane.rs` proves acquire fails before lease use when a trusted base image would exceed the configured overlay-size ceiling in `control_plane_rejects_base_images_that_exceed_overlay_size_limit`.
- `testsuite/tests/honeypot_control_plane.rs` proves the process driver escalates recycle shutdown from `SIGTERM` to bounded `SIGKILL` cleanup, then returns the lease to the ready pool without leaving runtime artifacts behind in `control_plane_recycle_escalates_to_emergency_stop_after_stop_timeout`.

## Teardown Safety Evidence

- `AGENTS.md` pass row `Normal and failure-path teardown leave no orphaned QEMU processes, exposed control sockets, leaked overlays, stale containers, stale networks, stale volumes, or unredacted sensitive logs.` is satisfied by the combined Rust `lab-e2e`, `host-smoke`, and contract-tier teardown evidence.
- `testsuite/tests/honeypot_control_plane.rs` proves normal-path QEMU teardown removes the active snapshot, runtime dir, overlay, pid file, QMP socket, QGA socket, and fake-QEMU process in `control_plane_lab_harness_teardown_cleans_runtime_artifacts_on_posix_host`.
- `testsuite/tests/honeypot_release.rs` proves host-side orphan cleanup removes stale runtime artifacts plus stale containers, networks, and volumes in `orphan_cleanup_reclaims_vm_and_container_artifacts`.
- `testsuite/tests/honeypot_release.rs` proves the live three-service stack keeps POSIX runtime artifacts isolated and keeps compose logs redacted in `posix_host_artifact_checks_keep_runtime_artifacts_isolated_and_redacted`.
- `testsuite/tests/honeypot_release.rs` proves the rollback failure path preserves the current healthy stack, keeps failure-path compose logs redacted, and still tears down cleanly through the shared cleanup path in `rollback_failure_keeps_the_current_stack_running_and_reports_the_error`.
- `testsuite/tests/cli/dgw/preflight.rs` provides the contract-tier secret-redaction baseline by proving proxy and target passwords stay out of logs on both successful and validation-failure credential provisioning paths.

## Retention And Forensic Boundary Evidence

- `AGENTS.md` pass row `Add retention and forensic boundaries for recordings, streams, operator actions, and vote history.` is satisfied by the canonical retention matrix in [risk.md](risk.md), the operator hygiene steps in [runbook.md](runbook.md), and the current enforcement evidence below.
- `testsuite/tests/honeypot_release.rs` proves the default `host-smoke` compose path leaves no retained stream or recording scratch artifacts on disk in `posix_host_artifact_checks_keep_runtime_artifacts_isolated_and_redacted`.
- `testsuite/tests/honeypot_control_plane.rs` proves the Rust `lab-e2e` teardown path removes lease-scoped overlays, runtime dirs, pid files, QMP sockets, and QGA sockets instead of retaining them after recycle in `control_plane_lab_harness_teardown_cleans_runtime_artifacts_on_posix_host`.
- `testsuite/tests/honeypot_release.rs` proves orphan cleanup reclaims stale runtime artifacts plus stale containers, networks, and volumes in `orphan_cleanup_reclaims_vm_and_container_artifacts`.
- `testsuite/tests/honeypot_release.rs` and `testsuite/tests/cli/dgw/preflight.rs` prove normal and failure-path logs stay redacted, which enforces the policy that secrets are not retained as forensic artifacts.
- [contracts.md](contracts.md) and [operator-content-policy.md](operator-content-policy.md) enforce a zero-retention vote-history boundary today because the `gateway.honeypot.command.propose` and `gateway.honeypot.command.approve` placeholders are both non-executing and non-persistent, and no vote surface may persist state until the deferred interactive rows are implemented.

## Deferred Command Placeholder Evidence

- `AGENTS.md` pass rows `Add a command proposal skeleton for future state-messing features.` and `Add a command voting skeleton for future state-messing features.` are satisfied by the current contract-tier placeholder coverage.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the proxy command proposal and vote routes stay disabled by default, enforce their own scoped tokens when enabled, and return typed placeholder responses without execution.
- `testsuite/tests/honeypot_frontend.rs` proves the HTMX-facing frontend proposal and vote routes relay to the proxy placeholders, render deferred or rejected outcomes, and keep execution disabled.
- `honeypot/contracts/src/tests.rs` proves the typed proposal and vote request or response shapes are versioned and reject unsupported schema versions.

## Keyboard Placeholder Evidence

- `AGENTS.md` pass row `Add a keyboard capture placeholder behind explicit policy checks.` is satisfied by the current contract-tier placeholder coverage.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the proxy keyboard placeholder route stays disabled by default, requires the explicit placeholder-approval scope when enabled, and returns a typed `disabled_by_policy` response without execution.
- `testsuite/tests/honeypot_frontend.rs` proves the HTMX-facing frontend keyboard placeholder route relays to the proxy, renders the disabled outcome, and does not echo the submitted keyboard payload back into the UI.
- `honeypot/contracts/src/tests.rs` proves the typed keyboard placeholder request or response shapes are versioned and reject unsupported schema versions.

## Clipboard Placeholder Evidence

- `AGENTS.md` pass row `Add a clipboard capture placeholder behind explicit policy checks.` is satisfied by the current contract-tier placeholder coverage.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the proxy clipboard placeholder route stays disabled by default, requires the explicit placeholder-approval scope when enabled, and returns a typed `disabled_by_policy` response without execution.
- `testsuite/tests/honeypot_frontend.rs` proves the HTMX-facing frontend clipboard placeholder route relays to the proxy, renders the disabled outcome, and does not echo the submitted clipboard payload back into the UI.
- `honeypot/contracts/src/tests.rs` proves the typed clipboard placeholder request or response shapes are versioned and reject unsupported schema versions.

## Matrix Authority Evidence

- `AGENTS.md` pass row `Keep the Decision Freeze Matrix and Ownership Matrix authoritative.` is satisfied by the current docs-governance coverage.
- `testsuite/tests/honeypot_docs.rs` proves the core honeypot docs still route frozen policy through `DF-*` rows, route seam ownership through `OM-*` rows, and keep the replacement-note requirement on any future seam change.
- `docs/honeypot/decisions.md`, `docs/honeypot/architecture.md`, and `docs/honeypot/contracts.md` are the canonical authority chain enforced by that test.

## Milestone Gate Evidence

- `AGENTS.md` pass row `Milestone 0 and Milestone 0.5 are complete before Milestone 1 through Milestone 6 implementation starts.` is enforced by docs-governance coverage in `testsuite/tests/honeypot_docs.rs`.
- That test proves Milestone 0 and Milestone 0.5 checklist rows are fully checked whenever Milestone 1 through Milestone 6 rows are marked complete, and it binds the gate statement to the checked verification-matrix row in `AGENTS.md`.
- This keeps the milestone-order claim fail-closed in repo validation instead of leaving it as a one-time prose assertion.

## Audit Logging Evidence

- `AGENTS.md` pass row `Add audit logging for control-plane actions, session kills, and frontend vote actions.` is satisfied by the existing typed control-plane envelopes, honeypot lifecycle events, and the typed non-executing proposal or vote placeholders.
- `testsuite/tests/honeypot_control_plane.rs` proves acquire, reset, stream-endpoint, release, and recycle responses all carry stable correlation keys in `control_plane_assigns_resets_streams_and_recycles_a_typed_lease`.
- `testsuite/tests/honeypot_visibility.rs` proves session kill auditability in `honeypot_terminate_recycles_vm_and_cleans_up_live_state` by asserting `operator_id`, `session_id`, `vm_lease_id`, and `correlation_id` across `session.killed`, `session.recycle.requested`, and `host.recycled`.
- `testsuite/tests/honeypot_visibility.rs` also proves quarantine auditability in `honeypot_quarantine_recycles_vm_with_quarantined_audit_fields`, including the quarantined recycle outcome and the operator-bound reason code.
- `testsuite/tests/honeypot_visibility.rs` proves stream-bound session termination keeps the same audit identifiers through recycle in `honeypot_stream_binding_is_revoked_after_terminate_recycle`.
- `testsuite/tests/cli/dgw/honeypot.rs` proves the global emergency-stop route remains explicitly scoped to `gateway.honeypot.system.kill`, which is the operator action that fans out into the per-session audited lifecycle sequence.
- `testsuite/tests/cli/dgw/honeypot.rs` and `testsuite/tests/honeypot_frontend.rs` now prove the non-executing proposal and vote placeholders return stable typed identifiers and reason codes for operator-visible audit context without enabling live command execution.
