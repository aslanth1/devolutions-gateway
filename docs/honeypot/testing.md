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

## Teardown Safety Evidence

- `AGENTS.md` pass row `Normal and failure-path teardown leave no orphaned QEMU processes, exposed control sockets, leaked overlays, stale containers, stale networks, stale volumes, or unredacted sensitive logs.` is satisfied by the combined Rust `lab-e2e`, `host-smoke`, and contract-tier teardown evidence.
- `testsuite/tests/honeypot_control_plane.rs` proves normal-path QEMU teardown removes the active snapshot, runtime dir, overlay, pid file, QMP socket, QGA socket, and fake-QEMU process in `control_plane_lab_harness_teardown_cleans_runtime_artifacts_on_posix_host`.
- `testsuite/tests/honeypot_release.rs` proves host-side orphan cleanup removes stale runtime artifacts plus stale containers, networks, and volumes in `orphan_cleanup_reclaims_vm_and_container_artifacts`.
- `testsuite/tests/honeypot_release.rs` proves the live three-service stack keeps POSIX runtime artifacts isolated and keeps compose logs redacted in `posix_host_artifact_checks_keep_runtime_artifacts_isolated_and_redacted`.
- `testsuite/tests/honeypot_release.rs` proves the rollback failure path preserves the current healthy stack, keeps failure-path compose logs redacted, and still tears down cleanly through the shared cleanup path in `rollback_failure_keeps_the_current_stack_running_and_reports_the_error`.
- `testsuite/tests/cli/dgw/preflight.rs` provides the contract-tier secret-redaction baseline by proving proxy and target passwords stay out of logs on both successful and validation-failure credential provisioning paths.
