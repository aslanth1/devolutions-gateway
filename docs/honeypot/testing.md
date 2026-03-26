# Honeypot Test Tiers

## Purpose

This document defines the honeypot verification tiers required by `DF-09`.
It works with [decisions.md](decisions.md), [contracts.md](contracts.md), and `testsuite`.
It must keep the default test path CI-safe and must fail closed before any lab-only work runs.

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
