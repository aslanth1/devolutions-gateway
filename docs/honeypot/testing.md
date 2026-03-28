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
- When `DGW_HONEYPOT_RUNTIME_PROOF_STRICT=1` is also set, the runtime-only row-`706` proof anchors fail closed on missing `lab-e2e` or interop prerequisites instead of skipping.
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

## Release Input Contract Evidence

- `AGENTS.md` pass rows around `DF-07` release governance are now anchored by the always-on contract tier before any host-smoke or lab-e2e release drill is attempted.
- `testsuite/src/honeypot_release.rs` validates the checked-in `honeypot/docker/promotion-manifest.json` contract, requires a non-empty `signature_ref`, rejects unknown or duplicate service records plus floating tags, and binds manifest service records to the `current` entries in `honeypot/docker/images.lock`.
- `testsuite/tests/honeypot_release.rs` proves the checked-in release inputs still satisfy that binding in `release_inputs_on_disk_match_the_honeypot_lockfile_contract` and includes negative tests for missing `signature_ref`, floating tags, duplicate or unknown service records, and lockfile-manifest drift.
- This contract-tier release evidence is intentionally narrower than protected-branch or release-time provenance workflows: it proves one manifest-shaped rollout input is present and bound to the checked-in lockfile, but it does not by itself claim external PKI or registry-backed promotion proof.

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

## Canonical Tiny11 Lab Gate

- `AGENTS.md` pass row `Add a canonical Tiny11 availability and readiness gate for lab-backed runs.` is satisfied by `testsuite::honeypot_control_plane::evaluate_tiny11_lab_gate` plus the lab-backed `load_external_client_interop_config` wrapper in `testsuite/tests/honeypot_control_plane.rs`.
- The canonical store root resolves from `DGW_HONEYPOT_INTEROP_IMAGE_STORE` when explicitly configured and otherwise falls back to the documented host default `/srv/honeypot/images`; the manifest dir resolves from `DGW_HONEYPOT_INTEROP_MANIFEST_DIR` or `<store>/manifests`.
- Relevant `lab-e2e` row-`706` anchors now execute one shared fail-closed gate before lease work begins instead of relying on ad hoc env checks.
- The blocker order is `missing_store_root`, `invalid_provenance`, `unclean_state`, `missing_runtime_inputs`, then `ready`.
- `missing_store_root` and `invalid_provenance` both point operators at the sanctioned Rust import path `honeypot-control-plane consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>` instead of permitting manual manifest edits or shell wrappers.
- `invalid_provenance` is still owned by `load_honeypot_interop_store_evidence`, so the gate reuses the existing manifest-backed Tiny11 authority instead of inventing a second verifier.
- `unclean_state` currently rejects stale `.importing` markers in the image store or manifest dir so interrupted imports cannot masquerade as ready Tiny11 state.
- `missing_runtime_inputs` currently covers the required RDP username, RDP password, QEMU binary path, `/dev/kvm`, and `xfreerdp` availability checks that the live interop lane needs before it can claim readiness.

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
- The `manual_stack_startup_shutdown` runtime anchor is now machine-validated instead of free-form.
- Its artifact must be a JSON object under the manual-headed artifacts root with ordered `startup_captured_at_unix_secs` and `teardown_captured_at_unix_secs` fields.
- That same artifact must provide exactly three `services` entries named `control-plane`, `proxy`, and `frontend`.
- Each service entry must declare `evidence_kind` as `health` or `bootstrap` plus `startup_status` as `healthy`, `ready`, or `reachable`.
- Teardown evidence must record `teardown_disposition` as `clean_shutdown` or `explicit_failure`.
- If `teardown_disposition` is `explicit_failure`, the artifact must also provide non-empty `failure_code` and `failure_reason` fields so teardown failure is explicit instead of implied.
- The `manual_tiny11_rdp_ready` runtime anchor is now machine-validated in the shared verifier path rather than left as a free-form provisioning note.
- Its artifact must be a JSON object with `probe`, `identity`, `provenance`, and `key_source` sections.
- `probe.method`, `probe.endpoint`, and `probe.evidence_ref` must stay non-empty, `probe.captured_at_unix_secs` must be positive, and `probe.ready` must be `true`.
- `identity.vm_lease_id` must match the bound runtime anchor identity, and `identity.session_id` must also match whenever the artifact chooses to record it.
- `provenance.row706_run_id`, `provenance.attestation_ref`, and `provenance.interop_store_root` must match the verified row-`706` envelope instead of drifting into detached lineage notes.
- `key_source.class` must be `repo_allowlisted_windows_license` or `non_git_secret_alias`, and `key_source.alias` must name the approved source without storing raw Windows key material or an absolute or host-specific path.
- When `key_source.class` is `repo_allowlisted_windows_license`, the alias is fixed to `WINDOWS11-LICENSE.md`.
- The `manual_video_evidence` runtime anchor is now machine-validated in the shared verifier path rather than only at writer time.
- Its artifact must be a JSON object with `video_sha256`, `duration_floor_secs`, `timestamp_window`, `storage_uri`, and `retention_window`.
- `video_sha256` must be a 64-character hex digest, `duration_floor_secs` must be greater than zero, and `timestamp_window.start_unix_secs` plus `timestamp_window.end_unix_secs` must form a valid ordered range.
- `retention_window` must provide both a non-empty policy string and a positive `expires_at_unix_secs`, and `storage_uri` must remain non-empty so the approved artifact backend can be re-read later.
- When the runtime video anchor is bound to a `session_id` or `vm_lease_id`, the metadata artifact must carry matching values instead of detached or free-form notes.
- The `manual_headed_qemu_chrome_observation` runtime anchor is now machine-validated in the shared verifier path rather than treated as a free-form screenshot note.
- Its artifact must be a JSON object with `qemu_display_mode`, `qemu_launch_reference`, `browser_family`, `frontend_access_path`, and `correlation_snapshot`.
- `qemu_display_mode` must be `headed`, `browser_family` must be `chrome`, and both `qemu_launch_reference` and `frontend_access_path` must remain non-empty.
- `correlation_snapshot` must provide `observed_surface` as `tile` or `session`, plus `observed_session_id` and `observed_vm_lease_id` that match the bound runtime anchor identity.
- The verifier also requires the headed-observation anchor and the Tiny11 RDP-ready anchor to agree on the same `vm_lease_id` inside one manual-headed run.
- The `manual_bounded_interaction` runtime anchor is now machine-validated in the shared verifier path rather than left as a free-form operator note.
- Its artifact must be a JSON object with `interaction_window`, `session_id`, `vm_lease_id`, and `modalities`.
- `interaction_window.start_unix_secs` and `interaction_window.end_unix_secs` must form an ordered positive range whose duration stays within the shared sanity bound.
- `modalities.mouse`, `modalities.keyboard`, and `modalities.browsing` must each provide `event_count > 0` and at least one non-empty `evidence_refs` entry.
- The verifier also requires the bounded-interaction anchor to agree on the same `session_id` and `vm_lease_id` as the headed-observation and video anchors, and it requires the interaction window to stay within the recorded video `timestamp_window`.
- A preflight-only manual-headed run may end in `blocked_prereq`, but that disposition is never sufficient to complete row `735`.
- The sanctioned non-test evidence writer is `cargo run -p testsuite --bin honeypot-manual-headed-writer -- <preflight|runtime|finalize> ...`.
- Its `preflight` mode may record blocked prerequisites under an existing row-`706` run envelope before guest boot, while `runtime` mode refuses to write any runtime anchor unless `verify_row706_evidence_envelope` already passes for the same `run_id`.
- The redaction lane still fails closed for tracked plaintext RDP credentials, session tokens, and similar secrets, but it now allows the single repo-local Windows provisioning key file documented in `WINDOWS11-LICENSE.md` for local Win11 host creation only.
- That allowlist does not extend to manual-headed evidence, exports, screenshots, or any second tracked artifact; the provisioning key must stay confined to that one documented file or an approved mounted secret path.

## Manual Three-Host Observation Deck

- The sanctioned live operator deck launcher is `cargo run -p testsuite --bin honeypot-manual-lab -- preflight|up|status|down`.
- The repo root `Makefile` provides `make manual-lab-preflight`, `make manual-lab-up`, `make manual-lab-up-no-browser`, `make manual-lab-status`, and `make manual-lab-down` as thin wrappers around that same Rust launcher.
- The Make targets only create a local lab-e2e gate file and set `DGW_HONEYPOT_LAB_E2E=1` plus `DGW_HONEYPOT_TIER_GATE` for `preflight` and `up`; they do not replace the required `DGW_HONEYPOT_INTEROP_*` inputs.
- The required manual sequence is `preflight -> remediate -> preflight -> up`.
- This lane is Rust-native and lives in `testsuite::honeypot_manual_lab`; it does not permit Bash or Python wrappers for service startup, Tiny11 fan-out, or teardown.
- The launcher reuses the canonical Tiny11 interop gate instead of inventing a second store verifier.
- It therefore requires the same `DGW_HONEYPOT_LAB_E2E`, `DGW_HONEYPOT_TIER_GATE`, and `DGW_HONEYPOT_INTEROP_*` runtime contract as the external-client live proof path.
- `preflight` and `up` now share one readiness evaluator.
- They must agree on blocker class, image-store root, manifest dir, and remediation anchor for the same blocked fixture.
- `preflight` is advisory and side-effect free.
- `up` reruns the same readiness check immediately before launch and still fails closed if the host drifts after preflight.
- If the blocker is `missing_store_root`, the sanctioned remediation is `honeypot-control-plane consume-image --config honeypot/docker/config/control-plane/config.toml --source-manifest <bundle-manifest.json>`, followed by another `preflight` run.
- The expected ready state is a trusted-image store under `/srv/honeypot/images`, a manifest set under `/srv/honeypot/images/manifests`, and a `preflight` result of `ready`.
- `up` clones one attested Tiny11 manifest lineage into three trusted-image identities with unique `vm_name` and guest RDP ports, starts host-process `control-plane`, `proxy`, and `frontend`, creates three real proxy-backed RDP sessions, requests stream tokens, and only succeeds after the frontend reports three ready tiles.
- `status` reads the active state file at `target/manual-lab/active.json` and reports the bound run root, dashboard URL, process ids, health snapshots, and the known `session_id`, `vm_lease_id`, and `stream_id` values for each slot.
- `down` uses that same active state to best-effort terminate helper clients, terminate live proxy sessions, release plus recycle known leases, stop the three services, and remove the active state file.
- The live three-host deck uses host processes instead of `docker compose` because the current Tiny11 lease path exposes guest RDP through host-loopback forwards such as `127.0.0.1:<guest_rdp_port>`.
- That loopback-scoped transport is compatible with a host-process proxy and hidden `xfreerdp` drivers, but it is not a safe assumption for a separate proxy container.
- Compose therefore remains the validated readiness, health, and rollback topology, while `honeypot-manual-lab` is the sanctioned live observation topology for a real three-host operator deck.
- Chrome opens automatically by default when `up` succeeds.
- Pass `--no-browser` to leave the deck running without opening Chrome, and set `DGW_HONEYPOT_MANUAL_LAB_CHROME` or `DGW_HONEYPOT_MANUAL_LAB_XVFB` if your host needs non-default binary paths.
- A full live-proof run remains separate from the contract-tier tests because it needs an operator host with isolated helper-display support such as `Xvfb`, or the helper `xfreerdp` sessions will render on the active desktop.

## Tiny11 Production And Recycle Evidence

- `AGENTS.md` row `The control plane can produce and recycle at least one Tiny11-derived Windows 11 VM with RDP enabled and host-side cleanup verified.` is stricter than a compile-only or skipped lane.
- That row is only complete after the Rust `lab-e2e` path runs without skip against a prepared Tiny11-derived interop image store and produces live evidence on the current workstation or lab host.
- The configured interop image store is now fail-closed by `testsuite::honeypot_control_plane::load_honeypot_interop_store_evidence`, which requires manifest-backed Windows 11 Pro x64 provenance fields, approval identity, relative in-store base-image paths, and attestation-to-base-image binding.
- The canonical row `706` evidence gate is now `testsuite::honeypot_control_plane::verify_row706_evidence_envelope`, which reads one explicit run-scoped manifest and fragment set under `target/row706/runs/<run_id>/` instead of auto-discovering mixed files from a shared directory.
- The canonical static verifier command is `cargo run -p testsuite --bin honeypot-manual-headed-writer -- verify-row706 --run-id <uuid>`, and it intentionally requires an explicit `run_id` instead of inferring the newest row-`706` directory.
- `testsuite::honeypot_control_plane::attempt_row706_evidence_run` now wraps one explicit row-`706` attempt around that same manifest-and-fragment contract and classifies the result as `verified`, `blocked_prereq`, or `failed_runtime` without inventing a second evidence authority.
- The positive-path proof anchor is `control_plane_gold_image_acceptance_boots_reaches_rdp_and_recycles_cleanly`, which acquires one attested image-backed lease, verifies live RDP readiness with `xfreerdp +auth-only`, and proves recycle removes lease-scoped runtime artifacts.
- The repeatability proof anchor is `control_plane_gold_image_acceptance_repeats_boot_and_recycle_without_leaking_runtime_artifacts`, which runs that same acquire, RDP, recycle, and cleanup cycle twice against one control-plane instance and requires the pool to return to `Ready` after each cycle.
- The independent-client proof anchor is `control_plane_external_client_interoperability_smoke_uses_xfreerdp`, which exercises the same prepared image store through an external RDP client flow instead of relying only on control-plane-local readiness checks.
- All three positive anchors must bind to the same validated interop store root and manifest attestation identity at lease time, so a generic `win11` or `win11-canary` lab only counts if it was first imported into that attested Tiny11-derived store through the documented consume path.
- The fail-closed negative controls are `control_plane_reports_host_unavailable_when_base_image_digest_mismatches_on_acquire` plus the contract-tier interop-store evidence checks, which prove tampered or escaped base-image paths are rejected before lease use.
- The verifier only accepts row `706` evidence when the selected run manifest is `complete`, all four fragments are present in that run, all required positive anchors are `executed=true` and `passed`, the negative control is `executed=true` and `passed`, and the positive anchors agree on `attestation_ref`, `base_image_path`, and `image_store_root`.
- The authoritative live proof run on `2026-03-27` is `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/`, whose manifest is `complete` and whose three positive anchors plus one negative control all passed against the sealed Tiny11 import from `target/run-20260327-173919/artifacts/live-proof/import/images`.
- Fragment writers now fail closed unless the run manifest already exists, and the run-scoped directory is canonicalized so symlinked or escaped paths cannot masquerade as legitimate row-`706` evidence.
- Skipped `lab-e2e` anchors now record explicit `executed=false` row-`706` fragments inside the active run, which means the verifier fails closed instead of letting old, partial, or cross-run artifacts masquerade as live Tiny11 proof.
- If the local machine does not have a prepared Tiny11-derived interop image store plus the explicit `DGW_HONEYPOT_INTEROP_*` inputs, this row must remain unchecked even when the gated tests compile and skip cleanly, and env presence alone is not enough without the validated store-binding checks above.
- Startup-time full attestation remains on the control-plane boot path for large imported Tiny11 stores because request-path qcow2 hashing is already removed, and two clean startup samples against the sealed import reached `ready` in `106785 ms` and `106011 ms` with `trusted_image_count = 1`.
- The documented readiness budget for that single sealed imported store is `120` seconds to reach authenticated `/api/v1/health` `ready`, while the `DGW_HONEYPOT_INTEROP_READY_TIMEOUT_SECS=180` lab-e2e harness value remains the guard-band timeout for slower hosts.

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
