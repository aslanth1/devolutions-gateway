# Honeypot Release Policy

## Purpose

This document is the source of truth for registry namespaces, tag policy, digest promotion, lockfile authority, and rollback behavior for the honeypot fork.
It carries the release details required by `DF-07` in [decisions.md](decisions.md).
It works with [deployment.md](deployment.md), [contracts.md](contracts.md), and [testing.md](testing.md).
It must not be read as permission to add a fourth runtime service, a second release policy, or floating tags as the rollout source of truth.

## Canonical Image Families

- The canonical registry root is `ghcr.io/<fork-owner>/devolutions-gateway-honeypot`.
- The canonical `control-plane` image is `ghcr.io/<fork-owner>/devolutions-gateway-honeypot/control-plane`.
- The canonical `proxy` image is `ghcr.io/<fork-owner>/devolutions-gateway-honeypot/proxy`.
- The canonical `frontend` image is `ghcr.io/<fork-owner>/devolutions-gateway-honeypot/frontend`.
- No alternate registry namespace or alternate image family may become the rollout source of truth for these three services without updating this file first.

## Tag Policy

- Every promoted image may publish a semver tag and a commit-SHA tag.
- The semver tag format is `v<workspace-version>`.
- The commit-SHA tag format is `git-<12-char-sha>`.
- The semver tag is for human-readable release inspection and stable release references.
- The commit-SHA tag is for traceability to the exact source revision that produced the image.
- Floating tags such as `latest`, `stable`, or branch names are forbidden as rollout inputs.
- Compose and tests may display a semver tag for diagnostics, but they must resolve the runtime image by digest from `honeypot/docker/images.lock`.

## Digest Promotion Rules

- Digest promotion is the only supported release mechanism.
- A service is not considered promoted until its immutable digest is written into `honeypot/docker/images.lock`.
- `honeypot/docker/images.lock` is the sole rollout input for compose bring-up and rollback drills.
- Promotion never rebuilds a service during rollout or rollback.
- Promotion may update one or more services at a time, but each service is still pinned independently by digest.

## `images.lock` Contract

- `honeypot/docker/images.lock` must contain exactly the top-level service entries `control-plane`, `proxy`, and `frontend`.
- Each service entry records `image`, `registry`, `current.tag`, `current.digest`, `current.source_ref`, `previous.tag`, `previous.digest`, and `previous.source_ref`.
- `current` is the default production or lab runtime choice for that service.
- `previous` is the last known-good promoted digest for that service and is retained for rollback.
- The `image` and `registry` fields in `images.lock` must match the canonical image family defined in this file.
- Direct manual edits to `honeypot/docker/images.lock` are forbidden.

## Promotion Manifest

- The only allowed writer for `honeypot/docker/images.lock` is an immutable or attested artifact named `promotion-manifest.json`.
- `promotion-manifest.json` must carry `schema_version`, `generated_at`, `builder_id`, `source_commit`, `source_ref`, and `signature_ref`.
- `promotion-manifest.json` must also carry one service record for each promoted service.
- Each service record must carry `service`, `image`, `registry`, `tag`, `digest`, and `source_ref`.
- The lockfile update step shifts the existing `current` fields into `previous` when a new promoted digest differs from the existing `current` digest.
- A promotion manifest that leaves `current` and `previous` identical for a service is rejected unless it is an audited no-op validation run.

## Validation And Rejection Rules

- The manifest signature or attestation referenced by `signature_ref` must verify before any lockfile update is allowed.
- The `image` and `registry` in the manifest must match the canonical image family for the named service.
- The `digest` in the manifest must resolve in the registry and match the bytes addressed by the named `tag`.
- The `source_ref` in the manifest must match the signed build metadata for that digest.
- A manifest is rejected as stale if it attempts to promote an older source ref over a newer `current.source_ref` without an explicit audited rollback action.
- A manifest is rejected as mismatched if the service name, registry, image path, tag, digest, or source ref disagrees with the signed build metadata.
- A manifest is rejected if it relies on a floating tag as the proof of image identity.
- A manifest is rejected if it omits any field required to write the `current` and `previous` lockfile entries.

## Retention Policy

- The registry must retain at least the `current` and `previous` digests for each of `control-plane`, `proxy`, and `frontend`.
- Registry cleanup must not delete a digest that is still referenced by `honeypot/docker/images.lock`.
- A newly promoted `current` digest does not remove the existing `previous` digest until a newer promotion safely shifts the window.
- Rollback is always performed by selecting an already retained digest and never by rebuilding an old source revision on demand.

## Rollout Policy

- The default rollout path promotes validated digests into `current` entries in `honeypot/docker/images.lock`.
- Rollout may proceed service by service only when the mixed-version rules in [contracts.md](contracts.md) allow the resulting `current` and `previous` mix.
- Rollout validation must reject any service combination that depends on an unsupported `current -> previous` or `previous -> current` contract pairing.
- Deployment tooling must consume the digests from `honeypot/docker/images.lock` rather than recomputing tags or querying mutable registry state at runtime.

## Rollback Policy

- Rollback restores a prior version by selecting the `previous` digest for the affected service from `honeypot/docker/images.lock`.
- Rollback must not rebuild images.
- A single-service rollback is preferred when the compatibility rules in [contracts.md](contracts.md) allow the mixed-version stack.
- A full-stack rollback is required when the target downgrade would violate the allowed compatibility window.
- After a successful rollback, the runtime stack still remains pinned by digest and does not switch to floating tags.

## Mixed-Version Validation Evidence

- The compatibility authority for mixed-version peers lives in [contracts.md](contracts.md) under `Compatibility Rules`.
- The documented supported downgrade directions are `previous/current/current`, `current/previous/current`, and `current/current/previous`.
- The documented supported restore directions are the symmetric `previous -> current` return to `current/current/current` for one adjacent release when the major `schema_version` remains compatible.
- `testsuite/tests/honeypot_release.rs` validates those downgraded contract and compose combinations with `downgraded_control_plane_*`, `downgraded_proxy_*`, and `downgraded_frontend_*` coverage.
- The same test file rejects unsupported mixed-version pairings and schema drift with `downgraded_service_contract_compatibility_rejects_unsupported_previous_pairings`, `downgraded_*_compose_compatibility_rejects_unsupported_previous_pairings`, and the matching `*_rejects_schema_version_drift` cases.
- The same test file validates the restore path with `restored_control_plane_contract_compatibility_is_allowed`, `restored_proxy_contract_compatibility_is_allowed`, and `restored_frontend_contract_compatibility_is_allowed`.
- The same test file rejects unsupported restore starting points and restore-time schema drift with `restored_service_contract_compatibility_rejects_service_that_is_not_previous`, `restored_service_contract_compatibility_rejects_unsupported_starting_point`, and `restored_service_contract_compatibility_rejects_schema_version_drift`.
- Host-smoke rollback drills in the same file validate live mixed-version rollback and recovery for `control-plane`, `proxy`, and `frontend`.
- Rejoin recovery tests in the same file validate that a downgraded or restored service rejoins current peers cleanly before rollback is treated as safe.

## Relationship To Future Files

- `honeypot/docker/images.lock` is the concrete file that will encode the policy defined here.
- `honeypot/docker/compose.yaml` must consume `honeypot/docker/images.lock` and not bypass it with direct tag references.
- Later milestones may add the lockfile and compose file, but they must follow the canonical image names, tag policy, promotion-manifest contract, and current or previous retention window frozen here.
