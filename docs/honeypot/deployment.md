# Honeypot Deployment

## Purpose

This document is the source of truth for the Docker topology, runtime mounts, healthchecks, startup order, and rollback flow for the honeypot fork.
It carries the deployment details required by `DF-01`, `DF-06`, `DF-07`, and `DF-08` in [decisions.md](decisions.md).
It works with [architecture.md](architecture.md), [contracts.md](contracts.md), and [risk.md](risk.md).
It must not be read as permission to add a fourth runtime service, a parallel control plane, or a second container bundle for the same service.

## Compose Identity

- The canonical compose file path is `honeypot/docker/compose.yaml`.
- The fixed compose project name is `dgw-honeypot`.
- The only compose service IDs are `control-plane`, `proxy`, and `frontend`.
- `proxy` is the only service that may bind a public listener on an untrusted network.
- `control-plane` never publishes a host port.
- `frontend` is operator-facing and must bind only to loopback or an operator-only ingress path during local bring-up.

## Image And Build Targets

- `control-plane` uses `honeypot/docker/control-plane/Dockerfile`.
- `proxy` uses `honeypot/docker/proxy/Dockerfile`.
- `frontend` uses `honeypot/docker/frontend/Dockerfile`.
- The build context for each image is the repository root so shared crates and workspace metadata remain available.
- The legacy `package/Linux/Dockerfile` path is reference-only and must not be used as the honeypot `proxy` or `frontend` image base by accident.

## Images Lock Consumption

- `honeypot/docker/images.lock` is the only source of truth for the `current` and `previous` image digests used by compose bring-up and rollback drills.
- Compose resolution must pin each service by digest rather than by floating tag.
- The default bring-up path uses the `current` digest for `control-plane`, `proxy`, and `frontend`.
- The rollback path may swap exactly one service to its `previous` digest while the other two remain on `current` if the compatibility rules in [contracts.md](contracts.md) allow that mix.
- Any change to `images.lock` must come from the release promotion flow rather than an ad hoc compose edit.

## Runtime Env Files

- `control-plane` reads `honeypot/docker/env/control-plane.env`.
- `proxy` reads `honeypot/docker/env/proxy.env`.
- `frontend` reads `honeypot/docker/env/frontend.env`.
- These env files hold non-secret runtime wiring such as bind addresses, internal service URLs, feature gates, and file-path references.
- Secret values must not be stored in these env files.

## Runtime Config Mounts

- `control-plane` mounts `honeypot/docker/config/control-plane/config.toml` at `/etc/honeypot/control-plane/config.toml` as read-only and resolves `auth.proxy_verifier_public_key_pem_file` from the control-plane secret mount rather than from checked-in PEM content.
- `proxy` mounts `honeypot/docker/config/proxy/gateway.json` at `/etc/honeypot/proxy/gateway.json` as read-only, uses `DGATEWAY_CONFIG_PATH=/etc/honeypot/proxy` from its env file so the existing Gateway loader reads the mounted `gateway.json`, and resolves `Honeypot.ControlPlane.ServiceBearerTokenFile` from the proxy secret mount rather than from checked-in config content.
- `frontend` mounts `honeypot/docker/config/frontend/config.toml` at `/etc/honeypot/frontend/config.toml` as read-only and uses `HONEYPOT_FRONTEND_CONFIG_PATH=/etc/honeypot/frontend/config.toml` from its env file so the frontend binary reads the mounted config explicitly.
- Config mount paths are restart-safe and are the only supported path for service-specific runtime configuration.

## Secret Mounts

- `control-plane` mounts `honeypot/docker/secrets/control-plane/` at `/run/secrets/honeypot/control-plane/` as read-only, and the proxy verifier public key must arrive at `/run/secrets/honeypot/control-plane/proxy-verifier-public-key.pem`.
- `proxy` mounts `honeypot/docker/secrets/proxy/` at `/run/secrets/honeypot/proxy/` as read-only, and the MVP proxy-to-control-plane bearer token must arrive at `/run/secrets/honeypot/proxy/control-plane-service-token`.
- `frontend` mounts `honeypot/docker/secrets/frontend/` at `/run/secrets/honeypot/frontend/` as read-only.
- Private signing keys, verification key sets, backend credential references, and similar sensitive inputs must enter the containers only through these secret mount paths.
- Secret rotation is applied by replacing the mounted secret content and then restarting the affected service in dependency order.

## Networks

- The internal service network is `honeypot-control`.
- The public ingress network is `honeypot-edge`.
- `control-plane` joins only `honeypot-control`.
- `proxy` joins both `honeypot-control` and `honeypot-edge`.
- `frontend` joins only `honeypot-control`.
- Local operator access to `frontend` uses a loopback-bound published port rather than attaching `frontend` to the public ingress network.

## Volumes And Host Mounts

- `control-plane` mounts a persistent service data volume at `/var/lib/honeypot/control-plane`.
- `proxy` mounts a persistent service data volume at `/var/lib/honeypot/proxy`.
- `frontend` may use an ephemeral writable filesystem and does not require a persistent data volume for the MVP.
- `control-plane` mounts the host image store at `/srv/honeypot/images` to `/var/lib/honeypot/images` as read-write.
- `control-plane` mounts the host lease and overlay store at `/srv/honeypot/leases` to `/var/lib/honeypot/leases` as read-write.
- `control-plane` mounts the host quarantine store at `/srv/honeypot/quarantine` to `/var/lib/honeypot/quarantine` as read-write.
- `control-plane` mounts the host QMP socket directory at `/srv/honeypot/run/qmp` to `/run/honeypot/qmp` as read-write.
- `control-plane` mounts the host QGA socket directory at `/srv/honeypot/run/qga` to `/run/honeypot/qga` as read-write only if guest-agent support is enabled.
- `proxy` and `frontend` must not mount qcow2 stores, QMP sockets, or QGA sockets.

## Gold Image And Provenance Contract

- The image store may hold only approved Windows 11 Pro x64 base inputs, Tiny11-derived transformation inputs, attestation manifests, and resulting reusable base images.
- Each reusable base image must have a machine-readable manifest that records the ISO acquisition channel, acquisition date, filename, size, edition, language, SHA-256, transformation input refs, transformation timestamp, and resulting base-image digest.
- `control-plane` must refuse to report `ready` if the configured image set lacks the required provenance records or if the recorded digests fail validation.
- `proxy` and `frontend` must never mount, read, or modify base images, manifests, or quarantine artifacts directly.

## QEMU Runtime Contract

- `control-plane` launches `qemu-system-x86_64` directly from the container image and must not delegate launch, reset, or recycle to Bash, Python, libvirt, or unpublished host wrappers.
- Each leased VM gets a unique `vm_lease_id`, a dedicated overlay path under `/var/lib/honeypot/leases/<lease_id>/overlay.qcow2`, a dedicated QMP socket under `/run/honeypot/qmp/<lease_id>.sock`, and an optional QGA socket under `/run/honeypot/qga/<lease_id>.sock`.
- Any runtime temp files, display artifacts, or per-lease metadata must stay inside control-plane-owned paths tied to `vm_lease_id`.
- A lease is reusable only after QEMU exit is confirmed, sockets are removed, the overlay and tempdirs are deleted, and the base-image chain still passes integrity and provenance checks.
- Failure at boot, reset, recycle, socket cleanup, or integrity verification moves the affected lease and related artifacts to `/var/lib/honeypot/quarantine` and marks the host state degraded or unsafe until operator review.

## Control-Plane Least-Privilege Contract

- `control-plane` receives `/dev/kvm` and no wildcard `/dev` mount.
- `control-plane` runs without `privileged: true`.
- `control-plane` may mount only the documented image, lease, quarantine, QMP, and optional QGA paths plus its own service data volume.
- `control-plane` must not mount `/var/run/docker.sock`, the host root filesystem, or unrelated device nodes.
- `control-plane` must not mount a libvirt socket, a system bus, or another hidden runtime-control surface as a substitute for the documented QEMU contract.
- `control-plane` must not use host networking.
- `control-plane` may attach only to `honeypot-control` plus any explicitly documented host bridge needed for guest networking.
- Extra Linux capabilities are forbidden unless a later deployment revision documents the exact need and scope.
- Guest egress controls belong to the host bridge and QEMU networking policy, not to an unrestricted container capability set.

## Service Ports And Healthchecks

- `control-plane` exposes only its internal HTTPS API on `honeypot-control`.
- `control-plane` health is checked through `GET /api/v1/health` and must report `ready`, `degraded`, or `unsafe` according to [contracts.md](contracts.md).
- `proxy` exposes its public listener on `honeypot-edge` and its internal API surfaces on `honeypot-control`.
- `proxy` health is checked through `GET /jet/health`.
- `frontend` exposes its operator HTTP endpoint only on loopback during local compose bring-up.
- `frontend` health is checked through `GET /health`.
- A service is considered ready for downstream startup only after its healthcheck is passing.

## Startup Order

- `control-plane` starts first.
- `proxy` starts only after `control-plane` is healthy because lease acquisition, recycle, and stream-source lookup depend on it.
- `frontend` starts only after `proxy` is healthy because bootstrap, events, auth, and stream-token issuance depend on it.
- A failed `control-plane` healthcheck blocks `proxy` and `frontend` from entering ready state.
- A failed `proxy` healthcheck blocks `frontend` from entering ready state.

## Public Entry And Operator Access

- `proxy` remains the only service that accepts attacker traffic.
- `frontend` is not a public anonymous dashboard.
- The default local compose path binds `frontend` to `127.0.0.1` only.
- If a remote operator ingress is later added, it must remain operator-scoped and must not place `frontend` directly on an untrusted edge network.

## Bring-Up Flow

- Resolve the `current` digests for all three services from `honeypot/docker/images.lock`.
- Start `control-plane` with its env file, config mount, secret mount, data volume, host mounts, and `/dev/kvm`.
- Wait for `control-plane` to validate the configured image manifests, host mounts, QMP or QGA paths, and `/dev/kvm` access before it may report `ready` or a documented `degraded` state that still permits lease lookup.
- Start `proxy` with its env file, `gateway.json` config mount, secret mount, and data volume.
- Wait for `proxy` health to pass before starting `frontend`.
- Start `frontend` with its env file, config mount, and secret mount.
- Confirm that the compose stack reports healthy `control-plane`, `proxy`, and `frontend` services before any operator or attacker traffic is allowed.

## Rollback Flow

- Rollback always starts from `honeypot/docker/images.lock`.
- To roll back one service, keep two services on `current` and select the target service `previous` digest from `images.lock`.
- Stop and recreate only the target service while keeping the other two running if the compatibility rules in [contracts.md](contracts.md) allow that combination.
- Verify the downgraded service health before resuming observation or traffic.
- To restore the rolled-back service, repeat the same flow with the `current` digest.
- If a rollback crosses an unsupported compatibility boundary, stop the stack and redeploy all three services from a known-good `current` or `previous` set instead of forcing a mixed version.

## Emergency Stop And Quarantine

- A global emergency stop starts at `proxy`, halts new intake, kills live sessions, revokes live stream and credential material, and requests recycle for every assigned lease.
- `control-plane` quarantines any lease or image chain that fails reset, recycle, integrity, or provenance checks.
- Quarantine moves or snapshots the affected overlay, runtime metadata, and related review artifacts under `/var/lib/honeypot/quarantine` without reopening those paths to `proxy` or `frontend`.
- Deployment wiring must preserve access to the quarantine and image stores for post-incident review without reopening them to `proxy` or `frontend`.
- Cleanup and quarantine behavior must not depend on unpublished ad hoc host scripts.

## Release And Future Files

- This document defines the runtime contract that `honeypot/docker/compose.yaml` must eventually encode.
- This document assumes `honeypot/docker/images.lock` exists and is maintained by the release process described in the future [release.md](release.md).
- Later milestones may create `honeypot/docker/compose.yaml`, `honeypot/docker/images.lock`, and the three Dockerfiles, but they must follow the service IDs, path contracts, startup order, and rollback rules frozen here.
