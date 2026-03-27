# Honeypot Risk Policy

## Purpose

This document defines the safety, provenance, and teardown boundary for the honeypot fork.
It works with `docs/honeypot/architecture.md` and the `DF-*` rows in `AGENTS.md`.
This document does not by itself approve any deployment, artifact, or operator workflow.
This document must not be read as permission to add a fourth runtime service or a parallel control plane.

## Authorized Use

- This fork is for authorized defensive research only.
- Written authorization from the owner of the target environment, network, credentials, and storage is required before the stack is exposed to untrusted traffic.
- Unauthorized deployment, credential harvesting, or use against third-party systems is out of scope.
- Public internet deployment is out of scope until the operator auth, exposure guards, retention rules, and kill-switch controls are frozen under `DF-02` and `DF-08`.
- This repository policy is not a substitute for legal review by the operator’s organization.

## Operator Authorization

- No operator-facing surface should ship until `DF-02` freezes the identity source, authentication flow, and audit envelope.
- Only approved operators may access the honeypot frontend, proxy operator actions, control-plane administration, or stored evidence.
- The roles for watch, propose, approve, and kill must be explicitly separated or intentionally collapsed with written justification in the design record.
- Shared operator credentials are prohibited.
- Every operator-visible action must be attributable to a named identity and linked to `session_id` and `vm_lease_id` where available.
- Until the role model is frozen, future interactive features such as keyboard capture, clipboard capture, and voted command execution remain disabled or stubbed.

## Exposure Limits

- Only `proxy` may accept attacker traffic.
- `control-plane`, host storage, QMP sockets, QGA sockets, qcow2 overlays, and secret mounts must remain on an internal boundary that is not directly internet-exposed.
- `frontend` is an operator surface and must not be treated as an anonymous public dashboard.
- Direct guest RDP exposure outside the `proxy` path is prohibited for the honeypot workflow.
- No deployment may expose host control channels, image stores, or mounted secrets to untrusted networks.
- Public listener rollout requires explicit allowlists, rate controls, and a documented emergency stop before use.
- The deployment gate for that path is `Honeypot.Exposure.PublicInternetEnabled = true` together with a non-empty `Honeypot.Exposure.AllowCidrs` list and a positive `Honeypot.Exposure.IntakeLimitRate`.
- `Honeypot.Exposure.DenyCidrs` may narrow the public allowlist further, but it does not waive the allowlist requirement.
- Public rollout is prohibited if `Honeypot.KillSwitch.EnableSessionKill`, `Honeypot.KillSwitch.EnableSystemKill`, or `Honeypot.KillSwitch.HaltNewSessionsOnSystemKill` is disabled.

## Windows And Tiny11 Provenance

- Windows installation media must come from an official Microsoft distribution path recorded in the repo documentation.
- The approved MVP guest lineage is Windows 11 Pro x64 in one documented language variant, and Windows 11 Home is not acceptable for the gold image.
- The source ISO record must capture the acquisition channel, acquisition date, filename, size, SHA-256, edition, and language before any derived image is trusted.
- Tiny11 transformation inputs, scripts, update level, input checksums, and output checksums must be recorded so the derived artifact can be reproduced or independently verified.
- Every reusable base image must carry an attestation manifest that binds the Microsoft ISO record, the Tiny11-derived transformation inputs, the resulting base-image digest, and the approval identity that released it for lease use.
- Community-repacked ISOs, hand-maintained qcow2 images, and any transformed output that cannot be traced to the approved ISO record are prohibited as lease inputs.
- `WINDOWS11-LICENSE.md` is at most a provisional operator note and must not be treated as a trusted provenance record, license validation artifact, or release approval.
- The control plane must refuse to lease any image whose provenance record, checksum chain, or attestation is incomplete, mismatched, or missing.

## Attacker Content Handling

- Treat recordings, screenshots, logs, stream output, and operator notes as sensitive attacker content.
- Collection must be minimized to what is needed for authorized defensive research and operational safety.
- Secrets, credentials, and personally identifying information must be redacted from exported evidence unless explicit authorization and a documented need require otherwise.
- Recordings and logs must stay on access-controlled storage and must not be mirrored to third-party analytics or cloud services by default.
- Operators must not browse, share, or replay attacker content outside the scope of the authorized research objective.
- The detailed role-to-content rules for attacker material live in [operator-content-policy.md](operator-content-policy.md).
- Retention windows, export rules, and deletion behavior must be frozen under `DF-08` before long-running capture or external reporting workflows are enabled.

## Teardown And Incident Response

- Session end must trigger session-bound credential revocation and a request to recycle or quarantine the assigned VM lease.
- Suspected guest compromise requires the affected lease or image chain to leave the reusable pool until reviewed.
- Suspected control-plane or host compromise requires intake to stop, active tokens and credentials to be revoked where possible, and the affected host to be isolated from further attacker traffic.
- Provenance failure, checksum mismatch, or image corruption must be treated as a hard stop for leasing rather than a warning.
- A lease may return to service only after QEMU exit, overlay discard, socket cleanup, and base-image revalidation succeed together.
- Any reset, recycle, cleanup, or integrity failure must move the affected lease artifacts into quarantine instead of silently returning a dirty VM to service.
- Teardown must remove or quarantine stale QEMU processes, control sockets, overlays, tempdirs, recordings, and related runtime artifacts according to the documented cleanup path.
- Incident response must preserve enough audit data to explain operator actions without keeping unnecessary access to unsafe content alive.
- The step-by-step operator response flow for startup, emergency stop, quarantine, evidence capture, and recovery lives in [runbook.md](runbook.md).

## Decision Links

- `DF-02` owns the operator identity, service-to-service auth, and audit envelope that this policy requires.
- `DF-05` owns the Windows and Tiny11 provenance decisions that this policy constrains.
- `DF-08` owns the exposure, retention, redaction, emergency-stop, and quarantine decisions that this policy constrains.
- `docs/honeypot/architecture.md` owns the three-service boundary and reuse map that this policy assumes.
