# Honeypot Operator Content Policy

## Purpose

This document is the source of truth for who may access attacker content, who may act on a live session, and how sensitive attacker content must be handled.
It works with [contracts.md](contracts.md), [risk.md](risk.md), and [runbook.md](runbook.md).
It carries the operator-content rules required by `DF-02` and `DF-08`.
It must not be read as approval to enable deferred interactive features before their implementation rows are complete.

## Scope

- This policy applies to live streams, replayable recordings, screenshots, logs, audit records, operator notes, exported evidence, and quarantined honeypot artifacts.
- This policy applies to `frontend`, `proxy` operator routes, `control-plane` administration, and any host-side incident review tied to the honeypot stack.
- Retention windows and deletion behavior are defined in [risk.md](risk.md).
- This policy does not replace the dedicated audit-logging requirement that remains open elsewhere in `AGENTS.md`.

## Role Model

- `watch` is the active observation role.
- `kill` is the active intervention role.
- `propose` is a reserved future role and is disabled for MVP.
- `approve` is a reserved future role and is disabled for MVP.
- Shared operator credentials are prohibited.
- Every operator-visible action must remain attributable to a named identity.

## Role To Scope Mapping

- `watch` maps to `gateway.honeypot.watch`.
- Live stream access also requires `gateway.honeypot.stream.read`.
- `kill` maps to `gateway.honeypot.session.kill` for single-session kill and quarantine.
- `kill` also maps to `gateway.honeypot.system.kill` for global emergency stop.
- `propose` maps to `gateway.honeypot.command.propose`, but that scope remains reserved only.
- `approve` maps to `gateway.honeypot.command.approve`, but that scope remains reserved only.
- No operator may use `propose` or `approve` for real command execution until the deferred voting and command rows are implemented and explicitly enabled.

## Allowed Actions

- `watch` may load bootstrap state, consume live events, observe active sessions, and request stream tokens when paired with `gateway.honeypot.stream.read`.
- `watch` may review operator-safe evidence that has already been captured and redacted for the authorized research objective.
- `watch` may not kill sessions, quarantine guests, halt intake, or reopen quarantined host artifacts through operator workflows.
- `kill` may do everything `watch` may do.
- `kill` may terminate a live honeypot session, quarantine a suspicious guest, and invoke the global emergency stop when the matching scope is present.
- `kill` may trigger evidence capture only as part of an authorized defensive workflow that preserves audit context and follows the export limits below.
- `propose` and `approve` remain non-operational placeholders in MVP and authorize no live feature today.

## Sensitive Content Classes

- Live stream output is sensitive attacker content because it may contain credentials, PII, malware behavior, or unrelated third-party data.
- Recordings and screenshots are sensitive attacker content for the same reason and must be handled as evidence, not as general media.
- Logs and audit records are sensitive when they contain session metadata, host state, or operator actions tied to a live incident.
- Operator notes are sensitive when they include attacker identifiers, captured commands, screenshots, or incident conclusions.
- Quarantined overlays, QMP or QGA metadata, attestation files, and related host artifacts are sensitive incident material and must stay off the normal operator dashboard path.

## Handling Rules

- Access to attacker content must follow least privilege and the authorized research objective.
- Operators must access only the minimum content needed for observation, intervention, or incident response.
- Secrets, guest credentials, service tokens, private keys, and personally identifying information must be redacted from exported material by default.
- Operators must not mirror attacker content to third-party analytics, personal cloud storage, chat systems, or ad hoc external tools.
- Operators must not reopen quarantined overlays or host control artifacts through `proxy` or `frontend`.
- Operators must not browse attacker content for curiosity, training, or unrelated research outside the written authorization scope.
- Operators must stop and escalate if the content appears to exceed the authorized scope or requires a separate legal or incident response path.

## Evidence Export And Review

- Export requires a named operator, a documented reason, and a case record tied to the authorized defensive objective.
- Every exported bundle must preserve `operator_id`, `session_id`, `vm_lease_id`, and `correlation_id` when those values exist.
- Every exported bundle must record the export time, the reason for export, and whether the material was redacted.
- Export must include only the minimum logs, screenshots, recordings, notes, or quarantine artifacts needed for the case.
- Exported material must follow the retention windows and deletion boundaries defined in [risk.md](risk.md).
- Secret mounts must never be copied into an evidence bundle.
- Unredacted evidence requires explicit authorization and a documented need that outweighs the default redaction rule.
- Review of quarantined host artifacts must happen through the host-side incident path described in [runbook.md](runbook.md), not through browser-facing surfaces.

## Prohibited Actions

- Shared or anonymous operator access is prohibited.
- Off-scope sharing of attacker content is prohibited.
- Exporting raw secrets, private keys, bearer tokens, or backend credentials is prohibited.
- Using deferred `propose` or `approve` concepts as a pretext for live command execution is prohibited.
- Reusing attacker content in demos, screenshots, or external communication without redaction and authorization is prohibited.
- Deleting or mutating quarantined artifacts before the incident record is complete is prohibited.

## Incident Escalation

- Suspected illegal or out-of-scope content must be escalated through the operator's authorized incident path instead of being handled ad hoc inside the honeypot UI.
- Suspected host compromise, guest compromise, or provenance failure must move the affected lease or image into quarantine and follow the recovery steps in [runbook.md](runbook.md).
- If there is uncertainty about whether content may be viewed, exported, or shared, default to preserving audit context and restricting access until an authorized reviewer decides otherwise.
