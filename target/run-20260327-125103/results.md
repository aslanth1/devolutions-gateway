# Success / Failure

Success for row `707`.
The repo now treats the manual startup and shutdown checklist as a machine-validated runtime contract instead of free-form evidence.

# Observable Signals

- `manual_stack_startup_shutdown` artifacts are now rejected unless they:
  - are JSON objects
  - include ordered startup and teardown timestamps
  - include exactly three service entries named `control-plane`, `proxy`, and `frontend`
  - record `evidence_kind` as `health` or `bootstrap`
  - record `startup_status` as `healthy`, `ready`, or `reachable`
  - record teardown as `clean_shutdown` or `explicit_failure`
  - include non-empty `failure_code` and `failure_reason` when teardown is `explicit_failure`
- The writer rejects weak stack runtime artifacts before they enter the manual-headed run envelope.
- The verifier rejects weak stack artifacts even when digests and row-`706` bindings are otherwise valid.
- Docs and governance tests now assert the same contract text.
- `AGENTS.md` row `707` is now checked.

# Unexpected Behavior

- Two unrelated full-suite flakes appeared during baseline verification:
  - `cli::dgw::honeypot::honeypot_session_quarantine_route_respects_kill_switch`
  - `honeypot_visibility::honeypot_quarantine_recycles_vm_with_quarantined_audit_fields`
- Both passed on exact reruns, and the final full-suite rerun passed cleanly with `286 passed`.
- No new Tiny11 runtime proof was created in this run, so the remaining Milestone `6a` runtime rows stay open.
