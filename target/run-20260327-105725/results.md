# Success / Failure

Partial success.

Completed this turn:

- added a tested manual-headed checklist profile under the existing `row706` evidence root
- narrowed the Windows provisioning key policy to one explicit tracked file
- added runtime/preflight split wording to the manual-headed docs
- updated AGENTS to check the checklist rows that now have explicit enforced surfaces:
  - `698`
  - `701`
  - `719`
  - `722`

Still open:

- `704`
- `707`
- `710`
- `713`
- `716`
- `735`

Those rows still require real runtime artifacts or a real live Tiny11-derived interop run.

# Observable Signals

- new integration tests passed:
  - `honeypot_manual_headed::manual_headed_profile_accepts_complete_runtime_bound_profile`
  - `honeypot_manual_headed::manual_headed_profile_rejects_runtime_anchor_without_verified_row706_binding`
  - `honeypot_manual_headed::manual_headed_profile_rejects_digest_mismatch`
  - `honeypot_manual_headed::manual_headed_profile_rejects_escape_relpath`
  - `honeypot_manual_headed::manual_headed_profile_rejects_missing_session_binding_for_headed_observation`
- docs tests passed, including the narrow Windows key allowlist guard
- `cargo clippy --workspace --tests -- -D warnings` passed
- final exact `cargo test -p testsuite --test integration_tests` passed with `275 passed`

# Unexpected Behavior

- two unrelated tests flaked on intermediate full-suite attempts:
  - one port bind conflict in `proxy_health_recovers_after_control_plane_outage`
  - one transient session-removal assertion in `honeypot_quarantine_recycles_vm_with_quarantined_audit_fields`
- both were resolved by rerun and were not caused by the new manual-headed profile
- the current shell still lacks the explicit Tiny11 interop env required to close row `735`
