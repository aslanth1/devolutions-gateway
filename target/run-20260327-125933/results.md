# Success / Failure

Success for row `719`.
The repo now treats manual-headed video evidence as a shared verifier contract instead of a writer-only check.

# Observable Signals

- `manual_video_evidence` is now validated in the shared manual-headed authority, not only in the CLI writer.
- Weak video metadata is rejected during envelope verification even when the artifact digest matches the recorded digest.
- The enforced video metadata contract now requires:
  - `video_sha256`
  - `duration_floor_secs`
  - `timestamp_window`
  - `storage_uri`
  - `retention_window`
  - matching `session_id` and `vm_lease_id` when those identifiers are expected
- Docs and governance tests now describe the same contract.
- `AGENTS.md` row `719` is checked.

# Unexpected Behavior

- One unrelated full-suite flake appeared in `cli::dgw::honeypot::honeypot_events_route_is_disabled_by_default`.
- It passed immediately on exact rerun, and the final exact full-suite rerun passed with `287 passed`.
- No new live Tiny11 runtime proof was produced in this run, so rows `710`, `713`, `716`, and `738` remain open.
