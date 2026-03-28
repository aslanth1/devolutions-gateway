# Results

## Success Or Failure

Success.
The live operator proof row for the three-host manual deck is now satisfied and was checked in `AGENTS.md`.
The baseline verification path is green after the recycle-path fix.

## Observable Signals

The authoritative live proof run was `manual-lab-837e08fd6ad24ff98cf955d8c8116a82`.
`up.log` records three distinct session assignments, three `vm_lease_id` values, three stream ids, and Chrome plus helper-display startup.
`status-after-up.txt` records `control_plane_health.active_lease_count=3`, `frontend_health.live_session_count=3`, and `frontend_health.ready_tile_count=3`.
`down.txt` records `notes=<none>`, which is meaningful because teardown now emits explicit notes for release, recycle, and lease-drain failures.
`status-after-down.txt` records `manual lab is not active`.
The full baseline gate completed with `307 passed; 0 failed`.

## Unexpected Behavior

The earlier failed proof run `manual-lab-91d9942683ab41ed942b69bd903724f1` showed that `down` could remove the active-state file while still failing to drain control-plane leases.
The direct runtime evidence showed that release was fast and recycle was the blocking step.
The first recycle optimization restored live teardown speed but briefly regressed the expected quarantine response when the trusted-image catalog had gone stale.
