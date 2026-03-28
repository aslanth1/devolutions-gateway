# Results

## Outcome

Success.

The repo now has first-class Make shortcuts for the prepared-host tiers:

- `make test-host-smoke`
- `make test-lab-e2e`

`test-host-smoke` stays non-mutating by default.
`test-lab-e2e` now checks for known-good artifacts first and only falls back to the sanctioned Rust artifact path when needed.

## Observable Signals

- `make -n test-host-smoke` prints only the `DGW_HONEYPOT_HOST_SMOKE=1` test launch and no artifact precheck.
- `make -n test-lab-e2e` prints:
  - a generated tier gate under `target/honeypot/lab-e2e-gate.json`
  - a profile-aware `manual-lab-ensure-artifacts` precheck
  - the final `DGW_HONEYPOT_LAB_E2E=1` test launch
- `LAB_E2E_PRECHECK=0 make -n test-lab-e2e` prints the explicit skip message and does not expand the nested Rust `ensure-artifacts` recipe.
- `MANUAL_LAB_PROFILE=local make test-lab-e2e LAB_E2E_TEST_ARGS='control_plane_lab_harness_startup_reaches_rdp_readiness_on_posix_host -- --nocapture'` passed and reused the warmed local artifact store.

## Unexpected Behavior

- `make test-host-smoke HOST_SMOKE_TEST_ARGS='pull_by_digest_host_smoke_resolves_current_service_images -- --nocapture'` failed because `honeypot/docker/images.lock` still carries placeholder current tags.
- That is an existing release-input blocker surfaced by the wrapper, not a regression in the Make target itself.
