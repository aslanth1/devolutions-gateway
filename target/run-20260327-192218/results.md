# Success / Failure

- Success: the authoritative live row-`706` envelope is complete at `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/`.
- Success: `external_client_interop.json`, `gold_image_acceptance.json`, `gold_image_repeatability.json`, and `digest_mismatch_negative_control.json` all recorded `executed=true` and `status=passed`.
- Success: the three positive anchors agree on the same `attestation_ref`, `base_image_path`, and `image_store_root`, which satisfies the documented envelope contract.
- Success: startup-time trusted-image attestation stayed fail-closed and reached authenticated `ready` in `106785 ms` and `106011 ms` for the single sealed imported Tiny11 store.
- Success: `AGENTS.md` rows `426` and `765` are now complete.

# Observable Signals

- `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/manifest.json` reports `status = "complete"`.
- `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/external_client_interop.json` reports `xfreerdp auth-only succeeded and recycle returned the pool to ready`.
- `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/gold_image_acceptance.json` reports one full acquire, RDP, recycle, and cleanup cycle.
- `target/row706/runs/5c6c2ece-0c30-4694-a569-353ee88ffae9/gold_image_repeatability.json` reports two full acquire, RDP, recycle, and cleanup cycles.
- The startup measurement harness reported `trusted_image_count = 1`, `service_state = "ready"`, and no degraded reasons on both samples.

# Unexpected Behavior

- The first two manual measurement attempts overlapped and had shell-quoting drift, which made them unsuitable as evidence and forced a clean rerun.
- Startup-time full attestation is still materially expensive at about `106` seconds for the sealed imported store, even though request-path hashing is already removed.
