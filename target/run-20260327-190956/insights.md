What worked:
- a startup-loaded trusted-image catalog removed the repeated qcow2 hash from authenticated health and acquire
- keeping drift detection cheap on the hot path while failing closed preserved the safety posture
- the existing `xfreerdp` interop smoke is the right proof for imported Tiny11 auth parity

What failed:
- leaving the full integration suite unrerun after changing the failure envelope caused avoidable expectation drift
- the live replay still showed that startup-time attestation on a 7.8 GiB imported store is expensive

What to avoid next time:
- do not assume request-path validation is the only latency sink once startup still performs a full attestation pass
- do not preserve old test wording blindly when the fail-closed boundary moves from per-request digest mismatches to catalog drift invalidation

Promising next directions:
- decide whether startup-time full attestation should remain on the control-plane boot path or move behind a narrower preload or refresh contract
- keep using the sealed boot-profile interop smoke as the acceptance bar for future Tiny11 control-plane changes
