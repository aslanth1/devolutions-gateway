# Success / Failure

- Success:
  - completed the required council process
  - identified the winning provenance-first plan
  - produced one fresh authoritative blocked row-`706` run for the actual host state
- Failure:
  - row `738` is still not complete
  - this host still lacks a truthful Tiny11 source manifest or attested interop store

# Observable Signals

- Source-manifest search under `/home/jf` returned no candidates.
- `/srv/honeypot/images` is absent.
- `kvm-win11` contains only:
  - `README.md`
  - `win11.sh`
  - `vm/windows11.qcow2`
  - `vm/OVMF_VARS.fd`
- `kvm-win11-canary` contains generic Win11/Canary assets and no Tiny11 or attestation metadata.
- Fresh row-`706` run:
  - run id: `c82e8c2a-749e-4a0d-8a46-6975296fae81`
  - manifest status: `complete`
  - `gold_image_acceptance`: `executed=false`, `status=skipped`
  - `gold_image_repeatability`: `executed=false`, `status=skipped`
  - `external_client_interop`: `executed=false`, `status=skipped`
  - `digest_mismatch_negative_control`: `executed=true`, `status=passed`
- The skipped-positive detail on all three live anchors is:
  - `Tiny11 lab gate blocked by invalid_provenance`
  - `interop manifest dir /home/jf/research/ned/labs/windows/kvm-win11/vm does not contain any .json manifests`
  - remediation points at `honeypot-control-plane consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>`

# Unexpected Behavior

- The first targeted pass used a relative `DGW_HONEYPOT_TIER_GATE` path and produced a non-authoritative skipped run because the harness could not resolve that gate file from its working directory.
- Correcting the gate path to an absolute path fixed the issue immediately and exposed the real blocker: missing Tiny11 provenance.
