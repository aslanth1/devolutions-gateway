# What Was Actually Done

1. Read recent insights from:
   - `target/run-20260327-120218/insights.md`
   - `target/run-20260327-123657/insights.md`
   - `target/run-20260327-125103/insights.md`
   - `target/run-20260327-125933/insights.md`
   - `target/run-20260327-130759/insights.md`
   - `target/run-20260327-131840/insights.md`
   - `target/run-20260327-133831/insights.md`
2. Ran a 3-seat council with `gpt-5.3-codex` / `high` reasoning.
3. Collected immutable host facts:
   - no `*bundle-manifest*.json`, `*interop*manifest*.json`, `*tiny11*manifest*.json`, or `*source-manifest*.json` files were found under `/home/jf`
   - `/srv/honeypot/images` is absent
   - local Windows labs exist only under `/home/jf/research/ned/labs/windows/kvm-win11*`
   - those labs expose generic Win11 assets and no Tiny11 or attestation metadata
4. Confirmed the sanctioned import seam is `cargo run -p honeypot-control-plane -- consume-image --config <control-plane.toml> --source-manifest <bundle-manifest.json>`.
5. Created a run-scoped lab gate file at `target/run-20260327-134944/artifacts/lab-e2e-gate.json`.
6. Ran one first control-plane integration pass with a relative `DGW_HONEYPOT_TIER_GATE` path.
7. Observed that the harness resolved the tier-gate path differently than expected and produced a non-authoritative skipped run due to `No such file or directory`.
8. Corrected the gate path to an absolute path and reran exactly once.
9. Bound the would-be interop store to `/home/jf/research/ned/labs/windows/kvm-win11/vm` and set `DGW_HONEYPOT_INTEROP_MANIFEST_DIR` to the same directory.
10. Observed the fresh row-`706` run fail closed on `invalid_provenance` because that directory contains no `.json` manifests.
11. Reviewed `AGENTS.md` and left row `738` unchecked.

# Commands / Actions Taken

- `date +%Y%m%d-%H%M%S`
- `mkdir -p target/run-20260327-134944/artifacts`
- `find /home/jf -maxdepth 6 \( -iname '*bundle-manifest*.json' -o -iname '*interop*manifest*.json' -o -iname '*tiny11*manifest*.json' -o -iname '*source-manifest*.json' \) 2>/dev/null | sort`
- `if [ -d /srv/honeypot/images ]; then find /srv/honeypot/images -maxdepth 3 -type f | sort; else echo MISSING_STORE; fi`
- `find /home/jf/research/ned/labs/windows/kvm-win11 -maxdepth 4 -type f | sort`
- `find /home/jf/research/ned/labs/windows/kvm-win11-canary -maxdepth 4 -type f | sort`
- `rg -n -i 'tiny11|attestation|bundle-manifest|source-manifest|interop manifest' /home/jf/research/ned/labs/windows/kvm-win11 /home/jf/research/ned/labs/windows/kvm-win11-canary -g '!**/*.qcow2' -g '!**/*.img'`
- `sed -n '1,220p' /home/jf/research/ned/labs/windows/kvm-win11/README.md`
- `sed -n '1,260p' /home/jf/research/ned/labs/windows/kvm-win11-canary/README.md`
- `sed -n '1,220p' /home/jf/research/ned/labs/isos/windows/README.md`
- `sed -n '1,220p' honeypot/control-plane/Cargo.toml`
- `cargo metadata --no-deps --format-version 1 | jq -r '.packages[] | select(.manifest_path|endswith("honeypot/control-plane/Cargo.toml")) | .name, (.targets[] | select(.kind[]=="bin") | .name)'`
- `DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE=target/run-20260327-134944/artifacts/lab-e2e-gate.json DGW_HONEYPOT_INTEROP_IMAGE_STORE=/home/jf/research/ned/labs/windows/kvm-win11/vm DGW_HONEYPOT_INTEROP_MANIFEST_DIR=/home/jf/research/ned/labs/windows/kvm-win11/vm DGW_HONEYPOT_INTEROP_RDP_USERNAME=jf DGW_HONEYPOT_INTEROP_RDP_PASSWORD='ChangeMe123!' cargo test -p testsuite --test integration_tests honeypot_control_plane::control_plane_ -- --nocapture`
- `DGW_HONEYPOT_LAB_E2E=1 DGW_HONEYPOT_TIER_GATE=/home/jf/src/devolutions-gateway/target/run-20260327-134944/artifacts/lab-e2e-gate.json DGW_HONEYPOT_INTEROP_IMAGE_STORE=/home/jf/research/ned/labs/windows/kvm-win11/vm DGW_HONEYPOT_INTEROP_MANIFEST_DIR=/home/jf/research/ned/labs/windows/kvm-win11/vm DGW_HONEYPOT_INTEROP_RDP_USERNAME=jf DGW_HONEYPOT_INTEROP_RDP_PASSWORD='ChangeMe123!' cargo test -p testsuite --test integration_tests honeypot_control_plane::control_plane_ -- --nocapture`

# Deviations From Plan

- The first `lab-e2e` pass used a relative gate path and produced run `526dd6db-8591-41c2-9d83-abb492c55b46`, which skipped for a gate-path resolution error instead of for provenance.
- I treated that as operator error, corrected the path to an absolute path, and reran exactly once.
- After the corrected rerun proved `invalid_provenance`, I did not attempt `consume-image` import or any VM boot, because Gate A had already failed and no truthful source manifest exists on this host.
- I did not rerun the full baseline suite because there were no source-code changes and a baseline rerun would have created additional unrelated row-`706` artifacts.
