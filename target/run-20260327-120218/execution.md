# Execution

## What Was Actually Done

1. Confirmed the host is still cold for the manual checklist:
   - `docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'`
   - `ps -ef | rg 'qemu-system' | rg -v rg || true`
2. Re-read the stable Windows lab metadata:
   - `sed -n '1,220p' /home/jf/research/ned/labs/windows/kvm-win11/README.md`
   - `/home/jf/research/ned/labs/windows/kvm-win11/win11.sh snapshot-list`
3. Searched the local Windows lab roots, license roots, repo docs, and prior run bundles for Tiny11 attestation lineage:
   - `rg -n "tiny11|Tiny11|attest|attestation|manifest|source_ref|base_image|digest|consume-image|interop" /home/jf/research/ned/labs/windows/kvm-win11 /home/jf/VirtualMachines/kvm-win11 /home/jf/research/ned/labs/windows/licenses docs/honeypot target/run-* -S`
   - `find /srv/honeypot/images /home/jf/research/ned/labs/windows/kvm-win11 /home/jf/VirtualMachines/kvm-win11 -maxdepth 4 \( -name '*.json' -o -name '*.md' -o -name '*.txt' -o -name '*.qcow2' -o -name '*.fd' \) | sort`
4. Verified only the key file presence, without printing the key contents:
   - `test -f /home/jf/research/ned/labs/windows/licenses/windows11-pro-key.md && echo PRESENT`
5. Re-ran the sanctioned manual-headed runtime negative control against the existing blocked row-`706` run:
   - `cargo run -p testsuite --bin honeypot-manual-headed-writer -- runtime --evidence-root target/row706 --run-id 6ed7055a-c844-47c0-b2e1-962e63ff354a --anchor-id manual_stack_startup_shutdown --status passed --producer manual-headed-writer --artifact target/run-20260327-115026/artifacts/manual-headed-preflight/runtime/stack-startup-shutdown.json --artifact-relpath runtime/stack-startup-shutdown.json`
6. Re-ran the sanctioned manual-headed finalize negative control against the same blocked row-`706` run:
   - `cargo run -p testsuite --bin honeypot-manual-headed-writer -- finalize --evidence-root target/row706 --run-id 6ed7055a-c844-47c0-b2e1-962e63ff354a`
7. Re-ran the baseline verification path:
   - `cargo +nightly fmt --all --check`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests`

## Deviations From Plan

- I did not attempt to boot the local headed Win11 guest or start the three-service stack because Gate 0 failed before there was admissible Tiny11 lineage.
- I did not try to write duplicate preflight anchors into the existing row-`706` run because the sanctioned writer intentionally rejects duplicate or out-of-order writes.
- I did not update any checklist boxes in `AGENTS.md` because the live Tiny11-backed runtime proof rows remain unfulfilled.
