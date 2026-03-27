# What Was Done

1. Read the currently open AGENTS rows and the prior run `insights.md` files.
2. Inspected the local host state:
   - `DISPLAY=:0`
   - Chrome present
   - `qemu-system-x86_64`, `xfreerdp`, and `/dev/kvm` present
   - Win11 lab roots present under `/home/jf/research/ned/labs/windows/`
   - no `DGW_HONEYPOT_*` interop or lab gate env in the current shell
3. Ran the 3-seat council and selected the single-authority `row706`-profile plan.
4. Mid-turn, the user directed that the repo-local Windows provisioning key must remain tracked.
5. Updated policy and docs to allow exactly one tracked Windows provisioning key file while forbidding that key from evidence bundles and secondary tracked artifacts.
6. Implemented the manual-headed checklist profile under `testsuite/src/honeypot_control_plane.rs`.
7. Added the new manual-headed integration tests and docs-governance assertions.
8. Updated AGENTS progress conservatively.

# Commands And Actions

Host and prerequisite inspection:

```bash
rg -n "^- \\[ \\]" AGENTS.md
sed -n '690,760p' AGENTS.md
sed -n '100,150p' docs/honeypot/testing.md
sed -n '1,240p' /home/jf/research/ned/labs/windows/kvm-win11/README.md
bash /home/jf/research/ned/labs/windows/kvm-win11/win11.sh snapshot-list
env | sort | rg '^(DISPLAY|XAUTHORITY|DGW_HONEYPOT_|WIN11_|NED_WINDOWS_)'
which xfreerdp qemu-system-x86_64 google-chrome
```

Focused verification during implementation:

```bash
cargo test -p testsuite --test integration_tests honeypot_manual_headed -- --nocapture
cargo test -p testsuite --test integration_tests honeypot_docs -- --nocapture
cargo +nightly fmt --all
cargo +nightly fmt --all --check
cargo clippy --workspace --tests -- -D warnings
```

Full-suite verification:

```bash
cargo test -p testsuite --test integration_tests
```

# Deviations From Plan

- The initial plan treated the tracked Windows key as a blocker for row `719`.
- The user overrode that assumption and asked to keep the key, so the implementation changed from "remove/redact key" to "add a narrow allowlist rule for exactly one repo-local Windows provisioning key file."
- The first exact full-suite rerun hit two unrelated flaky tests on separate attempts:
  - `cli::dgw::honeypot::proxy_health_recovers_after_control_plane_outage`
  - `honeypot_visibility::honeypot_quarantine_recycles_vm_with_quarantined_audit_fields`
- Both failures were isolated from the new manual-headed work; the final exact full-suite rerun passed cleanly.
