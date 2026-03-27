# Results

## Success Or Failure

Failure for checklist completion, by design.

The turn succeeded at proving the remaining checklist still cannot be performed honestly on this host.

## Observable Signals

- The host has no running honeypot Docker services.
- The host has no running QEMU guest.
- `/srv/honeypot/images` does not exist on this host.
- The stable `kvm-win11` lab still points at a generic Windows 11 ISO and snapshot set, not a documented Tiny11 consume path.
- The local Windows provisioning key file exists, but repo docs still treat that file as key material only, not as provenance.
- The authoritative row-`706` run `6ed7055a-c844-47c0-b2e1-962e63ff354a` remains blocked for manual-headed runtime use because:
  - `gold_image_acceptance` is `executed=false`, `status="skipped"`
  - `gold_image_repeatability` is `executed=false`, `status="skipped"`
  - `external_client_interop` is `executed=false`, `status="skipped"`
  - `digest_mismatch_negative_control` is `executed=true`, `status="passed"`
- The runtime writer still fails closed with:
  - `row706 positive anchor gold_image_acceptance must be executed and passed`
- Finalize still fails closed with:
  - `manual-headed run 6ed7055a-c844-47c0-b2e1-962e63ff354a is incomplete and cannot be finalized yet`
- Baseline verification stayed green:
  - `cargo +nightly fmt --all --check`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests` with `279 passed`

## Unexpected Behavior

- The canonical trusted image-store root from prior docs and runs, `/srv/honeypot/images`, is absent on this machine rather than merely empty.
- The local stable Windows lab has a snapshot named `win11-hellsd-gateway-base`, but there is still no accompanying Tiny11 attestation manifest or consume-image record that would let it count for row `706`.
