# Results

## Outcome

Success for the local hardening objective.
Failure for full row `706` closure, by design, because the required Tiny11-derived interop inputs are still missing.

## Observable Signals

- The new contract-tier store-evidence tests passed.
- The existing digest-mismatch negative control still passed.
- The gated gold-image acceptance and external-client interop lanes compiled and skipped cleanly under the contract tier.
- `cargo clippy --workspace --tests -- -D warnings` passed.
- `cargo test -p testsuite --test integration_tests` passed with `255 passed`.

## Important Findings

- Future row `706` proof must bind lease-time `attestation_ref` and `launch_plan.base_image_path` back to the validated interop manifest store.
- Escaped manifest base-image paths and unattested in-store images are now rejected in contract-tier coverage.
- Generic `win11` or `win11-canary` labs are still insufficient unless they are first imported into the attested Tiny11-derived interop store.

## Unexpected Behavior

- The local Windows lab roots existed and were usable as reference, but they did not provide trustworthy Tiny11 lineage by themselves.
- An initial targeted test run surfaced an unnecessary `std::fs::write` qualification warning, which was fixed immediately before the full verification pass.
