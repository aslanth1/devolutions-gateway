# Success / Failure

Success.

`BS-25` is now closed with a bounded protocol proof.

# Observable Signals

- `ManualLabDriverKind` now supports an opt-in `ironrdp-gfx` mode that emits `driver_lane=ironrdp-rdpgfx`.
- The repo-owned IronRDP manual driver now accepts `--rdpgfx` and attaches a rdpgfx DVC probe instead of only supporting the no-gfx path.
- The rdpgfx probe advertises capabilities on `Microsoft::Windows::RDS::Graphics` and frame-acknowledges server `EndFrame` PDUs.
- The canonical runbook and docs-policy test now recognize `ironrdp-rdpgfx` as a sanctioned black-screen experiment lane.
- Verification passed:
  - `cargo +nightly fmt --all`
  - `cargo clippy --workspace --tests -- -D warnings`
  - `cargo test -p testsuite --test integration_tests`
- Full integration result: `371 passed; 0 failed`.

# Unexpected Behavior

- The first compile failed on a missing `Decode` import in the new rdpgfx probe module.
- Bare targeted test filters under the `integration_tests` harness matched zero tests until the fully qualified names were used.
- Parallel targeted Rust test invocations only contended on the build lock and did not provide any useful speedup.
