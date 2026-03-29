# What Worked

- Reusing the pinned IronRDP DVC seam was enough for a bounded rdpgfx probe even without an off-the-shelf `RdpgfxClient`.
- A small protocol-level proof was sufficient to close `BS-25` without widening the black-screen evidence JSON.
- Keeping the lane contract explicit and machine-checkable fit the same Guacamole-inspired design direction as earlier tranches.

# What Failed

- The first compile failed on a missing trait import.
- Bare test-name filters under `tests/main.rs` were misleading and matched zero tests.
- Parallel Rust build/test launches just fought over the lockfile and build directory.

# What To Avoid Next Time

- Do not run multiple `cargo` validation commands in parallel when one compile is already in flight.
- Do not update docs or `AGENTS.md` before the bounded protocol seam has compiled and been proven by tests.
- Do not trust short test filters in the `integration_tests` harness; use the fully qualified test path when targeting one test.

# Promising Next Directions

- `BS-27` now has a real IronRDP with/without graphics comparison seam and can focus on visible-output improvement rather than protocol ambiguity.
- If `ironrdp-rdpgfx` and `ironrdp-no-rdpgfx` still leave counters and visible output effectively unchanged, `BS-28` becomes a much stronger next closeout.
