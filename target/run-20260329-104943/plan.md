# Hypothesis

A bounded repo-owned rdpgfx DVC probe can close `BS-25` by creating a real opt-in `ironrdp-rdpgfx` comparison lane without widening the black-screen evidence contract.

# Steps

1. Re-read recent `target/*/insights.md` artifacts and summarize what worked, what failed, dead ends, and reusable techniques.
2. Run a 3-agent council to choose between a bounded `BS-25` rdpgfx lane proof and a `BS-28` plateau-stop rule.
3. If `BS-25` wins, add the smallest possible IronRDP rdpgfx DVC probe using the pinned `DrdynvcClient`, `DvcProcessor`, and `gfx` PDU surfaces.
4. Add an opt-in `ironrdp-gfx` lane contract that emits `driver_lane=ironrdp-rdpgfx` and preserves the existing black-screen artifact contract.
5. Add focused tests for the lane contract and the rdpgfx probe protocol behavior.
6. Update the canonical runbook and docs-policy test only after the protocol seam is real.
7. Run `cargo +nightly fmt --all`, `cargo clippy --workspace --tests -- -D warnings`, and `cargo test -p testsuite --test integration_tests`.

# Assumptions

- The pinned IronRDP stack does not ship an off-the-shelf `RdpgfxClient`, but its DVC primitives are sufficient for a tiny repo-owned probe.
- `BS-25` can be closed with protocol-meaningful lane proof even before any visible-output win is established.
- If the first compile spike proves the seam is not bounded, the work must stop immediately and pivot to `BS-28` instead of faking a graphics-on lane.
