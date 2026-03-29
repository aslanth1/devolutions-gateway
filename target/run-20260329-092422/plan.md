# Hypothesis

`BS-36` can be closed by adding a single run-level black-screen verdict reducer to the existing manual-lab evidence contract, using the slot-aware reducers from `BS-34` and `BS-35` instead of inventing a new runtime lane or free-form label system.

The guacd review reinforced the design direction:
make graphics or playback state explicit in the contract rather than inferred later from blended behavior.

# Steps

1. Re-ingest prior `target/*/insights.md` artifacts and summarize what worked, failed, and should be reused.
2. Run a three-agent council on the next open `BS-*` row.
3. Use the council to critique whether `BS-36` should be a JSON-only reducer or a JSON-plus-markdown output.
4. Implement the winning plan in `testsuite/src/honeypot_manual_lab.rs`:
   - add a three-state run verdict enum
   - add fixed reason codes
   - add a top-level verdict summary on `ManualLabBlackScreenEvidence`
   - compute it from existing slot-aware and browser/artifact reducers
5. Add focused tests in `testsuite/tests/honeypot_manual_lab.rs` for:
   - green
   - amber
   - missing-slot red
   - duplicate-slot red
   - alignment-gap red
6. Run the baseline verification path:
   - `cargo +nightly fmt --all`
   - `cargo clippy --workspace --tests -- -D warnings`
   - `cargo test -p testsuite --test integration_tests`
7. Update `AGENTS.md` only if the reducer and verification stay green.

# Assumptions

- The existing evidence is already rich enough to classify the run without new orchestration or capture primitives.
- JSON should remain the only decision surface for `BS-36`; markdown, if used later, must be derived rather than authoritative.
- Failing closed is better than widening the taxonomy beyond the three AGENTS buckets.
