# What Worked

- Reusing the existing ready-path sustain reducer pattern made the multi-session proof additive instead of invasive.
- Turning slot accounting into a top-level persisted summary closed the proof gap without changing runtime ownership.
- Focused tests through the real `integration_tests` harness caught contract issues cheaply before the full baseline run.
- Guacd’s explicit graphics-policy mindset was a useful reminder to encode named states directly rather than infer them from blended summaries.

# What Failed

- Assuming the manual-lab tests had their own dedicated Cargo test target wasted one iteration.
- Adding a new field to the evidence envelope without updating every constructor caused an immediate compile failure.

# What To Avoid Next Time

- Do not accept multi-session claims that only mention “the run” or “a representative session” without slot-scoped accounting.
- Do not create a new live-lab lane first when the real defect is a missing sanctioned reducer in persisted evidence.
- Do not trust focused test target names without checking `testsuite/Cargo.toml` and `testsuite/tests/main.rs`.

# Promising Next Directions

- `BS-36`: build green/amber/red run verdicts on top of the new slot-scoped reducer so the classification model has stable inputs.
- Add a same-day control-run artifact that records multi-session slot outcomes beside experimental lanes once the verdict taxonomy lands.
