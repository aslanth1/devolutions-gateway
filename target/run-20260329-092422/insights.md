# What Worked

- The slot-aware reducers from `BS-34` and `BS-35` were strong enough to support a run-level verdict without new runtime work.
- Treating JSON as the only decision surface kept the design simpler and more testable.
- Fixed reason codes prevented the run verdict from turning into another narrative summary.
- The existing integration harness made it cheap to prove green, amber, and multiple red paths directly.
- Guacd’s explicit graphics-policy mindset remained a useful guide for keeping verdicts reducer-owned and named.

# What Failed

- The council could not separate the final plan variants cleanly enough to avoid a tie.
- The tempting path to also wire markdown now would have widened scope and risked decision-surface drift.

# What To Avoid Next Time

- Do not introduce a human-readable verdict artifact as a second computation path before the structured reducer is canonical.
- Do not classify ambiguous artifact or slot-accounting states as amber just because the underlying producer signals look partly healthy.
- Do not widen the reason vocabulary beyond a fixed machine-checkable set.

# Promising Next Directions

- `BS-37`: add the do-not-retry ledger and attach it to the new canonical run verdicts.
- `BS-38`: use the new run verdict summary as the gate for same-day control-run requirements.
- Revisit `black-screen-verdict.md` only as a render of `run_verdict_summary`, not as its own logic path.
