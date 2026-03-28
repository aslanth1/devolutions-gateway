# What Worked

- Adding new AGENTS scope was the right move once the checklist had no unchecked rows but the user had a new concrete objective.
- The existing partial `honeypot_manual_lab` code was close enough that compile-driven cleanup plus focused tests landed it quickly.
- Keeping the topology decision explicit avoided a repeated dead end:
  compose is still the right readiness or rollback lane, while the live deck must use host processes.
- Focused non-lab tests for manifest fan-out, proxy-config rendering, and CLI help were high-signal and cheap.

# What Failed

- Marking all new Milestone `6b` rows complete before checking live-proof host prerequisites would have overstated the result.
- A large multi-file patch was brittle; smaller patch batches were more reliable.

# What To Avoid Next Time

- Do not claim a live operator proof run unless the host has isolated helper-display support such as `Xvfb` or another equivalent path.
- Do not leave runtime-only pass criteria hidden inside rows that can only be proven with contract-tier tests.
- Do not treat `DISPLAY` alone as sufficient for an honest background-driver proof run if it would steal focus on the active desktop.

# Promising Next Directions

- Run the remaining Milestone `6b` live-proof row on a host with `Xvfb` or equivalent isolated helper-display support.
- Add a focused live-proof test note or harness artifact format once that operator run is completed.
- If this operator deck becomes a common workflow, consider adding an explicit preflight check that refuses `up` on active desktop fallback unless the operator opted in.
