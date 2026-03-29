# What Worked

- Restoring the default `xfreerdp` lane to the pre-experiment HEAD arguments prevented the earlier RFX experiment from silently becoming the baseline.
- `black-screen-evidence.json` is now a durable control-run stamp with `git rev`, row IDs, env fingerprint, exact args, and per-session stream results.
- Fresh 1/2/3-session control runs are cheap enough to keep rerunning as same-day comparators.

# What Failed

- No-browser control captures still cannot close rows that explicitly require player console output or websocket-close reasons.
- The restored control lane does not produce a uniformly ready result; the single-session run stays truthful `503`, and the multi-session runs still leave the last slot unavailable.

# What To Avoid Next Time

- Do not mark `BS-*` rows complete from console scrollback alone.
- Do not reopen driver churn until the current control roots are referenced beside any new variant result.
- Do not let an opt-in graphics experiment become the new baseline by accident.

# Promising Next Directions

- Add explicit cleanup or teardown proof for `BS-04`.
- Extend the machine-readable evidence with negotiation counters and warning tallies for `BS-11..19`.
- Run a browser-attached capture lane next so `BS-05`, `BS-09`, and `BS-10` can be judged against actual player console and websocket evidence.
