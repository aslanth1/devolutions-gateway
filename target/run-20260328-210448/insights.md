# Insights

## What Worked

- The council converged quickly on the same structure: a hypothesis-and-evidence matrix is much better than a generic checklist for avoiding repeated black-screen work.
- Replacing the earlier short `Milestone 6v` stub with row IDs and pass criteria made the playback investigation lane much more referenceable.
- `git diff --check -- AGENTS.md` was a useful lightweight validation step for a docs-only change even though cargo validation was blocked elsewhere.

## What Failed

- The relevant docs test path is currently blocked by unrelated dependency compilation failures in `sspi 0.15.14` and friends, so AGENTS validation cannot presently rely on cargo alone.
- A shorter checklist would have been easier to land, but it would not have enforced the anti-duplication rules the user explicitly wanted.

## What To Avoid Next Time

- Do not reopen black-screen experiments without citing the specific `BS-*` row and the prior artifact root it is extending or replacing.
- Do not silently promote any `xfreerdp` flag experiment into the baseline lane without first satisfying `BS-02`.
- Do not treat a cargo compile failure in unrelated dependency work as evidence that the AGENTS matrix itself is invalid.

## Promising Next Directions

- Start execution at `BS-01` through `BS-10` to freeze the control-lane evidence contract before touching playback code again.
- Once the current dependency compile blocker is cleared, rerun the honeypot docs tests and then begin clearing the instrumentation rows `BS-11` through `BS-20`.
- Use the new row IDs in future run bundles and commits so black-screen work is tracked by evidence branch rather than by vague narrative summaries.
