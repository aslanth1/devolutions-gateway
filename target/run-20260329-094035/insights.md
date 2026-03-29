# What Worked

- Extending the existing `ManualLabBlackScreenEvidence` envelope kept the new ledger on the canonical proof path.
- Reusing `run_verdict_summary.primary_reason` avoided inventing a second rejection-reason vocabulary.
- Keeping `BS-37` record-only prevented accidental scope bleed into `BS-38`.
- Explicit hypothesis identity plus fixed retry-condition codes matched the repo’s recent reducer-owned direction.

# What Failed

- A large patch was more fragile than a set of smaller seam-local edits.
- A broad focused-test prefix can miss a new contract slice if the new test names use a different stem.

# What To Avoid Next Time

- Do not treat a driver lane or row id as if it were the hypothesis itself.
- Do not let retry conditions slip into free-form prose.
- Do not add retry enforcement before the recording contract is trusted.

# Promising Next Directions

- `BS-38`: require a same-day control-run verdict beside any new variant result.
- `BS-39`: keep fallback capture blocked until the proxy-owned producer seam is explicitly rejected.
- If a human-readable ledger render is added later, keep it derived from `do_not_retry_ledger` rather than turning it into a second decision surface.
