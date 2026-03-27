# What Worked

- Reusing the existing row-`706` manual-headed envelope kept the change small and fail-closed.
- Shared verifier logic for stack artifacts prevented the writer and verifier from drifting.
- Focused negative tests caught a real test-design mistake before the baseline suite.

# What Failed

- A negative semantic test that rewrote an artifact after recording its digest only proved the digest guard, not the new runtime contract.
- Full-suite baseline verification still shows unrelated timing flakes in quarantine-related tests on this host.

# What To Avoid Next Time

- Do not add free-form runtime checklist rows when the evidence can be expressed as a typed JSON contract.
- Do not mutate committed test artifacts after writing their recorded digest unless the test is explicitly about digest mismatch.
- Do not mark remaining Milestone `6a` runtime rows complete without live Tiny11-backed row-`706` proof.

# Promising Next Directions

- Apply the same writer-plus-verifier contract pattern to rows `710`, `713`, `716`, and `719`.
- If the quarantine-route flakes keep recurring, isolate them separately from checklist work so baseline verification noise is reduced.
