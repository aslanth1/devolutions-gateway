# Hypothesis

The next honest checklist item to close is `AGENTS.md` row `719`, the manual-headed video-evidence checklist.
The repo already has video metadata validation in the writer, but row `719` is not honestly complete until the shared manual-headed verifier enforces the same contract inside the single `row706` authority.

# Steps

1. Reuse the recent `target/*/insights.md` memory bundle to avoid repeating dead ends.
2. Run a 3-seat council against unchecked rows `710`, `713`, `716`, `719`, and `738`.
3. Select the best row using feasibility, testability, likelihood of real-world success, and clarity.
4. Move `manual_video_evidence` validation into the shared verifier path and keep the writer aligned to it.
5. Add focused negative coverage proving verifier-side rejection of weak video metadata even when digests match.
6. Update `docs/honeypot/testing.md`, `docs/honeypot/runbook.md`, and `testsuite/tests/honeypot_docs.rs`.
7. Check `AGENTS.md` row `719` only if code, docs, and tests agree.
8. Run the baseline verification path and save a clean exact rerun.

# Assumptions

- This host still lacks new live Tiny11-backed runtime proof, so rows `710`, `713`, `716`, and `738` must remain open.
- `manual_video_evidence` must stay inside `target/row706/runs/<run_id>/manual_headed/` and must not create a second evidence authority.
- Row `719` can be closed honestly as a typed contract row without claiming a live Tiny11 walkthrough happened on this host.
