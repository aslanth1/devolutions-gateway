# Plan

## Hypothesis

The most durable next step is not another ad hoc playback tweak but a detailed AGENTS-backed black-screen forensics matrix that keeps `xfreerdp` as the control lane, makes non-RDPGFX experiments opt-in, and forces every future run to record comparable evidence before the team retries a hypothesis.

## Steps

1. Read recent `target/*/insights.md` artifacts and summarize what already worked, failed, and should not be retried blindly.
2. Run a 3-agent council to generate, critique, refine, and vote on the best structure for a no-repeat black-screen troubleshooting matrix.
3. Insert the winning matrix into `AGENTS.md` under the playback milestone with explicit row IDs, pass criteria, and anti-duplication guardrails.
4. Validate the AGENTS edit with a diff sanity check and the relevant honeypot docs test path if the current worktree can compile it.
5. Save the outcome in a new run bundle and create a scoped save-point commit for the AGENTS update.

## Assumptions

- The proxy-owned `/jet/jrec/push/{session_id}` seam remains the canonical playback source unless explicitly rejected with evidence.
- `xfreerdp` remains the control lane for black-screen investigation until a variant proves both protocol and visible-output improvement.
- Existing worktree code changes outside `AGENTS.md` are unrelated to this docs task and should not be bundled into the save-point commit.
