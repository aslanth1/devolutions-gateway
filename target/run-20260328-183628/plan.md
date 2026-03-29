# Plan

## Hypothesis

The next useful action is not ad hoc code.
It is to create an explicit repo task lane for real honeypot RDP playback that stays on the existing proxy-owned JREC seam and does not drift into a fourth runtime service.

## Prior Insights Ingest

- What worked:
  - The repo-owned Docker webplayer closure removed the private registry blocker.
  - Stronger bundle validation prevented false-positive player roots.
  - Truthful proxy gating on producer readiness removed fake live bindings and made the stack coherent.
- What failed:
  - Session assignment was incorrectly treated as proof of a live recording producer.
  - Running a proof manual-lab session during active-state-sensitive CLI tests caused false-negative suite failures.
- Repeated dead ends to avoid:
  - Treating sibling-repo streaming work as a drop-in fix here.
  - Returning `200` or redirecting to `/jet/jrec/play/` before producer proof exists.
  - Opening an alternate capture stack before the proxy-owned JREC seam is proven insufficient.
- Promising techniques to reuse:
  - Existing `rdp_proxy.rs` plus `session.rs` plus `recording.rs` plus `jrec.rs` seam.
  - Existing `session.stream.failed` and truthful stream metadata clearing path.
  - Existing manual-lab stream probes and frontend state model.

## Winning Plan

1. Create a new AGENTS task lane for real JREC producer playback.
2. Make the preferred path explicit:
   `rdp_proxy/session lifecycle -> /jet/jrec/push/{session_id} -> recording manager readiness -> /jet/jrec/play/?isActive=true`.
3. Preserve the current truthful negative-path contract while playback work is added.
4. Task positive ready-path tests and a manual-lab proof run only after producer readiness is tied to recording-manager proof.
5. Keep any control-plane-assisted capture path blocked behind an explicit rejection of the preferred proxy seam.

## Assumptions

- The user asked for tasks, not immediate playback implementation.
- The existing Gateway JREC seam remains the canonical path under AGENTS and `DF-04`.
- A control-plane capture fallback should remain a follow-up task only if the preferred seam is explicitly proven unworkable.
