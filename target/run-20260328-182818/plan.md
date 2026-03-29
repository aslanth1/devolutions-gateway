# Plan

## Hypothesis

The blank or broken player is no longer a bundle problem.
The honeypot proxy is advertising a live JREC source even when no JREC push producer exists for the session.
If the proxy refuses to mint live stream bindings until a producer is actually connected, the frontend should stop failing through a fake live path and instead show an explicit stream-unavailable state.

## Prior Insights Ingest

- What worked:
  - Moving the manual-lab player build to a repo-owned Docker path removed the private registry blocker.
  - Tightening bundle validation prevented `index.html`-only false positives.
  - Serving `/jet/jrec/play/` correctly got the player past the first route-level failure.
- What failed:
  - Treating stream intent as proof of a live producer still led to shadow websocket shutdowns and fallback 404s.
  - Full-suite validation while a manual-lab run is active causes CLI tests that assert no active run to fail.
- Dead ends to avoid:
  - Re-reading the old `hellsd-gateway` streaming commit as if it secretly creates a producer here.
  - Minting stream tokens before checking JREC producer state.
- Promising techniques to reuse:
  - Record explicit `session.stream.failed` events and surface them in bootstrap/replay state.
  - Keep the frontend honest and retryable rather than pretending a dead live source exists.

## Steps

1. Review the runtime stream path and confirm whether manual-lab sessions ever create a JREC push producer.
2. Run the 3-agent council and choose the best corrective plan.
3. Change the proxy so stream-token issuance and stream redirects require a proven active recording producer.
4. Clear stale stream bindings when producer proof is absent and emit `session.stream.failed`.
5. Update the frontend and manual-lab harness to treat `stream unavailable` as a first-class, non-bogus state.
6. Re-run manual-lab to verify the stack reaches three live tiles without fake stream bindings.
7. Run the Rust baseline, write run artifacts, update AGENTS progress, and save-point commit the result.

## Assumptions

- Honeypot/manual-lab RDP sessions still do not have an in-tree JREC push writer.
- Returning `503` for absent producers is preferable to a false `200` that degrades into a frontend 404.
- A future real producer can still recover by requesting a fresh stream token later.
