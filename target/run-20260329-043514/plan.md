# BS-33 Plan

## Hypothesis

The current black-screen ambiguity can be closed by comparing what the browser player shows at a specific playback instant with what the persisted WebM artifact contains at that same instant.
If both surfaces are black, the run should classify as a true black artifact at that moment instead of conflating frontend and producer faults.
If the browser is black while the artifact contains visible frames, the defect is in the player or frontend path.

## Memory Ingest

What worked:
- teardown-flushed evidence and direct iframe attach
- explicit player telemetry instead of dashboard inference
- same-day controls and explicit verdict reducers
- repaired artifact visibility sampling from `BS-32`

What failed:
- dashboard-only proofs
- stale control comparisons
- early recording-directory creation from test code
- inferring truth from websocket or ready signals alone

Dead ends to avoid:
- checking off browser rows without browser-native evidence
- reopening lane churn before browser or artifact discrimination exists
- treating teardown parse failures as meaningful black-screen results

Promising techniques to reuse:
- direct player URL attach
- session-local evidence persistence
- reducer-driven named verdicts with confidence
- explicit insufficiency classes instead of implicit failure

## Winning Council Plan

Three sub-agents independently proposed `BS-33`.
The winning plan was to add multi-window browser visibility telemetry for the real player, align an artifact probe to the browser's representative playback time, and reduce both into one explicit browser-artifact correlation verdict.

## Steps

1. Extend player telemetry and proxy persistence with browser visibility window fields.
2. Add a browser-side probe that samples active or static player video across startup, stabilize, and steady windows.
3. Extend manual-lab reducers to persist:
   - `browser_visibility_summary`
   - `artifact_visibility_at_browser_time`
   - `browser_artifact_correlation_summary`
4. Prove the flow in a fresh one-session local manual-lab run by attaching Chrome directly to the iframe player URL.
5. Check off `BS-33` only if the run yields a named browser-artifact verdict instead of an inconclusive parse or timing failure.

## Assumptions

- The direct iframe player URL exercises the actual playback runtime more faithfully than the outer frontend shell.
- A representative browser playback timestamp is sufficient to compare the browser surface and the persisted WebM artifact.
- The Chrome-based artifact probe remains acceptable as the sanctioned reducer backend for this tranche.
