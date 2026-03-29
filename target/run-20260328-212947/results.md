# Success / Failure

- Success: `BS-01` is now satisfied by `black-screen-evidence.json`.
- Success: `BS-02` is now satisfied by restoring the default `xfreerdp` control lane to the pre-experiment HEAD argument shape and locking it with tests.
- Success: `BS-03` is now satisfied by preserving driver path, version, args, and per-session invocation details in the run artifacts.
- Partial: fresh 1-session, 2-session, and 3-session control captures now exist, but the richer rows that require browser-correlation or stronger cleanup proof remain open.

# Observable Signals

- Final 1-session control root:
  - `target/manual-lab/manual-lab-8301f5f0321e49248e868d02d098768f`
  - one lease assigned
  - stream probe result: `503 Service Unavailable`
- Final 2-session control root:
  - `target/manual-lab/manual-lab-ea0f508bcd5d457fb277477c551d2285`
  - two leases assigned
  - slot 1 `ready`
  - slot 2 truthful `503`
- Final 3-session control root:
  - `target/manual-lab/manual-lab-ad6582e35fa04de1a50129f7a46b4287`
  - three leases assigned
  - slot 1 `ready`
  - slot 2 `ready`
  - slot 3 truthful `503`
- Each final root contains:
  - `artifacts/black-screen-evidence.json`
  - per-session `recording-0.webm`
  - per-session `recording.json`
  - proxy, frontend, control-plane, and `xfreerdp` logs

# Unexpected Behavior

- Restoring the strict pre-experiment HEAD-like control lane means the 1-session control root is currently a truthful unavailable run, not a black-screen-ready run.
- The 2-session and 3-session controls still produce a mixed outcome: earlier slots can reach `ready` while the final slot remains explicitly unavailable.
- The no-browser control captures are strong enough for baseline and lane identity work, but they still do not satisfy the browser-console or websocket-close requirements in the later `BS-*` rows.
