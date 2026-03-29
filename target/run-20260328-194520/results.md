# Success / Failure

Success.
The proxy now produces real honeypot RDP playback artifacts and honest live-ready stream state through the existing JREC seam.

# Observable Signals

- Fresh proof run: `manual-lab-4b85d24fc9cc431c9b3c2fa20343f89a`
- Service startup:
  - `control-plane.ready`
  - `proxy.ready`
  - `frontend.ready`
  - `services.ready`
- Session assignment:
  - slot 1 assigned `vm_lease_id=lease-00000001`
  - slot 2 assigned `vm_lease_id=lease-00000002`
  - slot 3 assigned `vm_lease_id=lease-00000003`
- Live stream state:
  - slot 1 `session.stream.ready` with `stream-bb4ac167-c5df-4ace-af94-a0d78247357d`
  - slot 2 `session.stream.ready` with `stream-561c6d8c-b1e8-4ab1-a70b-9b2ad059a512`
  - slot 3 remained explicitly truthful with `HTTP/1.1 503 Service Unavailable`
- Recording artifacts were created for all three sessions:
  - `.../b9bde1e3-cea7-4785-9bce-74917245112f/recording-0.webm` size `39573`
  - `.../ad770117-a643-4175-ae96-c34fdadf6e8b/recording-0.webm` size `24084`
  - `.../83641198-ee9d-4f85-8cdc-f4f2b0d6403b/recording-0.webm` size `5917`
  - each session directory also contains `recording.json`
- Proxy log evidence from `target/manual-lab/manual-lab-4b85d24fc9cc431c9b3c2fa20343f89a/config/proxy/gateway.2026-03-29.0.log`:
  - `GFX filter initialized` for all three sessions
  - `Learned drdynvc static-channel position from ConnectInitial`
  - `Attached drdynvc static-channel ID from ConnectResponse`
- Validation:
  - `cargo +nightly fmt --all` passed
  - `cargo clippy --workspace --tests -- -D warnings` passed
  - `cargo test -p testsuite --test integration_tests -- --nocapture` passed with `348 passed; 0 failed`

# Unexpected Behavior

- The proxy still logs repeated `Passive FastPath observer failed to process server frame` warnings during playback.
- The third session produced a `.webm` recording artifact even though its immediate stream probe still returned `503`.
- One full-suite run briefly failed on a honeypot health test and then passed on immediate rerun.
