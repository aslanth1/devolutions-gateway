# Hypothesis

The winning council plan is the proxy-owned JREC producer seam.
If the proxy starts a real playback producer inside the existing `rdp_proxy.rs` session lifecycle, captures the client and server handshake bytes early enough to discover `drdynvc` and `rdpgfx`, and feeds decoded frames into the current recording stack, then honeypot RDP sessions can produce honest live-ready playback without adding a fourth runtime service or a parallel stream API.

# Steps

1. Reuse the prior council winner rather than inventing a new capture path.
2. Start the playback producer from the proxy session lifecycle before the RDP connect-confirm path drops the client negotiation context.
3. Feed both client and server byte streams into the producer, including early handshake leftovers needed to learn the wrapped `drdynvc` and `rdpgfx` channels.
4. Reuse the existing recording stack so `session.stream.ready` is emitted only after recording-manager proof instead of stream intent.
5. Preserve the negative path so sessions with no active producer still return `503 honeypot stream is unavailable` and emit `session.stream.failed`.
6. Validate with `fmt`, `clippy`, integration tests, and a fresh `manual-lab-selftest-up-no-browser` proof run.

# Assumptions

- The existing `/jet/jrec/push/{session_id}` producer contract is sufficient for honeypot playback.
- Manual-lab can provide an XMF-backed environment for end-to-end proof.
- The local Tiny11/manual-lab artifacts are already trusted and ready for a local self-test lane.
- No control-plane-assisted fallback is needed if the proxy seam can emit JREC bytes.
