# What Worked

- Starting the producer before `intercept_connect_confirm` was the key fix because it preserved the handshake bytes needed to bootstrap wrapped `drdynvc` and `rdpgfx`.
- Feeding both client and server leftovers into the producer allowed the wrapped GFX extractor to learn the dynamic channel mapping and emit real frames.
- Keeping `session.stream.ready` gated on recording-manager proof preserved the honest negative path while enabling true live-ready sessions.

# What Failed

- Starting playback too late in the proxy lifecycle left the producer blind to the wrapped graphics channel negotiation.
- The transplanted upstream graphics tests did not survive the in-repo API adaptations and blocked `clippy` until they were gated off.

# What To Avoid Next Time

- Do not advertise live stream availability based on intent alone.
- Do not import large upstream protocol test suites unchanged when the local seam has already diverged.
- Do not assume a missing ready signal means no recording bytes exist without checking the recording artifacts.

# Promising Next Directions

- Add a repo-level positive ready-path playback test in `testsuite/tests/`.
- Reduce the remaining passive FastPath warnings and cache-miss noise in the playback logs.
- Make the third session's live-ready transition deterministic instead of relying on partial artifact success.
