# What Worked

- The manual-good Tiny11 launch profile remained a reliable differential anchor.
- Fresh overlays per variant made the comparison cleaner.
- Direct `xfreerdp /auth-only` probes quickly separated successful NLA, TLS negotiation requirements, and transport resets.

# What Failed

- Treating the imported qcow2 as a self-contained trusted image.
- Treating preserved OVMF code and writable vars as the only missing external state.
- Assuming that reaching TCP 3389 meant the launch profile was already good enough for auth.

# What To Avoid Next Time

- Do not retry the full row-706 lease lane before sealing the manual-good boot profile.
- Do not assume qcow2 parity implies auth parity.
- Do not collapse all launch differences into "firmware" when disk, NIC, RTC, and other boot-shape inputs still differ.

# Promising Next Directions

- Extend the trusted-image contract to carry the full boot profile, not just the qcow2 digest.
- Teach the control-plane launch path to replay the sealed manual-good profile.
- Re-run the imported lease acceptance lane only after the runtime can express that profile exactly.
