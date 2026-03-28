# What Worked

- A split-lane model works here: canonical default plus explicit local profile.
- `MANUAL_LAB_CONTROL_PLANE_CONFIG` was the right reuse seam for profile switching.
- Reusing the same Rust preflight/bootstrap authority kept the profile change small and testable.
- Typed `store_root_not_writable` remediation is much more actionable than a generic `consume_image_failed`.

# What Failed

- The canonical `/srv` lane is still unusable for non-root operators without host ownership prep.

# What To Avoid Next Time

- Do not silently auto-fallback from canonical to local.
- Do not treat local self-test proof as equivalent to canonical `/srv` host readiness.
- Do not move profile logic into shell scripting beyond thin variable threading.

# Promising Next Directions

- Add an optional read-only helper that prints the active manual-lab profile, config path, image-store root, and manifest dir before mutation.
- If desired, add a separate host-prep checklist for the canonical `/srv` lane, but keep it distinct from the local self-test lane.
- The next operator step on this host is to set `DGW_HONEYPOT_INTEROP_RDP_USERNAME` and `DGW_HONEYPOT_INTEROP_RDP_PASSWORD`, then rerun `make manual-lab-preflight MANUAL_LAB_PROFILE=local` and `make manual-lab-up MANUAL_LAB_PROFILE=local`.
