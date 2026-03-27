# What Worked

- The fail-closed `consume-image` path correctly rejected an early bad digest and succeeded once the manifest matched the final bundle hash.
- A run-local interop store made it possible to test the imported Tiny11 artifact without mutating the shared canonical or prep roots.
- Extending the live-test startup wait to the interop readiness budget removed a real false blocker and let the row-706 positive anchors reach actual lease startup.

# What Failed

- Hashing a compacted qcow2 before the conversion process has truly exited produces bad manifest data.
- The control-plane-launched imported lease path still fails real RDP auth even though the manual verification overlay had already accepted the same credentials.
- TLS-only fallback is not a viable bypass because the guest requires hybrid security.

# What To Avoid Next Time

- Do not treat an in-progress `qemu-img convert` session as done just because the output file is present.
- Do not assume a manually verified qcow2 boot proves the qcow2-only trusted-image contract preserves all boot and auth state needed by the control plane.
- Do not leave stale disposable prep VMs running while measuring live proof behavior.

# Promising Next Directions

- Compare the control-plane launch shape against the manual verified boot, especially firmware and NVRAM assumptions.
- Capture the exact runtime delta between the manual overlay boot that accepted NLA and the imported control-plane lease that rejected it.
- Decide whether the trusted-image contract must carry sealed firmware inputs in addition to the qcow2 before row `747` can truthfully pass.
