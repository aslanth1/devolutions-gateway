# What Worked

- Reusing the existing gold-image acceptance lane was better than inventing a new one.
- A reusable acceptance-cycle helper made repeatability coverage cheap and readable.
- Treating skipped `lab-e2e` tests as non-evidence kept the AGENTS review honest.
- The existing negative-control digest-mismatch test already gave row `706` a good fail-closed anchor once the positive path was documented explicitly.

# What Failed

- The workstation did not have a prepared Tiny11-derived interop image store or the required `DGW_HONEYPOT_INTEROP_*` inputs.
- Standard Windows 11 QEMU labs were not sufficient evidence for the Tiny11-specific row.

# Dead Ends To Avoid

- Do not satisfy Tiny11-specific AGENTS rows by pointing the tests at generic Windows 11 labs.
- Do not treat compile-only or skip-only `lab-e2e` runs as completion evidence.

# Promising Next Directions

- Produce or import a real Tiny11-derived interop image store that matches the existing manifest contract.
- Re-run the single-cycle, repeatability, and external-client `lab-e2e` lanes without skip on that store.
- Only then check off `AGENTS.md:706`, and likely `393` and `396` if the same evidence closes them honestly.
- Preserve the exact `DGW_HONEYPOT_INTEROP_*` env contract because it already cleanly separates default CI-safe verification from intentional lab validation.
