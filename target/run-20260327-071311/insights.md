# Insights

## What Worked

- Keeping the canonical anchor tests authoritative and adding a verifier around their emitted fragments was cleaner than adding a new execution runner.
- Explicit skip fragments for the three `lab-e2e` anchors made the row-`706` blocker concrete instead of implied.
- Synthetic verifier tests gave strong coverage for malformed, missing, skipped, and inconsistent evidence without needing a live Tiny11 lab.

## What Failed

- This workstation still cannot close row `706` because the real Tiny11 interop env and live store are absent.
- The verifier correctly refuses to treat a passing negative control plus skipped live anchors as closure evidence.

## Avoid Next Time

- Do not add a second runner when a verifier around canonical anchors is enough.
- Do not treat partial or stale row-`706` artifacts as meaningful without the verifier.
- Do not check `AGENTS.md:706` unless the live anchors become `executed=true` and `passed`.

## Promising Next Directions

- Provision the real `DGW_HONEYPOT_INTEROP_*` inputs and rerun the canonical anchors so the verifier can observe non-skipped live proof.
- If needed, add one small manual or test helper that clears `target/row706/` before an intentional live evidence run so operators start from a known-clean fragment set.
