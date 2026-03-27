# Hypothesis

A sanctioned non-test manual-headed writer can record honest Milestone 6a preflight evidence inside the existing row-706 run envelope without creating a second authority.
The same writer must fail closed for runtime anchors and finalization until the bound row-706 run verifies successfully.

# Steps

- Continue the in-flight 3-agent council for this turn instead of restarting it.
- Read recent `target/*/insights.md` artifacts and summarize what worked, what failed, dead ends, and reusable techniques.
- Add a Rust `testsuite` bin named `honeypot-manual-headed-writer` with `preflight`, `runtime`, and `finalize` subcommands.
- Reuse only the existing row-706 and manual-headed helper surfaces from `testsuite::honeypot_control_plane`.
- Add focused CLI coverage for preflight success, runtime rejection without verified row-706 evidence, runtime success with a verified fixture, and weak video-metadata rejection.
- Bind a live preflight attempt to the existing blocked row-706 run `6ed7055a-c844-47c0-b2e1-962e63ff354a`.
- Attempt one runtime write and one finalize step so the tool itself proves the checklist cannot close on this host today.

# Assumptions

- This host still lacks an attested Tiny11 interop store, so row-706 positive anchors remain skipped.
- The existing blocked row-706 run is the right authoritative envelope for this Milestone 6a preflight attempt.
- Rows `704`, `707`, `710`, `713`, `716`, and `735` must remain open after this run.
