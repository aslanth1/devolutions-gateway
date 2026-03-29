# Insights

## What Worked

- Gating live stream issuance on actual JREC producer readiness removed the fake-live path cleanly.
- Emitting `session.stream.failed` and clearing stream metadata kept bootstrap, replay, and frontend state aligned.
- Manual-lab is more robust when it treats stream unavailability as a legitimate outcome instead of a setup failure.

## What Failed

- Assuming a session assignment implies a live recording producer was the core design error.
- Running the proof lab while executing active-state-sensitive CLI tests causes false-negative suite failures.

## Avoid Next Time

- Do not return `200` or a `/jet/jrec/play/` redirect unless the proxy can prove an active recording producer.
- Do not validate manual-lab CLI preflight tests while an `active.json` proof run is still present.

## Promising Next Directions

- Add a real honeypot-side JREC push producer if true live RDP streaming is still required.
- Move the owned player closure fully under `honeypot/frontend/` as the permanent manual-lab build path and retire the remaining legacy `webapp/` dependency edges.
