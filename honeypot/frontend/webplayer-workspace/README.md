# Honeypot Webplayer Workspace

This workspace contains the repo-owned player closure used by manual-lab.

It intentionally carries only:

- `apps/recording-player`
- `packages/multi-video-player`
- `packages/shadow-player`

The manual-lab Docker builder uses this workspace instead of the legacy `webapp/` tree so local self-test bring-up does not depend on unrelated private frontend packages.
