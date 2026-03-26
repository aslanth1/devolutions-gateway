# Honeypot Workspace

This directory is the workspace boundary for the honeypot fork.
It contains the shared contracts area plus the dedicated `control-plane`, `frontend`, and `docker` workspace areas.
The `proxy` runtime service remains rooted in the existing `devolutions-gateway/` binary and is not a separate crate under this directory.
Concrete crate manifests, entrypoints, Dockerfiles, and lockfiles land in follow-on scaffold tasks.
