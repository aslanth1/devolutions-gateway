# Results

## Success / Failure

- `BS-24`: confirmed on the current branch
- `BS-26`: confirmed again on the current branch with a fresh same-day rerun
- `BS-25`: still open; bounded spike stopped at the current IronRDP graphics-plumbing boundary

## Observable Signals

- Fresh control proof:
  - run `manual-lab-4e696bf3d1e8417587bc63232c6289ac`
  - `driver_lane=xfreerdp-control-default`
  - `stream_probe_http_status=503`
  - `playback_ready_correlation=probe_before_ready`
  - `rdpegfx_pdu_count=462`
  - `emitted_surface_update_count=242`
  - `black_screen_branch=player_loss`
- Fresh IronRDP no-gfx proof:
  - run `manual-lab-907a8f42279e43259b0dcf685d1b5549`
  - `driver_lane=ironrdp-no-rdpgfx`
  - `stream_probe_http_status=503`
  - `playback_ready_correlation=probe_before_ready`
  - `rdpegfx_pdu_count=0`
  - `emitted_surface_update_count=0`
  - `black_screen_branch=negotiation_loss`
- Matching proxy summary for the no-gfx proof:
  - `rdpgfx_dynamic_channel_open_count=0`
  - `rdpgfx_dynamic_payload_count=0`
- Fresh `BS-26` gate outcome:
  - both runs emitted the same evidence families
  - the no-warning IronRDP lane emitted a non-`null` zero `fastpath_warning_summary`
  - remaining path-level differences were value-level, not contract drift
- Bounded `BS-25` viability result:
  - `cargo tree` showed the pinned stack includes `ironrdp-session`, `ironrdp-dvc`, `ironrdp-displaycontrol`, and `ironrdp-graphics`
  - source inspection did not find a minimal `RdpgfxClient`-style surface to attach in the current dependency set

## Unexpected Behavior

- The earlier apparent `BS-26` drift was stale, not structural.
- The fresh same-day rerun showed the current worktree already emitted deterministic zero warning summaries on the IronRDP no-gfx lane.
