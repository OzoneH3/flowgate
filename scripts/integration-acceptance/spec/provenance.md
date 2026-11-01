# Provenance of the frozen candidate (read-only checks, 2026-11-01)

- Candidate: **93eaa868ec2a1f98c0b66b27a682e2f332a23746** ("Show saved application rules independently of
  socket attribution", 2026-10-31 23:46). Repository: `.workspace/socket-enforcement-release/source`
  (origin `.workspace/socket-auth-prototype`). The commit is **not in master's history**: master 3761aa9e has
  no socket-authorization code at all. This acceptance worktree is a git worktree of that repository at 93eaa868.
- Installed: `/usr/local/lib/flowgate/current -> releases/93eaa868…`. Its `manifest.json` has release=source=93eaa868,
  experimental=true, host_shaping_activation_authorized=false, live_kernel_collectors_verified=false,
  checks_reused_from=1716a644 ("All Go/C/H code unchanged from 1716"), shaping_artifacts_from=50835463.
  **All 22 manifest file hashes match the installed files.**
- Installed GUI: autostart → `.workspace/automatic-zone-releases/93eaa868…/launch-ui` (runtime/electron +
  electron/dist). matched-manifest source=93eaa868, and the 18 electron/runtime file hashes match.
- Installed `launch` ALWAYS appends `--socket-authorization` AND `--experimental-upload-host-trial
  --experimental-upload-interface enp7s0 …`. The deployed build therefore runs fast path + shaper together
  through the production session path. Shaping config is session-scoped (empty after restart), and its live
  content was NOT read (no live API access in this task).
- Installed `controller.py` sha256 1bc75830… == worktree `experimental/upload-shaper/controller.py`.
- 50835463 (shaping artifact source) is an ancestor of 93eaa868 and of master. `git diff 50835463 93eaa868 --
  internal/uploadshape experimental/upload-shaper internal/daemon/upload_shaping.go` is empty.

## 93eaa868 vs reviewed master 3761aa9e (shaping-relevant paths)
Identical: internal/uploadshape/*, experimental/upload-shaper/* (controller, BPF, kernel), internal/daemon/
upload_shaping.go, docs/TRAFFIC-PRIORITY.txt, ZONE-SHAPING.txt, DOWNLOAD-LIMITER.txt, UPLOAD-SHAPING-STATUS.txt,
electron/src/shaping-defaults-view.ts.
Different: cmd/flowgate/serve.go, internal/daemon/engine.go, internal/daemon/api.go (socket-authorization
integration, zone publisher, which master lacks); electron/src/upload-shaping.ts and upload-shaping-view.ts
(`shapingUnavailableReason`, `paintAvailability`, changed slot aria-labels).
The earlier RESEARCH review of master therefore covers the shaping core of 93eaa868, but NOT its
fast-path/shaping integration or the changed GUI slots. Those were re-read in this worktree (socket_session.go,
socket_authorization.go, serve.go, upload-shaping*.ts).
