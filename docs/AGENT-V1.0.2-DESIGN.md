# pcc2k-agent v1.0.2 — Final Release (Design)

**Status:** Draft, 2026-05-18. Not yet implemented. v1.0.1 shipped
earlier today (6 agent commits + 1 FleetHub cross-repo commit).
After v1.0.2 ships, the agent matches FleetHub v1.0 surface area
and the v1.0.0 git tag goes on master. Anything not in scope here
becomes **v1.1** (operator-driven follow-up) or non-goal.

**Scope of this doc:** 5 workstreams. Like FleetHub phase docs,
each is independently shippable, and the spec IS the contract.

The 5 workstreams (architect-tightened from 4-audit synthesis):

- **0a — AGENT-PROTOCOL.md namespace edit (FH side, doc-only).**
  Reserve `fleet.services.*` + `fleet.processes.*` + `fleet.av.*`
  rows in §8. Plus contract additions: `services.list` pagination
  cursor shape, `capabilities.update` notification schema,
  `av.cancel` semantics ("cancels via product-native API, NOT
  process kill"), `Fl_Error.code = "response-too-large"` for the
  256KB frame cap.
- **0b — Agent scaffold (session_io frame cap + detect cache +
  capabilities.update plumbing).** `maxOutboundFrameBytes = 256KB`
  in `session_io.go` with `Fl_Error.code = "response-too-large"`
  return when exceeded. `detect_cache.go` TTL=60s helper so
  `detectBackup() / detectAv() / detectRustdeskId() / detectServices()`
  share a cached path across capability + posture + verb-handler
  call sites. `capabilities.update` notification fired on posture
  cadence when sorted-slice diff. **Deterministic sort BEFORE
  equality check** (architect §10 v1.0.1-hotfix pre-empt — slice
  order drift would fire update every cycle = infinite log spam).
- **0c — FH `lib/agent-capabilities.ts` shared constant pattern.**
  Single constant export for the capability strings the FH-side
  UI checks. Mirrors AGENT-PROTOCOL §8 verbatim so a future rename
  fails the typecheck if not synced.
- **A — fleet.processes (list, all 3 platforms) + fleet.services
  (control, linux+windows only).** Architect's split: capability
  string IS the contract. `fleet.processes` advertised everywhere
  list works; `fleet.services` advertised only when start/stop/
  restart works (linux + windows). macOS hosts get list capability
  but no control buttons in FH UI — capability-gated cleanly. Verbs:
  `fleet.processes.list` (snapshot RPC; cursor-paginated; normalized
  canonical schema `{pid, name, user, cpuPct, rssMb, startedAt}`)
  + `fleet.services.list` + `fleet.services.start/stop/restart`
  (4-eyes-gated via Phase 11 `shouldRequireApproval`).
- **B — fleet.av (Defender end-to-end only).** No CrowdStrike code
  in v1.0 (architect §5 option a — per-product capability).
  `fleet.av.scan/update-defs/quarantine/release` verbs in
  `av_defender_windows.go`. Capability `fleet.av` advertised only
  when `Get-MpComputerStatus` succeeds (Windows + Defender + service
  running). `av.cancel` calls `Stop-MpScan` (NOT process kill).
- **C — RustDesk peer-id + capabilities.update wire + bootstrap
  scripts in agent repo.** Posture sweep extension: read peer-id
  from Windows registry / Linux ~/.config/rustdesk/RustDesk.toml /
  macOS Library/Preferences toml. Graceful fallback to null on
  read fail (v1.0.1-hotfix pre-empt #b). New `/api/agent/posture/
  remote` FH route + `RemoteReport` struct. Fire `capabilities.
  update` notify when detect-cache delta detected (closes silent-
  failure-risk #2). Copy `scripts/bootstrap.sh` + `scripts/
  bootstrap.ps1` into agent repo as FH-down fallback.
- **D — Release polish + RUNBOOK + CHANGELOG + LICENSE + systemd
  fix + v1.0.0 tag.** `--version` flag wired via build-time
  ldflags `-X main.version=v1.0.0 -X main.gitSha=$(git rev-parse
  --short HEAD)`. `docs/AGENT-RUNBOOK.md` (9 sections per ops audit
  — see §1.WS-D below). `docs/AGENT-CHANGELOG.md` (one-liner per
  tag v0.3 → v1.0.0). `LICENSE` (MIT) at repo root. `systemd/
  pcc2k-agent.service` flipped from `User=nobody` to `User=root`
  (v1.0.2 verbs require root). Tag `v1.0.0` + GitHub release.
  Cross-repo: FleetHub ships `/install/latest-version/route.ts`
  + `/install/pcc2k-agent-[platform]/route.ts` (Phase 13 close
  artifact; this design's WS-D commits the FH-side route stubs
  pointing at a manifest file).

**Cross-references:**

- [`AGENT-BACKLOG.md`](AGENT-BACKLOG.md) — v1.0.1 LIVE section + the
  original 4-WS v1.0.2 sketch. This doc supersedes the v1.0.2
  sketch with the audit-tightened 5-WS shape.
- [`../fleethub/docs/PHASE-13-DESIGN.md`](../../fleethub/docs/PHASE-13-DESIGN.md)
  §1.WS-0a names the namespace edit; §3 footgun 1 names the cross-
  repo ordering; §1.WS-B names the Fl_ProcessSnapshot + Fl_AvAction
  schema.
- [`../fleethub/docs/AGENT-PROTOCOL.md`](../../fleethub/docs/AGENT-PROTOCOL.md)
  §8 namespace table — WS-0a edits.

---

## 1. What v1.0.2 ships

**Workstream 0a — AGENT-PROTOCOL.md namespace edit (FH-side, own commit):**

Edits `~/fleethub/docs/AGENT-PROTOCOL.md` §8 to add:
- `fleet.processes.*` (FleetHub-owned; process inventory only — list)
- `fleet.services.*` (FleetHub-owned; service inventory + control —
  list + start + stop + restart)
- `fleet.av.*` (FleetHub-owned; AV management — Defender in v1.0,
  CrowdStrike in v1.1+)

Plus 4 contract additions in the §8 (or §10) appendix:
1. **`fleet.processes.list` pagination contract** — request takes
   `{cursor?: string, limit?: number}`; response returns
   `{processes: [...], nextCursor?: string, truncated: boolean}`.
   Default limit 500; max 500. Cursor is opaque base64 string —
   server treats as black-box (lets agent change pagination
   backend without protocol break).
2. **`capabilities.update` notification schema** —
   `{capabilities: string[]}` fired by agent when sorted-deduped
   capability list differs from last advertised. FH-side handler
   updates `Op_Agent.capabilities` JSONB column.
3. **`av.cancel` semantics** — "Must invoke product-native cancel
   API (Stop-MpScan for Defender). Killing the child process is
   NOT sufficient; the scan continues in the AV service."
4. **`Fl_Error.code = "response-too-large"`** — agent returns this
   when a response would exceed `maxOutboundFrameBytes` (256KB).
   FH-side UI surfaces as "result too large — narrow your query
   or use cursor pagination."
5. **Backwards-compat policy** — agent v1.0.0 frame shapes are
   field-additive only. Any rename ships under a new method with
   the old method preserved as a deprecated alias for ≥1 minor.

**Workstream 0b — Agent scaffold:**

- `cmd/agent/session_io.go`:
  - Add `const maxOutboundFrameBytes = 256 * 1024`.
  - `writeFrame` marshals to bytes first; if `len > max`, returns
    a sentinel error. Callers that emit large responses handle
    via the cursor pagination contract.
- New `cmd/agent/detect_cache.go`:
  - TTL=60s wrapper around `detectBackup() / detectAv() /
    detectRustdeskId() / detectServices()`. Functions:
    `cachedDetect[T](key string, ttl Duration, fill func() T) T`.
  - Used by capability detection + posture sweep + verb handlers
    so all 3 call sites share one shell-out per minute per detector.
- `cmd/agent/capabilities.go` extension:
  - Append `fleet.processes` always (every platform supports list).
  - Append `fleet.services` when linux or windows (control verbs
    work).
  - Append `fleet.av` when Defender-only path succeeds (Windows +
    `Get-MpComputerStatus` returns ok).
  - **Sort slice deterministically before return** (architect
    v1.0.1-hotfix pre-empt).
- `cmd/agent/capabilities_update.go` (new):
  - `fireCapabilitiesUpdateIfChanged(s *session)` called from the
    posture loop in `main.go`. Compares sorted-slice equality
    against last-advertised cache; if differ, sends
    `s.notify("capabilities.update", {capabilities: [...]})`.

**Workstream 0c — FH `lib/agent-capabilities.ts` shared constants:**

New file (or extension of existing `lib/agent-capabilities.ts`
from Phase 12 WS-D capability-gating helper):
```ts
export const AGENT_CAPABILITIES = {
  shell:     "fleet.shell",
  file:      "fleet.file",
  backup:    "fleet.backup",
  processes: "fleet.processes",
  services:  "fleet.services",
  av:        "fleet.av",
} as const

export type AgentCapability =
  typeof AGENT_CAPABILITIES[keyof typeof AGENT_CAPABILITIES]
```

Existing `agentSupports(deviceId, cap)` switches to take
`AgentCapability` typed argument. Rename of a value here
fails the typecheck if not propagated everywhere.

**Workstream A — fleet.processes + fleet.services:**

- New `cmd/agent/processes.go` (router + `fleet.processes.list`
  handler):
  ```go
  registerInboundHandler("fleet.processes.list", handleProcessesList)
  ```
- Per-platform `cmd/agent/processes_linux.go` (parses `/proc`):
  - PID, name from `/proc/<pid>/comm`, user from `/proc/<pid>/status`
    Uid: line resolved via /etc/passwd, CPU% via delta on
    `/proc/<pid>/stat` utime+stime (first-call returns `cpuPct:
    null`), RSS from `/proc/<pid>/statm` page count × pagesize ÷
    1MB, startedAt from `/proc/<pid>/stat` start_time field.
- Per-platform `cmd/agent/processes_windows.go` (uses
  `tasklist /v /fo csv` parsed):
  - Or `golang.org/x/sys/windows` directly for PID + RSS + CPU
    time. CSV parsing keeps no new deps; direct API is faster +
    safer for long process names.
- Per-platform `cmd/agent/processes_darwin.go` (uses `ps aux`
  parsed):
  - Same canonical schema; macOS RSS already in KB (convert).
- Cursor: agent stores last full-list snapshot per session keyed
  by (sessionId, snapshotId); cursor is `base64(snapshotId+":"
  +offset)`. Stale snapshots GC'd after 5 min.

- New `cmd/agent/services.go` (router + 4 verbs):
  ```go
  registerInboundHandler("fleet.services.list", handleServicesList)
  registerInboundHandler("fleet.services.start", handleServicesStart)
  registerInboundHandler("fleet.services.stop", handleServicesStop)
  registerInboundHandler("fleet.services.restart", handleServicesRestart)
  ```
  - `fleet.services.list` ships on all 3 platforms (advertised via
    `fleet.processes` capability — since they're inventory-only
    sibling).
  - `start/stop/restart` only on linux + windows (capability
    `fleet.services` not advertised on macOS).
- Per-platform `cmd/agent/services_linux.go` (systemctl):
  - `systemctl list-units --type=service --all --no-legend --plain`
    parsed for list.
  - `systemctl {start,stop,restart} <name>` for control.
- Per-platform `cmd/agent/services_windows.go` (sc.exe + Get-Service):
  - `Get-Service` via powershell for list.
  - `sc.exe {start,stop} <name>` + `Restart-Service` for control.
- Per-platform `cmd/agent/services_darwin.go` (launchctl list only):
  - `launchctl list` parsed for list.
  - No start/stop/restart in v1.0 (architect §4 — LaunchAgent vs
    LaunchDaemon split is its own design pass; v1.1 territory).

**Workstream B — fleet.av (Defender only):**

- New `cmd/agent/av.go` (router + Defender presence check):
  ```go
  registerInboundHandler("fleet.av.scan", handleAvScan)
  registerInboundHandler("fleet.av.update-defs", handleAvUpdateDefs)
  registerInboundHandler("fleet.av.quarantine", handleAvQuarantine)
  registerInboundHandler("fleet.av.release", handleAvRelease)
  registerInboundHandler("fleet.av.cancel", handleAvCancel)
  ```
- `av.go` checks `Get-MpComputerStatus` succeeds at startup.
  Caches result in detect_cache.go. Capability `fleet.av`
  advertised only on Windows + status-ok.
- New `cmd/agent/av_defender_windows.go`:
  - `defenderScan(ctx, kind)` — `powershell.exe Start-MpScan
    -ScanType QuickScan|FullScan|CustomScan` + scan path for
    custom. Long-running; goroutine emits `av.action-complete`.
  - `defenderUpdateDefs(ctx)` — `Update-MpSignature`.
  - `defenderQuarantine(ctx, filePath)` — `Add-MpThreat -ThreatID
    <calculated-by-Defender-after-scan>`. v1.0 limitation: can
    only quarantine items Defender's already-identified-and-
    skipped (not arbitrary operator-chosen files). Documented
    in handler.
  - `defenderRelease(ctx, threatId)` — `Restore-MpThreat -ThreatID`.
  - `defenderCancelScan(ctx, runId)` — `Stop-MpScan` (architect
    silent-failure-risk #3 — NOT process.Kill).
- Per-OS stub `cmd/agent/av_unsupported.go` (linux + darwin):
  - `//go:build linux || darwin` build tag.
  - All verbs return `{state: "unsupported-os", os: runtime.GOOS}`.
  - Capability `fleet.av` never advertised on these platforms.
  - File exists so `av.go` router can compile cross-platform.

**Workstream C — RustDesk peer-id + capabilities.update wire +
bootstrap scripts:**

- Extend `cmd/agent/posture.go`:
  - New `RemoteReport { ClientName, Hostname, RustdeskId? }`.
  - New `newPostureClient.sendRemote(report)` POST to
    `/api/agent/posture/remote`.
- New `cmd/agent/posture_remote_windows.go`:
  - Read `HKLM\SOFTWARE\RustDesk\rendezvous_server` if present.
  - Read `%APPDATA%\RustDesk\config\RustDesk.toml` for peer ID.
  - Graceful fallback to `nil` on read fail (architect v1.0.1-
    hotfix pre-empt #b — non-default install paths must not 500
    the posture sweep).
- New `cmd/agent/posture_remote_unix.go`:
  - Read `~/.config/rustdesk/RustDesk.toml` (Linux) or
    `~/Library/Preferences/com.carriez.rustdesk/RustDesk.toml` (macOS).
- `main.go` posture loop adds `sendRemote` call alongside the
  existing `sendBackup` + `sendAv`.
- Same posture loop calls `fireCapabilitiesUpdateIfChanged()`
  from WS-0b after each detect cycle.
- **Bootstrap scripts copied to agent repo:**
  - `scripts/bootstrap.sh` (copied from `/install/bootstrap.sh`
    FH-side content; signed by maintainer).
  - `scripts/bootstrap.ps1` (same).
  - Operator can install from agent repo directly:
    `curl https://raw.githubusercontent.com/.../scripts/bootstrap.sh
    | PCC2K_BOOTSTRAP_TOKEN=... PCC2K_FLEETHUB_URL=... bash` as
    FH-down fallback.

**Workstream D — Release polish + RUNBOOK + CHANGELOG + LICENSE +
systemd + v1.0.0 tag:**

- `cmd/agent/main.go`:
  - Add `--version` flag.
  - Build-time ldflags via `scripts/build.sh`:
    `-X main.version=v1.0.0 -X main.gitSha=$(git rev-parse --short HEAD)`.
  - `main.go` exports `var version, gitSha = "dev", "unknown"`;
    `--version` prints `pcc2k-agent v1.0.0 (a1b2c3d)`.
- `scripts/build.sh` updated to pass `version` + `gitSha` ldflags.
- `systemd/pcc2k-agent.service`:
  - `User=root` (was `nobody`). v1.0.2 verbs (shell, services,
    av) require root. Comment documents the change.
  - Adds `EnvironmentFile=/var/lib/pcc2k-agent/secret`.
- `docs/AGENT-RUNBOOK.md` — 9 sections per architect §8 with
  named source-of-truth pointers:
  1. **Install** — `<!-- source-of-truth: scripts/bootstrap.sh -->`
     one-liner Unix + Windows + manual MSI + macOS `xattr -d`
     unquarantine.
  2. **Service Control** —
     `<!-- source-of-truth: systemd/pcc2k-agent.service + cmd/agent/main.go -->`
     systemctl / sc.exe / launchctl invocation matrix.
  3. **Env Vars** — `<!-- source-of-truth: cmd/agent/main.go -->`
     table of all flag-mappable env vars.
  4. **Logs** — `<!-- source-of-truth: cmd/agent/main.go (log calls) -->`
     `/var/log/pcc2k-agent.log` (Unix), Event Viewer (Windows),
     `~/Library/Logs/pcc2k-agent.log` (macOS).
  5. **Token Rotation** —
     `<!-- source-of-truth: cmd/agent/enroll.go -->`
     FH-side regenerate via `/clients/[name]?tab=install`; on
     host run `pcc2k-agent --bootstrap-token <NEW>
     --bootstrap-url <URL>`; restart service.
  6. **Upgrade** — manual `file.push` + `shell.open` path
     (auto-update is v1.1). Operator runs `pcc2k-agent --version`
     to verify post-upgrade.
  7. **Uninstall** — `<!-- source-of-truth: installer/pcc2k-agent.wxs -->`
     systemd: `systemctl disable --now pcc2k-agent` + `rm
     /usr/local/bin/pcc2k-agent /var/lib/pcc2k-agent`. Windows:
     `msiexec /x` or `sc delete pcc2k-agent`. macOS:
     `launchctl unload` + plist delete.
  8. **DR / forensics** —
     `<!-- source-of-truth: AGENT-PROTOCOL §reconnect + cmd/agent/enroll.go -->`
     Where `agentSecret` is stored, how to extract
     `/var/lib/pcc2k-agent/`.
  9. **Source-of-truth** — "If this file disagrees with the
     pointed source, the source wins. File a bug."
- `docs/AGENT-CHANGELOG.md`:
  - One-liner per tag: v0.3.0 (initial), v0.4.0 (Phase 8 posture),
    v1.0.1 (shell + file + backup verbs + deploy-from-panel),
    v1.0.2 (services + AV + RustDesk + release polish), v1.0.0
    (release tag — no code beyond v1.0.2).
- `LICENSE` — MIT at repo root.
- Cross-repo FH stubs (committed to FH repo):
  - `app/install/latest-version/route.ts` — reads
    `app/install/agent-manifest.json` committed in FH repo.
    Initial manifest points at agent v1.0.0 GitHub release.
  - `app/install/pcc2k-agent-[platform]/route.ts` — fetches
    from the manifest's downloadUrl with `fetch()` + streams to
    response. v1: GitHub release URLs; v1.1 may switch to S3.
- Final commit: tag `v1.0.0` on `master`. `gh release create
  v1.0.0` with binaries (manual, ~5min — operator).

---

## 2. Schema deltas (FleetHub side, v1.0.2 cross-repo)

Phase 13 already adds `Fl_ProcessSnapshot` + `Fl_AvAction`. Agent
v1.0.2 cross-repo additions on top:

- `Fl_RemoteSession` already has `rustdeskId`? Check — Phase 7
  added `Fl_Device.rustdeskId`. No new column.
- `Op_Agent.capabilities Json?` already exists (Phase 8) — agent
  v1.0.2 just keeps it populated via `capabilities.update`.
- 1 new FH route: `POST /api/agent/posture/remote` — no schema
  change, just route.

No new tables. Pure-additive.

---

## 3. Hard ordering (§5)

The architect's gut-check + audit synthesis surfaced 12 footguns.
Phase v1.0.2 sequences around them:

1. **AGENT-PROTOCOL.md §8 namespace edit FIRST** (WS-0a, own commit,
   FH-side). Cross-repo implication — agent v1.0.2 implementation
   references these names. Without the doc, agent squats on names
   the protocol reserves for OpsHub's `windows.services.*`.
2. **`fleet.processes.list` pagination contract committed to §8
   BEFORE platform implementations** (architect §2).
3. **`capabilities.update` notification schema committed to §8
   BEFORE WS-0b scaffold** (it's protocol surface, not just method
   call).
4. **`av.cancel` semantics doc committed to §8 BEFORE WS-B**
   (silent-failure-risk #3 — Defender scan continues even after
   process kill).
5. **`Fl_Error.code = "response-too-large"` defined in §8 BEFORE
   WS-A** (FH side needs to handle the error).
6. **WS-0b scaffold (frame cap + detect cache + capabilities.update
   plumbing) BEFORE WS-A/B verbs**. Otherwise three verb
   implementations re-derive the same caching + size-cap logic.
7. **WS-0c FH-side shared constants pattern BEFORE WS-A verbs
   ship** (otherwise FH-side hardcodes capability strings, drift
   on next rename).
8. **FH `/api/agent/posture/remote` route deployed LIVE BEFORE
   agent v1.0.2 ships** (architect §2 — agent's POST 404s
   otherwise; logs fill with noise).
9. **Capability slice sort BEFORE equality check** (architect §10
   — sort drift = infinite-loop `capabilities.update` firing
   forever).
10. **shell.output chunks must stay BELOW 256KB at the producer**
    — `outputFrameMaxBytes = 16KB` already does this in
    `shell.go`; verify it survives the frame cap addition.
11. **RustDesk read graceful-fallback to null** — registry / toml
    read failure must not 500 the posture sweep.
12. **v1.0.0 git tag LAST** — RUNBOOK + CHANGELOG + LICENSE +
    systemd unit fix all land first; tag is the project-close
    commit.

---

## 4. Migrations + activation checklist

- [ ] FleetHub: `~/fleethub/docs/AGENT-PROTOCOL.md` §8 edit
  committed (WS-0a).
- [ ] FleetHub: `app/lib/agent-capabilities.ts` constants exported
  (WS-0c).
- [ ] FleetHub: `app/app/api/agent/posture/remote/route.ts`
  shipped + crontab confirms 200 OK on smoke (`curl -H
  Authorization: Bearer ...`).
- [ ] FleetHub: `app/install/latest-version/route.ts` + manifest
  file pointing at agent v1.0.0 GitHub release.
- [ ] Agent: `./scripts/build.sh both` + cross-compile darwin
  amd64+arm64 produce platform binaries.
- [ ] Agent: `./scripts/build-msi.sh 1.0.0.0` produces unsigned
  MSI (operator-confirmed; signing punted to v1.1).
- [ ] Agent: SHA256SUMS file generated manually.
- [ ] Agent: cosign-sign Linux + darwin binaries (free, ~90s).
  MSI shipped unsigned with documented `Right-click → Properties
  → Unblock` UX in RUNBOOK §Install.
- [ ] Agent: `gh release create v1.0.0` with all binaries +
  SHA256SUMS + cosign sigs.
- [ ] Agent: `git tag v1.0.0 && git push origin v1.0.0`.

---

## 5. v1.1 territory (architect-confirmed punts)

After v1.0.2 ships + v1.0.0 tags, these become **v1.1**
(operator-driven follow-up release), NOT Phase 14:

- **Auto-update mechanism** — silent-failure-risk #5; ops-audit
  release-blocker if not properly scoped. v1.0 answer: operator
  drives upgrades via existing `file.push` + `shell.open` verbs
  + the manual `pcc2k-agent --version` check in RUNBOOK.
- **Authenticode MSI signing** — needs EV cert ($300+/yr) +
  signing host operator doesn't have. v1.0 ships unsigned MSI
  with documented Unblock UX.
- **macOS notarization** — needs Apple Developer Program.
  RUNBOOK documents `xattr -d com.apple.quarantine` workaround.
- **PTY for shell** — plain pipes work for v1.0 demos. Adds
  creack/pty dep + Windows pseudoconsole branch.
- **macOS service control (launchctl start/stop/restart)** —
  LaunchAgent vs LaunchDaemon split is its own design pass.
  macOS hosts get `fleet.processes` (list) but not `fleet.services`
  (control). Split named explicitly in §8.
- **CrowdStrike AV verbs** — detect-only stub deferred entirely.
  Per-product capability advertisement means `fleet.av` simply
  isn't advertised on CrowdStrike hosts. No 502 risk.
- **tmp-sweeper for file_transfer** — add `agent.cleanup` admin
  verb in v1.0.2 instead so operator can manually clean stuck
  `.tmp` files. (Actually punt this — v1.0 has no clean-up UX;
  operator-side `find /var/lib/pcc2k-agent -name "*.tmp" -mtime
  +1 -delete` cron is the v1 answer.)
- **Release pipeline CI** — manual `gh release create` for
  v1.0.0; `scripts/release.sh` arrives when releases get frequent
  (v1.1+).
- **winget + choco third-party patch listing** — Phase 4 already
  ships WUA-only patches. Third-party listing has no UI consumer
  in Phase 13; defer until operator demand.
- **Containerized agent** — host-binary only.
- **Sophos / SentinelOne / Bitdefender AV** — Defender + (future)
  CrowdStrike only.
- **HSM-backed agent secret** — local keystore (DPAPI / keyring /
  Keychain) is the v1.0 model.
- **SysV init / OpenRC** — systemd-only Linux.

---

## 6. Out-of-scope deliberate non-goals (post-v1.0 ideas)

Documented in `docs/AGENT-CHANGELOG.md` "Future work" section:

- Bidirectional file-transfer streaming (large-file applies before
  fully transferred)
- Server-driven `shell.resize` for PTY-aware drawer
- Agent-to-agent file transfer (peer-to-peer)
- Agent telemetry export (Prometheus / OpenTelemetry)
- Self-hosted GitHub Actions runner pattern
- macOS Endpoint Security Framework integration

---

## 7. Test gates

- **`go vet ./...`** clean (mirror v1.0.1 build verification).
- **Build matrix:** linux/amd64, windows/amd64, darwin/amd64,
  darwin/arm64 — all produce binaries via `./scripts/build.sh`
  + cross-compile.
- **Unit tests** (architect §10 — sort-idempotency + capability-
  hotfix preempt):
  - `cmd/agent/capabilities_test.go` — `detectCapabilities()`
    returns sorted slice; same inputs → same output 100 times.
  - `cmd/agent/detect_cache_test.go` — TTL respected; cache miss
    on first call; cache hit on second within TTL.
  - `cmd/agent/processes_canonical_test.go` — synthetic /proc
    fixture → expected canonical JSON shape.
- **Manual smoke** (before v1.0.0 tag):
  - shell.open + interactive bash session via FH XtermDrawer.
  - file.push of a 100MB binary + sha256 verify ok.
  - backup.trigger against restic (Linux test host) +
    backup.complete delivered.
  - fleet.processes.list returns paginated 500 procs +
    nextCursor.
  - fleet.services.list + .start + .stop on systemd service
    (try `cron`).
  - fleet.av.scan QuickScan + fleet.av.cancel verified via
    `Get-MpComputerStatus` showing ScanInProgress flip back.
  - RustDesk peer-id appears on `Fl_Device.rustdeskId` after
    posture sweep.
  - `capabilities.update` fires when AV is uninstalled + reinstalled
    during agent session.
  - Bootstrap-via-FH flow end-to-end on a fresh VM.

---

## 8. Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| Capabilities slice sort drift → infinite-loop update | high | Sort deterministically in `detectCapabilities()` before any compare. Unit test asserts idempotency 100 runs. (Architect §10 v1.0.1-hotfix pre-empt.) |
| 500KB `fleet.processes.list` silently drops at WSS gateway | high | 256KB frame cap + cursor pagination contract committed to §8 BEFORE platform impl. response-too-large error code on cap exceeded. |
| Defender scan can't be cancelled via process kill | high | `av.cancel` invokes `Stop-MpScan` explicitly. Documented in §8. (Silent-failure-risk #3.) |
| Agent ships `fleet.services` name before AGENT-PROTOCOL §8 edit | high | WS-0a commit lands FIRST; agent v1.0.2 PR description requires link to FH WS-0a commit SHA. |
| Half-working macOS services UI = silent-failure-risk | medium | Split `fleet.processes` (advertised on all 3) from `fleet.services` (advertised on linux+windows only). macOS hosts get list-only — capability-gated cleanly. (Architect §4.) |
| RustDesk read fails on non-default install path | medium | Graceful fallback to null. Posture sweep continues. Logged at debug level. |
| Manual `gh release create` produces mismatched SHA256s in FH manifest | medium | Generate SHA256SUMS as part of build; copy-paste into FH `app/install/agent-manifest.json` BEFORE running gh release create. (Cross-repo step in activation checklist.) |
| Unsigned MSI shows SmartScreen warning → operator abandons enrollment | low | Documented Unblock UX in RUNBOOK. v1.1 Authenticode if operator obtains EV cert. |
| `User=root` on systemd unit fails on existing v1.0.1 deployments at upgrade time | medium | RUNBOOK upgrade section explicit: stop service, drop new unit, daemon-reload, start. Cannot upgrade via auto-update (which v1.0 doesn't have anyway). |
| `Op_Agent.capabilities` column gets stale if `capabilities.update` handler doesn't exist FH-side | low | Notification is harmless if FH ignores it. FH-side handler in Phase 14 if/when capability-aware features arrive. |

---

## 9. Sequencing summary

```
WS-0a  ~/fleethub/docs/AGENT-PROTOCOL.md §8 edit
       (fleet.processes.* + fleet.services.* + fleet.av.* rows,
        + pagination + capabilities.update + av.cancel + error code
        + back-compat policy)
       OWN COMMIT, FH repo

WS-0b  cmd/agent/session_io.go frame cap
       + cmd/agent/detect_cache.go (60s TTL)
       + cmd/agent/capabilities_update.go (sort + diff + notify)
       agent repo

WS-0c  ~/fleethub/app/lib/agent-capabilities.ts shared constants
       FH repo

WS-A   cmd/agent/processes.go + processes_{linux,windows,darwin}.go
       + cmd/agent/services.go + services_{linux,windows,darwin}.go
       + capability append (fleet.processes always; fleet.services
         linux+windows only)
       agent repo

WS-B   cmd/agent/av.go + av_defender_windows.go + av_unsupported.go
       + capability append (fleet.av on Windows + Defender only)
       agent repo

WS-C   cmd/agent/posture.go RemoteReport extension
       + cmd/agent/posture_remote_{windows,unix}.go
       + main.go posture loop adds sendRemote + capabilities.update
       + scripts/bootstrap.sh + scripts/bootstrap.ps1 (FH-down fallback)
       + ~/fleethub/app/app/api/agent/posture/remote/route.ts (FH repo)
       agent + FH repo

WS-D   cmd/agent/main.go --version + ldflags wire
       + scripts/build.sh ldflags propagation
       + systemd/pcc2k-agent.service User=root flip
       + docs/AGENT-RUNBOOK.md (9 sections, source-of-truth pointers)
       + docs/AGENT-CHANGELOG.md
       + LICENSE (MIT)
       + ~/fleethub/app/app/install/latest-version/route.ts (FH repo)
       + ~/fleethub/app/app/install/agent-manifest.json (FH repo)
       + ~/fleethub/app/app/install/pcc2k-agent-[platform]/route.ts (FH repo)
       + git tag v1.0.0 + gh release create v1.0.0
       agent + FH repo
```

Total expected commits: **~12** (architect target). Split across 2
repos: ~8 agent commits + ~4 FH cross-repo commits.

---

## 10. Open questions deferred to in-flight decisions

- **Manifest pinning** — does FH's `agent-manifest.json` get
  per-tenant override? v1: single global manifest. v1.1 can add
  per-tenant for canary rollouts.
- **Cursor expiry** — `fleet.processes.list` snapshots GC'd after
  5 min. Operator visits a slow page → cursor expired? Surface
  via `Fl_Error.code = "cursor-expired"`. Document in §8.
- **Long-name truncation** — Windows service names can be 80
  chars; agent reports verbatim. FH-side truncates display.
  Decision deferred.

---

## 11. Why this phase, why these workstreams

The AGENT-BACKLOG.md committed earlier today drafted v1.0.2 as
4 workstreams (services + AV + RustDesk/patches + release polish).
The 4-audit + architect gut-check tightened this to 5:

1. **Split WS-0** (cross-repo doc edit + agent scaffold + FH
   shared constants) into its own preamble — these are protocol
   surface, not feature work.
2. **Split processes from services** — capability string IS the
   contract; macOS list-only without start/stop control means
   different capability names. Cleaner long-term.
3. **CrowdStrike entirely cut** — detect-only stub still has the
   stale-button risk; per-product capability advertisement
   eliminates the failure mode. Saves a file.
4. **winget+choco listing cut** — no UI consumer in Phase 13;
   v1.1 territory.
5. **scripts/release.sh cut** — manual `gh release create` works
   for the ONE v1.0.0 release; script when frequent.

The cap-at-v1.0.0 commitment survives if WS-0a lands first,
namespace is resolved before any verb implementation, the 4 cuts
are accepted, and the cross-repo FH stubs (lib/agent-capabilities
.ts, /api/agent/posture/remote, /install/latest-version,
agent-manifest.json, /install/pcc2k-agent-[platform]) all land
clean.

**The "is the agent actually done?" answer** (architect §10):

YES — IF v1.0.0 ships with:
- `--version` flag returning the build-time ldflag version
- `capabilities.update` proven to NOT infinite-loop (sort-idempotent
  capability slice)
- RUNBOOK source-of-truth pointers actually pointing at extant
  files
- Bootstrap-from-FH end-to-end smoke green on a fresh VM
- v1.0.0 git tag and GitHub release with cosign-signed Linux +
  darwin binaries + unsigned MSI

Anything not in scope here is v1.1 (operator-driven; new design
pass required) or non-goal (Phase 14+ ideas; new project required).

---

**End of design.**
