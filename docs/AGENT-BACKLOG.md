# pcc2k-agent Backlog — v1.0.1 + v1.0.2 (2-Phase Final Plan)

**Status:** v1.0.1 **LIVE** 2026-05-18 — see "v1.0.1 SHIPPED" section
below. v1.0.2 design remains as drafted. FleetHub server-side capped
at Phase 13 per `~/fleethub/docs/ROADMAP.md`. The agent has its own
backlog spread across multiple FleetHub phases — this doc consolidates
that into **two agent phases** that take the agent from current
shipped state to **v1.0.0 release-tagged + deploy-from-panel
functional**.

## v1.0.1 SHIPPED (2026-05-18)

5 workstreams / 6 agent commits + 1 FleetHub cross-repo commit:

| WS | Commit | What |
|---|---|---|
| A | `145951f` | capabilities.go — feature-detect at startup. Hello payload sends `["agent", "inventory", "alerts", "fleet.shell"?, "fleet.file", "fleet.backup"?]` based on real host probes. |
| B | `eed6041` | shell.go + shell_unix.go + shell_windows.go. shell.open/input/close verbs; shell.exited callback. Plain stdio pipes (not PTY); PTY is v1.0.2 polish. |
| C | `d51a99f` | file_transfer.go. file.push/pull verbs + file.transfer.complete callback. SHA-256 verify, atomic tmp→rename, 5GB hard cap. No new deps (stdlib only). |
| D | `f01babd` | backup.go + backup_unix.go + backup_windows.go. backup.trigger/cancel verbs + backup.complete callback. Per-product invocation matrix: wbadmin/veeam/macrium (Win), restic/borg/duplicati/macos-tm (Unix). |
| E.FH | FH `1983548` | Fl_EnrollToken + Fl_AgentRegistration schema. /api/admin/enroll-tokens (ADMIN-only, withAudit redactKeys:["token"]). /api/agent-ingest/enroll (token-authed). /install/bootstrap.sh + /install/bootstrap.ps1 static. /clients/[name]?tab=install page. bcryptjs dep. |
| E.agent | `4828346` | enroll.go bootstrap consumer. main.go --bootstrap-token + --bootstrap-url flags. Single-shot enrollment that prints env-file format to stdout for the wrapping script to write to systemd EnvironmentFile / Windows service env. |

Build matrix verified: linux/amd64 (5.7MB), windows/amd64 (6.0MB),
darwin/amd64 (6.0MB). `go vet ./...` clean.

**Operator flow now functional:**

```
FH /clients/<tenant>?tab=install
  → click "Generate install command" (24h default TTL)
  → copy Unix or Windows one-liner

Target host:
  curl -fsSL https://fleethub.pcc2k.com/install/bootstrap.sh \
    | PCC2K_BOOTSTRAP_TOKEN=<T> PCC2K_FLEETHUB_URL=<U> sudo bash

Host appears in /devices within seconds of first poll.
```

Token shown ONCE; 410-Gone on re-use; auto-expires per the
approval-expiry-sweep cron (Phase 12 WS-C.5 — operator crontab
already wired).

---

After v1.0.2 ships, the agent matches FleetHub v1.0 surface area;
further verbs become v1.1 alongside FleetHub.

**Scope of this doc:** two agent phases. The spec IS the contract.

---

## Current state (what the agent ships today)

Working verbs (from `cmd/agent/main.go` router + per-feature files):

| Surface | Verbs | File |
|---|---|---|
| Software lifecycle | `install`, `uninstall`, `start`, `stop` | `software_unix.go`, `software_windows.go` |
| Patch dispatch (Windows) | `wusa`, `dism-remove-package`, `restore-point`, `vm-snapshot` | `patches_windows.go` |
| Script execution | bash / sh / powershell / python / cmd | `scripts_unix.go`, `scripts_windows.go` |
| Inventory + posture sweep | (push-cadence to FH `/api/agent/posture/*`) | `inventory_*.go`, `posture_*.go` |
| Signed-script verification | Ed25519 signature check | `scripts_signing.go` |

`agent.hello` capabilities array currently hardcoded:

```go
"capabilities": []string{"agent", "inventory", "alerts"}
```

Enrollment: `--token` flag or `PCC2K_AGENT_TOKEN` env. No FH-side
enrollment endpoint exists — operator places token on host manually
via OS keystore (DPAPI on Windows).

---

## Gaps mapped to FleetHub phases (the source-of-truth backlog)

| FH Phase | Surface | Agent gap | Severity |
|---|---|---|---|
| 7 | RustDesk peer ID self-report | `Fl_Device.rustdeskId` column exists; agent doesn't populate | nice-to-have |
| 8 | Backup posture detection | `Fl_Device.backupProduct` checked by Phase 9 mutable-backup gate; agent's posture sweep doesn't detect/report | loses-demo (Phase 9 verbs 400 without it) |
| 9 + 10 | shell verbs | `shell.open` / `shell.close` / `shell.input` not implemented; FH-side XtermDrawer is a placeholder | loses-demo |
| 9 + 10 | file transfer | `file.push` / `file.pull` not implemented; FH UI exists but pushes nothing | loses-demo |
| 9 + 10 | mutable backup | `backup.trigger` / `backup.cancel` not implemented; per-tenant toggle gates nothing | loses-demo |
| 10 | ingest envelope callbacks | Agent never SENDS `shell.exited`, `file.transfer.complete`, `backup.complete`; FH handlers (commit `323f923`) execute zero times today | silent-failure-risk |
| 11 | Capability advertisement | `agent.hello.capabilities` is hardcoded; Phase 13 capability-gating relies on feature-detected values | growth-cost (Phase 13 buttons can't disable correctly) |
| 13 | `fleet.services.*` | services.list / .start / .stop / .restart not implemented | (Phase 13 ships UI; agent ships in v1.0.2) |
| 13 | `fleet.av.*` | av.scan / .update-defs / .quarantine / .release not implemented; Defender + CrowdStrike scope | (Phase 13 ships UI; agent ships in v1.0.2) |
| All | Deploy from panel | Operator types token by hand today; no panel-driven installer flow | loses-demo |
| All | Third-party patch source | WUA + KB only; winget / chocolatey upgrade lists not in agent posture | nice-to-have |

11 items. Distributed across two agent phases per the user's
two-phase cap:

- **v1.0.1 = the verbs FleetHub already designed-and-shipped UI for
  + deploy-from-panel.** Without these, Phase 9, 10, 11 features are
  zero-functional in the field.
- **v1.0.2 = Phase 13 verbs (services + AV) + polish + ship as v1.0
  release tag.** After v1.0.2, the agent matches FleetHub v1.0 surface.

---

# Agent v1.0.1 — Close FH-side-ready verbs + deploy-from-panel

**Goal:** every Phase 9 / 10 / 11 FleetHub feature that depends on an
agent verb becomes functional. Deploy-from-panel ships so operators
can enroll a host from `/clients/[name]?tab=install` without
hand-distributing tokens.

**5 workstreams.**

## WS-A — Capability self-detection + agent.hello v2

**Files**: `cmd/agent/main.go` (line 310-322, hello payload),
new `cmd/agent/capabilities.go`.

Today's hardcoded `["agent", "inventory", "alerts"]` breaks Phase 13's
capability-gated buttons design. Replace with runtime feature-detection:

```go
// capabilities.go
package main

func detectCapabilities() []string {
    caps := []string{"agent", "inventory", "alerts"}
    if shellAvailable() {
        caps = append(caps, "fleet.shell")
    }
    if fileTransferAvailable() {
        caps = append(caps, "fleet.file")
    }
    if backupProductDetected() != "none" {
        caps = append(caps, "fleet.backup")
    }
    // v1.0.2 adds fleet.services + fleet.av
    return caps
}
```

`shellAvailable()` checks for powershell.exe (Windows) or `/bin/bash` /
`/bin/sh` (Unix). `fileTransferAvailable()` always true once WS-B ships.
`backupProductDetected()` is the WS-D posture helper.

**Lands first** — every subsequent workstream's verb only renders in
FH after capability is advertised.

## WS-B — Shell verbs + `shell.exited` callback

**Files**: new `cmd/agent/shell.go` (router), `cmd/agent/shell_unix.go`,
`cmd/agent/shell_windows.go`.

Mirrors the existing `service_other.go` / `service_windows.go` split.

**Verbs handled** (router cases added to `main.go` switch):
- `shell.open { sessionId, maxDurationMin }` — spawn powershell.exe
  (Windows) or `/bin/bash` (Unix). Hook stdio to a WSS stream channel
  keyed by sessionId. Register sessionId in the agent's in-process
  session map.
- `shell.input { sessionId, bytes }` — write base64-decoded bytes to
  the running session's stdin.
- `shell.close { sessionId }` — terminate session, fire
  `shell.exited` callback.

**Callback** (agent → FH `POST /api/agent-ingest`):
```json
{
  "method": "shell.exited",
  "params": {
    "sessionId": "...",
    "exitReason": "operator-close" | "max-duration" | "process-exit",
    "bytesTx": <int>,
    "bytesRx": <int>
  }
}
```

FH's Phase-10 handler updates `Fl_ShellSession.state="closed"` +
`closedAt` + `exitReason`.

**WSS stream channel**: Reuse the existing WSS connection from
`main.go:307` (the same conn that carries the hello). Add a frame
type discriminator so stdio bytes interleave with regular RPC
without collision — JSON frames like
`{"type":"stream","sessionId":"...","data":"<b64>"}`.

**Cross-platform notes**:
- Windows: `powershell.exe -NoLogo -NoProfile -NonInteractive` spawned
  via `os/exec`. Pseudoconsole via `golang.org/x/sys/windows` for
  proper PTY behavior; falls back to plain stdio pipes if PTY
  allocation fails.
- Unix: `pty.Start` via `github.com/creack/pty` (already in
  go.sum if not, add). bash with `--norc --noprofile` for clean
  state.
- Max duration: `time.AfterFunc(maxDurationMin*Minute, killSession)`
  with cancellation on natural exit.

**Safety**: shell.open verb refuses without operator justification —
Phase 9 + 11 already gate FH-side. Agent doesn't re-check; assumes FH's
4-eyes / step-up wrapping is authoritative.

## WS-C — File transfer verbs + `file.transfer.complete` callback

**Files**: new `cmd/agent/file_transfer.go` (works cross-platform with
standard io).

**Verbs**:
- `file.push { transferId, signedUrl, remotePath, sha256Expected }`
  — agent fetches from `signedUrl`, writes to `remotePath`, hashes,
  emits callback with actual sha256 + sizeBytes.
- `file.pull { transferId, remotePath, signedUploadUrl }` — agent
  reads from `remotePath`, chunks upload to `signedUploadUrl`,
  emits callback.

**Callback**:
```json
{
  "method": "file.transfer.complete",
  "params": {
    "transferId": "...",
    "state": "ok" | "checksum-mismatch" | "read-error" | "write-error" | "network-error",
    "sha256": "<hex>",
    "sizeBytes": <int>,
    "errorMsg": "..."
  }
}
```

**Size cap**: agent enforces a hard ceiling (default 1 GB) to defend
against FH-side misconfiguration. Per-tenant
`Fl_Tenant.fileTransferMaxSizeMb` is the FH-side authoritative gate;
agent's hard ceiling is a belt-and-suspenders against agent OOM.

**Atomic writes** (push): write to `<remotePath>.tmp`, fsync, rename
to `<remotePath>` only on hash-verify success. Partial-write cleanup
on agent crash via startup sweep of `.tmp` files older than 1h.

## WS-D — Backup verbs + product posture + `backup.complete` callback

**Files**: new `cmd/agent/backup.go` (router + posture helper),
`cmd/agent/backup_windows.go`, `cmd/agent/backup_unix.go`.

**Posture helper** (called by WS-A capability detection + by the
existing `posture_*.go` sweep cadence):
- Windows: check for wbadmin / Veeam Agent / Acronis / Macrium
  service registration + binary presence.
- Linux/macOS: check for restic / borg / duplicati / TimeMachine
  binary on PATH.
- Returns `"none" | "wbadmin" | "veeam" | "acronis" | "macrium" |
  "restic" | "borg" | "duplicati" | "timemachine"`.
- This value goes into `agent.hello.posture.backupProduct` AND
  the regular posture sweep at `Fl_Device.backupProduct`.

**Verbs**:
- `backup.trigger { runId, product, options? }` — dispatches the
  per-product binary in a goroutine, emits `backup.complete` on
  exit. `options.passthroughArgs` allows operator-supplied
  product-specific flags (validated FH-side).
- `backup.cancel { runId }` — kill the running goroutine, emit
  `backup.complete` with `state="cancelled"`.

**Per-product invocation** (`backup_windows.go`):
```go
func runBackup(runId, product string, opts BackupOpts) {
    switch product {
    case "wbadmin":
        cmd = exec.Command("wbadmin", "start", "backup", "-quiet", ...)
    case "veeam":
        cmd = exec.Command("C:\\Program Files\\Veeam\\Veeam Agent\\Veeam.Agent.Configurator.exe", ...)
    case "macrium":
        // reflect.exe with /backup
    }
    // stream stdout/stderr to a log file at /var/lib/pcc2k-agent/backups/<runId>.log
}
```

**Callback**:
```json
{
  "method": "backup.complete",
  "params": {
    "runId": "...",
    "state": "ok" | "failed" | "cancelled",
    "exitCode": <int>,
    "logPath": "/var/lib/pcc2k-agent/backups/<runId>.log",
    "errorMsg": "..."
  }
}
```

## WS-E — Deploy from panel

**Goal**: operator clicks "Install agent" on `/clients/[name]?tab=install`,
gets a per-tenant one-time bootstrap snippet, pastes it on the target
host, agent enrolls and reports back. No more hand-distributing tokens.

**Two-sided work**:

### Agent side (this repo)

**Files**: `cmd/agent/main.go` (new `-bootstrap-url` flag),
new `cmd/agent/enroll.go`, `installer/pcc2k-agent.wxs` updates,
`scripts/bootstrap.sh` (new), `scripts/bootstrap.ps1` (new).

**New flow**:

1. **First invocation with bootstrap URL** (no agent secret stored yet):
   ```bash
   pcc2k-agent --bootstrap-url=https://fleethub.pcc2k.com/api/agent-ingest/enroll \
               --bootstrap-token=<one-time-token>
   ```
   Agent POSTs to bootstrap URL with `{ token, hostname, os, osVersion, ipAddresses[] }`.
   FH validates token (one-time, unused, unexpired), creates
   `Op_Agent` row, returns `{ agentId, agentSecret, fleethubBaseUrl }`.
   Agent stores `agentSecret` via OS keystore (DPAPI on Windows;
   keyring on Linux via `github.com/zalando/go-keyring`; Keychain on
   macOS via the same package).

2. **All subsequent invocations**: agent reads stored secret + base
   URL, connects normally (existing `--token` flow remains valid for
   operators who prefer manual token).

3. **Bootstrap one-liner** (Unix; same shape Windows via `iwr`):
   ```bash
   curl -fsSL https://fleethub.pcc2k.com/install/bootstrap.sh | \
     PCC2K_BOOTSTRAP_TOKEN=<token> sudo bash
   ```
   `bootstrap.sh` downloads the platform binary, places it at
   `/usr/local/bin/pcc2k-agent`, installs the systemd unit, runs
   first-invocation enrollment, starts the service.

**Files added**:
- `cmd/agent/enroll.go` — bootstrap-token consumer + secret-storage
- `scripts/bootstrap.sh` — Unix one-liner
- `scripts/bootstrap.ps1` — Windows one-liner (run via `iwr | iex`)

**Files updated**:
- `cmd/agent/main.go` — `--bootstrap-url` + `--bootstrap-token` flags
  + branch to `enroll.go` when both present and no stored secret
- `installer/pcc2k-agent.wxs` — MSI accepts `BOOTSTRAP_URL=...
  BOOTSTRAP_TOKEN=...` properties at install time, passes them to
  the first agent invocation

### FleetHub side (depends on `~/fleethub/docs/PHASE-13-DESIGN.md`)

**Add to Phase 13 scope** (small additions to existing WS-D close docs):

- `Fl_EnrollToken` schema:
  ```prisma
  model Fl_EnrollToken {
    token         String    @id // 32-byte hex
    tenantName    String
    createdBy     String
    createdAt     DateTime  @default(now())
    expiresAt     DateTime  // default now + 24h
    consumedAt    DateTime?
    consumedByAgentId String?
    @@index([tenantName, consumedAt])
  }
  ```

- `POST /api/admin/enroll-tokens` — operator creates a token. Body:
  `{ tenantName, ttlHours? }`. Returns `{ token, expiresAt,
  bootstrapSnippet }` where the snippet is the platform-specific
  one-liner string.

- `POST /api/agent-ingest/enroll` — bootstrap consumer. Validates
  token, creates `Op_Agent` row + per-agent secret, marks token
  consumed. Returns `{ agentId, agentSecret, fleethubBaseUrl }`.

- `GET /install/bootstrap.sh` and `GET /install/bootstrap.ps1` —
  serve the bootstrap shell scripts (signed from the agent repo's
  `scripts/` directory; CI publishes them as static files).

- `/clients/[name]?tab=install` page — operator picks a TTL,
  clicks "Generate install command", gets the one-liner with the
  fresh token embedded + a "Copy" button. Token revealed once.

**Cross-references**:
- FleetHub `PHASE-13-DESIGN.md` WS-D adds the install-token routes
  as a project-close cross-app gate.
- The bootstrap one-liner is the ONLY UX operators learn —
  matches the "single command to enroll" convention from other RMM
  tools.

---

# Agent v1.0.2 — Phase 13 services + AV + release polish

**Goal:** every FleetHub Phase 13 button works. v1.0 release tag
applied to the agent.

**4 workstreams.**

## WS-A — `fleet.services.*` (process + service inspector)

**Files**: extend existing `service_other.go` / `service_windows.go`
(currently empty/scaffold). New `services_unix.go`,
`services_windows.go` (process inspector).

**Verbs** (matching FleetHub Phase 13 §1.WS-B):

- `fleet.services.list` — synchronous RPC. Returns full process +
  service inventory:
  ```json
  {
    "processes": [
      {"pid": 1234, "name": "powershell.exe", "user": "SYSTEM",
       "cpuPct": 0.5, "rssMb": 120, "startedAt": "ISO8601"}
    ],
    "services": [
      {"name": "wuauserv", "displayName": "Windows Update",
       "state": "running", "startupType": "delayed-auto"}
    ]
  }
  ```
  Limit ~2000 processes / 500 services per response. Agent returns
  what's there; FH-side `Fl_ProcessSnapshot` stores the JSON blob
  per Phase 13 design.

- `fleet.services.start { name }` — start a named service.
- `fleet.services.stop { name }` — stop a named service.
- `fleet.services.restart { name }` — stop + start.

**Cross-platform**:
- Windows: `sc.exe start <name>` / `Stop-Service` via powershell.
  Process inspector via `tasklist /v /fo csv` parsed, or
  `golang.org/x/sys/windows/svc/mgr` for service state.
- Linux: `systemctl start/stop/restart <name>`. Process inspector
  via `/proc` parsing (PID, /proc/<pid>/stat for CPU, /proc/<pid>/status
  for RSS). systemd-only — no SysV init support in v1 (Phase 14+ idea).
- macOS: `launchctl start/stop/kickstart`. Process inspector via
  `ps aux` parsed.

**4-eyes**: agent does NOT re-check. FH-side `Fl_ActionApproval` is
authoritative; agent acts on receipt.

## WS-B — `fleet.av.*` (mutable AV/EDR)

**Files**: new `cmd/agent/av.go` (router + product detection),
`cmd/agent/av_defender_windows.go`, `cmd/agent/av_crowdstrike.go`.

**Product detection** (extends Phase 9's existing posture/av
sweep; agent already reports `Fl_Device.avProduct`):
- Detected products in v1: Microsoft Defender (Windows built-in),
  CrowdStrike Falcon Sensor (Windows + Linux + macOS).
- Other products (Sophos, SentinelOne, etc.) → "not supported in v1",
  agent returns `{state: "unsupported-product", product: "..."}`
  on any verb attempt. FH-side surfaces this gracefully.

**Verbs**:

- `fleet.av.scan { runId, kind }` where kind in
  `"quick" | "full" | "custom"`:
  - Defender: `Start-MpScan -ScanType QuickScan|FullScan` via
    powershell. Long-running; agent emits `av.scan-progress`
    periodically + `av.scan-complete` at end.
  - CrowdStrike: Falcon doesn't expose imperative scan trigger via
    CLI. Agent returns `{state: "unsupported-verb", reason: "Falcon
    is signature-driven; trigger from Falcon console"}`. FH-side
    Phase-13 UI disables the button for CrowdStrike hosts.

- `fleet.av.update-defs { runId }`:
  - Defender: `Update-MpSignature` via powershell.
  - CrowdStrike: `falconctl update` (Linux) / built-in (Windows).

- `fleet.av.quarantine { runId, filePath }`:
  - Defender: `Add-MpThreat` or `Set-MpPreference -QuarantinePurgeItemsAfterDelay`;
    operator-provided path goes into quarantine via threat-add-by-path.
  - CrowdStrike: `falconctl quarantine` (where supported).

- `fleet.av.release { runId, threatId }`:
  - Defender: `Restore-MpThreat -ThreatID`.
  - CrowdStrike: Falcon CLI quarantine-restore where supported.

**Callbacks** for long-running verbs (scan, update-defs):
```json
{
  "method": "av.action-complete",
  "params": {
    "runId": "...",
    "verb": "scan" | "update-defs" | "quarantine" | "release",
    "state": "ok" | "failed" | "unsupported-verb" | "unsupported-product",
    "result": { /* product-specific payload */ },
    "errorMsg": "..."
  }
}
```

FH-side `Fl_AvAction` row state-machines from `queued → acked → completed | failed`.

## WS-C — RustDesk peer-id self-report + posture polish

**Files**: extend `cmd/agent/posture_windows.go` +
`cmd/agent/posture_linux.go` + `cmd/agent/posture_darwin.go`.

**RustDesk peer ID**:
- Windows: read `HKLM\SOFTWARE\RustDesk\rendezvous_server` + the
  per-install peer ID from `%APPDATA%\RustDesk\config\RustDesk.toml`.
- Linux: read `~/.config/rustdesk/RustDesk.toml` (or
  `/root/.config/rustdesk/` for service install).
- macOS: read `~/Library/Preferences/com.carriez.rustdesk/RustDesk.toml`.

Reported as `Fl_Device.rustdeskId` via the existing posture sweep
(new field on the posture POST body).

**Third-party patch sources**:
- Windows: `winget upgrade --include-unknown` parsed to JSON,
  `choco outdated -r` parsed.
- Linux: already covered by existing `apt list --upgradable` /
  `dnf check-update` paths (Phase 1).

Reported via existing patch-source posture ingest.

## WS-D — v1.0 release polish

- `--version` flag returns `v1.0.0` + git SHA from build-time
  ldflags. Matches Phase 13 `/api/health` `buildSha`.
- Auto-update mechanism: agent checks `GET /install/latest-version`
  (returns `{ version, sha256, downloadUrl }`) on a 24h cadence;
  if version higher than self AND signature-verified, downloads to
  `<binPath>.new` + restart via systemd / NSSM. Operator-toggleable
  via `--no-auto-update` flag (default ON for hipaaMode tenants,
  off for dev/lab).
- Signed installer + binary: MSI signed via authenticode (existing
  WiX flow). Linux binary signed via `cosign` + GitHub release
  attestation.
- `docs/AGENT-RUNBOOK.md` — agent-side ops doc mirroring
  FleetHub's `docs/RUNBOOK.md`. Covers: install (one-liner +
  manual), service-control (`systemctl`, sc.exe), log locations
  (`/var/log/pcc2k-agent.log`, Event Viewer), token rotation,
  uninstall, upgrade path.
- `LICENSE` at agent repo root.
- `go.mod` module path locked at v1.0.0.
- Final tag: `v1.0.0` on the agent repo. GitHub release with msi
  + darwin + linux binaries + signed checksums.

---

# Cross-references

- **FleetHub Phase 13 dependency** — `~/fleethub/docs/PHASE-13-DESIGN.md`:
  - WS-A capability advertisement (agent v1.0.1) gates Phase 13 button
    rendering. FH renders DISABLED if capability missing.
  - WS-E deploy-from-panel adds 4 FH-side artifacts:
    `Fl_EnrollToken` schema, `/api/admin/enroll-tokens`,
    `/api/agent-ingest/enroll`, `/install/bootstrap.{sh,ps1}` static
    serving, + `/clients/[name]?tab=install` page. **Add these to
    Phase 13 WS-D close docs** — they're project-close cross-app gates.

- **AGENT-PROTOCOL.md** — `~/fleethub/docs/AGENT-PROTOCOL.md`:
  Phase 13 WS-0a edits the §8 namespace table. Agent v1.0.2 must
  not implement `fleet.services.*` or `fleet.av.*` BEFORE that doc
  commit lands.

- **TicketHub time-card sync** — agent has no role here; FH-side
  `lib/bff-th-client.ts` handles the outbound HMAC. Agent v1.0.1
  + v1.0.2 are TH-decoupled.

---

# Sequencing summary

```
AGENT v1.0.1 (close FH-side-ready verbs + deploy-from-panel)

  WS-A.1  cmd/agent/capabilities.go — feature-detect at startup
  WS-A.2  cmd/agent/main.go hello payload → use detectCapabilities()

  WS-D.1  cmd/agent/backup.go posture helper (backupProductDetected)
  WS-D.2  cmd/agent/backup_windows.go + backup_unix.go (verbs)
  WS-D.3  backup.complete callback wiring

  WS-B.1  cmd/agent/shell.go router
  WS-B.2  cmd/agent/shell_unix.go + shell_windows.go (PTY spawn)
  WS-B.3  WSS stream-channel framing in main.go
  WS-B.4  shell.exited callback wiring

  WS-C.1  cmd/agent/file_transfer.go (push/pull + sha256 verify)
  WS-C.2  file.transfer.complete callback wiring

  WS-E.1  FleetHub Fl_EnrollToken schema + 3 routes (cross-repo PR)
  WS-E.2  cmd/agent/enroll.go bootstrap consumer + secret storage
  WS-E.3  scripts/bootstrap.sh + scripts/bootstrap.ps1
  WS-E.4  installer/pcc2k-agent.wxs accepts BOOTSTRAP_URL/TOKEN
  WS-E.5  FleetHub /clients/[name]?tab=install page (cross-repo PR)

AGENT v1.0.2 (Phase 13 services + AV + release tag)

  WS-A.1  cmd/agent/services_unix.go (systemctl + /proc parsing)
  WS-A.2  cmd/agent/services_windows.go (sc.exe + tasklist)
  WS-A.3  fleet.services.list + start/stop/restart router
  WS-A.4  capabilities.go: append "fleet.services"

  WS-B.1  cmd/agent/av.go router + product detection
  WS-B.2  cmd/agent/av_defender_windows.go (4 verbs)
  WS-B.3  cmd/agent/av_crowdstrike.go (Windows + Linux + macOS)
  WS-B.4  av.action-complete callback wiring
  WS-B.5  capabilities.go: append "fleet.av"

  WS-C.1  RustDesk peer-id extraction in posture_*.go
  WS-C.2  winget + choco third-party patch source

  WS-D.1  --version + auto-update mechanism
  WS-D.2  Signed installer + binary release pipeline
  WS-D.3  docs/AGENT-RUNBOOK.md
  WS-D.4  LICENSE at repo root + go.mod v1.0.0
  WS-D.5  Tag v1.0.0 + GitHub release
```

Expected commit count: **~12 per phase** (24 total across the two
phases). Phase 1 has more files (5 new feature modules + cross-repo
deploy PR); Phase 2 has more discrete platform variants.

---

# Risk register

| Risk | Severity | Mitigation |
|---|---|---|
| WSS stream-channel framing collides with regular RPC | high | Discriminator field `type: "stream" \| "rpc"` on every frame. Sessions multiplex by `sessionId`. Add agent-side unit test for interleaved frame ordering. |
| Bootstrap token leaks (one-line snippet visible in shell history) | medium | Token is one-time + 24h TTL. Server marks consumed on first POST; second use 410-Gone. Agent stores per-agent secret separately. |
| Per-agent secret storage on Linux without keyring | medium | Fall back to `0600` file at `/var/lib/pcc2k-agent/secret`. Logged at startup. |
| backup.trigger blocks the agent process (long-running) | medium | Goroutine + cancellable context. Agent main loop keeps polling FH. |
| AV verbs depend on product-specific CLI behavior | medium | v1 only supports Defender + CrowdStrike. Unsupported products return explicit `{state: "unsupported-product"}` instead of crashing. FH UI gates buttons by detected product. |
| shell.open with PTY allocation fails on Windows Server Core | low | Fall back to plain stdio pipes (line-buffered). Most operator workflows survive without full PTY. |
| Auto-update bricks an agent mid-update | low | `<binPath>.new` written first, atomic rename last. systemd / NSSM restart fails → operator sees stale-but-working agent, FH /api/health degrades. Manual recovery is fine. |
| `fleet.services.*` namespace squat before AGENT-PROTOCOL edit | high | Agent v1.0.2 implementation refuses to ship until namespace doc commit lands. Hard ordering enforced in Sequencing summary above. |

---

# After v1.0.2 — what's v1.1+ (NOT v1.0)

- **SysV init / OpenRC support** (current v1.0 is systemd-only on Linux)
- **macOS launchd inspector** (current v1.0 covers process + service
  state on macOS but no launchd manipulation)
- **Sophos / SentinelOne / Bitdefender AV integrations** (v1.0
  ships Defender + CrowdStrike only)
- **OS-native pseudoconsole on Windows Server Core** (v1.0 falls
  back to pipes)
- **Containerized agent** (Docker / k8s sidecar shape; v1.0 is
  host-binary only)
- **Bidirectional file-transfer streaming** (v1.0 is fetch-then-write
  / read-then-upload; streaming would let large files start
  applying before fully transferred)

These map to FleetHub v1.1 once an operator surfaces real demand.
Do NOT pre-build.

---

**End of backlog.**
