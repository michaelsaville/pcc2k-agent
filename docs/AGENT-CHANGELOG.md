# pcc2k-agent Changelog

Versioning is one-track: every release tag is `vMAJOR.MINOR.PATCH`.
The contract is `docs/AGENT-PROTOCOL.md` — any breaking change
there bumps MAJOR. Capability additions bump MINOR. Bug fixes and
hardening that preserve the wire contract bump PATCH.

---

## v1.0.0 — 2026-05-18

First stable release. Five workstream rollup of v1.0.2 design:

- **WS-0a (protocol):** AGENT-PROTOCOL §8 namespace ownership +
  §21–25 cursor pagination, frame cap, capabilities.update,
  av.cancel semantics, backward-compat policy.
- **WS-0b (foundations):** 256KB outbound frame cap with
  `-32070` response-too-large + `-32071` cursor-expired error
  codes; detect-cache with 60s TTL; capabilities canonicalizer
  with deterministic sort+dedupe (preempts hello-loop hotfix).
- **WS-A (process + service control):** `fleet.processes.list`
  (all 3 platforms with cursor pagination + 5min snapshot TTL);
  `fleet.services.list/start/stop/restart` on Linux (systemd) +
  Windows (sc.exe + Restart-Service) — macOS list-only.
- **WS-B (AV control):** `fleet.av.scan` /
  `update-defs` / `quarantine` / `release` / `cancel` Defender
  via PowerShell with `Stop-MpScan` for cancel. CrowdStrike
  dropped from v1.0 per architect §5 option (a).
- **WS-C (remote desktop):** Posture beacon now reads the
  RustDesk peer-id from local TOML and POSTs to FH
  `/api/agent/posture/remote`; FH stores in
  `Fl_Device.rustdeskId` only on change. Bootstrap fallback +
  capabilities.update wire complete.
- **WS-D (release polish):** `--version` flag stamps
  build-time `version` + `gitSha` via ldflags;
  systemd unit hardened with PrivateTmp + ProtectKernel* (kept
  User=root for control verbs); AGENT-RUNBOOK + LICENSE +
  CHANGELOG shipped; FleetHub `/install/*` routes serving signed
  manifest + binaries for bootstrap.

Breaking changes from v0.x: agent-id + agent-secret format
finalized. v0.x dev installs must re-enroll.

---

## v1.0.1 — 2026-05-17 (skipped public; -hotfix track)

Internal-only hardening track between Phase 12 + v1.0.2 design.
- Sort-idempotent capability list (now lifted into v1.0.0 proper
  as part of WS-0b architect §10 preempt).
- Bootstrap script audit + permission tightening (now lifted
  into WS-C as the bootstrap fallback path).

---

## v0.3.0 — 2026-05-15

Phase 12 wire — last v0.x dev release.
- `shell.*` and `file.*` verbs.
- Posture loop cadence.
- Initial capability advertisement in `agent.hello`.

---

## v0.2.0 — 2026-05-13

- Long-running verb pattern (`replyResult queued → goroutine →
  notify complete`).
- 4-eyes approval gate FH-side (see Phase 11 design).

---

## v0.1.0 — 2026-05-11

Initial scaffold — WSS dialer + agent.hello + agent.ping. Single
binary, single config file.

---

## Backward-compat policy

Per AGENT-PROTOCOL §25: an agent N versions behind FleetHub MUST
remain functional for at least 90 days. Verbs added in a newer
agent version simply don't appear in the older agent's
capability list, and the FleetHub UI hides them on a per-device
basis. There is no flag day.

The only hard break is the agent-id + agent-secret format change
between v0.x and v1.0.0 — handled by forcing re-enrollment on
the affected dev installs.
