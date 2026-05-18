# pcc2k-agent Operator Runbook

**Audience:** field technicians and on-call operators who install,
update, troubleshoot, or remove pcc2k-agent on customer endpoints.

This is the v1.0 release contract. The agent has 1 binary per OS,
1 environment file, and 1 service unit. Nothing else. If you find
yourself touching anything outside this document on a real host,
stop and escalate.

---

## 1. What the agent is

A single Go-compiled binary that connects to FleetHub via a WSS
gateway and exposes a fixed verb namespace (see
`docs/AGENT-PROTOCOL.md`). The agent does NOT run scheduled jobs on
its own — every action is a server-initiated JSON-RPC call. The
agent's only autonomous behavior is the posture loop (heartbeat
every 60s, capability re-advertise on change).

Per-platform install layout:

| Platform | Binary path | Env file | Service |
|----------|-------------|----------|---------|
| Linux    | `/usr/local/bin/pcc2k-agent` | `/etc/pcc2k-agent/agent.env` | systemd `pcc2k-agent.service` |
| Windows  | `C:\Program Files\pcc2k-agent\pcc2k-agent.exe` | `C:\ProgramData\pcc2k-agent\agent.env` | Windows Service `pcc2k-agent` |
| macOS    | `/usr/local/bin/pcc2k-agent` | `/etc/pcc2k-agent/agent.env` | launchd `com.pcc2k.agent` |

`agent.env` is `chmod 600` root-owned. It contains the WSS URL,
agent ID, and agent secret. Do not check it into git, sync it to a
backup that escapes the host, or paste it into a chat. Rotating
the secret is a 2-step API call documented in §7.

---

## 2. Install (first-time)

Operators run `scripts/bootstrap.sh` (linux/mac) or
`scripts/bootstrap.ps1` (windows) on the target host. Both scripts:

1. Prompt for the FleetHub URL and the one-time bootstrap token
   (the FleetHub `/clients/[name]/install` page generates a token
   good for 15 minutes).
2. Download the platform-correct binary from
   `https://fleethub.pcc2k.com/install/pcc2k-agent-{platform}`
   (signed against the manifest at `/install/agent-manifest.json`).
3. Call `pcc2k-agent --bootstrap-token=<TOKEN>
   --fleethub-url=<URL>` which POSTs `/api/agent-ingest/enroll` and
   prints back the agentId + agentSecret in env-file format.
4. Write `agent.env` with `chmod 600 root:root`.
5. Install the appropriate service unit and enable+start it.

On success the agent is online inside ~10 seconds. FleetHub
`/clients/[name]/devices` shows the new device with a green dot.

If bootstrap exits non-zero, the script leaves no partial install
behind — `/etc/pcc2k-agent/` is empty and no service is registered.
Read stderr for the exact failure (most common: clock skew vs
FleetHub > 5min, or HTTPS cert untrusted on RHEL/Alma derivatives
where the CA bundle is stale).

---

## 3. Update (binary swap, no re-enroll)

The agentId + secret survive a binary update — only the on-disk
executable changes.

**Linux/macOS:**
```bash
systemctl stop pcc2k-agent
curl -fsSLo /usr/local/bin/pcc2k-agent \
  https://fleethub.pcc2k.com/install/pcc2k-agent-linux
chmod 755 /usr/local/bin/pcc2k-agent
systemctl start pcc2k-agent
```

**Windows (PowerShell as admin):**
```powershell
Stop-Service pcc2k-agent
Invoke-WebRequest -OutFile "C:\Program Files\pcc2k-agent\pcc2k-agent.exe" `
  -Uri "https://fleethub.pcc2k.com/install/pcc2k-agent-windows"
Start-Service pcc2k-agent
```

After update, verify version on the device record (FleetHub
`/clients/[name]/devices/[id]` shows `agentVersion` updated from
the next posture beacon, usually within 60s).

In v1.0 there is no in-place self-update mechanism. Phase v1.1 will
add `agent.update` as a server-initiated verb gated on signed
manifest + 4-eyes approval.

---

## 4. Uninstall

The bootstrap scripts ship a companion `uninstall.sh` /
`uninstall.ps1` that:
- stops + disables the service,
- removes the binary,
- removes `agent.env` and the service unit,
- POSTs `/api/agent-ingest/revoke` to mark the agentId revoked in
  FleetHub (so the device shows as decommissioned, not just
  offline).

Run uninstall when retiring or wiping a host. Do NOT just stop the
service — FleetHub will continue to alert on the device as offline.

---

## 5. Diagnostic verbs (read-only)

Every verb below is safe to call from the FleetHub device page
without affecting the host. They're free of side effects.

| Verb | What it returns |
|------|-----------------|
| `agent.hello` | Capability list + version + OS string |
| `agent.ping` | Round-trip latency |
| `inventory.snapshot` | Full hw/sw inventory snapshot |
| `fleet.processes.list` | Process table with cursor pagination |
| `fleet.services.list` | systemd / Windows service list |
| `fleet.av.status` | Defender posture (Windows only) |
| `backup.status` | Backup product detection |

If you can call `agent.hello` and see a recent timestamp, the
agent is online and the gateway is healthy. If you can't,
proceed to §6.

---

## 6. Troubleshooting

**Symptom: device shows offline in FleetHub.**

1. Check the service is running.
   - Linux: `systemctl status pcc2k-agent --no-pager`
   - Windows: `Get-Service pcc2k-agent`
2. Tail the logs.
   - Linux: `journalctl -u pcc2k-agent -n 200 --no-pager`
   - Windows: `Get-EventLog -LogName Application -Source pcc2k-agent -Newest 50`
3. Common causes:
   - **Clock skew > 5min:** sync with `chronyc makestep` or
     `w32tm /resync`. The WSS handshake rejects skewed
     certificates.
   - **Proxy/firewall:** the agent dials
     `wss://fleethub.pcc2k.com/agent-ws` over TCP 443. Some
     corporate proxies break long-lived WSS connections — set
     `HTTPS_PROXY` in `agent.env` to point at the corporate proxy.
   - **Stale CA bundle:** `update-ca-trust` (RHEL) or
     `update-ca-certificates` (Debian).
   - **Revoked agent:** if `/api/agent-ingest/heartbeat` returns
     410, the device was deactivated in FleetHub. Re-enroll.

**Symptom: agent online but verb returns error.**

Check the `data.code` in the JSON-RPC error envelope.
`-32070` = response-too-large (rare; expect on huge process tables
with >10k entries — operator should narrow the filter).
`-32071` = cursor-expired (the device rebooted or restarted the
agent between page fetches; restart from page 1).
`-32601` = unknown method (agent on an older version than FleetHub
expects; update the agent per §3).

**Symptom: high CPU from agent.**

The agent itself is steady-state ~3MB RSS and <1% CPU. If you see
>50% CPU, it's almost certainly a verb invocation in flight (AV
scan, big inventory). Check `fleet.av.cancel` if a scan is hung.

---

## 7. Secret rotation

If the agentSecret in `agent.env` is suspected compromised:

1. In FleetHub UI: `/clients/[name]/devices/[id]` → **Rotate
   secret**. This issues a new secret valid for 15 minutes for the
   operator to apply.
2. SSH to the host, write the new secret into `agent.env`,
   `systemctl restart pcc2k-agent`.
3. Confirm the device shows the next heartbeat within 60s.

The old secret is invalidated server-side the moment the new one
is generated. There is no rollback. Don't lose the new secret
between step 1 and step 2 — there's no recovery short of
re-enroll.

---

## 8. Cross-platform reference

| Concern | Linux | Windows | macOS |
|---------|-------|---------|-------|
| Logs | `journalctl -u pcc2k-agent` | Event Viewer: Application / pcc2k-agent | `log show --predicate 'subsystem=="com.pcc2k.agent"'` |
| Restart | `systemctl restart pcc2k-agent` | `Restart-Service pcc2k-agent` | `launchctl kickstart -k system/com.pcc2k.agent` |
| `fleet.services.*` control | systemd (full) | Windows Service Manager (full) | NOT advertised — list only |
| `fleet.av.*` control | NOT advertised | Defender via PowerShell | NOT advertised |
| `backup.*` detection | borg/restic/rsync | Veeam/wbadmin/Acronis | TimeMachine |
| `file.*` (Phase v1.0.0) | Available | Available | Available |
| `shell.*` (Phase v1.0.0) | bash | PowerShell | zsh |

Capability advertisement is per-host. If `fleet.av` isn't in the
hello's capabilities array for a given device, the FleetHub UI
won't show the AV tab for that device — no 502 on click.

---

## 9. Escalation

If anything in this runbook didn't resolve the issue:

1. Capture the output of `pcc2k-agent --version` and the last 200
   lines of the agent log.
2. File against `pcc2k-agent` repo issues with the exact device id
   from FleetHub.
3. For production outages: page on-call via the on-call schedule
   in FleetHub `/oncall` (Phase 7 WS-A escalation routing).

Do NOT delete `agent.env` or reinstall the agent as a first
response — most "offline" symptoms are environmental (clock,
proxy, CA) and re-enroll loses the per-host alert history.
