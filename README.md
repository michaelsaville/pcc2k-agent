# pcc2k-agent

The single Go binary that runs on every PCC2K-managed host and connects
outbound to the [WSS gateway](https://github.com/michaelsaville/pcc2k-gateway),
which in turn forwards FleetHub-owned namespaces to FleetHub and OpsHub-
owned namespaces to OpsHub. Wire spec lives in
[fleethub/docs/AGENT-PROTOCOL.md](../fleethub/docs/AGENT-PROTOCOL.md) —
this repo is the reference implementation of the client side.

**Status:** Phase 1 dev (2026-05-01). Linux + Windows. Ships
`agent.hello` → `session.proof` → `session.accept` handshake,
HMAC-signed `inventory.report` + `agent.heartbeat`. macOS and the
OpsHub namespaces (`ad.*`, `windows.services.*`) are deferred. The
Windows build runs as a console app today; the SCM-service wrapper +
DPAPI token storage + signed MSI land in Phase 1.5b.

## Build

No system Go required — build via Docker.

**Linux x86-64:**

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.22-alpine sh -c "
  go mod tidy && \
  CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags='-s -w' -o pcc2k-agent ./cmd/agent"
```

**Windows x86-64 (cross-compile from Linux/macOS):**

```bash
docker run --rm -v "$PWD:/src" -w /src \
  -e GOOS=windows -e GOARCH=amd64 -e CGO_ENABLED=0 \
  golang:1.22-alpine sh -c "
  go build -trimpath -buildvcs=false -ldflags='-s -w' -o pcc2k-agent.exe ./cmd/agent"
```

Both produce static stripped binaries (~5 MB). `-trimpath` and
`-buildvcs=false` make the build reproducible — running the same
command twice on the same source produces byte-identical output. Per
`fleethub/docs/HIPAA-READY.md` §4 this is mandatory; auditors can
verify the signed binary matches published source.

Or use the bundled helper:

```bash
./scripts/build.sh         # both targets
./scripts/build.sh linux   # just Linux
./scripts/build.sh windows # just Windows
```

## Run

**Linux:**

```bash
./pcc2k-agent \
  --gateway ws://127.0.0.1:3012/agent/v1 \
  --token   "$(grep ^GATEWAY_DEV_TOKEN ~/pcc2k-gateway/.env | cut -d= -f2)" \
  --agent-id  myhost-01 \
  --client    "Acme Clinic" \
  --hostname  myhost-01 \
  --role      workstation \
  --insecure                      # required while gateway speaks plain ws
```

**Windows (test box, no service wrapper yet):**

Copy `pcc2k-agent.exe` to the target host and run from an Administrator
PowerShell (registry reads for installed software need elevated
context to enumerate everything; non-admin works but misses HKLM
entries).

```powershell
.\pcc2k-agent.exe `
  --gateway "ws://gateway-host:3012/agent/v1" `
  --token   "<enrollment-token>" `
  --agent-id  "<op_agent-id>" `
  --client    "Test Tenant" `
  --hostname  "$env:COMPUTERNAME" `
  --role      workstation `
  --insecure
```

The Windows build collects inventory via PowerShell `Get-CimInstance`
(works back to PowerShell 5.1, the Win 10/11 baseline) plus direct
registry reads for installed-app enumeration. PS 7-only flags like
`ConvertTo-Json -AsArray` are deliberately avoided per the
`feedback_powershell_version_compat.md` rule.

Once mode (smoke test, single inventory.report then exit):

```bash
./pcc2k-agent --once ...           # same flags as above
.\pcc2k-agent.exe --once ...       # Windows
```

## Phase 1 dev shortcuts

- **No mTLS.** `--insecure` flag is required to dial `ws://`. Production
  uses `wss://` with mTLS, fronted by nginx vhost binding to
  `gateway.pcc2k.com` (open question §19).
- **Plain enrollment token.** Production stores the token in encrypted
  local cache (HIPAA-READY §1) and the OpsHub side uses
  `Op_Agent.proofKeyEnc` (column add tracked separately). Tonight every
  host sharing `GATEWAY_DEV_TOKEN` can connect.
- **Linux + Windows console mode.** macOS collectors deferred. Windows
  Service wrapper (golang.org/x/sys/windows/svc), DPAPI token storage,
  and signed MSI installer are tracked as Phase 1.5b — for testing
  outside clinical networks the unsigned exe runs fine; clinical
  deployment needs the Authenticode EV signature first per HIPAA spec.
- **No script execution.** Phase 2 adds `scripts.*` namespace + signed-
  script enforcement (HIPAA tenants).

## Sister projects

- [pcc2k-gateway](https://github.com/michaelsaville/pcc2k-gateway) —
  WSS termination + protocol enforcement
- [fleethub](https://github.com/michaelsaville/fleethub) — fleet/RMM
  console (consumer of `inventory.*`, `alert.*`)
- [opshub](https://github.com/michaelsaville/opshub) — identity console
  (future consumer of `ad.*`, `windows.services.*`)
