# pcc2k-agent

The single Go binary that runs on every PCC2K-managed host and connects
outbound to the [WSS gateway](https://github.com/michaelsaville/pcc2k-gateway),
which in turn forwards FleetHub-owned namespaces to FleetHub and OpsHub-
owned namespaces to OpsHub. Wire spec lives in
[fleethub/docs/AGENT-PROTOCOL.md](../fleethub/docs/AGENT-PROTOCOL.md) —
this repo is the reference implementation of the client side.

**Status:** Phase 1 dev (2026-05-01). Linux-only. Ships
`agent.hello` → `session.proof` → `session.accept` handshake,
HMAC-signed `inventory.report` + `agent.heartbeat`. macOS, Windows,
and the OpsHub namespaces (`ad.*`, `windows.services.*`) are deferred.

## Build

No system Go required — build via Docker:

```bash
docker run --rm -v "$PWD:/src" -w /src golang:1.22-alpine \
  sh -c "go mod tidy && CGO_ENABLED=0 go build -ldflags='-s -w' -o pcc2k-agent ./cmd/agent"
```

Produces a static stripped Linux x86-64 binary (~5 MB).

## Run

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

Once mode (smoke test, single inventory.report then exit):

```bash
./pcc2k-agent --once ...
```

## Phase 1 dev shortcuts

- **No mTLS.** `--insecure` flag is required to dial `ws://`. Production
  uses `wss://` with mTLS, fronted by nginx vhost binding to
  `gateway.pcc2k.com` (open question §19).
- **Plain enrollment token.** Production stores the token in encrypted
  local cache (HIPAA-READY §1) and the OpsHub side uses
  `Op_Agent.proofKeyEnc` (column add tracked separately). Tonight every
  host sharing `GATEWAY_DEV_TOKEN` can connect.
- **Linux only.** macOS and Windows collectors are placeholders. Targets
  for Phase 1.5.
- **No script execution.** Phase 2 adds `scripts.*` namespace + signed-
  script enforcement (HIPAA tenants).

## Sister projects

- [pcc2k-gateway](https://github.com/michaelsaville/pcc2k-gateway) —
  WSS termination + protocol enforcement
- [fleethub](https://github.com/michaelsaville/fleethub) — fleet/RMM
  console (consumer of `inventory.*`, `alert.*`)
- [opshub](https://github.com/michaelsaville/opshub) — identity console
  (future consumer of `ad.*`, `windows.services.*`)
