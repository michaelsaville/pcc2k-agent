#!/usr/bin/env bash
set -euo pipefail

# pcc2k-agent Unix bootstrap.
# Required env: PCC2K_BOOTSTRAP_TOKEN, PCC2K_FLEETHUB_URL
# Optional: PCC2K_INSTALL_DIR (default /usr/local/bin)
#           PCC2K_SECRET_PATH (default /var/lib/pcc2k-agent/secret)

if [ -z "\${PCC2K_BOOTSTRAP_TOKEN:-}" ]; then
  echo "PCC2K_BOOTSTRAP_TOKEN env var required" >&2
  exit 2
fi
if [ -z "\${PCC2K_FLEETHUB_URL:-}" ]; then
  echo "PCC2K_FLEETHUB_URL env var required" >&2
  exit 2
fi

INSTALL_DIR="\${PCC2K_INSTALL_DIR:-/usr/local/bin}"
SECRET_PATH="\${PCC2K_SECRET_PATH:-/var/lib/pcc2k-agent/secret}"
BIN_PATH="\$INSTALL_DIR/pcc2k-agent"

# Detect arch
ARCH=\$(uname -m)
OS=\$(uname -s | tr '[:upper:]' '[:lower:]')
case "\$OS-\$ARCH" in
  linux-x86_64)  PLATFORM="linux-amd64" ;;
  linux-aarch64) PLATFORM="linux-arm64" ;;
  darwin-x86_64) PLATFORM="darwin-amd64" ;;
  darwin-arm64)  PLATFORM="darwin-arm64" ;;
  *) echo "unsupported platform: \$OS-\$ARCH" >&2; exit 3 ;;
esac

echo "==> downloading pcc2k-agent (\$PLATFORM)"
curl -fsSL "\$PCC2K_FLEETHUB_URL/install/pcc2k-agent-\$PLATFORM" -o "\$BIN_PATH.new"
chmod 0755 "\$BIN_PATH.new"
mv "\$BIN_PATH.new" "\$BIN_PATH"

echo "==> enrolling with FleetHub"
mkdir -p "\$(dirname "\$SECRET_PATH")"
chmod 0700 "\$(dirname "\$SECRET_PATH")"

ENROLL_RESPONSE=\$(curl -fsSL -X POST \\
  -H 'content-type: application/json' \\
  -d "{\\"token\\": \\"\$PCC2K_BOOTSTRAP_TOKEN\\", \\"hostname\\": \\"\$(hostname)\\", \\"os\\": \\"\$OS\\", \\"osVersion\\": \\"\$(uname -r)\\"}" \\
  "\$PCC2K_FLEETHUB_URL/api/agent-ingest/enroll")

AGENT_ID=\$(echo "\$ENROLL_RESPONSE" | sed -n 's/.*"agentId":"\\([^"]*\\)".*/\\1/p')
AGENT_SECRET=\$(echo "\$ENROLL_RESPONSE" | sed -n 's/.*"agentSecret":"\\([^"]*\\)".*/\\1/p')

if [ -z "\$AGENT_ID" ] || [ -z "\$AGENT_SECRET" ]; then
  echo "enrollment failed:" >&2
  echo "\$ENROLL_RESPONSE" >&2
  exit 4
fi

# Write secret with restrictive perms BEFORE writing config.
umask 077
cat > "\$SECRET_PATH" <<EOF
PCC2K_AGENT_ID=\$AGENT_ID
PCC2K_FLEETHUB_AGENT_SECRET=\$AGENT_SECRET
PCC2K_FLEETHUB_URL=\$PCC2K_FLEETHUB_URL
EOF
chmod 0600 "\$SECRET_PATH"

echo "==> installing systemd unit"
cat > /etc/systemd/system/pcc2k-agent.service <<EOF
[Unit]
Description=pcc2k-agent (FleetHub managed)
After=network-online.target
Wants=network-online.target

[Service]
EnvironmentFile=\$SECRET_PATH
ExecStart=\$BIN_PATH
Restart=on-failure
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now pcc2k-agent
systemctl status pcc2k-agent --no-pager || true

echo "==> pcc2k-agent enrolled as \$AGENT_ID and started."
