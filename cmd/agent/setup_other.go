//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// Linux: the same steps the /install/k/<key>/pcc2k-agent.sh script
// performs, for operators who copied the binary by hand. macOS is
// script-only for now (launchd plist lives in the script).
func setupInstall(o setupOptions) (string, error) {
	if runtime.GOOS != "linux" {
		return "", fmt.Errorf("setup is supported on Linux and Windows; on %s use the install script", runtime.GOOS)
	}
	if os.Geteuid() != 0 {
		return "", fmt.Errorf("run as root (sudo)")
	}
	res, err := enrollRequest(o.url, o.key)
	if err != nil {
		return "", fmt.Errorf("enroll: %w", err)
	}
	if res.GatewayURL == "" {
		return "", fmt.Errorf("server returned no gatewayUrl")
	}
	self, _ := os.Executable()
	bin := "/usr/local/bin/pcc2k-agent"
	if self != bin {
		_ = exec.Command("systemctl", "stop", "pcc2k-agent").Run()
		if err := exec.Command("install", "-m", "0755", self, bin).Run(); err != nil {
			return "", fmt.Errorf("install binary: %w", err)
		}
	}
	env := fmt.Sprintf("PCC2K_AGENT_ID=%s\nPCC2K_AGENT_TOKEN=%s\nPCC2K_FLEETHUB_AGENT_SECRET=%s\nPCC2K_FLEETHUB_URL=%s\nPCC2K_GATEWAY_URL=%s\nPCC2K_CLIENT_NAME=%s\n",
		res.AgentID, res.AgentSecret, res.AgentSecret, o.url, res.GatewayURL, res.TenantName)
	if err := os.WriteFile("/etc/pcc2k-agent.env", []byte(env), 0o600); err != nil {
		return "", fmt.Errorf("write env: %w", err)
	}
	unit := fmt.Sprintf("[Unit]\nDescription=pcc2k-agent (FleetHub managed)\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nEnvironmentFile=/etc/pcc2k-agent.env\nExecStart=%s\nRestart=on-failure\nRestartSec=10\nUser=root\n\n[Install]\nWantedBy=multi-user.target\n", bin)
	if err := os.WriteFile("/etc/systemd/system/pcc2k-agent.service", []byte(unit), 0o644); err != nil {
		return "", fmt.Errorf("write unit: %w", err)
	}
	for _, c := range [][]string{{"systemctl", "daemon-reload"}, {"systemctl", "enable", "--now", "pcc2k-agent"}, {"systemctl", "restart", "pcc2k-agent"}} {
		if out, err := exec.Command(c[0], c[1:]...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%v: %w (%s)", c, err, string(out))
		}
	}
	hn, _ := os.Hostname()
	return fmt.Sprintf("%s enrolled as %s (%s)", hn, res.AgentID, res.TenantName), nil
}

func setupReport(ok bool, msg string, _ bool) {
	if ok {
		fmt.Println("==> " + msg)
	} else {
		fmt.Fprintln(os.Stderr, "setup failed: "+msg)
	}
}
