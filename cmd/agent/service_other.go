//go:build !windows

package main

import "fmt"

// Stubs for non-Windows builds. The install/uninstall/start/stop
// subcommands are Windows-only — Linux uses systemd (see ./systemd/).

func isWindowsService() bool { return false }

func runAsService() {
	fmt.Println("pcc2k-agent: --service is windows-only; use systemd on Linux")
}

func installService(args []string) error {
	return fmt.Errorf("install: windows-only (use systemd on Linux — see systemd/pcc2k-agent.service)")
}

func uninstallService() error {
	return fmt.Errorf("uninstall: windows-only (use systemctl disable on Linux)")
}

func startServiceCmd() error {
	return fmt.Errorf("start: windows-only (use systemctl start on Linux)")
}

func stopServiceCmd() error {
	return fmt.Errorf("stop: windows-only (use systemctl stop on Linux)")
}
