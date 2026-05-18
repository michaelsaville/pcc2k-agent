//go:build darwin

package main

// Phase v1.0.2 WS-A — macOS launchctl list-only.
//
// LaunchAgent vs LaunchDaemon split (different `bootstrap` domains;
// gui/<uid> vs system) is its own design pass — punted to v1.1 per
// architect §4. macOS hosts get fleet.processes capability (list)
// via processes.go BUT NOT fleet.services capability for control.
//
// listServices() is implemented; controlService() returns
// unsupported-os because the fleet.services capability gating means
// the verb shouldn't reach us. Defense in depth.

import (
	"fmt"
	"os/exec"
	"strings"
)

func listServices() ([]Service, error) {
	out, err := exec.Command("launchctl", "list").Output()
	if err != nil {
		return nil, fmt.Errorf("launchctl list: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return nil, nil
	}
	// Header line: "PID    Status  Label"
	svcs := make([]Service, 0, len(lines)-1)
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// PID = "-" means not running.
		pid := fields[0]
		status := fields[1]
		label := strings.Join(fields[2:], " ")
		state := "stopped"
		if pid != "-" && pid != "" {
			state = "running"
		}
		if status != "0" && status != "-" {
			state = "failed"
		}
		svcs = append(svcs, Service{
			Name:        label,
			DisplayName: label,
			State:       state,
			StartupType: "unknown",
		})
	}
	return svcs, nil
}

func controlService(name, verb string) (string, error) {
	return "", fmt.Errorf("fleet.services.%s: unsupported on macOS in v1.0 "+
		"(LaunchAgent/LaunchDaemon split is v1.1+ territory)", verb)
}
