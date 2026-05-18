//go:build linux

package main

// Phase v1.0.2 WS-A — Linux service control via systemd.
//
// `systemctl list-units --type=service --all --plain --no-legend`
// gives one row per service; column 3 (active) maps to canonical
// state.
//
// SysV init / OpenRC are NOT supported in v1 — systemd-only is
// documented in AGENT-BACKLOG v1.1+ idea list.

import (
	"fmt"
	"os/exec"
	"strings"
)

func listServices() ([]Service, error) {
	out, err := exec.Command("systemctl",
		"list-units", "--type=service", "--all",
		"--plain", "--no-legend", "--no-pager").Output()
	if err != nil {
		return nil, fmt.Errorf("systemctl list-units: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	svcs := make([]Service, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		name := fields[0]
		// fields[1]=load (loaded/masked), [2]=active (active/inactive/failed)
		// [3]=sub (running/dead/exited), [4..]=description
		active := fields[2]
		sub := fields[3]
		desc := ""
		if len(fields) > 4 {
			desc = strings.Join(fields[4:], " ")
		}
		state := "unknown"
		switch active {
		case "active":
			if sub == "running" {
				state = "running"
			} else if sub == "exited" {
				state = "stopped"
			} else {
				state = sub
			}
		case "inactive":
			state = "stopped"
		case "failed":
			state = "failed"
		}
		// Startup type via `systemctl is-enabled <name>`. Spawning per-
		// service is too expensive; skip in v1 — surface "unknown".
		// v1.1 can batch-query.
		svcs = append(svcs, Service{
			Name:        strings.TrimSuffix(name, ".service"),
			DisplayName: desc,
			State:       state,
			StartupType: "unknown",
		})
	}
	return svcs, nil
}

func controlService(name, verb string) (string, error) {
	var systemdVerb string
	switch verb {
	case "start", "stop", "restart":
		systemdVerb = verb
	default:
		return "", fmt.Errorf("unknown verb %q", verb)
	}
	out, err := exec.Command("systemctl", systemdVerb, name).CombinedOutput()
	return string(out), err
}
