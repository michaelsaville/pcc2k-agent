//go:build darwin

package main

// Phase v1.0.2 WS-A — macOS process inventory via `ps aux`.
//
// macOS hosts get fleet.processes capability (list) but NOT
// fleet.services capability (start/stop/restart). Operators see
// process tab on /devices/[id] but action buttons render disabled
// with tooltip — capability-gated cleanly.
// Cross-platform canonical schema (see processes.go).

import (
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectProcesses() ([]Process, error) {
	out, err := exec.Command("ps", "axo",
		"pid,user,%cpu,rss,lstart,comm").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) < 2 {
		return nil, nil
	}
	procs := make([]Process, 0, len(lines)-1)
	// Skip header (first line).
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			// lstart is "Mon May 18 12:34:56 2026" — 5 fields.
			// Minimum: pid user %cpu rss + 5 lstart + comm = 10.
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		username := fields[1]
		cpuStr := fields[2]
		rssKb, _ := strconv.Atoi(fields[3])
		// lstart spans 5 fields (Day Mon DD HH:MM:SS YYYY)
		lstartStr := strings.Join(fields[4:9], " ")
		// comm is the rest joined back together
		comm := strings.Join(fields[9:], " ")

		var cpuPct *float64
		if pct, err := strconv.ParseFloat(cpuStr, 64); err == nil {
			cpuPct = &pct
		}
		// Parse "Mon May 18 12:34:56 2026" into ISO8601.
		started := lstartStr
		if t, err := time.Parse("Mon Jan _2 15:04:05 2006", lstartStr); err == nil {
			started = t.UTC().Format(time.RFC3339)
		}

		procs = append(procs, Process{
			PID:       pid,
			Name:      comm,
			User:      username,
			CPUPct:    cpuPct,
			RSSMb:     rssKb / 1024,
			StartedAt: started,
		})
	}
	return procs, nil
}
