//go:build windows

package main

// Phase v1.0.2 WS-A — Windows process inventory via `tasklist /v /fo csv`.
//
// Direct golang.org/x/sys/windows enumeration is faster + safer but
// requires per-handle WTSGetActiveConsoleSessionId calls for the user
// resolution. tasklist parsed gives us the operator's view (user
// column, working set in K, started-at) in one shell-out at ~200ms.
// Cross-platform canonical schema (see processes.go).

import (
	"encoding/csv"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func collectProcesses() ([]Process, error) {
	out, err := exec.Command("tasklist", "/v", "/fo", "csv", "/nh").Output()
	if err != nil {
		return nil, err
	}
	reader := csv.NewReader(strings.NewReader(string(out)))
	reader.FieldsPerRecord = -1
	rows, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}
	// tasklist /v columns:
	//   0=Name 1=PID 2=Session 3=SessionNum 4=MemUsage 5=Status
	//   6=Username 7=CPUTime 8=WindowTitle
	out2 := make([]Process, 0, len(rows))
	for _, r := range rows {
		if len(r) < 8 {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(r[1]))
		if err != nil {
			continue
		}
		// MemUsage like "12,345 K"; strip non-digits.
		memDigits := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return r
			}
			return -1
		}, r[4])
		memKb, _ := strconv.Atoi(memDigits)
		rssMb := memKb / 1024
		// CPUTime like "0:00:12" — convert to seconds; agent reports
		// cpuPct null on first sample. tasklist doesn't give per-tick
		// snapshot; we can't compute delta from a one-shot. Leave null.
		out2 = append(out2, Process{
			PID:       pid,
			Name:      r[0],
			User:      r[6],
			CPUPct:    nil,
			RSSMb:     rssMb,
			StartedAt: time.Now().UTC().Format(time.RFC3339), // approximate; tasklist /v doesn't expose
		})
	}
	return out2, nil
}
