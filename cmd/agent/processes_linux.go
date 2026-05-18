//go:build linux

package main

// Phase v1.0.2 WS-A — Linux process inventory via /proc.
//
// Cross-platform canonical schema (see processes.go) — caller never
// branches on OS. CPU% is single-core 0-100; first call returns null
// (sample warming up) until we have a stat_time delta.

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// cpu sample cache. CPU% requires a delta: (utime+stime now) vs
// (utime+stime then) over (clock-time-now - clock-time-then).
// First sample for a pid returns null in the API.
type cpuSample struct {
	at         time.Time
	totalTicks uint64
}

var (
	cpuSamplesMu sync.Mutex
	cpuSamples   = map[int]cpuSample{}
)

const clockTicksPerSec = 100 // _SC_CLK_TCK on linux/amd64

func collectProcesses() ([]Process, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("readdir /proc: %w", err)
	}
	pageSize := os.Getpagesize()
	bootTimeSec := readBootTime()
	now := time.Now()
	out := make([]Process, 0, 256)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		p, ok := readProcEntry(pid, pageSize, bootTimeSec, now)
		if !ok {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func readProcEntry(pid, pageSize int, bootTimeSec int64, now time.Time) (Process, bool) {
	base := "/proc/" + strconv.Itoa(pid)
	stat, err := os.ReadFile(filepath.Join(base, "stat"))
	if err != nil {
		return Process{}, false
	}
	statStr := string(stat)
	// /proc/<pid>/stat fields:
	//   pid (1) (comm) (2) state(3) ppid(4) ... utime(14) stime(15) ...
	//   starttime(22) ...
	// `comm` contains spaces + parens; split using the outer parens.
	openParen := strings.IndexByte(statStr, '(')
	closeParen := strings.LastIndexByte(statStr, ')')
	if openParen < 0 || closeParen < 0 || closeParen < openParen {
		return Process{}, false
	}
	name := statStr[openParen+1 : closeParen]
	rest := strings.Fields(statStr[closeParen+2:])
	if len(rest) < 22 {
		return Process{}, false
	}
	// rest[0] = state, rest[11]=utime (field 14 — index 14-3=11),
	// rest[12]=stime, rest[19]=starttime
	utime, _ := strconv.ParseUint(rest[11], 10, 64)
	stime, _ := strconv.ParseUint(rest[12], 10, 64)
	starttime, _ := strconv.ParseUint(rest[19], 10, 64)
	totalTicks := utime + stime

	// CPU% delta
	var cpuPct *float64
	cpuSamplesMu.Lock()
	prev, hadPrev := cpuSamples[pid]
	cpuSamples[pid] = cpuSample{at: now, totalTicks: totalTicks}
	cpuSamplesMu.Unlock()
	if hadPrev && now.Sub(prev.at) > 0 {
		ticksDelta := float64(totalTicks - prev.totalTicks)
		secDelta := now.Sub(prev.at).Seconds()
		pct := (ticksDelta / float64(clockTicksPerSec)) / secDelta * 100.0
		if pct >= 0 {
			cpuPct = &pct
		}
	}

	// RSS from /proc/<pid>/statm — field 2 = resident set in pages
	statm, err := os.ReadFile(filepath.Join(base, "statm"))
	rssMb := 0
	if err == nil {
		fields := strings.Fields(string(statm))
		if len(fields) >= 2 {
			pages, _ := strconv.ParseUint(fields[1], 10, 64)
			rssMb = int((pages * uint64(pageSize)) / (1024 * 1024))
		}
	}

	// User from /proc/<pid>/status Uid: line
	username := readProcUser(filepath.Join(base, "status"))

	// startedAt = bootTime + (starttime / CLK_TCK)
	startedAt := time.Unix(bootTimeSec+int64(starttime/clockTicksPerSec), 0).UTC()

	return Process{
		PID:       pid,
		Name:      name,
		User:      username,
		CPUPct:    cpuPct,
		RSSMb:     rssMb,
		StartedAt: startedAt.Format(time.RFC3339),
	}, true
}

func readProcUser(statusPath string) string {
	data, err := os.ReadFile(statusPath)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				u, err := user.LookupId(fields[1])
				if err == nil {
					return u.Username
				}
				return fields[1] // uid as fallback
			}
		}
	}
	return ""
}

var bootTimeOnce sync.Once
var bootTimeSec int64

func readBootTime() int64 {
	bootTimeOnce.Do(func() {
		data, err := os.ReadFile("/proc/stat")
		if err != nil {
			return
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "btime ") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					bootTimeSec, _ = strconv.ParseInt(fields[1], 10, 64)
				}
				return
			}
		}
	})
	return bootTimeSec
}
