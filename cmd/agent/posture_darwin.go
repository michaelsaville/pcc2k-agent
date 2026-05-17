//go:build darwin

package main

// Phase 8 Workstream B step 2 — macOS posture detectors.
//
// Backup: Time Machine via `tmutil status` — the JSON-like output
// returns BackupPhase + DateOfLastBackup when a destination is
// configured. Parsing is keep-it-simple regex; the binary's
// output is stable across recent macOS releases.
//
// AV: macOS bundles XProtect by default but doesn't expose a
// scriptable enabled/disabled query. CrowdStrike / SentinelOne
// on Macs are detected by process-presence (TODO). For v1 the
// detector reports engine="none".
//
// FileVault: `fdesetup status` returns "FileVault is On."
// or "FileVault is Off."; mapped to bitlockerOn for now (the
// FleetHub column is named bitlockerOn for legacy reasons; it
// represents "system-volume encryption" on both OSes).

import (
	"regexp"
	"strings"
	"time"
)

func detectBackup() BackupReport {
	r := BackupReport{Product: "none"}
	out := runShell("tmutil", "status")
	if strings.TrimSpace(out) == "" {
		return r
	}
	// Output looks like:
	//   Backup session status:
	//   {
	//     BackupPhase = ThinningPostBackup;
	//     DateOfLastBackup = "2026-05-17 08:00:00";
	//     ...
	//   }
	r.Product = "macos-tm"
	re := regexp.MustCompile(`DateOfLastBackup\s*=\s*"([^"]+)"`)
	if m := re.FindStringSubmatch(out); len(m) > 1 {
		if t, err := time.ParseInLocation("2006-01-02 15:04:05", m[1], time.Local); err == nil {
			r.LastSuccessAt = rfc3339Ptr(t.UTC())
		}
	}
	return r
}

func detectAv() AvReport {
	r := AvReport{Engine: "none"}

	// FileVault → bitlockerOn. Re-used because the FH column is
	// the canonical "system-disk encryption on" signal.
	out := runShell("fdesetup", "status")
	if strings.Contains(out, "FileVault is On") {
		r.BitlockerOn = boolPtr(true)
	} else if strings.Contains(out, "FileVault is Off") {
		r.BitlockerOn = boolPtr(false)
	}

	return r
}
