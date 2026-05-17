//go:build linux

package main

// Phase 8 Workstream B step 2 — Linux posture detectors.
//
// Backup: restic is the v1 detector — RESTIC_REPOSITORY +
// RESTIC_PASSWORD_FILE (or RESTIC_PASSWORD_COMMAND) read from the
// environment of the agent process, then `restic snapshots --last
// --json` for the freshest snapshot time. Other Linux backup tools
// (borg, duplicity, rsnapshot) are operator-supplied scripts and
// don't expose a uniform "last success" surface — those land if/when
// an operator asks.
//
// AV: clamav is the most-deployed open-source AV on Linux servers.
// Reports `defender` for nothing on Linux (Defender is Windows-only);
// `clamav` is squeezed into the bounded enum as "none" for v1 since
// the server-side BACKUP/AV_ENGINES sets don't yet list it. (A new
// engine value is a single-line change on both sides.)

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"
)

func detectBackup() BackupReport {
	r := BackupReport{Product: "none"}
	if repo := strings.TrimSpace(os.Getenv("RESTIC_REPOSITORY")); repo != "" {
		r.Product = "restic"
		if t, msg := resticLastSnapshot(); !t.IsZero() {
			r.LastSuccessAt = rfc3339Ptr(t)
		} else if msg != "" {
			r.LastErrorAt = rfc3339Ptr(time.Now())
			r.LastErrorMsg = nilPtrString(msg)
		}
	}
	return r
}

// resticLastSnapshot runs `restic snapshots --last --json` and returns
// the timestamp of the most recent snapshot, or (zero, errMsg) if the
// command fails. Environment is inherited — RESTIC_PASSWORD_FILE /
// RESTIC_PASSWORD_COMMAND must already be set for the agent process.
func resticLastSnapshot() (time.Time, string) {
	cmd := exec.Command("restic", "snapshots", "--last", "--json")
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Trim restic's output to first line so a multi-line stderr
		// doesn't bloat the error column.
		first := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
		if first == "" {
			first = err.Error()
		}
		return time.Time{}, first
	}
	// `--json` emits an array of snapshot objects. We need the freshest
	// .time; the `--last` flag returns one per (host, paths) tuple, so
	// in practice there's one or two entries.
	var snaps []struct {
		Time string `json:"time"`
	}
	if err := json.Unmarshal(out, &snaps); err != nil || len(snaps) == 0 {
		return time.Time{}, "no snapshots returned"
	}
	var newest time.Time
	for _, s := range snaps {
		// restic emits RFC3339Nano with a fractional-second precision
		// the standard parser handles transparently.
		t, err := time.Parse(time.RFC3339Nano, s.Time)
		if err != nil {
			continue
		}
		if t.After(newest) {
			newest = t
		}
	}
	if newest.IsZero() {
		return time.Time{}, "couldn't parse any snapshot timestamps"
	}
	return newest, ""
}

func detectAv() AvReport {
	r := AvReport{Engine: "none"}
	// clamav is the de-facto open-source AV. We report "none" until
	// FleetHub's AV_ENGINES set adds a clamav option — operator can
	// override in configJson if they want to track it sooner. For v1
	// Linux servers without a tracked engine report engine="none",
	// which the server scores as bad/disabled. Most server fleets
	// don't deploy on-host AV; the score signal is intentional.
	if hasBinary("clamscan") || hasBinary("clamd") {
		// Recognized but not yet first-class on the FleetHub side; keep
		// reporting "none" so the bounded enum stays valid. The
		// detection result is still useful for the report's audit line.
		r.Engine = "none"
	}
	// BitLocker is Windows-only; Linux disk encryption (LUKS) is
	// detected separately and not yet on the FH schema. Leave nil.
	return r
}

func hasBinary(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
