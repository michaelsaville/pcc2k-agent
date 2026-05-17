//go:build windows

package main

// Phase 8 Workstream B step 2 — Windows posture detectors.
//
// Backup: Windows Server Backup (wbadmin) is the in-box option.
// Latest success comes from `Get-WBSummary` (PowerShell). v1 only
// detects wbadmin / Get-WBSummary; Veeam/Datto agents on Windows
// boxes are detected by registry / Get-Service presence (TODO).
//
// AV/EDR: Microsoft Defender via Get-MpComputerStatus. The cmdlet
// returns AntivirusEnabled, RealTimeProtectionEnabled, and
// AntivirusSignatureLastUpdated. CrowdStrike / SentinelOne / Sophos
// are detected via Win32_Service presence in a follow-up cut.
//
// BitLocker: Get-BitLockerVolume against the system drive (C:).

import (
	"encoding/json"
	"strings"
	"time"
)

func detectBackup() BackupReport {
	r := BackupReport{Product: "none"}

	// Windows Server Backup detection. Get-WBSummary returns nothing
	// on workstations / hosts where the role isn't installed. The
	// cmdlet exists on Server SKUs only; on Pro / Home it ErrorActions.
	type wbSummary struct {
		LastSuccessfulBackupTime  string `json:"LastSuccessfulBackupTime"`
		LastBackupResultHR        int    `json:"LastBackupResultHR"`
		LastBackupTime            string `json:"LastBackupTime"`
		LastBackupResultDetailedHR int    `json:"LastBackupResultDetailedHR"`
	}
	const wbScript = `
		try {
		  $s = Get-WBSummary -ErrorAction Stop
		  $s | Select-Object LastSuccessfulBackupTime, LastBackupResultHR, LastBackupTime, LastBackupResultDetailedHR | ConvertTo-Json -Compress
		} catch { "" }
	`
	out := powershellOut(wbScript)
	if strings.TrimSpace(out) != "" {
		var summary wbSummary
		if err := json.Unmarshal([]byte(out), &summary); err == nil {
			r.Product = "windows-backup"
			if t := parseDotNetDate(summary.LastSuccessfulBackupTime); !t.IsZero() {
				r.LastSuccessAt = rfc3339Ptr(t)
			}
			if summary.LastBackupResultHR != 0 {
				if t := parseDotNetDate(summary.LastBackupTime); !t.IsZero() {
					r.LastErrorAt = rfc3339Ptr(t)
				}
				r.LastErrorMsg = nilPtrString(
					"WBSummary HR=" + intToStr(summary.LastBackupResultHR) +
						" Detailed=" + intToStr(summary.LastBackupResultDetailedHR),
				)
			}
		}
	}

	return r
}

func detectAv() AvReport {
	r := AvReport{Engine: "none"}

	// Defender via Get-MpComputerStatus. Falls back silently when
	// the cmdlet is missing (older Server SKUs without the MpProvider).
	type mp struct {
		AntivirusEnabled                  bool   `json:"AntivirusEnabled"`
		RealTimeProtectionEnabled         bool   `json:"RealTimeProtectionEnabled"`
		AntivirusSignatureLastUpdated     string `json:"AntivirusSignatureLastUpdated"`
		AntivirusSignatureLastUpdatedDate string `json:"AntivirusSignatureLastUpdatedDate"`
	}
	const mpScript = `
		try {
		  $m = Get-MpComputerStatus -ErrorAction Stop
		  $m | Select-Object AntivirusEnabled, RealTimeProtectionEnabled, AntivirusSignatureLastUpdated, AntivirusSignatureLastUpdatedDate | ConvertTo-Json -Compress
		} catch { "" }
	`
	out := powershellOut(mpScript)
	if strings.TrimSpace(out) != "" {
		var m mp
		if err := json.Unmarshal([]byte(out), &m); err == nil {
			r.Engine = "defender"
			r.Enabled = boolPtr(m.AntivirusEnabled && m.RealTimeProtectionEnabled)
			if t := parseDotNetDate(coalesceStr(m.AntivirusSignatureLastUpdated, m.AntivirusSignatureLastUpdatedDate)); !t.IsZero() {
				r.SignaturesAt = rfc3339Ptr(t)
			}
		}
	}

	// BitLocker — C: drive only. ProtectionStatus=1 means On; 0 Off.
	const blScript = `
		try {
		  $v = Get-BitLockerVolume -MountPoint "C:" -ErrorAction Stop
		  $v.ProtectionStatus
		} catch { "" }
	`
	switch strings.TrimSpace(powershellOut(blScript)) {
	case "1", "On":
		r.BitlockerOn = boolPtr(true)
	case "0", "Off":
		r.BitlockerOn = boolPtr(false)
	}

	return r
}

// parseDotNetDate accepts both ISO-8601 (most modern PowerShell
// ConvertTo-Json output) and the legacy `/Date(1234567890)/` format
// .NET emits when the cmdlet returns a DateTime directly.
func parseDotNetDate(s string) time.Time {
	s = strings.Trim(s, `" `)
	if s == "" {
		return time.Time{}
	}
	if strings.HasPrefix(s, "/Date(") {
		// Format: /Date(1700000000000)/ — ms since epoch.
		mid := strings.TrimPrefix(s, "/Date(")
		mid = strings.TrimSuffix(mid, ")/")
		// Strip optional timezone suffix /Date(168...000+0500)/
		if i := strings.IndexAny(mid, "+-"); i > 0 {
			mid = mid[:i]
		}
		if ms, err := strToInt64(mid); err == nil {
			return time.Unix(ms/1000, (ms%1000)*1_000_000).UTC()
		}
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func intToStr(i int) string {
	// fmt.Sprintf("%d", i) would pull fmt — keep this file dep-light
	// since it's already imported in main.
	return _itoa(i)
}

func _itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func strToInt64(s string) (int64, error) {
	// Tiny ascii parser to avoid importing strconv just for this.
	var n int64
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
	}
	for _, c := range []byte(s) {
		if c < '0' || c > '9' {
			return 0, errInvalidNumber
		}
		n = n*10 + int64(c-'0')
	}
	if neg {
		n = -n
	}
	return n, nil
}

var errInvalidNumber = &dateError{"not a number"}

type dateError struct{ msg string }

func (e *dateError) Error() string { return e.msg }

func coalesceStr(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

// powershellOut runs a snippet through powershell.exe with a single
// argument. Returns trimmed stdout; "" on any error.
func powershellOut(script string) string {
	return runShell("powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script)
}
