//go:build windows

package main

// Phase v1.0.2 WS-B — Microsoft Defender invocation matrix.
//
// AGENT-PROTOCOL §24: av.cancel MUST invoke Stop-MpScan (NOT process
// kill). Defender scans run inside MsMpEng.exe; killing the agent's
// child PowerShell does NOT stop the scan.
//
// Get-MpComputerStatus is the universal "is Defender installed and
// active" probe. If it errors or returns AMRunningMode = "Not running"
// the capability is not advertised.

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// defenderPresent — capability probe. Cached 60s via detect_cache.go
// when called from capabilities.go.
func defenderPresent() bool {
	out, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
		"-Command",
		"$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "+
			"if ($s -and $s.AMServiceEnabled) { 'yes' } else { 'no' }").Output()
	if err != nil {
		return false
	}
	return strings.TrimSpace(string(out)) == "yes"
}

// defenderScan — Start-MpScan with quick / full / custom kinds.
// Long-running; agent's runAvScan goroutine emits av.action-complete
// when this returns.
func defenderScan(ctx context.Context, kind, scanPath string) (state, output string, err error) {
	var args []string
	switch kind {
	case "quick":
		args = []string{"-NoLogo", "-NoProfile", "-Command",
			"Start-MpScan -ScanType QuickScan"}
	case "full":
		args = []string{"-NoLogo", "-NoProfile", "-Command",
			"Start-MpScan -ScanType FullScan"}
	case "custom":
		// scanPath validated upstream in av.go handler.
		// Escape single quotes for PowerShell.
		safe := strings.ReplaceAll(scanPath, "'", "''")
		args = []string{"-NoLogo", "-NoProfile", "-Command",
			fmt.Sprintf("Start-MpScan -ScanType CustomScan -ScanPath '%s'", safe)}
	default:
		return "failed", "", fmt.Errorf("unknown scan kind %q", kind)
	}
	cmd := exec.CommandContext(ctx, "powershell.exe", args...)
	rawOut, runErr := cmd.CombinedOutput()
	output = string(rawOut)
	if ctx.Err() == context.Canceled {
		return "cancelled", output, nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "failed", output, fmt.Errorf("scan exceeded timeout")
	}
	if runErr != nil {
		return "failed", output, runErr
	}
	return "ok", output, nil
}

// defenderUpdateDefs — Update-MpSignature. ~5-30s typical.
func defenderUpdateDefs(ctx context.Context) (state, output string, err error) {
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo", "-NoProfile", "-Command", "Update-MpSignature")
	rawOut, runErr := cmd.CombinedOutput()
	output = string(rawOut)
	if runErr != nil {
		return "failed", output, runErr
	}
	return "ok", output, nil
}

// defenderQuarantine — Add-MpThreat by ThreatID. v1 limitation:
// can only quarantine items Defender has ALREADY identified-and-
// skipped (the ThreatID arg comes from Get-MpThreat). Arbitrary
// operator-chosen file paths are not supported — that's a different
// Defender API (Set-MpPreference -QuarantinePurgeItemsAfterDelay
// route).
func defenderQuarantine(threatID string) (state, output string, err error) {
	// Get the threat, then quarantine via remove-mpthreat -ID.
	safe := strings.ReplaceAll(threatID, "'", "''")
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
		"-Command",
		fmt.Sprintf("Remove-MpThreat -ThreatID '%s'", safe))
	rawOut, runErr := cmd.CombinedOutput()
	output = string(rawOut)
	if runErr != nil {
		return "failed", output, runErr
	}
	return "ok", output, nil
}

// defenderRelease — Restore-MpThreat by ThreatID. Releases from quarantine.
func defenderRelease(threatID string) (state, output string, err error) {
	safe := strings.ReplaceAll(threatID, "'", "''")
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
		"-Command",
		fmt.Sprintf("Restore-MpThreat -ThreatID '%s'", safe))
	rawOut, runErr := cmd.CombinedOutput()
	output = string(rawOut)
	if runErr != nil {
		return "failed", output, runErr
	}
	return "ok", output, nil
}

// defenderCancelScan — Stop-MpScan. CRITICAL per AGENT-PROTOCOL §24:
// this is the ONLY correct cancel verb. The agent's context-cancel
// kills the agent's child powershell.exe but Defender keeps scanning
// inside MsMpEng.exe service process.
func defenderCancelScan() error {
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
		"-Command", "Stop-MpScan")
	_, err := cmd.CombinedOutput()
	return err
}

// Static guard against drift — unused-import doesn't survive go vet,
// so this keeps json package referenced for future serialization
// additions without forcing a runtime check.
var _ = json.Marshal
