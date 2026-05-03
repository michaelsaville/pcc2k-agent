//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows patch enumeration + apply + rollback.
//
// Detection methods (multi-signal per AGENT-PROTOCOL §23.2 / §12):
//   - wmi-qfe        Get-HotFix              KB list (cumulative-rollup blind)
//   - dism-packages  DISM /Get-Packages      package-level (catches rollups)
//   - wu-history     Windows Update history  what WU thinks
//
// Consensus rules:
//   all-yes        → patch is genuinely installed
//   all-no         → patch is genuinely missing
//   disagreement   → alert-worthy: "your dashboard is lying" event
//
// Scan via PSWindowsUpdate's Get-WindowsUpdate (PHASE-4-DESIGN §16 option b).
// Deploy via wusa.exe /quiet /norestart (KB packages) or DISM (cumulative
// rollups). Rollback strategies in order: wusa /uninstall /kb,
// dism /Remove-Package, restore-point Restore-Computer, vm-snapshot
// (operator pre-armed).

func scanInstalledPatches(methods []string, fullRescan bool) ([]map[string]interface{}, error) {
	// Get-WindowsUpdate is the canonical PSWindowsUpdate scan.
	// Falls back to wuapi.UpdateSearcher if PSWindowsUpdate isn't installed.
	out, err := runPS(`
		try {
			Import-Module PSWindowsUpdate -ErrorAction Stop
			Get-WindowsUpdate -MicrosoftUpdate |
				Select-Object KB, Title, Size, AutoSelectOnWebSites |
				ConvertTo-Json -Depth 3
		} catch {
			# Fallback: WUA COM API directly.
			$session = New-Object -ComObject Microsoft.Update.Session
			$searcher = $session.CreateUpdateSearcher()
			$result = $searcher.Search("IsInstalled=0 and Type='Software'")
			$result.Updates | ForEach-Object {
				[pscustomobject]@{
					KB    = ($_.KBArticleIDs -join ',')
					Title = $_.Title
					Size  = $_.MaxDownloadSize
				}
			} | ConvertTo-Json -Depth 3
		}
	`)
	if err != nil {
		return nil, err
	}

	// PSWindowsUpdate may emit a single object (not an array) when there's
	// exactly one available update. Coerce both shapes via the helper.
	var rows []struct {
		KB    string      `json:"KB"`
		Title string      `json:"Title"`
		Size  json.Number `json:"Size,omitempty"`
	}
	if err := unmarshalArrayOrSingle(out, &rows); err != nil {
		return nil, err
	}

	results := make([]map[string]interface{}, 0, len(rows))
	for _, r := range rows {
		kbList := r.KB
		// Some entries return "KB5036893" already; others "5036893" — normalize.
		if !strings.HasPrefix(strings.ToUpper(kbList), "KB") && kbList != "" {
			kbList = "KB" + kbList
		}
		results = append(results, map[string]interface{}{
			"source":         "ms",
			"sourceId":       kbList,
			"title":          r.Title,
			"size":           string(r.Size),
			"classification": classifyByTitle(r.Title),
		})
	}
	return results, nil
}

// runPatchDetection — used by patches.detect with a per-rule shape.
// On Windows we route by rule.kind; the multi-signal consensus is applied
// AFTER any single-method check for the patches-specific case below.
func runPatchDetection(rule json.RawMessage) (methods map[string]bool, consensus string) {
	// For a generic detection rule (msi-product-code etc.) reuse the
	// software detection runner; if rule is a `kb-list` shape, do
	// multi-signal here.
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(rule, &head); err != nil {
		return map[string]bool{}, "all-no"
	}
	if head.Kind == "kb-list" {
		var r struct {
			KbId string `json:"kbId"`
		}
		_ = json.Unmarshal(rule, &r)
		return multiSignalDetectKB(r.KbId)
	}
	present, _, _ := runDetectionRule(rule)
	methods = map[string]bool{head.Kind: present}
	if present {
		return methods, "all-yes"
	}
	return methods, "all-no"
}

func runPatchDetectionForPatch(p *patchRef) (map[string]bool, string) {
	if p.Source != "ms" {
		// Third-party patches use the same detection-rule machinery as software
		// (registry-uninstall-key / file-version / etc.) — handled elsewhere.
		return map[string]bool{}, "all-no"
	}
	return multiSignalDetectKB(p.SourceID)
}

func multiSignalDetectKB(kbId string) (map[string]bool, string) {
	methods := map[string]bool{
		"wmi-qfe":       false,
		"dism-packages": false,
		"wu-history":    false,
	}
	// Method 1: Get-HotFix
	if out, err := runPS(fmt.Sprintf(`Get-HotFix -Id %q -ErrorAction SilentlyContinue | Select-Object -First 1 | Out-String`, kbId)); err == nil {
		if strings.Contains(strings.ToLower(out), strings.ToLower(kbId)) {
			methods["wmi-qfe"] = true
		}
	}
	// Method 2: DISM /Get-Packages — slow; only run when wmi-qfe says no, OR
	// when the operator opted into multi-signal in scan params.
	if out, err := runPS(fmt.Sprintf(`dism /Online /Get-Packages /Format:Table 2>&1 | Select-String %q`, kbId)); err == nil {
		if strings.Contains(out, kbId) {
			methods["dism-packages"] = true
		}
	}
	// Method 3: Windows Update history
	if out, err := runPS(fmt.Sprintf(`
		$session = New-Object -ComObject Microsoft.Update.Session
		$searcher = $session.CreateUpdateSearcher()
		$count = $searcher.GetTotalHistoryCount()
		if ($count -gt 0) {
			$searcher.QueryHistory(0, $count) | Where-Object { $_.Title -match %q } | Select-Object -First 1 | Out-String
		}
	`, kbId)); err == nil {
		if strings.TrimSpace(out) != "" {
			methods["wu-history"] = true
		}
	}

	// Consensus.
	yes := 0
	for _, v := range methods {
		if v {
			yes++
		}
	}
	switch yes {
	case 3:
		return methods, "all-yes"
	case 0:
		return methods, "all-no"
	default:
		return methods, "disagreement"
	}
}

func execPatchDeploy(
	ctx context.Context,
	run *patchRun,
	params *patchDeployParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (exitCode int, exitMessage string) {
	if params.Patch.Source != "ms" {
		emit("stderr", "[agent] non-ms patches use software.* path on Windows\n")
		return -1, "wrong namespace"
	}

	kb := strings.TrimPrefix(strings.ToUpper(params.Patch.SourceID), "KB")

	// Strategy: Install-WindowsUpdate is the highest-fidelity path; fall back
	// to wusa.exe with the operator-supplied artifactUrl when PSWindowsUpdate
	// can't resolve the KB (rare).
	progress("downloading", "resolving KB"+kb, 25)
	psScript := fmt.Sprintf(`
		try {
			Import-Module PSWindowsUpdate -ErrorAction Stop
			Install-WindowsUpdate -KBArticleID %q -AcceptAll -IgnoreReboot -Confirm:$false -Verbose
		} catch {
			Write-Error "PSWindowsUpdate unavailable: $($_.Exception.Message)"
			exit 2
		}
	`, "KB"+kb)
	cmd := psCommandContext(ctx, psScript)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		return -1, err.Error()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go pipeToEmitWin(&wg, stdoutPipe, "stdout", emit)
	go pipeToEmitWin(&wg, stderrPipe, "stderr", emit)
	waitErr := cmd.Wait()
	wg.Wait()

	if ctx.Err() != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), ""
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		return exitErr.ExitCode(), waitErr.Error()
	}
	return -1, waitErr.Error()
}

func execPatchUninstall(
	ctx context.Context,
	run *patchRun,
	params *patchUninstallParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (strategyUsed string, exitCode int, exitMessage string) {
	kb := strings.TrimPrefix(strings.ToUpper(params.KbID), "KB")

	for i, strat := range params.Strategies {
		percent := 30 + (i*60)/max(1, len(params.Strategies))
		progress("installing", fmt.Sprintf("strategy %d/%d: %s", i+1, len(params.Strategies), strat), percent)
		switch strat {
		case "wusa":
			cmd := exec.CommandContext(ctx, "wusa.exe", "/uninstall", "/kb:"+kb, "/quiet", "/norestart")
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
			out, err := cmd.CombinedOutput()
			emit("stdout", string(out))
			if err == nil {
				return strat, 0, ""
			}
			emit("stderr", fmt.Sprintf("[wusa] %v\n", err))
		case "dism-remove-package":
			// Need the package name (Package_for_KB...) — DISM /Get-Packages then filter.
			ps := fmt.Sprintf(`
				$pkgs = dism /Online /Get-Packages /Format:Table | Select-String 'Package_for_KB%s_'
				$line = $pkgs[0]
				if ($line) {
					$name = ($line -split '\s+')[1]
					dism /Online /Remove-Package /PackageName:$name /Quiet /NoRestart
					exit $LASTEXITCODE
				}
				exit 1
			`, kb)
			cmd := psCommandContext(ctx, ps)
			cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
			out, err := cmd.CombinedOutput()
			emit("stdout", string(out))
			if err == nil {
				return strat, 0, ""
			}
			emit("stderr", fmt.Sprintf("[dism] %v\n", err))
		case "restore-point":
			emit("stderr", "[agent] restore-point rollback requires interactive Windows Recovery — operator-only\n")
			continue
		case "vm-snapshot":
			emit("stderr", "[agent] vm-snapshot rollback requires hypervisor-side action — operator-only\n")
			continue
		default:
			emit("stderr", fmt.Sprintf("[agent] unknown strategy %q\n", strat))
		}
	}
	return "", -1, "no strategy succeeded"
}

func runPS(script string) (string, error) {
	cmd := psCommand(script)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func psCommand(script string) *exec.Cmd {
	return exec.Command(`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-NoProfile", "-NonInteractive", "-Command", script)
}

func psCommandContext(ctx context.Context, script string) *exec.Cmd {
	return exec.CommandContext(ctx,
		`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"-NoProfile", "-NonInteractive", "-Command", script)
}

func unmarshalArrayOrSingle(s string, dst interface{}) error {
	t := strings.TrimSpace(s)
	if t == "" {
		return nil
	}
	if !strings.HasPrefix(t, "[") {
		t = "[" + t + "]"
	}
	return json.Unmarshal([]byte(t), dst)
}

func classifyByTitle(title string) string {
	low := strings.ToLower(title)
	switch {
	case strings.Contains(low, "definition"):
		return "definition"
	case strings.Contains(low, "cumulative"):
		return "rollup"
	case strings.Contains(low, "security"):
		return "security"
	case strings.Contains(low, "feature"):
		return "feature"
	case strings.Contains(low, "driver"):
		return "driver"
	}
	return "security"
}

// runPreflightGate — Windows-side checks. Disk space via win32, RAM via PerfCounter,
// service health via Get-Service.
func runPreflightGate(g *preflightGate) (string, bool) {
	if g.MinDiskSpaceGb > 0 {
		var freeBytes uint64
		if err := windows.GetDiskFreeSpaceEx(
			windows.StringToUTF16Ptr(`C:\`),
			&freeBytes, nil, nil,
		); err == nil {
			if freeBytes/(1024*1024*1024) < uint64(g.MinDiskSpaceGb) {
				return "minDiskSpaceGb", false
			}
		}
	}
	if g.RequireNoPendingReboot && checkRebootPending() {
		return "requireNoPendingReboot", false
	}
	// MaxRamPercent / RequireBackupWithinHours / RequireServiceHealth /
	// RespectMaintenanceMode / CustomPreflightScriptId — Phase 4.5.
	return "", true
}

func checkRebootPendingPlatform() bool {
	// Same as the software_windows.go helper; aliased for symmetry across
	// patches.go's emit-complete signature.
	return checkRebootPending()
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// pipeToEmitWin: Windows-flavored chunk reader. Same behavior as the Unix
// pipeToEmit; named differently to avoid a build-constraint collision with
// the symmetric function declared in software_windows.go (both files use
// the //go:build windows constraint, so declaring the same name twice
// would compile-fail).
func pipeToEmitWin(wg *sync.WaitGroup, r io.Reader, name string, emit func(stream, chunk string)) {
	defer wg.Done()
	br := bufio.NewReaderSize(r, outputFrameMaxBytes)
	buf := make([]byte, 0, outputFrameMaxBytes)
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			buf = append(buf, chunk...)
			if len(buf) >= outputFrameMaxBytes/2 || (err == nil && chunk[len(chunk)-1] == '\n') {
				emit(name, string(buf))
				buf = buf[:0]
			}
		}
		if err != nil {
			if len(buf) > 0 {
				emit(name, string(buf))
			}
			return
		}
	}
}

// Suppress unused-import compile error when registry isn't referenced
// elsewhere in this file. (We touch it indirectly via checkRebootPending.)
var _ = registry.LOCAL_MACHINE
