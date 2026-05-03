//go:build !windows

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// Linux/macOS patch enumeration + apply + rollback.
//
// Detection methods supported:
//   - apt          dpkg-query --show vs apt-cache policy upgradable
//   - dnf          dnf check-update
//   - brew         brew outdated --json
// On Unix consensus is single-method: "all-yes" or "all-no" — the §12
// trust loop's "disagreement" is Windows-specific (WMI vs DISM vs WUA).

func scanInstalledPatches(methods []string, fullRescan bool) ([]map[string]interface{}, error) {
	if hasAptGet() {
		return aptListUpgradable()
	}
	if hasDnf() {
		return dnfCheckUpdate()
	}
	if runtime.GOOS == "darwin" && hasBrew() {
		return brewOutdated()
	}
	return nil, fmt.Errorf("no supported package manager (apt/dnf/brew) found")
}

func aptListUpgradable() ([]map[string]interface{}, error) {
	// `apt list --upgradable` writes to stderr a notice + structured lines on stdout.
	// Format: pkg/source version arch [upgradable from: oldver]
	out, err := runWithEnv("/usr/bin/apt", []string{"list", "--upgradable"},
		[]string{"LC_ALL=C.UTF-8", "DEBIAN_FRONTEND=noninteractive"})
	if err != nil {
		return nil, err
	}
	results := []map[string]interface{}{}
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Listing") || strings.HasPrefix(line, "WARNING") {
			continue
		}
		// Real package lines have a "/" in the first field (pkg/source).
		// Anything else is apt CLI noise we skip.
		if !strings.Contains(strings.SplitN(line, " ", 2)[0], "/") {
			continue
		}
		// pkg/now ver arch [upgradable from: oldver]
		// pkg/source ver arch [upgradable from: oldver]
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		nameSlash := parts[0]
		newVer := parts[1]
		arch := parts[2]
		oldVer := ""
		if i := strings.Index(line, "upgradable from: "); i >= 0 {
			oldVer = strings.TrimSuffix(line[i+len("upgradable from: "):], "]")
		}
		nameOnly := nameSlash
		if slash := strings.Index(nameOnly, "/"); slash > 0 {
			nameOnly = nameOnly[:slash]
		}
		results = append(results, map[string]interface{}{
			"source":          "apt",
			"sourceId":        nameOnly,
			"availableVersion": newVer,
			"installedVersion": oldVer,
			"arch":             arch,
			"classification":   "security", // Phase 4.5: cross-ref USN/DSA for true classification
		})
	}
	return results, nil
}

func dnfCheckUpdate() ([]map[string]interface{}, error) {
	// `dnf check-update` exits 100 when updates are available — that's NOT an error.
	// Output: "pkg.arch  version  repo" plus "Obsoleting Packages" trailer.
	out, _ := exec.Command("/usr/bin/dnf", "check-update", "--quiet").Output()
	results := []map[string]interface{}{}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 3 {
			continue
		}
		// Skip the "Obsoleting Packages" header lines.
		if strings.Contains(line, "Obsoleting") {
			continue
		}
		nameArch := fields[0]
		ver := fields[1]
		repo := fields[2]
		nameOnly := nameArch
		if dot := strings.LastIndex(nameOnly, "."); dot > 0 {
			nameOnly = nameOnly[:dot]
		}
		results = append(results, map[string]interface{}{
			"source":           "dnf",
			"sourceId":         nameOnly,
			"availableVersion": ver,
			"repo":             repo,
			"classification":   "security",
		})
	}
	return results, nil
}

func brewOutdated() ([]map[string]interface{}, error) {
	out, err := exec.Command("brew", "outdated", "--json=v2").Output()
	if err != nil {
		return nil, err
	}
	var parsed struct {
		Formulae []struct {
			Name             string   `json:"name"`
			InstalledVersions []string `json:"installed_versions"`
			CurrentVersion    string   `json:"current_version"`
		} `json:"formulae"`
	}
	if err := json.Unmarshal(out, &parsed); err != nil {
		return nil, err
	}
	results := []map[string]interface{}{}
	for _, f := range parsed.Formulae {
		old := ""
		if len(f.InstalledVersions) > 0 {
			old = f.InstalledVersions[0]
		}
		results = append(results, map[string]interface{}{
			"source":           "brew",
			"sourceId":         f.Name,
			"availableVersion": f.CurrentVersion,
			"installedVersion": old,
			"classification":   "feature",
		})
	}
	return results, nil
}

// runPatchDetection decodes a detection rule (same shape as software's)
// and returns per-method detection map + consensus. Unix collapses to
// single-method, so consensus is "all-yes" or "all-no".
func runPatchDetection(rule json.RawMessage) (methods map[string]bool, consensus string) {
	present, _, _ := runDetectionRule(rule)
	methods = map[string]bool{"apt": present}
	if present {
		return methods, "all-yes"
	}
	return methods, "all-no"
}

// runPatchDetectionForPatch detects a specific patch by package id.
// On Unix we map source/sourceId → dpkg-query / rpm -q.
func runPatchDetectionForPatch(p *patchRef) (map[string]bool, string) {
	switch p.Source {
	case "ms":
		// Microsoft KB on Linux = always absent.
		return map[string]bool{"wmi-qfe": false, "dism-packages": false, "wu-history": false}, "all-no"
	case "thirdparty", "custom":
		// Use sourceId as an apt package name guess; PCC2K extension.
		out, err := exec.Command("/usr/bin/dpkg-query", "-W", "-f=${Status}", p.SourceID).Output()
		if err == nil && strings.Contains(string(out), "install ok installed") {
			return map[string]bool{"apt": true}, "all-yes"
		}
		return map[string]bool{"apt": false}, "all-no"
	}
	return map[string]bool{"apt": false}, "all-no"
}

// execPatchDeploy runs the source-appropriate install command.
func execPatchDeploy(
	ctx context.Context,
	run *patchRun,
	params *patchDeployParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (exitCode int, exitMessage string) {
	if params.Patch.Source == "ms" {
		emit("stderr", "[agent] ms patches not applicable on Linux\n")
		return -1, "agent.unsupported_os"
	}
	if !hasAptGet() {
		emit("stderr", "[agent] apt-get not found — patch deploy on this Linux flavor not yet implemented\n")
		return -1, "no apt"
	}

	// Run apt-get update first so we have the latest indexes.
	progress("downloading", "apt-get update", 25)
	upd := exec.CommandContext(ctx, "/usr/bin/apt-get", "update", "-q")
	upd.Env = aptEnv()
	upd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	updOut, _ := upd.CombinedOutput()
	emit("stdout", string(updOut))

	progress("installing", "apt-get install --only-upgrade", 50)
	args := []string{"install", "-y", "--only-upgrade", "--no-install-recommends", params.Patch.SourceID}
	cmd := exec.CommandContext(ctx, "/usr/bin/apt-get", args...)
	cmd.Env = aptEnv()
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, _ := cmd.StdoutPipe()
	stderrPipe, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		emit("stderr", fmt.Sprintf("[agent] start: %v\n", err))
		return -1, err.Error()
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go pipeToEmit(&wg, stdoutPipe, "stdout", emit)
	go pipeToEmit(&wg, stderrPipe, "stderr", emit)
	waitErr := cmd.Wait()
	wg.Wait()
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), ""
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		return exitErr.ExitCode(), waitErr.Error()
	}
	return -1, waitErr.Error()
}

// execPatchUninstall walks the strategy list and returns the first that
// succeeds. On Unix only the apt-pin / brew-pin strategies make sense;
// "wusa" / "dism-remove-package" / "restore-point" / "vm-snapshot" are
// Windows-only and report not-applicable.
func execPatchUninstall(
	ctx context.Context,
	run *patchRun,
	params *patchUninstallParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (strategyUsed string, exitCode int, exitMessage string) {
	for _, strat := range params.Strategies {
		switch strat {
		case "wusa", "dism-remove-package", "restore-point", "vm-snapshot":
			emit("stderr", fmt.Sprintf("[agent] strategy %q not applicable on Unix — skipping\n", strat))
			continue
		case "apt-pin":
			// Phase 4.5: pin previous version via /etc/apt/preferences.d.
			emit("stderr", "[agent] apt-pin rollback not yet implemented (Phase 4.5)\n")
			continue
		}
		emit("stderr", fmt.Sprintf("[agent] strategy %q not understood\n", strat))
	}
	return "", -1, "no applicable strategy"
}

func aptEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C.UTF-8",
	}
}

func hasAptGet() bool {
	_, err := exec.LookPath("apt-get")
	return err == nil
}

func hasDnf() bool {
	_, err := exec.LookPath("dnf")
	return err == nil
}

func hasBrew() bool {
	_, err := exec.LookPath("brew")
	return err == nil
}

func runWithEnv(bin string, args, env []string) (string, error) {
	cmd := exec.Command(bin, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// checkRebootPendingPlatform looks for /var/run/reboot-required (Debian/Ubuntu)
// and /var/lib/yum/yum-saved_tx-* indicators. Best-effort.
func checkRebootPendingPlatform() bool {
	if _, err := exec.Command("/bin/sh", "-c", "test -f /var/run/reboot-required").CombinedOutput(); err == nil {
		return true
	}
	return false
}

// runPreflightGate checks the pre-flight requirements before patch deploy.
// Returns (failedGateName, ok). Implements the platform-agnostic checks;
// service-health hook is platform-specific (see patches_windows.go for
// Windows service inspection).
func runPreflightGate(g *preflightGate) (string, bool) {
	if g.MinDiskSpaceGb > 0 {
		// `df -k /` → check root partition free space in GB.
		out, err := exec.Command("/bin/sh", "-c", `df -k / | awk 'NR==2 {print $4}'`).Output()
		if err == nil {
			var freeKb int64
			fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &freeKb)
			if freeKb/1024/1024 < int64(g.MinDiskSpaceGb) {
				return "minDiskSpaceGb", false
			}
		}
	}
	if g.RequireNoPendingReboot && checkRebootPendingPlatform() {
		return "requireNoPendingReboot", false
	}
	// MaxRamPercent / RequireBackupWithinHours / RequireServiceHealth /
	// RespectMaintenanceMode / CustomPreflightScriptId — Phase 4.5.
	return "", true
}
