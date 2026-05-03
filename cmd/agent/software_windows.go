//go:build windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// Windows software install + uninstall + detection.
//
// Sources supported:
//   - winget   primary; resolves catalog ids like Google.Chrome
//   - choco    fallback for shops that prefer chocolatey
//   - custom   direct MSI download → msiexec /i /quiet
//
// Detection rule kinds (per PHASE-3-DESIGN §3.2):
//   - msi-product-code         registry HKLM\...\Uninstall product code lookup
//   - registry-uninstall-key   DisplayName scan + DisplayVersion
//   - file-version             VersionInfo via Win32 API (best-effort: file mtime)
//   - winget-list              winget list --id <id> --exact
//   - custom-script            "powershell:" or "cmd:" prefix
//
// Reboot detection: `RebootPending` registry keys post-install.

func execSoftware(
	ctx context.Context,
	run *softwareRun,
	params *softwareInstallParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (exitCode int, exitMsg string, rebootPending bool) {
	bin, args, err := resolveSoftwareCommand(params)
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] %v\r\n", err))
		return -1, err.Error(), false
	}

	progress("installing", fmt.Sprintf("%s %s", bin, strings.Join(args, " ")), 30)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = append(os.Environ(),
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C.UTF-8",
	)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW,
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stdout pipe: %v\r\n", err))
		return -1, err.Error(), false
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stderr pipe: %v\r\n", err))
		return -1, err.Error(), false
	}
	if err := cmd.Start(); err != nil {
		emit("stderr", fmt.Sprintf("[agent] start: %v\r\n", err))
		return -1, err.Error(), false
	}

	var streamWg sync.WaitGroup
	streamWg.Add(2)
	go pipeToEmit(&streamWg, stdoutPipe, "stdout", emit)
	go pipeToEmit(&streamWg, stderrPipe, "stderr", emit)

	waitErr := cmd.Wait()
	streamWg.Wait()

	if ctx.Err() != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	progress("verifying", "command finished", 90)
	rebootPending = checkRebootPending()

	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), "", rebootPending
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		// MSI / winget can return non-zero "success" codes (e.g. 3010 = reboot
		// required). Caller treats these per result-mapping in software.go.
		if exitErr.ExitCode() == 3010 {
			return 0, "reboot required (msiexec 3010)", true
		}
		return exitErr.ExitCode(), waitErr.Error(), rebootPending
	}
	return -1, waitErr.Error(), rebootPending
}

func resolveSoftwareCommand(p *softwareInstallParams) (bin string, args []string, err error) {
	pkg := p.Package.SourceID

	switch p.Package.Source {
	case "winget":
		// winget install --id <id> --exact --silent --accept-source-agreements
		// --accept-package-agreements [--version V] [--scope machine|user]
		base := []string{
			"--id", pkg,
			"--exact",
			"--silent",
			"--accept-source-agreements",
			"--accept-package-agreements",
			"--disable-interactivity",
		}
		if p.Package.Version != "" {
			base = append(base, "--version", p.Package.Version)
		}
		if p.Package.Scope == "user" {
			base = append(base, "--scope", "user")
		} else {
			base = append(base, "--scope", "machine")
		}
		verb := "install"
		if p.Action == "uninstall" {
			verb = "uninstall"
		}
		args = append([]string{verb}, base...)
		return "winget.exe", args, nil
	case "choco":
		verb := "install"
		if p.Action == "uninstall" {
			verb = "uninstall"
		}
		args = []string{verb, pkg, "-y", "--no-progress"}
		if p.Package.Version != "" {
			args = append(args, "--version", p.Package.Version)
		}
		return `C:\ProgramData\chocolatey\bin\choco.exe`, args, nil
	case "custom":
		// Custom MSI: must be downloaded already at a path the agent expects.
		// v1: download path is a server-pinned URL — Phase 3.5 wires a fetcher.
		// For now require the artifact to be on disk at a deterministic path.
		if p.Package.ArtifactURL == "" {
			return "", nil, fmt.Errorf("custom source requires artifactUrl")
		}
		// TODO(phase-3.5): wget/Invoke-WebRequest with sha256 verify.
		return "", nil, fmt.Errorf("custom MSI fetch not yet implemented (Phase 3.5)")
	}
	return "", nil, fmt.Errorf("unsupported source for Windows: %q", p.Package.Source)
}

func runDetectionRule(rule json.RawMessage) (bool, string, error) {
	if len(rule) == 0 {
		return false, "", nil
	}
	var head struct {
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(rule, &head); err != nil {
		return false, "", err
	}
	switch head.Kind {
	case "msi-product-code":
		var r struct {
			ProductCode string `json:"productCode"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		// Look up under HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\<code>
		k, err := registry.OpenKey(
			registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\`+r.ProductCode,
			registry.QUERY_VALUE)
		if err != nil {
			// Try Wow6432Node for 32-bit on 64-bit
			k2, err2 := registry.OpenKey(
				registry.LOCAL_MACHINE,
				`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\`+r.ProductCode,
				registry.QUERY_VALUE)
			if err2 != nil {
				return false, "", nil
			}
			k = k2
		}
		defer k.Close()
		v, _, _ := k.GetStringValue("DisplayVersion")
		return true, v, nil
	case "registry-uninstall-key":
		var r struct {
			DisplayName string `json:"displayName"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		for _, base := range []string{
			`SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`,
			`SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall`,
		} {
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.ENUMERATE_SUB_KEYS)
			if err != nil {
				continue
			}
			subs, err := k.ReadSubKeyNames(-1)
			k.Close()
			if err != nil {
				continue
			}
			for _, sub := range subs {
				sk, err := registry.OpenKey(registry.LOCAL_MACHINE, base+`\`+sub, registry.QUERY_VALUE)
				if err != nil {
					continue
				}
				dn, _, _ := sk.GetStringValue("DisplayName")
				dv, _, _ := sk.GetStringValue("DisplayVersion")
				sk.Close()
				if strings.EqualFold(dn, r.DisplayName) {
					return true, dv, nil
				}
			}
		}
		return false, "", nil
	case "file-version":
		var r struct {
			Path       string `json:"path"`
			MinVersion string `json:"minVersion,omitempty"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		fi, err := os.Stat(r.Path)
		if err != nil {
			return false, "", nil
		}
		// VersionInfo extraction would need the windows api GetFileVersionInfo
		// — defer to Phase 3.5; mtime is a v1 placeholder for "present".
		_ = fi
		return true, "", nil
	case "winget-list":
		var r struct {
			PackageID string `json:"packageId"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		out, err := exec.Command("winget.exe", "list", "--id", r.PackageID, "--exact",
			"--accept-source-agreements", "--disable-interactivity").Output()
		if err != nil {
			return false, "", nil
		}
		// winget list output is pipe-delimited tabular; second column = Id, third = Version.
		// Cheap parse: scan for the id, take the next non-empty token as version.
		lines := strings.Split(string(out), "\n")
		for _, ln := range lines {
			if !strings.Contains(ln, r.PackageID) {
				continue
			}
			cols := strings.Fields(ln)
			for i, c := range cols {
				if c == r.PackageID && i+1 < len(cols) {
					return true, cols[i+1], nil
				}
			}
			return true, "", nil
		}
		return false, "", nil
	case "custom-script":
		var r struct {
			Script string `json:"script"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		var bin string
		var argv []string
		switch {
		case strings.HasPrefix(r.Script, "powershell:"):
			bin = `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
			argv = []string{"-NoProfile", "-NonInteractive", "-Command", strings.TrimPrefix(r.Script, "powershell:")}
		case strings.HasPrefix(r.Script, "cmd:"):
			bin = `C:\Windows\System32\cmd.exe`
			argv = []string{"/Q", "/D", "/S", "/C", strings.TrimPrefix(r.Script, "cmd:")}
		default:
			return false, "", fmt.Errorf("custom-script needs powershell: or cmd: prefix on Windows")
		}
		out, err := exec.Command(bin, argv...).CombinedOutput()
		if err != nil {
			return false, "", nil
		}
		return true, strings.TrimSpace(string(out)), nil
	case "dpkg-list", "rpm-list", "brew-list", "which":
		// Unix-only kinds. Always absent on Windows.
		return false, "", nil
	}
	return false, "", fmt.Errorf("unknown detection kind %q", head.Kind)
}

// checkRebootPending scans the standard Windows reboot-pending registry
// keys. Used to surface software.complete with rebootPending=true so the
// deploy monitor's reboot policy can kick in.
func checkRebootPending() bool {
	checks := []struct {
		root registry.Key
		path string
		val  string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending`, ""},
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired`, ""},
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager`, "PendingFileRenameOperations"},
	}
	for _, c := range checks {
		k, err := registry.OpenKey(c.root, c.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		if c.val == "" {
			// Key existence alone signals pending.
			k.Close()
			return true
		}
		_, _, err = k.GetStringValue(c.val)
		k.Close()
		if err == nil {
			return true
		}
	}
	return false
}

// pipeToEmit symmetric with scripts_windows.go's scanStream — kept here
// to align with the file's build constraint. Same line-aware chunking.
func pipeToEmit(wg *sync.WaitGroup, r io.Reader, name string, emit func(stream, chunk string)) {
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
