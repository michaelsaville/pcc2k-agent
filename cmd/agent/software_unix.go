//go:build !windows

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"syscall"
)

// Linux/macOS software install + uninstall + detection.
//
// Sources supported:
//   - apt    (Ubuntu/Debian)        — apt-get install -y / -s for dry-run
//   - dnf    (Fedora/RHEL)          — dnf install -y / --assumeno for dry-run
//   - brew   (macOS Homebrew)       — brew install / --dry-run
//   - custom (URL artifact)         — wget + dpkg/rpm/installer per OS
//
// Detection rule kinds supported:
//   - file-version    (cross-platform) — file existence + optional minVersion
//   - custom-script   (cross-platform) — escape hatch
//   - dpkg-list       (Linux .deb)     — dpkg-query -W -f='${Version}'
//   - rpm-list        (Linux .rpm)     — rpm -q
//   - brew-list       (macOS)          — brew list --versions
//   - winget-list     (Windows)        — N/A on Unix, returns false
//   - msi-product-code, registry-uninstall-key — N/A on Unix

func execSoftware(
	ctx context.Context,
	run *softwareRun,
	params *softwareInstallParams,
	emit func(stream, chunk string),
	progress func(phase, message string, percent int),
) (exitCode int, exitMsg string, rebootPending bool) {
	bin, args, env, err := resolveSoftwareCommand(params)
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] %v\n", err))
		return -1, err.Error(), false
	}

	progress("installing", fmt.Sprintf("%s %s", bin, strings.Join(args, " ")), 30)

	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Env = env
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stdout pipe: %v\n", err))
		return -1, err.Error(), false
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stderr pipe: %v\n", err))
		return -1, err.Error(), false
	}
	if err := cmd.Start(); err != nil {
		emit("stderr", fmt.Sprintf("[agent] start: %v\n", err))
		return -1, err.Error(), false
	}

	var streamWg sync.WaitGroup
	streamWg.Add(2)
	go pipeToEmit(&streamWg, stdoutPipe, "stdout", emit)
	go pipeToEmit(&streamWg, stderrPipe, "stderr", emit)

	waitErr := cmd.Wait()
	streamWg.Wait()

	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	progress("verifying", "command finished", 90)

	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), "", false
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		return exitErr.ExitCode(), waitErr.Error(), false
	}
	return -1, waitErr.Error(), false
}

func resolveSoftwareCommand(p *softwareInstallParams) (bin string, args []string, env []string, err error) {
	defaultEnv := []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"DEBIAN_FRONTEND=noninteractive",
		"LC_ALL=C.UTF-8",
	}
	pkg := p.Package.SourceID
	if p.Package.Version != "" {
		// apt: name=version. dnf: name-version. brew: name@version (formula:tap).
		// Keep simple — pass through as the source-specific selector.
		switch p.Package.Source {
		case "apt":
			pkg = pkg + "=" + p.Package.Version
		case "dnf":
			pkg = pkg + "-" + p.Package.Version
		case "brew":
			pkg = pkg + "@" + p.Package.Version
		}
	}

	switch p.Package.Source {
	case "apt":
		baseArgs := []string{"-y", "--no-install-recommends"}
		if p.Action == "uninstall" {
			args = append([]string{"remove"}, baseArgs...)
		} else {
			args = append([]string{"install"}, baseArgs...)
		}
		args = append(args, pkg)
		return "/usr/bin/apt-get", args, defaultEnv, nil
	case "dnf":
		verb := "install"
		if p.Action == "uninstall" {
			verb = "remove"
		}
		return "/usr/bin/dnf", []string{verb, "-y", pkg}, defaultEnv, nil
	case "brew":
		if runtime.GOOS != "darwin" {
			return "", nil, nil, fmt.Errorf("brew source requires macOS")
		}
		verb := "install"
		if p.Action == "uninstall" {
			verb = "uninstall"
		}
		return "/opt/homebrew/bin/brew", []string{verb, pkg}, defaultEnv, nil
	case "custom":
		// v1: only support .deb/.rpm/.pkg via direct URL fetch + native installer.
		// MSI flow is Windows-only; Unix custom is one of: dpkg, rpm, installer.
		return "", nil, nil, fmt.Errorf("custom source on Unix not yet implemented (Phase 3.5)")
	}
	return "", nil, nil, fmt.Errorf("unsupported source for Unix: %q", p.Package.Source)
}

// runDetectionRule decodes the per-rule shape and returns (present, version, error).
// Cross-platform on Unix; Windows-only kinds return present=false.
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
	case "file-version":
		var r struct {
			Path       string `json:"path"`
			MinVersion string `json:"minVersion,omitempty"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		if _, err := os.Stat(r.Path); err != nil {
			return false, "", nil
		}
		// On Unix we can't easily extract a "file version" — return present=true.
		return true, "", nil
	case "custom-script":
		var r struct {
			Script string `json:"script"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		// custom-script is "shell:..." or "powershell:..." (Windows). On
		// Unix only the shell: prefix is honored. Any non-zero exit = absent.
		if !strings.HasPrefix(r.Script, "shell:") {
			return false, "", nil
		}
		body := strings.TrimPrefix(r.Script, "shell:")
		out, err := exec.Command("/bin/sh", "-c", body).CombinedOutput()
		if err != nil {
			return false, "", nil
		}
		return true, strings.TrimSpace(string(out)), nil
	case "dpkg-list":
		var r struct {
			Package string `json:"package"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		out, err := exec.Command("/usr/bin/dpkg-query", "-W", "-f=${Version}", r.Package).Output()
		if err != nil {
			return false, "", nil
		}
		v := strings.TrimSpace(string(out))
		return v != "", v, nil
	case "rpm-list":
		var r struct {
			Package string `json:"package"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		out, err := exec.Command("/usr/bin/rpm", "-q", "--queryformat=%{VERSION}", r.Package).Output()
		if err != nil {
			return false, "", nil
		}
		return true, strings.TrimSpace(string(out)), nil
	case "brew-list":
		var r struct {
			Formula string `json:"formula"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		out, err := exec.Command("brew", "list", "--versions", r.Formula).Output()
		if err != nil {
			return false, "", nil
		}
		// "formula 1.2.3" — second token is the version.
		fields := strings.Fields(string(out))
		if len(fields) < 2 {
			return false, "", nil
		}
		return true, fields[1], nil
	case "which":
		// PCC2K extension: returns present=true if `which <bin>` resolves.
		var r struct {
			Binary string `json:"binary"`
		}
		if err := json.Unmarshal(rule, &r); err != nil {
			return false, "", err
		}
		path, err := exec.LookPath(r.Binary)
		if err != nil {
			return false, "", nil
		}
		return true, path, nil
	case "winget-list", "msi-product-code", "registry-uninstall-key":
		// Windows-only kinds. Always absent on Unix.
		return false, "", nil
	}
	return false, "", fmt.Errorf("unknown detection kind %q", head.Kind)
}

// pipeToEmit reads from a pipe and emits chunks. Same pattern as scanStream
// but consolidated here to avoid duplicating between stream readers.
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
