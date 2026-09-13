//go:build windows

package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const installDir = `C:\Program Files\pcc2k-agent`

func isElevated() bool {
	return windows.GetCurrentProcessToken().IsElevated()
}

// relaunchElevated re-runs this exact binary + args through the UAC
// prompt. x/sys/windows only exposes the fire-and-forget ShellExecute
// (no handle to wait on), so the elevated child owns the outcome: it
// shows the message box / prints the report itself, and this parent
// simply exits once the prompt has been accepted.
func relaunchElevated() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	args := make([]string, 0, len(os.Args))
	for _, a := range os.Args[1:] {
		args = append(args, syscall.EscapeArg(a))
	}
	verb, _ := syscall.UTF16PtrFromString("runas")
	file, _ := syscall.UTF16PtrFromString(exe)
	params, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))
	dir, _ := syscall.UTF16PtrFromString(filepath.Dir(exe))
	if err := windows.ShellExecute(0, verb, file, params, dir, windows.SW_SHOWNORMAL); err != nil {
		return fmt.Errorf("elevation refused or failed: %w", err)
	}
	return nil
}

func setupInstall(o setupOptions) (string, error) {
	if !isElevated() {
		if err := relaunchElevated(); err != nil {
			return "", err
		}
		// The elevated child shows its own report.
		os.Exit(0)
	}

	self, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("locate self: %w", err)
	}
	self, _ = filepath.Abs(self)
	target := filepath.Join(installDir, "pcc2k-agent.exe")

	// Re-install cleanly: stop + delete an existing service so the copy
	// below isn't blocked by a running image and the SCM entry points at
	// the fresh binary. Config in %ProgramData% is overwritten on save.
	if err := removeExistingService(); err != nil {
		return "", err
	}

	if !strings.EqualFold(self, target) {
		if err := os.MkdirAll(installDir, 0o755); err != nil {
			return "", fmt.Errorf("create %s: %w", installDir, err)
		}
		if err := copyFile(self, target); err != nil {
			return "", fmt.Errorf("copy to %s: %w", target, err)
		}
	}

	res, err := enrollRequest(o.url, o.key)
	if err != nil {
		return "", fmt.Errorf("enroll: %w", err)
	}
	gateway := res.GatewayURL
	if gateway == "" {
		return "", fmt.Errorf("server returned no gatewayUrl")
	}

	// Reuse the existing install subcommand so there is one service
	// registration path. It calls os.Executable() for the image path, so
	// it must run from the installed copy — hand off to it.
	args := []string{"install",
		"--gateway", gateway,
		"--token", res.AgentSecret,
		"--agent-id", res.AgentID,
		"--client", res.TenantName,
		"--role", o.role,
	}
	if err := runHidden(target, args...); err != nil {
		return "", fmt.Errorf("register service: %w", err)
	}
	if err := runHidden(target, "start"); err != nil {
		return "", fmt.Errorf("start service: %w", err)
	}
	hn, _ := os.Hostname()
	return fmt.Sprintf("%s is enrolled with FleetHub as %s.\n\nClient: %s\nAgent ID: %s\n\nIt will appear in the device list within a minute.",
		hn, res.TenantName, res.TenantName, res.AgentID), nil
}

func removeExistingService() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("scm connect: %w", err)
	}
	defer m.Disconnect()
	s, err := m.OpenService(serviceName)
	if err != nil {
		return nil // not installed
	}
	defer s.Close()
	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		deadline := time.Now().Add(15 * time.Second)
		for time.Now().Before(deadline) {
			if st, err := s.Query(); err != nil || st.State == svc.Stopped {
				break
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("remove previous service: %w", err)
	}
	// SCM deletes lazily; give it a moment so CreateService doesn't
	// collide with the marked-for-deletion entry.
	time.Sleep(1500 * time.Millisecond)
	return nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".new"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Rename(tmp, dst)
}

func runHidden(exe string, args ...string) error {
	p, err := os.StartProcess(exe, append([]string{exe}, args...), &os.ProcAttr{
		Files: []*os.File{os.Stdin, os.Stdout, os.Stderr},
	})
	if err != nil {
		return err
	}
	st, err := p.Wait()
	if err != nil {
		return err
	}
	if !st.Success() {
		return fmt.Errorf("%s %s: exit %d", filepath.Base(exe), strings.Join(args, " "), st.ExitCode())
	}
	return nil
}

// setupReport shows the outcome. Double-click users have no console worth
// reading, so a message box is the report; scripts pass --no-pause.
func setupReport(ok bool, msg string, noPause bool) {
	if ok {
		fmt.Println("==> " + msg)
	} else {
		fmt.Fprintln(os.Stderr, "setup failed: "+msg)
	}
	if noPause {
		return
	}
	caption := "PCC2K Agent — installed"
	flags := uint32(windows.MB_OK | windows.MB_ICONINFORMATION | windows.MB_SETFOREGROUND)
	if !ok {
		caption = "PCC2K Agent — setup failed"
		flags = windows.MB_OK | windows.MB_ICONERROR | windows.MB_SETFOREGROUND
	}
	text, _ := syscall.UTF16PtrFromString(msg)
	cap, _ := syscall.UTF16PtrFromString(caption)
	_, _ = windows.MessageBox(0, text, cap, flags)
}
