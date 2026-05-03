//go:build windows

package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// execScript on Windows runs the script body via PowerShell (pwsh > 7
// preferred, falling back to powershell.exe 5.1) or cmd.exe, with the
// process attached to a JobObject so we can TerminateJobObject() on
// cancel and reach every grandchild.
//
// Body is fed via stdin — no on-disk artifacts. Per AGENT-PROTOCOL §13,
// the integrity check (SHA-256 + Ed25519) ran before we got here.
func execScript(
	ctx context.Context,
	run *scriptRun,
	params *scriptExecParams,
	emit func(stream, chunk string),
) (exitCode int, exitMessage string) {
	bin, baseArgs, err := resolveInterpreter(params.Interpreter)
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] %v\r\n", err))
		return -1, err.Error()
	}

	cmd := exec.CommandContext(ctx, bin, append(baseArgs, params.Args...)...)
	cmd.Stdin = strings.NewReader(params.ScriptBody)

	// Suppress the console window — when running as the SCM service this
	// is moot, but interactive console runs also hide the child window.
	cmd.SysProcAttr = &syscall.SysProcAttr{
		HideWindow:    true,
		CreationFlags: windows.CREATE_NO_WINDOW | windows.CREATE_SUSPENDED,
	}

	// Locked-down env: only what the server passes plus a sane PATH.
	envSlice := make([]string, 0, len(params.Env)+3)
	envSlice = append(envSlice, "PATH="+windowsDefaultPath())
	envSlice = append(envSlice, "SystemRoot="+envOrDefault("SystemRoot", `C:\Windows`))
	envSlice = append(envSlice, "TEMP="+envOrDefault("TEMP", `C:\Windows\Temp`))
	for k, v := range params.Env {
		envSlice = append(envSlice, k+"="+v)
	}
	cmd.Env = envSlice

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stdout pipe: %v\r\n", err))
		return -1, err.Error()
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stderr pipe: %v\r\n", err))
		return -1, err.Error()
	}

	if err := cmd.Start(); err != nil {
		emit("stderr", fmt.Sprintf("[agent] start: %v\r\n", err))
		return -1, err.Error()
	}

	// Build a JobObject that kills all children when the handle closes,
	// attach our suspended process, then resume. Without this, calling
	// cmd.Process.Kill() leaves grandchildren orphaned.
	job, jobErr := newKillOnCloseJob()
	if jobErr == nil {
		ph := windows.Handle(cmd.Process.Pid)
		// Get a real process handle (Pid is just a DWORD).
		realHandle, openErr := windows.OpenProcess(
			windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE|0x0001 /* PROCESS_QUERY_INFORMATION */,
			false, uint32(cmd.Process.Pid))
		if openErr == nil {
			ph = realHandle
			defer windows.CloseHandle(realHandle)
			if assignErr := windows.AssignProcessToJobObject(job, ph); assignErr != nil {
				emit("stderr", fmt.Sprintf("[agent] AssignProcessToJobObject: %v\r\n", assignErr))
			}
		} else {
			emit("stderr", fmt.Sprintf("[agent] OpenProcess: %v\r\n", openErr))
		}
		// Resume the main thread now that we're in the job. Best-effort —
		// if we can't get the thread handle, fall through and Wait() will
		// hang (a real Windows test catches this; emit stderr so we know).
		if rErr := resumeMainThread(uint32(cmd.Process.Pid)); rErr != nil {
			emit("stderr", fmt.Sprintf("[agent] resumeMainThread: %v\r\n", rErr))
		}
		defer windows.CloseHandle(job)
	} else {
		emit("stderr", fmt.Sprintf("[agent] CreateJobObject: %v\r\n", jobErr))
		// Fallback: try to resume even without a job — better than hanging.
		_ = resumeMainThread(uint32(cmd.Process.Pid))
	}

	var streamWg sync.WaitGroup
	streamWg.Add(2)
	go scanStream(&streamWg, stdoutPipe, "stdout", emit)
	go scanStream(&streamWg, stderrPipe, "stderr", emit)

	waitErr := cmd.Wait()
	streamWg.Wait()

	// On ctx cancel, JobObject auto-kills via JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	// when we close the handle (deferred above). Belt-and-braces:
	if ctx.Err() != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}

	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), ""
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if errors.Is(ctx.Err(), context.Canceled) {
			return exitErr.ExitCode(), "cancelled"
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return exitErr.ExitCode(), "timeout"
		}
		return exitErr.ExitCode(), ""
	}
	return -1, waitErr.Error()
}

func resolveInterpreter(name string) (string, []string, error) {
	switch strings.ToLower(name) {
	case "powershell", "":
		// Prefer pwsh.exe (cross-platform PS 7+) when present, else built-in.
		if path, err := exec.LookPath("pwsh.exe"); err == nil {
			return path, []string{"-NoProfile", "-NonInteractive", "-Command", "-"}, nil
		}
		return `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
			[]string{"-NoProfile", "-NonInteractive", "-Command", "-"}, nil
	case "pwsh":
		path, err := exec.LookPath("pwsh.exe")
		if err != nil {
			return "", nil, fmt.Errorf("pwsh.exe not on PATH (PowerShell 7+ not installed)")
		}
		return path, []string{"-NoProfile", "-NonInteractive", "-Command", "-"}, nil
	case "cmd":
		return `C:\Windows\System32\cmd.exe`, []string{"/Q", "/D", "/S", "/C", "@-"}, nil
	case "bash":
		path, err := exec.LookPath("bash.exe")
		if err != nil {
			return "", nil, fmt.Errorf("bash.exe not on PATH (Git Bash / WSL bash not installed)")
		}
		return path, []string{"-s"}, nil
	}
	return "", nil, fmt.Errorf("unknown interpreter %q", name)
}

func windowsDefaultPath() string {
	// Modeled after the SCM service's default path; avoids inheriting a
	// random user PATH at run-time.
	return `C:\Windows\System32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0`
}

// newKillOnCloseJob creates an unnamed JobObject configured so that when
// the handle is closed (or the job otherwise terminates), every process
// in the job — including the original child and all its descendants —
// is force-terminated. This is the only reliable way to kill a process
// tree on Windows from Go.
func newKillOnCloseJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return 0, err
	}
	type jobObjectExtendedLimitInformation struct {
		BasicLimitInformation windows.JOBOBJECT_BASIC_LIMIT_INFORMATION
		IoInfo                windows.IO_COUNTERS
		ProcessMemoryLimit    uintptr
		JobMemoryLimit        uintptr
		PeakProcessMemoryUsed uintptr
		PeakJobMemoryUsed     uintptr
	}
	info := jobObjectExtendedLimitInformation{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(
		job,
		windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&info)),
		uint32(unsafe.Sizeof(info)),
	); err != nil {
		windows.CloseHandle(job)
		return 0, err
	}
	return job, nil
}

// resumeMainThread reaches into the suspended process and resumes its
// primary thread. We need this because we used CREATE_SUSPENDED in
// CreationFlags so we could attach the JobObject before any code ran.
func resumeMainThread(pid uint32) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(snap)
	var entry windows.ThreadEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	if err := windows.Thread32First(snap, &entry); err != nil {
		return err
	}
	for {
		if entry.OwnerProcessID == pid {
			th, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, entry.ThreadID)
			if err == nil {
				_, _ = windows.ResumeThread(th)
				windows.CloseHandle(th)
				return nil
			}
		}
		if err := windows.Thread32Next(snap, &entry); err != nil {
			break
		}
	}
	return errors.New("main thread not found")
}

// envOrDefault — used to build the locked-down child env from the few
// values we actually want to pass through.
func envOrDefault(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// scanStream is symmetric with the Unix version. Pulled into this file
// so the build constraint isolates each file's compile unit.
func scanStream(wg *sync.WaitGroup, r io.Reader, name string, emit func(stream, chunk string)) {
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
