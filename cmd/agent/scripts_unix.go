//go:build !windows

package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
)

// execScript spawns the script body via the requested interpreter and
// streams stdout/stderr to the emit callback. Blocks until the process
// exits or ctx is cancelled.
//
// Linux/macOS path: write the script body to the interpreter's stdin
// (no temp files on disk — no cleanup, no race). Wrap in a process
// group so we can kill the whole tree on cancel.
func execScript(
	ctx context.Context,
	run *scriptRun,
	params *scriptExecParams,
	emit func(stream, chunk string),
) (exitCode int, exitMessage string) {
	bin, baseArgs, err := resolveInterpreter(params.Interpreter)
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] %v\n", err))
		return -1, err.Error()
	}

	cmd := exec.CommandContext(ctx, bin, append(baseArgs, params.Args...)...)
	// Feed the script body via stdin — no on-disk artifacts.
	cmd.Stdin = strings.NewReader(params.ScriptBody)

	// Build env: inherit nothing by default + only what the server
	// passes through. Phase 2 design §6 says capability drop happens
	// here; for v1 we just pass the explicit set.
	envSlice := make([]string, 0, len(params.Env)+1)
	envSlice = append(envSlice, "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
	for k, v := range params.Env {
		envSlice = append(envSlice, k+"="+v)
	}
	cmd.Env = envSlice

	// Process group so kill() reaches descendants.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stdout pipe: %v\n", err))
		return -1, err.Error()
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		emit("stderr", fmt.Sprintf("[agent] stderr pipe: %v\n", err))
		return -1, err.Error()
	}

	if err := cmd.Start(); err != nil {
		emit("stderr", fmt.Sprintf("[agent] start: %v\n", err))
		return -1, err.Error()
	}

	// Pipe scanner per stream — chunked at line boundaries primarily,
	// with a hard byte cap so a stream of binary output still flushes.
	var streamWg sync.WaitGroup
	streamWg.Add(2)
	go scanStream(&streamWg, stdoutPipe, "stdout", emit)
	go scanStream(&streamWg, stderrPipe, "stderr", emit)

	// Wait for both pipes to drain in tandem with cmd.Wait. ctx
	// cancellation kills the process group via the context-aware Cmd.
	waitErr := cmd.Wait()
	streamWg.Wait()

	// On context cancel, kill whole process group as a belt-and-braces
	// guarantee (CommandContext only kills the parent).
	if ctx.Err() != nil && cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	if waitErr == nil {
		return cmd.ProcessState.ExitCode(), ""
	}
	if exitErr, ok := waitErr.(*exec.ExitError); ok {
		// Distinguish ctx-cancel from genuine exit.
		if ctx.Err() == context.Canceled {
			return exitErr.ExitCode(), "cancelled"
		}
		if ctx.Err() == context.DeadlineExceeded {
			return exitErr.ExitCode(), "timeout"
		}
		return exitErr.ExitCode(), ""
	}
	return -1, waitErr.Error()
}

func resolveInterpreter(name string) (string, []string, error) {
	switch strings.ToLower(name) {
	case "bash", "":
		return "/bin/bash", []string{"-s"}, nil
	case "sh":
		return "/bin/sh", []string{"-s"}, nil
	case "powershell":
		// pwsh-on-Linux is fine if installed; this is the x-platform path.
		return "/usr/bin/pwsh", []string{"-NoProfile", "-NonInteractive", "-Command", "-"}, nil
	case "python", "python3":
		return "/usr/bin/python3", []string{"-"}, nil
	case "cmd":
		return "", nil, fmt.Errorf("agent.unsupported_os: cmd interpreter requires Windows")
	}
	return "", nil, fmt.Errorf("unknown interpreter %q", name)
}

func scanStream(wg *sync.WaitGroup, r io.Reader, name string, emit func(stream, chunk string)) {
	defer wg.Done()
	br := bufio.NewReaderSize(r, outputFrameMaxBytes)
	buf := make([]byte, 0, outputFrameMaxBytes)
	for {
		// Try to read a line; if it's longer than the buffer, ReadSlice
		// returns ErrBufferFull and we ship what we have.
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 {
			buf = append(buf, chunk...)
			// Flush at line boundary OR when the buffer is full.
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
