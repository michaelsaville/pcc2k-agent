//go:build windows

package main

// Phase 1 / v1.0.1 WS-B — Windows shell spawn.
//
// Spawns powershell.exe with stdin/stdout/stderr hooked to pipes.
// v1 uses plain stdio (not a pseudoconsole); see shell.go top
// comment.

import (
	"context"
	"io"
	"os/exec"
)

func spawnShell(ctx context.Context) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	// PowerShell with no profile and no logo — hermetic, no operator
	// dotfile drift. -NonInteractive would block our stdin path, so we
	// stay interactive.
	cmd := exec.CommandContext(ctx, "powershell.exe",
		"-NoLogo",
		"-NoProfile",
		"-ExecutionPolicy", "Bypass",
		"-Command", "-",
	)
	cmd.Env = []string{
		// Match the Unix env mask — TERM=dumb keeps progress-bar nonsense out
		// of stdout, and clipping HOME keeps profile auto-load off.
		"TERM=dumb",
	}

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, nil, nil, nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, nil, nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		_ = stderr.Close()
		return nil, nil, nil, nil, err
	}
	return cmd, stdin, stdout, stderr, nil
}
