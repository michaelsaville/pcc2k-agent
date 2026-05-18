//go:build !windows

package main

// Phase 1 / v1.0.1 WS-B — Unix shell spawn.
//
// Spawns /bin/bash (preferred) or /bin/sh, with stdin/stdout/stderr
// hooked to pipes. v1 uses plain stdio (not a PTY); see shell.go top
// comment for rationale. The agent calls cmd.Start() but defers
// cmd.Wait() to the streamReader / waitLoop goroutines in shell.go.

import (
	"context"
	"io"
	"os/exec"
)

func spawnShell(ctx context.Context) (*exec.Cmd, io.WriteCloser, io.ReadCloser, io.ReadCloser, error) {
	// Prefer bash; fall back to sh.
	binary := "/bin/sh"
	if _, err := exec.LookPath("bash"); err == nil {
		binary = "/bin/bash"
	}
	// -i = interactive (so PS1 fires + prompt rendering happens),
	// --norc / --noprofile to skip operator dotfiles for hermetic
	// behavior. /bin/sh ignores these — bash-only.
	args := []string{}
	if binary == "/bin/bash" {
		args = append(args, "--norc", "--noprofile", "-i")
	} else {
		args = append(args, "-i")
	}

	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Env = []string{
		"TERM=dumb", // no ANSI escapes without a PTY
		"HOME=/tmp",
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
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
