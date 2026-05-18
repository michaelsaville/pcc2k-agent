//go:build !windows

package main

// Phase 1 / v1.0.1 WS-D — Unix backup invocation matrix.
//
// Products in v1: restic, borg, duplicati, macos-tm (Time Machine).
// Per-product flags are intentionally conservative — operator's
// existing config (~/.config/borg, /etc/restic.conf, etc.) drives
// the actual semantics; agent's job is just to spawn the right
// binary with the right verb.

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

func invokeBackup(ctx context.Context, product string, opts map[string]any, logOut io.Writer) (int, error) {
	var cmd *exec.Cmd
	switch product {
	case "restic":
		// Operator MUST have RESTIC_REPOSITORY + RESTIC_PASSWORD_FILE
		// (or matching opts) configured in environment OR in /etc/
		// restic.env. Agent just calls `restic backup <paths>`.
		paths := optString(opts, "paths", "/etc /home")
		cmd = exec.CommandContext(ctx, "sh", "-c",
			fmt.Sprintf("restic backup %s", paths))
	case "borg":
		// Same shape: operator owns the repo + passphrase config.
		// `borg create` takes a repo::archive-name.
		archive := optString(opts, "archive", "{hostname}-{now:%Y%m%d-%H%M%S}")
		paths := optString(opts, "paths", "/etc /home")
		repo := optString(opts, "repo", "")
		if repo == "" {
			return -1, fmt.Errorf("borg: options.repo required")
		}
		cmd = exec.CommandContext(ctx, "borg", "create",
			fmt.Sprintf("%s::%s", repo, archive),
			paths)
	case "duplicati":
		// Duplicati CLI: `duplicati-cli backup <target-url> <source-dir>`.
		target := optString(opts, "target", "")
		source := optString(opts, "source", "/home")
		if target == "" {
			return -1, fmt.Errorf("duplicati: options.target required")
		}
		cmd = exec.CommandContext(ctx, "duplicati-cli", "backup", target, source)
	case "macos-tm":
		// `tmutil startbackup --block` — synchronous until done.
		cmd = exec.CommandContext(ctx, "tmutil", "startbackup", "--block")
	default:
		return -1, fmt.Errorf("backup: unsupported product %q on this platform", product)
	}

	cmd.Stdout = logOut
	cmd.Stderr = logOut
	if err := cmd.Run(); err != nil {
		if exErr, ok := err.(*exec.ExitError); ok {
			return exErr.ExitCode(), nil
		}
		return -1, err
	}
	return 0, nil
}

// optString reads a string option from the params bag with default.
func optString(opts map[string]any, key, defaultVal string) string {
	if v, ok := opts[key].(string); ok && v != "" {
		return v
	}
	return defaultVal
}
