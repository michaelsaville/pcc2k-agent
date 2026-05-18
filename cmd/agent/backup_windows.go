//go:build windows

package main

// Phase 1 / v1.0.1 WS-D — Windows backup invocation matrix.
//
// Products in v1: wbadmin (Windows Server Backup), veeam (Veeam
// Agent for Windows), macrium (Macrium Reflect).

import (
	"context"
	"fmt"
	"io"
	"os/exec"
)

func invokeBackup(ctx context.Context, product string, opts map[string]any, logOut io.Writer) (int, error) {
	var cmd *exec.Cmd
	switch product {
	case "wbadmin":
		// `wbadmin start backup -backupTarget:<X:> -include:<paths> -quiet`
		// Operator provides target via opts.backupTarget; without it we
		// default to "F:" (a common offline-disk slot).
		target := optString(opts, "backupTarget", "F:")
		include := optString(opts, "include", "C:")
		cmd = exec.CommandContext(ctx, "wbadmin",
			"start", "backup",
			fmt.Sprintf("-backupTarget:%s", target),
			fmt.Sprintf("-include:%s", include),
			"-quiet")
	case "veeam":
		// Veeam Agent for Windows CLI: `veeam.exe -backup -policy <name>`.
		// Policy name from opts.policy; without it the configured default
		// policy runs.
		policy := optString(opts, "policy", "")
		args := []string{"-backup"}
		if policy != "" {
			args = append(args, "-policy", policy)
		}
		veeamPath := optString(opts, "veeamPath",
			`C:\Program Files\Veeam\Endpoint Backup\Veeam.EndPoint.Manager.exe`)
		cmd = exec.CommandContext(ctx, veeamPath, args...)
	case "macrium":
		// Macrium Reflect CLI: `reflect.exe -e -w -full <xml-config>`.
		// Operator must have an XML backup definition file at the
		// configured path; opts.definitionFile points to it.
		defFile := optString(opts, "definitionFile", "")
		if defFile == "" {
			return -1, fmt.Errorf("macrium: options.definitionFile required (XML backup definition)")
		}
		reflectPath := optString(opts, "reflectPath",
			`C:\Program Files\Macrium\Reflect\reflect.exe`)
		cmd = exec.CommandContext(ctx, reflectPath, "-e", "-w", "-full", defFile)
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
