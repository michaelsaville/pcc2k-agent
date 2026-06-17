//go:build windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

// powerActionSupported — Windows handles all three via shutdown.exe.
func powerActionSupported(action string) error {
	switch action {
	case "reboot", "shutdown", "logoff":
		return nil
	default:
		return fmt.Errorf("unknown power action %q", action)
	}
}

func doPowerAction(action string, delaySec int, message string, force bool) error {
	var args []string
	switch action {
	case "reboot":
		args = []string{"/r", "/t", strconv.Itoa(delaySec)}
	case "shutdown":
		args = []string{"/s", "/t", strconv.Itoa(delaySec)}
	case "logoff":
		args = []string{"/l"} // logoff ignores delay + message
	default:
		return fmt.Errorf("unsupported power action %q", action)
	}
	if force && action != "logoff" {
		args = append(args, "/f")
	}
	if message != "" && action != "logoff" {
		args = append(args, "/c", message)
	}
	return exec.Command("shutdown", args...).Run()
}
