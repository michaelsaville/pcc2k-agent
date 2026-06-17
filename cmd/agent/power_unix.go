//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"strconv"
)

// powerActionSupported — Linux + macOS can reboot/shutdown via the
// `shutdown` utility (requires the agent to run as root; the bootstrap
// installs the service as root). Interactive logoff has no portable
// unix equivalent, so it's rejected rather than silently no-op'd.
func powerActionSupported(action string) error {
	switch action {
	case "reboot", "shutdown":
		return nil
	case "logoff":
		return fmt.Errorf("logoff is not supported on this platform")
	default:
		return fmt.Errorf("unknown power action %q", action)
	}
}

func doPowerAction(action string, delaySec int, message string, _ bool) error {
	// `shutdown` takes a time spec in minutes or the literal "now".
	// Sub-minute delays round to now.
	when := "now"
	if delaySec >= 60 {
		when = "+" + strconv.Itoa(delaySec/60)
	}
	var args []string
	switch action {
	case "reboot":
		args = []string{"-r", when}
	case "shutdown":
		args = []string{"-h", when}
	default:
		return fmt.Errorf("unsupported power action %q", action)
	}
	if message != "" {
		args = append(args, message)
	}
	return exec.Command("shutdown", args...).Run()
}
