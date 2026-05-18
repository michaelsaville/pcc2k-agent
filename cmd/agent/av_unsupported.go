//go:build !windows

package main

// Phase v1.0.2 WS-B — non-Windows AV stub.
//
// Architect §5 option (a): per-product capability advertisement.
// CrowdStrike on linux/macOS is v1.1+ territory; Defender is
// Windows-only. defenderPresent() returns false on these platforms,
// so capabilities.go never advertises "fleet.av" — the FH-side AV
// tab simply isn't shown for non-Windows hosts. No 502-on-click risk.
//
// av.go calls into these functions cross-platform, so the stubs
// have to exist on non-Windows even though the verbs aren't
// expected to fire (capability gating means FH never sends them
// here).

import (
	"context"
	"fmt"
)

func defenderPresent() bool { return false }

func defenderScan(_ context.Context, _, _ string) (string, string, error) {
	return "unsupported-os", "", fmt.Errorf("fleet.av: not supported on this platform")
}

func defenderUpdateDefs(_ context.Context) (string, string, error) {
	return "unsupported-os", "", fmt.Errorf("fleet.av: not supported on this platform")
}

func defenderQuarantine(_ string) (string, string, error) {
	return "unsupported-os", "", fmt.Errorf("fleet.av: not supported on this platform")
}

func defenderRelease(_ string) (string, string, error) {
	return "unsupported-os", "", fmt.Errorf("fleet.av: not supported on this platform")
}

func defenderCancelScan() error {
	return fmt.Errorf("fleet.av: not supported on this platform")
}
