//go:build !windows

package main

// Phase v1.0.2 WS-A — per-platform AV stub for non-Windows builds.
//
// avVerbAvailable() in capabilities.go calls defenderPresent() to
// decide whether to advertise "fleet.av". On Linux + macOS the
// answer is always false (Defender is Windows-only; CrowdStrike on
// non-Windows is v1.1+).
//
// WS-B replaces this on Windows with a real Get-MpComputerStatus
// check in av_defender_windows.go.

func defenderPresent() bool {
	return false
}
