//go:build windows

package main

// Phase v1.0.2 WS-A — placeholder Windows AV check. WS-B replaces
// this with a real Get-MpComputerStatus probe in
// av_defender_windows.go (which removes this stub since both share
// the same build tag and same function signature).
//
// Until WS-B lands: returns false so the agent does not advertise
// fleet.av capability prematurely.

func defenderPresent() bool {
	return false
}
