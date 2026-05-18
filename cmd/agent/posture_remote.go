package main

// Phase v1.0.2 WS-C — RustDesk peer-id self-report (router).
//
// Per-platform readers in posture_remote_{unix,windows}.go return
// the peer-id string ("123 456 789") or empty when RustDesk is not
// installed / config file unreadable. Graceful fallback to null in
// the RemoteReport — never 500s the posture sweep.

func detectRustdesk() string {
	return readRustdeskPeerID()
}

// readRustdeskPeerID is implemented per-platform:
//   posture_remote_unix.go    — Linux + macOS toml files
//   posture_remote_windows.go — registry + RustDesk2.toml
