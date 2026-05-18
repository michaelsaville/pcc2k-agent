//go:build windows

package main

// Phase v1.0.2 WS-C — Windows RustDesk peer-id read.
//
// Typical locations:
//   %APPDATA%\RustDesk\config\RustDesk2.toml   (user install)
//   C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml  (service install)
//
// Architect §10 v1.0.1-hotfix preempt: graceful fallback to "" on
// read fail. Non-default install paths must not 500 the posture sweep.

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

func readRustdeskPeerID() string {
	for _, path := range candidateRustdeskPathsWindows() {
		if id := readRustdeskTomlIDWin(path); id != "" {
			return id
		}
	}
	return ""
}

func candidateRustdeskPathsWindows() []string {
	out := []string{}
	if appdata := os.Getenv("APPDATA"); appdata != "" {
		out = append(out, filepath.Join(appdata, "RustDesk", "config", "RustDesk2.toml"))
	}
	out = append(out,
		`C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config\RustDesk2.toml`,
		`C:\Windows\ServiceProfiles\NetworkService\AppData\Roaming\RustDesk\config\RustDesk2.toml`,
		`C:\ProgramData\RustDesk\config\RustDesk2.toml`,
	)
	return out
}

func readRustdeskTomlIDWin(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "id =") || strings.HasPrefix(line, "id=") {
			rest := strings.TrimPrefix(line, "id")
			rest = strings.TrimSpace(rest)
			rest = strings.TrimPrefix(rest, "=")
			rest = strings.TrimSpace(rest)
			rest = strings.Trim(rest, `"'`)
			return rest
		}
	}
	return ""
}
