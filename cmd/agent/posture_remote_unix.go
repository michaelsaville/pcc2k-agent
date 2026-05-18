//go:build !windows

package main

// Phase v1.0.2 WS-C — Linux + macOS RustDesk peer-id read.
//
// Linux: ~/.config/rustdesk/RustDesk2.toml or
//        /root/.config/rustdesk/RustDesk2.toml (service install)
// macOS: ~/Library/Preferences/com.carriez.rustdesk/RustDesk2.toml
//
// The file is TOML with an `id = "<peer-id>"` line near the top.
// We parse with a tiny line-scan rather than pull a TOML dep — the
// shape has been stable since RustDesk 1.2.

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func readRustdeskPeerID() string {
	for _, path := range candidateRustdeskPaths() {
		if id := readRustdeskTomlID(path); id != "" {
			return id
		}
	}
	return ""
}

func candidateRustdeskPaths() []string {
	homes := []string{"/root", os.Getenv("HOME")}
	if u, err := os.UserHomeDir(); err == nil && u != "" {
		homes = append(homes, u)
	}
	out := []string{}
	for _, h := range homes {
		if h == "" {
			continue
		}
		switch runtime.GOOS {
		case "darwin":
			out = append(out,
				filepath.Join(h, "Library/Preferences/com.carriez.rustdesk/RustDesk2.toml"))
		default:
			out = append(out,
				filepath.Join(h, ".config/rustdesk/RustDesk2.toml"))
		}
	}
	return out
}

func readRustdeskTomlID(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "id =") || strings.HasPrefix(line, "id=") {
			// id = "123456789" — strip key + equals + quotes.
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
