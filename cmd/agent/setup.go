package main

// Deploy-on-the-fly (2026-09-13) — `pcc2k-agent setup`.
//
// One install routine per OS, reachable three ways:
//   1. explicit:     pcc2k-agent setup --key <tenant-key> [--url <fleethub>]
//   2. one-liner:    the /install/k/<key>/pcc2k-agent.{ps1,sh} scripts call (1)
//   3. double-click: the binary downloaded as `pcc2k-agent-<key>.exe` reads
//                    the key out of its OWN FILENAME when run with no args.
//                    Nothing is baked into the bytes, so every client gets
//                    the identical binary and a future Authenticode signature
//                    stays valid.
//
// The tenant key is long-lived (rotated from the FleetHub Install tab); the
// server hands back a per-host secret which is what actually gets stored.

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// defaultFleetHubURL is overridable at build time:
//
//	-ldflags "-X main.defaultFleetHubURL=https://fleethub.example.com"
var defaultFleetHubURL = "https://fleethub.pcc2k.com"

// Matches `pcc2k-agent-<40 hex>` anywhere in the basename, tolerant of the
// " (1)" suffix browsers add to repeat downloads and of the .exe extension.
var filenameKeyRe = regexp.MustCompile(`(?i)pcc2k-agent-([0-9a-f]{40})`)

func keyFromFilename(argv0 string) string {
	m := filenameKeyRe.FindStringSubmatch(filepath.Base(argv0))
	if m == nil {
		return ""
	}
	return strings.ToLower(m[1])
}

type setupOptions struct {
	key     string
	url     string
	role    string
	noPause bool // scripts pass this; the double-click path wants the window to stay
}

func parseSetupArgs(args []string) (setupOptions, error) {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	var o setupOptions
	fs.StringVar(&o.key, "key", os.Getenv("PCC2K_ENROLL_KEY"), "per-client enrollment key from the FleetHub Install tab")
	fs.StringVar(&o.url, "url", envDefault("PCC2K_FLEETHUB_URL", defaultFleetHubURL), "FleetHub base URL")
	fs.StringVar(&o.role, "role", "workstation", "role tag (workstation/server/laptop)")
	fs.BoolVar(&o.noPause, "no-pause", false, "don't wait for a keypress / message box at the end")
	if err := fs.Parse(args); err != nil {
		return o, err
	}
	if o.key == "" {
		o.key = keyFromFilename(os.Args[0])
	}
	if o.key == "" {
		return o, fmt.Errorf("no enrollment key: pass --key, or run the installer under its downloaded name (pcc2k-agent-<key>.exe)")
	}
	o.url = strings.TrimRight(o.url, "/")
	return o, nil
}

// runSetup is the entry point for all three paths. Platform code lives in
// setup_windows.go / setup_other.go.
func runSetup(args []string) int {
	o, err := parseSetupArgs(args)
	if err != nil {
		setupReport(false, err.Error(), o.noPause)
		return 2
	}
	msg, err := setupInstall(o)
	if err != nil {
		setupReport(false, err.Error(), o.noPause)
		return 1
	}
	setupReport(true, msg, o.noPause)
	return 0
}
