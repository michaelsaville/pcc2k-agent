package main

// Phase 1 / v1.0.1 WS-A — capability self-detection.
//
// Replaces the hardcoded `["agent", "inventory", "alerts"]` in the
// agent.hello payload. FleetHub Phase 13 capability-gates action
// buttons (XtermDrawer, /devices/[id]?tab=services + ?tab=av) by
// reading these flags off agent.hello — buttons render DISABLED
// with tooltip when the agent doesn't advertise the verb, instead
// of 502'ing on click.
//
// Detection runs ONCE at startup. We don't re-detect mid-session
// because (a) the protocol has no capability-change frame and (b) a
// host's installed software set rarely changes during a single
// session.

import (
	"os/exec"
	"runtime"
)

// detectCapabilities returns the list advertised in agent.hello.
// Always includes the baseline "agent" + "inventory" + "alerts" so
// existing FleetHub behavior never regresses; adds "fleet.shell" /
// "fleet.file" / "fleet.backup" when the host can actually handle
// the verbs.
//
// v1.0.2 will append "fleet.services" + "fleet.av" via separate
// detection branches.
func detectCapabilities() []string {
	caps := []string{"agent", "inventory", "alerts"}
	if shellAvailable() {
		caps = append(caps, "fleet.shell")
	}
	if fileTransferAvailable() {
		caps = append(caps, "fleet.file")
	}
	if backupVerbAvailable() {
		caps = append(caps, "fleet.backup")
	}
	// v1.0.2 — fleet.processes always (every platform can list);
	// fleet.services only when control verbs work (linux + windows;
	// macOS list-only is exposed via fleet.processes).
	caps = append(caps, "fleet.processes")
	if servicesControlAvailable() {
		caps = append(caps, "fleet.services")
	}
	if avVerbAvailable() {
		caps = append(caps, "fleet.av")
	}
	// WS-C — power control (reboot/shutdown/logoff). Every platform can
	// reboot/shutdown; logoff is Windows-only and gated in the handler.
	caps = append(caps, "fleet.power")
	return caps
}

// servicesControlAvailable returns true on linux + windows. macOS's
// services_darwin.go controlService() returns an error — don't
// advertise the capability so FH renders buttons disabled with
// tooltip rather than 502 on click.
func servicesControlAvailable() bool {
	switch runtime.GOOS {
	case "linux", "windows":
		return true
	default:
		return false
	}
}

// avVerbAvailable returns true when this host has a supported AV
// product the agent can drive. v1.0.2 supports Defender only on
// Windows (see av.go). Linux + Darwin always return false; CrowdStrike
// support is v1.1+ territory.
//
// The actual product probe lives in av_defender_windows.go behind
// a build tag; this thin helper just routes by OS and lets the
// platform decide.
func avVerbAvailable() bool {
	return defenderPresent()
}

// shellAvailable probes for a usable shell on this host. Windows:
// powershell.exe. Unix: /bin/bash falls back to /bin/sh. Caller
// guarantees the verb handler can spawn what it advertises.
func shellAvailable() bool {
	if runtime.GOOS == "windows" {
		_, err := exec.LookPath("powershell.exe")
		return err == nil
	}
	for _, candidate := range []string{"bash", "sh"} {
		if _, err := exec.LookPath(candidate); err == nil {
			return true
		}
	}
	return false
}

// fileTransferAvailable: the agent's file_transfer.go ships
// cross-platform with stdlib only, so this is always true once the
// build includes the file. Kept as a flag so the verb dispatcher
// and capability table stay in lockstep.
func fileTransferAvailable() bool {
	return true
}

// backupVerbAvailable reuses the existing Phase 8 posture detector.
// If the host has a known backup product installed (wbadmin / Veeam
// / Macrium / restic / borg / duplicati / TimeMachine), the agent
// can run backup.trigger against it. If detectBackup() returns
// product="none", the verb would 400 server-side anyway — better
// to not advertise capability than to mislead.
func backupVerbAvailable() bool {
	rep := detectBackup()
	return rep.Product != "" && rep.Product != "none"
}
