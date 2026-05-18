//go:build windows

package main

// Phase v1.0.2 WS-A — Windows service control via sc.exe + Get-Service.
//
// Get-Service via PowerShell gives Name + DisplayName + Status +
// StartType in one shot. sc.exe is faster for individual control
// verbs (avoids PowerShell startup cost ~300ms).

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

type psService struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Status      int    `json:"Status"`
	StartType   int    `json:"StartType"`
}

// Windows Service Status enum values from System.ServiceProcess.ServiceControllerStatus.
var winStatusMap = map[int]string{
	1: "stopped",
	2: "starting", // StartPending
	3: "stopping", // StopPending
	4: "running",
	5: "pausing", // ContinuePending
	6: "paused",  // PausePending
	7: "paused",  // Paused
}

var winStartTypeMap = map[int]string{
	0: "boot",
	1: "system",
	2: "auto",
	3: "manual",
	4: "disabled",
}

func listServices() ([]Service, error) {
	// PowerShell ConvertTo-Json on Get-Service is the cleanest cross-
	// version (Win10/Win11/Server) shape. Compress=$true keeps the
	// output small.
	cmd := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
		"-Command",
		"Get-Service | Select-Object Name, DisplayName, "+
			"@{n='Status';e={[int]$_.Status}}, "+
			"@{n='StartType';e={[int]$_.StartType}} "+
			"| ConvertTo-Json -Compress")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("Get-Service: %w", err)
	}
	raw := strings.TrimSpace(string(out))
	if raw == "" {
		return nil, nil
	}
	// Get-Service returns a bare object when there's only one service;
	// wrap in array for json.Unmarshal.
	if raw[0] == '{' {
		raw = "[" + raw + "]"
	}
	var rows []psService
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return nil, fmt.Errorf("parse Get-Service: %w", err)
	}
	svcs := make([]Service, 0, len(rows))
	for _, r := range rows {
		svcs = append(svcs, Service{
			Name:        r.Name,
			DisplayName: r.DisplayName,
			State:       winStatusMap[r.Status],
			StartupType: winStartTypeMap[r.StartType],
		})
	}
	return svcs, nil
}

func controlService(name, verb string) (string, error) {
	var args []string
	switch verb {
	case "start":
		args = []string{"start", name}
	case "stop":
		args = []string{"stop", name}
	case "restart":
		// sc.exe has no restart verb — do stop+start. PowerShell's
		// Restart-Service is the cleaner shape and handles
		// dependent services.
		out, err := exec.Command("powershell.exe", "-NoLogo", "-NoProfile",
			"-Command", fmt.Sprintf("Restart-Service -Name '%s' -Force",
				strings.ReplaceAll(name, "'", "''"))).CombinedOutput()
		return string(out), err
	default:
		return "", fmt.Errorf("unknown verb %q", verb)
	}
	out, err := exec.Command("sc.exe", args...).CombinedOutput()
	return string(out), err
}
