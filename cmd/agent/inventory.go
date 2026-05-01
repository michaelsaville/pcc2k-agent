package main

import (
	"os/exec"
	"runtime"
	"strings"
	"time"
)

type Hardware struct {
	Manufacturer string  `json:"manufacturer"`
	Model        string  `json:"model"`
	Serial       string  `json:"serial"`
	CPU          string  `json:"cpu"`
	RAMGb        float64 `json:"ramGb"`
	DiskGb       float64 `json:"diskGb"`
	DiskFreeGb   float64 `json:"diskFreeGb"`
	BIOSVersion  string  `json:"biosVersion"`
	BIOSDate     string  `json:"biosDate"`
	PurchaseDate string  `json:"purchaseDate"`
}

type OSFacts struct {
	Family      string `json:"family"`
	Version     string `json:"version"`
	Build       string `json:"build"`
	InstalledAt string `json:"installedAt"`
	LastBootAt  string `json:"lastBootAt"`
	Timezone    string `json:"timezone"`
}

type Patches struct {
	LastChecked string `json:"lastChecked"`
	Pending     int    `json:"pending"`
	Failed      int    `json:"failed"`
}

type Software struct {
	TotalInstalled int      `json:"totalInstalled"`
	Sample         []string `json:"sample"`
}

type Health struct {
	CPU7d   float64 `json:"cpu7d"`
	RAMPct  float64 `json:"ramPct"`
	DiskPct float64 `json:"diskPct"`
}

type InventorySnapshot struct {
	Hardware Hardware `json:"hardware"`
	OS       OSFacts  `json:"os"`
	Patches  Patches  `json:"patches"`
	Software Software `json:"software"`
	Health   Health   `json:"health"`
}

type DeviceFacts struct {
	ClientName string `json:"clientName"`
	Hostname   string `json:"hostname"`
	OS         string `json:"os,omitempty"`
	OSVersion  string `json:"osVersion,omitempty"`
	IPAddress  string `json:"ipAddress,omitempty"`
	Role       string `json:"role,omitempty"`
}

// collectInventory builds an InventorySnapshot for the host. The
// hardware/OS/software/health facts come from per-OS implementations
// (inventory_linux.go, inventory_windows.go) selected at compile time
// via build tags; this function is the platform-neutral assembler.
func collectInventory() InventorySnapshot {
	return InventorySnapshot{
		Hardware: hardwareFacts(),
		OS:       osFacts(),
		Patches:  Patches{LastChecked: time.Now().UTC().Format(time.RFC3339), Pending: 0, Failed: 0},
		Software: softwareFacts(),
		Health:   healthFacts(),
	}
}

func detectFamily() string {
	switch runtime.GOOS {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}

// runShell runs a command and returns its trimmed stdout, "" on error.
// Platform-neutral — both Linux helpers and the Windows PowerShell
// wrapper use it.
func runShell(name string, args ...string) string {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func coalesce(s ...string) string {
	for _, x := range s {
		if x != "" {
			return x
		}
	}
	return ""
}
