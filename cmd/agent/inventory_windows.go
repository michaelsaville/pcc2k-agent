//go:build windows

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

// Windows inventory uses PowerShell for CIM/WMI queries (broad
// compatibility back to PS 5.1 — see feedback memory
// `feedback_powershell_version_compat.md`) plus registry reads for
// installed-software enumeration (faster + no shell-out cost per app).
//
// Avoid PowerShell 7-only flags. `ConvertTo-Json -Compress` is fine
// (PS 5.1+); `-AsArray` is NOT (PS 7 only).

func hardwareFacts() Hardware {
	cs := psJSON(`Get-CimInstance Win32_ComputerSystem | Select-Object Manufacturer,Model,TotalPhysicalMemory | ConvertTo-Json -Compress`)
	bios := psJSON(`Get-CimInstance Win32_BIOS | Select-Object SerialNumber,SMBIOSBIOSVersion,ReleaseDate | ConvertTo-Json -Compress`)
	cpu := psJSON(`Get-CimInstance Win32_Processor | Select-Object -First 1 Name,NumberOfCores | ConvertTo-Json -Compress`)
	disk := psJSON(`Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace | ConvertTo-Json -Compress`)

	manufacturer := str(cs["Manufacturer"])
	if manufacturer == "" {
		manufacturer = "unknown"
	}
	model := str(cs["Model"])
	if model == "" {
		model = "unknown"
	}
	serial := str(bios["SerialNumber"])
	if serial == "" {
		serial = "n/a"
	}
	cpuName := strings.TrimSpace(str(cpu["Name"]))
	if cpuName == "" {
		cpuName = runtime.GOARCH + " cpu"
	}
	cores := numInt(cpu["NumberOfCores"])
	if cores == 0 {
		cores = runtime.NumCPU()
	}

	totalRAMBytes := numFloat(cs["TotalPhysicalMemory"])
	totalDiskBytes := numFloat(disk["Size"])
	freeDiskBytes := numFloat(disk["FreeSpace"])

	biosVer := str(bios["SMBIOSBIOSVersion"])
	if biosVer == "" {
		biosVer = "n/a"
	}
	biosDate := parseCimDate(str(bios["ReleaseDate"]))
	if biosDate == "" {
		biosDate = "1970-01-01"
	}

	return Hardware{
		Manufacturer: manufacturer,
		Model:        model,
		Serial:       serial,
		CPU:          fmt.Sprintf("%s (%dc)", cpuName, cores),
		RAMGb:        totalRAMBytes / (1024 * 1024 * 1024),
		DiskGb:       totalDiskBytes / (1024 * 1024 * 1024),
		DiskFreeGb:   freeDiskBytes / (1024 * 1024 * 1024),
		BIOSVersion:  biosVer,
		BIOSDate:     biosDate,
		PurchaseDate: "1970-01-01",
	}
}

func osFacts() OSFacts {
	o := psJSON(`Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,InstallDate,LastBootUpTime | ConvertTo-Json -Compress`)
	tz := os.Getenv("TZ")
	if tz == "" {
		tz = strings.TrimSpace(runShell("powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-TimeZone).Id"))
	}
	if tz == "" {
		tz = "UTC"
	}
	return OSFacts{
		Family:      "windows",
		Version:     coalesce(str(o["Caption"]), "Windows"),
		Build:       coalesce(str(o["BuildNumber"]), str(o["Version"])),
		InstalledAt: parseCimDate(str(o["InstallDate"])),
		LastBootAt:  parseCimDate(str(o["LastBootUpTime"])),
		Timezone:    tz,
	}
}

// softwareFacts enumerates installed apps from the standard Windows
// uninstall registry hives. We read three locations:
//   - HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
//   - HKLM\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall  (32-bit on 64-bit)
//   - HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
//
// Faster than `Get-CimInstance Win32_Product` (which triggers MSI
// repair on every package — known-bad — see KB 974524).
func softwareFacts() Software {
	seen := map[string]struct{}{}
	pkgs := []string{}

	for _, hive := range []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`},
		{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`},
	} {
		k, err := registry.OpenKey(hive.root, hive.path, registry.READ|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			continue
		}
		subKeys, err := k.ReadSubKeyNames(-1)
		k.Close()
		if err != nil {
			continue
		}
		for _, sub := range subKeys {
			subKey, err := registry.OpenKey(hive.root, hive.path+`\`+sub, registry.READ)
			if err != nil {
				continue
			}
			name, _, _ := subKey.GetStringValue("DisplayName")
			version, _, _ := subKey.GetStringValue("DisplayVersion")
			systemComp, _, _ := subKey.GetIntegerValue("SystemComponent")
			subKey.Close()
			name = strings.TrimSpace(name)
			if name == "" || systemComp == 1 {
				continue
			}
			entry := name
			if version != "" {
				entry = name + " " + version
			}
			if _, dup := seen[entry]; dup {
				continue
			}
			seen[entry] = struct{}{}
			pkgs = append(pkgs, entry)
		}
	}

	sample := pkgs
	if len(sample) > 6 {
		sample = sample[:6]
	}
	return Software{TotalInstalled: len(pkgs), Sample: sample}
}

func healthFacts() Health {
	mem := psJSON(`Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json -Compress`)
	disk := psJSON(`Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'" | Select-Object Size,FreeSpace | ConvertTo-Json -Compress`)

	totalKB := numFloat(mem["TotalVisibleMemorySize"])
	freeKB := numFloat(mem["FreePhysicalMemory"])
	ramPct := 0.0
	if totalKB > 0 {
		ramPct = ((totalKB - freeKB) / totalKB) * 100
	}

	totalDisk := numFloat(disk["Size"])
	freeDisk := numFloat(disk["FreeSpace"])
	diskPct := 0.0
	if totalDisk > 0 {
		diskPct = ((totalDisk - freeDisk) / totalDisk) * 100
	}

	return Health{
		CPU7d:   0,
		RAMPct:  ramPct,
		DiskPct: diskPct,
	}
}

func runtimeOSVersion() string {
	caption := strings.TrimSpace(runShell("powershell", "-NoProfile", "-NonInteractive", "-Command", "(Get-CimInstance Win32_OperatingSystem).Caption"))
	if caption == "" {
		return "windows"
	}
	return caption
}

func tryRead(path, fallback string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return fallback
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return fallback
	}
	return s
}

// psJSON runs a PowerShell command that emits JSON and unmarshals it
// into a map. Handles both `Get-CimInstance` (object) and array
// outputs (we collapse arrays to first element since we only ever
// query single-row info this way). Returns an empty map on error.
func psJSON(script string) map[string]interface{} {
	out := runShell("powershell", "-NoProfile", "-NonInteractive", "-Command", script)
	if out == "" {
		return map[string]interface{}{}
	}
	var single map[string]interface{}
	if err := json.Unmarshal([]byte(out), &single); err == nil {
		return single
	}
	var arr []map[string]interface{}
	if err := json.Unmarshal([]byte(out), &arr); err == nil && len(arr) > 0 {
		return arr[0]
	}
	return map[string]interface{}{}
}

func str(v interface{}) string {
	if v == nil {
		return ""
	}
	switch t := v.(type) {
	case string:
		return strings.TrimSpace(t)
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	default:
		return fmt.Sprintf("%v", t)
	}
}

func numFloat(v interface{}) float64 {
	switch t := v.(type) {
	case float64:
		return t
	case string:
		var f float64
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%f", &f)
		return f
	default:
		return 0
	}
}

func numInt(v interface{}) int {
	switch t := v.(type) {
	case float64:
		return int(t)
	case string:
		var n int
		_, _ = fmt.Sscanf(strings.TrimSpace(t), "%d", &n)
		return n
	default:
		return 0
	}
}

// parseCimDate accepts the two formats Get-CimInstance | ConvertTo-Json
// can emit for DateTime properties:
//   1. "/Date(1234567890123)/"      — millis-since-epoch wrapped
//   2. "20240301120000.000000-300"  — DMTF datetime (raw WMI form)
// Returns RFC3339 UTC, or "" on parse failure.
func parseCimDate(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "/Date(") && strings.HasSuffix(s, ")/") {
		inner := s[6 : len(s)-2]
		if idx := strings.IndexAny(inner, "+-"); idx > 0 {
			inner = inner[:idx]
		}
		var ms int64
		if _, err := fmt.Sscanf(inner, "%d", &ms); err == nil {
			return time.Unix(0, ms*int64(time.Millisecond)).UTC().Format(time.RFC3339)
		}
	}
	if len(s) >= 14 {
		t, err := time.Parse("20060102150405", s[:14])
		if err == nil {
			return t.UTC().Format(time.RFC3339)
		}
	}
	return ""
}
