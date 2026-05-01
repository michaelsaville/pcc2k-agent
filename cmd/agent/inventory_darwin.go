//go:build darwin

package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// macOS inventory collectors. Heavy lifting goes through:
//   - system_profiler -json    (hardware, OS, software/applications)
//   - sysctl                   (CPU model, memsize)
//   - sw_vers                  (OS version/build)
//   - df / vm_stat             (health metrics)
//   - netstat / lsof           (network sockets)
//
// Apps enumeration via system_profiler SPApplicationsDataType is slow
// (~10-30s on a typical laptop). For inventory.report we cap the
// sample at 6 entries like Linux/Windows; the full count is reported
// separately. The slow call is a once-per-15-min cost, fine.

func hardwareFacts() Hardware {
	hw := spJSON("SPHardwareDataType")
	mem := runShell("sysctl", "-n", "hw.memsize")
	cpuName := runShell("sysctl", "-n", "machdep.cpu.brand_string")

	manufacturer := "Apple"
	model := str(hw["machine_model"])
	if model == "" {
		model = str(hw["model_name"])
	}
	if model == "" {
		model = "Mac"
	}
	serial := str(hw["serial_number"])
	if serial == "" {
		serial = "n/a"
	}
	if cpuName == "" {
		cpuName = runtime.GOARCH + " cpu"
	}

	var ramGb float64
	if mem != "" {
		if n, err := strconv.ParseInt(strings.TrimSpace(mem), 10, 64); err == nil {
			ramGb = float64(n) / (1024 * 1024 * 1024)
		}
	}

	totalDisk, freeDisk := rootDiskGb()

	bios := spJSON("SPHardwareDataType")
	biosVer := str(bios["boot_rom_version"])
	if biosVer == "" {
		biosVer = "n/a"
	}
	smcVer := str(bios["SMC_version_system"])
	if smcVer != "" {
		biosVer = biosVer + " (SMC " + smcVer + ")"
	}

	return Hardware{
		Manufacturer: manufacturer,
		Model:        model,
		Serial:       serial,
		CPU:          fmt.Sprintf("%s (%dc)", cpuName, runtime.NumCPU()),
		RAMGb:        ramGb,
		DiskGb:       totalDisk,
		DiskFreeGb:   freeDisk,
		BIOSVersion:  biosVer,
		BIOSDate:     "1970-01-01",
		PurchaseDate: "1970-01-01",
	}
}

func osFacts() OSFacts {
	productName := strings.TrimSpace(runShell("sw_vers", "-productName"))
	productVer := strings.TrimSpace(runShell("sw_vers", "-productVersion"))
	build := strings.TrimSpace(runShell("sw_vers", "-buildVersion"))
	if productName == "" {
		productName = "macOS"
	}
	version := productName
	if productVer != "" {
		version = productName + " " + productVer
	}

	// Last boot via sysctl kern.boottime — Darwin emits e.g.
	//   { sec = 1714579200, usec = 0 } Wed May  1 12:00:00 2024
	lastBoot := time.Now().UTC()
	if raw := runShell("sysctl", "-n", "kern.boottime"); raw != "" {
		if idx := strings.Index(raw, "sec = "); idx >= 0 {
			rest := raw[idx+6:]
			if comma := strings.IndexAny(rest, ",}"); comma > 0 {
				if n, err := strconv.ParseInt(strings.TrimSpace(rest[:comma]), 10, 64); err == nil {
					lastBoot = time.Unix(n, 0).UTC()
				}
			}
		}
	}

	tz := os.Getenv("TZ")
	if tz == "" {
		tz = strings.TrimSpace(runShell("readlink", "/etc/localtime"))
		if idx := strings.Index(tz, "zoneinfo/"); idx >= 0 {
			tz = tz[idx+len("zoneinfo/"):]
		}
	}
	if tz == "" {
		tz = "UTC"
	}

	return OSFacts{
		Family:      "darwin",
		Version:     version,
		Build:       build,
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		LastBootAt:  lastBoot.Format(time.RFC3339),
		Timezone:    tz,
	}
}

// softwareFacts uses `system_profiler SPApplicationsDataType -json`.
// Slow but authoritative — covers /Applications, /Applications/Utilities,
// ~/Applications, and any third-party install root macOS knows about.
func softwareFacts() Software {
	out := runShell("system_profiler", "-json", "SPApplicationsDataType")
	if out == "" {
		return Software{}
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return Software{}
	}
	rawApps, ok := parsed["SPApplicationsDataType"].([]interface{})
	if !ok {
		return Software{}
	}
	pkgs := make([]string, 0, len(rawApps))
	for _, a := range rawApps {
		am, ok := a.(map[string]interface{})
		if !ok {
			continue
		}
		name := str(am["_name"])
		ver := str(am["version"])
		if name == "" {
			continue
		}
		entry := name
		if ver != "" {
			entry = name + " " + ver
		}
		pkgs = append(pkgs, entry)
	}
	sample := pkgs
	if len(sample) > 6 {
		sample = sample[:6]
	}
	return Software{TotalInstalled: len(pkgs), Sample: sample}
}

func healthFacts() Health {
	totalDisk, freeDisk := rootDiskGb()
	diskPct := 0.0
	if totalDisk > 0 {
		diskPct = ((totalDisk - freeDisk) / totalDisk) * 100
	}
	return Health{
		CPU7d:   0,
		RAMPct:  ramUsedPctDarwin(),
		DiskPct: diskPct,
	}
}

// ramUsedPctDarwin parses `vm_stat` output. Pages are 4 KiB on Apple
// Silicon and 4 KiB on Intel — vm_stat reports 4096 in both cases as
// the "page size of N bytes" header line.
func ramUsedPctDarwin() float64 {
	out := runShell("vm_stat")
	if out == "" {
		return 0
	}
	pageSize := 4096.0
	var free, active, inactive, wired, compressed float64
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "Mach Virtual Memory Statistics:") {
			continue
		}
		if strings.HasPrefix(line, "page size of ") {
			fields := strings.Fields(line)
			if len(fields) >= 4 {
				if n, err := strconv.ParseFloat(fields[3], 64); err == nil && n > 0 {
					pageSize = n
				}
			}
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(line[:idx])
		val := strings.TrimSpace(strings.TrimSuffix(line[idx+1:], "."))
		n, err := strconv.ParseFloat(val, 64)
		if err != nil {
			continue
		}
		switch key {
		case "Pages free":
			free = n
		case "Pages active":
			active = n
		case "Pages inactive":
			inactive = n
		case "Pages wired down":
			wired = n
		case "Pages occupied by compressor":
			compressed = n
		}
	}
	used := (active + wired + compressed) * pageSize
	total := (free + active + inactive + wired + compressed) * pageSize
	if total == 0 {
		return 0
	}
	return (used / total) * 100
}

func rootDiskGb() (totalGb, freeGb float64) {
	out := runShell("df", "-k", "/")
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return 0, 0
	}
	fields := strings.Fields(lines[1])
	if len(fields) < 4 {
		return 0, 0
	}
	totalKB, _ := strconv.ParseFloat(fields[1], 64)
	usedKB, _ := strconv.ParseFloat(fields[2], 64)
	availKB, _ := strconv.ParseFloat(fields[3], 64)
	totalGb = (totalKB + usedKB) / (1024 * 1024)
	if totalKB > 0 {
		totalGb = totalKB / (1024 * 1024)
	}
	freeGb = availKB / (1024 * 1024)
	return totalGb, freeGb
}

func networkFacts() Network {
	return Network{
		Interfaces:        darwinInterfaces(),
		ListeningPorts:    darwinListeningPorts(),
		RecentConnections: darwinRecentConnections(),
	}
}

func darwinInterfaces() []NetworkInterface {
	out := []NetworkInterface{}
	ifs, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, iface := range ifs {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		ni := NetworkInterface{
			Name: iface.Name,
			MAC:  iface.HardwareAddr.String(),
			Up:   iface.Flags&net.FlagUp != 0,
		}
		addrs, _ := iface.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil {
				continue
			}
			if ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() != nil {
				ni.IPv4 = append(ni.IPv4, ip.String())
			} else {
				ni.IPv6 = append(ni.IPv6, ip.String())
			}
		}
		out = append(out, ni)
	}
	return out
}

// darwinListeningPorts uses `lsof -nP -iTCP -sTCP:LISTEN` and the same
// for UDP. -n disables DNS lookup, -P keeps numeric ports.
func darwinListeningPorts() []ListeningPort {
	out := []ListeningPort{}
	out = append(out, parseLsofListening("tcp", runShell("lsof", "-nP", "-iTCP", "-sTCP:LISTEN"))...)
	out = append(out, parseLsofListening("udp", runShell("lsof", "-nP", "-iUDP"))...)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// parseLsofListening parses lsof's column-aligned output. lsof line:
//   COMMAND     PID  USER   FD   TYPE DEVICE SIZE/OFF NODE NAME
//   sshd        123  root    3u  IPv4   ...   ...    ...  *:22 (LISTEN)
func parseLsofListening(proto, raw string) []ListeningPort {
	out := []ListeningPort{}
	if raw == "" {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "COMMAND ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 9 {
			continue
		}
		cmd := fields[0]
		name := fields[8]
		// "*:22" or "127.0.0.1:8080"
		out = append(out, ListeningPort{
			Protocol: proto,
			Address:  name,
			Process:  cmd,
		})
	}
	return out
}

func darwinRecentConnections() []RecentConnection {
	out := []RecentConnection{}
	raw := runShell("netstat", "-an", "-p", "tcp")
	if raw == "" {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}
		// Active Internet connections header lines don't have 6 fields.
		if fields[0] != "tcp4" && fields[0] != "tcp6" {
			continue
		}
		local := fields[3]
		remote := fields[4]
		state := fields[5]
		if state != "ESTABLISHED" {
			continue
		}
		if strings.HasPrefix(local, "127.") || strings.HasPrefix(local, "::1") {
			continue
		}
		if strings.HasPrefix(remote, "127.") || strings.HasPrefix(remote, "::1") {
			continue
		}
		out = append(out, RecentConnection{
			Protocol: "tcp",
			Local:    local,
			Remote:   remote,
			State:    "ESTABLISHED",
		})
		if len(out) >= 50 {
			break
		}
	}
	return out
}

func runtimeOSVersion() string {
	productName := strings.TrimSpace(runShell("sw_vers", "-productName"))
	productVer := strings.TrimSpace(runShell("sw_vers", "-productVersion"))
	if productName == "" {
		return "darwin"
	}
	if productVer == "" {
		return productName
	}
	return productName + " " + productVer
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

// spJSON runs `system_profiler -json <type>` and unwraps the standard
// SPApplicationsDataType-style outer array → first object.
func spJSON(dataType string) map[string]interface{} {
	out := runShell("system_profiler", "-json", dataType)
	if out == "" {
		return map[string]interface{}{}
	}
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		return map[string]interface{}{}
	}
	if arr, ok := parsed[dataType].([]interface{}); ok && len(arr) > 0 {
		if first, ok := arr[0].(map[string]interface{}); ok {
			return first
		}
	}
	return map[string]interface{}{}
}

// Helpers shared with the windows path. inventory_windows.go also
// declares these — but darwin and windows builds are mutually exclusive
// at compile time, so no symbol collision.
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
