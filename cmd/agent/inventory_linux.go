//go:build linux

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func hardwareFacts() Hardware {
	return Hardware{
		Manufacturer: tryRead("/sys/class/dmi/id/sys_vendor", "unknown"),
		Model:        tryRead("/sys/class/dmi/id/product_name", "synthetic"),
		Serial:       tryRead("/sys/class/dmi/id/product_serial", "n/a"),
		CPU:          fmt.Sprintf("%s (%dc)", cpuModel(), runtime.NumCPU()),
		RAMGb:        ramGb(),
		DiskGb:       rootDisk("size") + rootDisk("used"),
		DiskFreeGb:   rootDisk("avail"),
		BIOSVersion:  tryRead("/sys/class/dmi/id/bios_version", "n/a"),
		BIOSDate:     tryRead("/sys/class/dmi/id/bios_date", "1970-01-01"),
		PurchaseDate: "1970-01-01",
	}
}

func osFacts() OSFacts {
	osRel := readOsRelease()
	return OSFacts{
		Family:      "linux",
		Version:     coalesce(osRel["PRETTY_NAME"], runtime.GOOS),
		Build:       runShell("uname", "-r"),
		InstalledAt: time.Now().UTC().Format(time.RFC3339),
		LastBootAt:  bootTime(),
		Timezone:    coalesce(os.Getenv("TZ"), "UTC"),
	}
}

func softwareFacts() Software {
	pkgs := []string{}
	if out := runShell("dpkg-query", "-W", "-f", "${Package} ${Version}\n"); out != "" {
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				pkgs = append(pkgs, line)
			}
		}
	}
	if len(pkgs) == 0 {
		if out := runShell("rpm", "-qa"); out != "" {
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line != "" {
					pkgs = append(pkgs, line)
				}
			}
		}
	}
	sample := pkgs
	if len(sample) > 6 {
		sample = sample[:6]
	}
	return Software{TotalInstalled: len(pkgs), Sample: sample}
}

func healthFacts() Health {
	return Health{
		CPU7d:   0,
		RAMPct:  ramPct(),
		DiskPct: rootDiskPct(),
	}
}

// networkFacts uses pure-Go net.Interfaces() for the NIC inventory and
// shells out to `ss` (iproute2) for socket enumeration. `ss -tlnH` and
// `ss -tnH state established` are the canonical sources; both are
// available on every modern Linux distro we'd manage.
func networkFacts() Network {
	return Network{
		Interfaces:        linuxInterfaces(),
		ListeningPorts:    linuxListeningPorts(),
		RecentConnections: linuxRecentConnections(),
	}
}

func linuxInterfaces() []NetworkInterface {
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
		// Read /sys/class/net/<name>/speed; -1 or absent means unknown
		// (down interface, virtual, etc.).
		if v := tryRead("/sys/class/net/"+iface.Name+"/speed", ""); v != "" {
			if n, err := strconv.Atoi(v); err == nil && n > 0 {
				ni.SpeedMbps = n
			}
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

func linuxListeningPorts() []ListeningPort {
	out := []ListeningPort{}
	out = append(out, parseSSListening("ss", "-tlnHp")...)
	out = append(out, parseSSListening("ss", "-ulnHp")...)
	if len(out) > 200 {
		out = out[:200]
	}
	return out
}

// parseSSListening parses `ss -[t|u]lnHp` output. -H drops the header,
// -p shows the owning process if we have permission. Lines look like:
//   LISTEN  0  128  0.0.0.0:22       0.0.0.0:*  users:(("sshd",pid=...))
// Process column is best-effort.
func parseSSListening(name string, args ...string) []ListeningPort {
	out := []ListeningPort{}
	raw := runShell(name, args...)
	if raw == "" {
		return out
	}
	proto := "tcp"
	if len(args) > 0 && strings.Contains(args[0], "u") {
		proto = "udp"
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// State (LISTEN/UNCONN), Recv-Q, Send-Q, LocalAddress:Port, Peer:*, [users:...]
		addr := fields[3]
		process := ""
		for _, f := range fields[5:] {
			if strings.HasPrefix(f, "users:") {
				// users:(("sshd",pid=12,fd=3)) → "sshd"
				if idx := strings.Index(f, "((\""); idx >= 0 {
					rest := f[idx+3:]
					if end := strings.Index(rest, "\""); end > 0 {
						process = rest[:end]
					}
				}
			}
		}
		out = append(out, ListeningPort{
			Protocol: proto,
			Address:  addr,
			Process:  process,
		})
	}
	return out
}

func linuxRecentConnections() []RecentConnection {
	out := []RecentConnection{}
	raw := runShell("ss", "-tnH", "state", "established")
	if raw == "" {
		return out
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// Recv-Q, Send-Q, Local, Peer
		local := fields[2]
		remote := fields[3]
		// Filter loopback + link-local v6 — local-only chatter, no fleet value.
		if strings.HasPrefix(local, "127.") || strings.HasPrefix(local, "[::1]") {
			continue
		}
		if strings.HasPrefix(remote, "127.") || strings.HasPrefix(remote, "[::1]") {
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
	if v := tryRead("/etc/os-release", ""); v != "" {
		osRel := readOsRelease()
		if pn := osRel["PRETTY_NAME"]; pn != "" {
			return pn
		}
	}
	return "linux"
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

func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH + " cpu"
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) == 2 {
				return strings.TrimSpace(parts[1])
			}
		}
	}
	return runtime.GOARCH + " cpu"
}

func ramGb() float64 {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		return 0
	}
	return float64(info.Totalram*uint64(info.Unit)) / (1024 * 1024 * 1024)
}

func ramPct() float64 {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	var total, available float64
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total, _ = strconv.ParseFloat(fields[1], 64)
		case "MemAvailable:":
			available, _ = strconv.ParseFloat(fields[1], 64)
		}
	}
	if total == 0 {
		return 0
	}
	return ((total - available) / total) * 100
}

func rootDisk(field string) float64 {
	out := runShell("df", "--output="+field, "-BG", "/")
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return 0
	}
	v := strings.TrimSpace(lines[1])
	v = strings.TrimSuffix(v, "G")
	n, _ := strconv.ParseFloat(v, 64)
	return n
}

func rootDiskPct() float64 {
	out := runShell("df", "--output=pcent", "/")
	lines := strings.Split(out, "\n")
	if len(lines) < 2 {
		return 0
	}
	v := strings.TrimSpace(lines[1])
	v = strings.TrimSuffix(v, "%")
	n, _ := strconv.ParseFloat(v, 64)
	return n
}

func bootTime() string {
	out := runShell("uptime", "-s")
	if out == "" {
		return time.Now().UTC().Format(time.RFC3339)
	}
	t, err := time.Parse("2006-01-02 15:04:05", out)
	if err != nil {
		return time.Now().UTC().Format(time.RFC3339)
	}
	return t.UTC().Format(time.RFC3339)
}

func readOsRelease() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		idx := strings.Index(line, "=")
		if idx < 0 {
			continue
		}
		k := line[:idx]
		v := strings.Trim(line[idx+1:], `"`)
		out[k] = v
	}
	return out
}
