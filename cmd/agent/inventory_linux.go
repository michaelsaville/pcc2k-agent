//go:build linux

package main

import (
	"bufio"
	"fmt"
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
