//go:build linux || darwin
// +build linux darwin

package monitor

import (
	"bufio"
	"os/exec"
	"runtime"
	"strings"
)

// getSoftwareList returns installed software on Unix systems.
func getSoftwareList() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	switch runtime.GOOS {
	case "linux":
		// Try dpkg first (Debian/Ubuntu)
		if items := getDpkgPackages(); len(items) > 0 {
			for k, v := range items {
				software[k] = v
			}
		}
		// Try rpm (RHEL/CentOS/Fedora)
		if items := getRpmPackages(); len(items) > 0 {
			for k, v := range items {
				software[k] = v
			}
		}
	case "darwin":
		// macOS: Use brew and system profiler
		if items := getBrewPackages(); len(items) > 0 {
			for k, v := range items {
				software[k] = v
			}
		}
	}

	return software
}

// getDpkgPackages returns installed dpkg packages.
func getDpkgPackages() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	cmd := exec.Command("dpkg-query", "-W", "-f=${Package}\t${Version}\n")
	output, err := cmd.Output()
	if err != nil {
		return software
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			software[parts[0]] = SoftwareItem{
				Name:    parts[0],
				Version: parts[1],
			}
		}
	}

	return software
}

// getRpmPackages returns installed RPM packages.
func getRpmPackages() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	cmd := exec.Command("rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n")
	output, err := cmd.Output()
	if err != nil {
		return software
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		parts := strings.Split(scanner.Text(), "\t")
		if len(parts) >= 2 {
			software[parts[0]] = SoftwareItem{
				Name:    parts[0],
				Version: parts[1],
			}
		}
	}

	return software
}

// getBrewPackages returns installed Homebrew packages.
func getBrewPackages() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	cmd := exec.Command("brew", "list", "--versions")
	output, err := cmd.Output()
	if err != nil {
		return software
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 2 {
			software[parts[0]] = SoftwareItem{
				Name:    parts[0],
				Version: parts[1],
			}
		}
	}

	return software
}

// getServiceList returns services on Unix systems.
func getServiceList() map[string]ServiceItem {
	services := make(map[string]ServiceItem)

	switch runtime.GOOS {
	case "linux":
		services = getSystemdServices()
	case "darwin":
		services = getLaunchdServices()
	}

	return services
}

// getSystemdServices returns systemd service states.
func getSystemdServices() map[string]ServiceItem {
	services := make(map[string]ServiceItem)

	cmd := exec.Command("systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain", "--no-legend")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			name := strings.TrimSuffix(fields[0], ".service")
			// fields[2] is ACTIVE, fields[3] is SUB
			state := fields[2]
			if fields[2] == "active" && len(fields) > 3 {
				state = fields[3] // Use sub-state (running, exited, etc.)
			}
			services[name] = ServiceItem{
				Name:   name,
				State:  state,
				Status: fields[2],
			}
		}
	}

	return services
}

// getLaunchdServices returns launchd service states on macOS.
func getLaunchdServices() map[string]ServiceItem {
	services := make(map[string]ServiceItem)

	cmd := exec.Command("launchctl", "list")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	// Skip header
	scanner.Scan()

	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 3 {
			name := fields[2]
			pid := fields[0]
			state := "stopped"
			if pid != "-" {
				state = "running"
			}
			services[name] = ServiceItem{
				Name:  name,
				State: state,
			}
		}
	}

	return services
}
