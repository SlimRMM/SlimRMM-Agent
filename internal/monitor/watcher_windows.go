//go:build windows

package monitor

import (
	"bufio"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/slimrmm/slimrmm-agent/internal/winget"
	"golang.org/x/sys/windows/registry"
)

// getSoftwareList returns installed software on Windows systems.
func getSoftwareList() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	// Query 64-bit registry
	if items := getRegistrySoftware(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`); len(items) > 0 {
		for k, v := range items {
			software[k] = v
		}
	}

	// Query 32-bit registry (WoW6432Node)
	if items := getRegistrySoftware(registry.LOCAL_MACHINE, `SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall`); len(items) > 0 {
		for k, v := range items {
			software[k] = v
		}
	}

	// Query current user installations
	if items := getRegistrySoftware(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall`); len(items) > 0 {
		for k, v := range items {
			software[k] = v
		}
	}

	// Try winget if available
	if items := getWingetPackages(); len(items) > 0 {
		for k, v := range items {
			if _, exists := software[k]; !exists {
				software[k] = v
			}
		}
	}

	return software
}

// getRegistrySoftware reads installed software from Windows registry.
func getRegistrySoftware(root registry.Key, path string) map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	key, err := registry.OpenKey(root, path, registry.READ)
	if err != nil {
		return software
	}
	defer key.Close()

	subkeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return software
	}

	for _, subkeyName := range subkeys {
		subkey, err := registry.OpenKey(key, subkeyName, registry.READ)
		if err != nil {
			continue
		}

		name, _, _ := subkey.GetStringValue("DisplayName")
		version, _, _ := subkey.GetStringValue("DisplayVersion")
		subkey.Close()

		if name == "" {
			continue
		}

		software[name] = SoftwareItem{
			Name:    name,
			Version: version,
		}
	}

	return software
}

// getWingetPackages returns installed packages via winget.
func getWingetPackages() map[string]SoftwareItem {
	software := make(map[string]SoftwareItem)

	// Check if winget is available using the winget client
	wingetClient := winget.GetDefault()
	if !wingetClient.IsAvailable() {
		slog.Debug("winget not available for software inventory")
		return software
	}

	wingetPath := wingetClient.GetBinaryPath()
	if wingetPath == "" {
		return software
	}

	cmd := exec.Command(wingetPath, "list", "--disable-interactivity", "--accept-source-agreements")
	output, err := cmd.Output()
	if err != nil {
		slog.Debug("winget list command failed", "error", err)
		return software
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	separatorFound := false

	for scanner.Scan() {
		line := scanner.Text()

		// Skip until we find the separator line (dashes)
		if !separatorFound {
			if strings.HasPrefix(line, "---") || strings.HasPrefix(line, "───") {
				separatorFound = true
			}
			continue
		}

		// Parse package line: Name Id Version Source
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			// Name might contain spaces, so we need to find the version
			name := fields[0]
			version := ""

			for i := 1; i < len(fields); i++ {
				if isVersionString(fields[i]) {
					version = fields[i]
					break
				}
				name += " " + fields[i]
			}

			if name != "" {
				software[name] = SoftwareItem{
					Name:    name,
					Version: version,
				}
			}
		}
	}

	return software
}

// isVersionString checks if a string looks like a version number.
func isVersionString(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Check if it starts with a digit and contains dots or dashes
	if s[0] < '0' || s[0] > '9' {
		return false
	}
	for _, c := range s {
		if c != '.' && c != '-' && c != '_' && (c < '0' || c > '9') && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') {
			return false
		}
	}
	return true
}

// getServiceList returns services on Windows systems.
func getServiceList() map[string]ServiceItem {
	services := make(map[string]ServiceItem)

	// Use sc query to get service list
	cmd := exec.Command("sc", "query", "type=", "service", "state=", "all")
	output, err := cmd.Output()
	if err != nil {
		return services
	}

	var currentService string
	var currentState string

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "SERVICE_NAME:") {
			// Save previous service if exists
			if currentService != "" {
				services[currentService] = ServiceItem{
					Name:  currentService,
					State: currentState,
				}
			}
			currentService = strings.TrimSpace(strings.TrimPrefix(line, "SERVICE_NAME:"))
			currentState = "unknown"
		} else if strings.HasPrefix(line, "STATE") {
			// Parse state: STATE              : 4  RUNNING
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				statePart := strings.TrimSpace(parts[1])
				stateFields := strings.Fields(statePart)
				if len(stateFields) >= 2 {
					currentState = strings.ToLower(stateFields[1])
				}
			}
		}
	}

	// Don't forget the last service
	if currentService != "" {
		services[currentService] = ServiceItem{
			Name:  currentService,
			State: currentState,
		}
	}

	return services
}
