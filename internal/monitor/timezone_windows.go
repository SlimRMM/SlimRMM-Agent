//go:build windows

package monitor

import (
	"time"

	"golang.org/x/sys/windows/registry"
)

// windowsToIANA maps Windows timezone IDs to IANA timezone names.
// This is a subset of common timezones; full mapping would be much larger.
var windowsToIANA = map[string]string{
	"Pacific Standard Time":           "America/Los_Angeles",
	"Mountain Standard Time":          "America/Denver",
	"Central Standard Time":           "America/Chicago",
	"Eastern Standard Time":           "America/New_York",
	"Atlantic Standard Time":          "America/Halifax",
	"Newfoundland Standard Time":      "America/St_Johns",
	"Alaskan Standard Time":           "America/Anchorage",
	"Hawaiian Standard Time":          "Pacific/Honolulu",
	"UTC":                             "UTC",
	"GMT Standard Time":               "Europe/London",
	"W. Europe Standard Time":         "Europe/Berlin",
	"Romance Standard Time":           "Europe/Paris",
	"Central European Standard Time":  "Europe/Warsaw",
	"E. Europe Standard Time":         "Europe/Chisinau",
	"FLE Standard Time":               "Europe/Kiev",
	"GTB Standard Time":               "Europe/Bucharest",
	"Russian Standard Time":           "Europe/Moscow",
	"E. Africa Standard Time":         "Africa/Nairobi",
	"South Africa Standard Time":      "Africa/Johannesburg",
	"Egypt Standard Time":             "Africa/Cairo",
	"W. Central Africa Standard Time": "Africa/Lagos",
	"Arabian Standard Time":           "Asia/Dubai",
	"India Standard Time":             "Asia/Kolkata",
	"Singapore Standard Time":         "Asia/Singapore",
	"China Standard Time":             "Asia/Shanghai",
	"Tokyo Standard Time":             "Asia/Tokyo",
	"Korea Standard Time":             "Asia/Seoul",
	"AUS Eastern Standard Time":       "Australia/Sydney",
	"AUS Central Standard Time":       "Australia/Darwin",
	"Cen. Australia Standard Time":    "Australia/Adelaide",
	"E. Australia Standard Time":      "Australia/Brisbane",
	"W. Australia Standard Time":      "Australia/Perth",
	"New Zealand Standard Time":       "Pacific/Auckland",
	"SA Eastern Standard Time":        "America/Sao_Paulo",
	"Argentina Standard Time":         "America/Buenos_Aires",
	"Venezuela Standard Time":         "America/Caracas",
	"Central America Standard Time":   "America/Guatemala",
	"Mexico Standard Time":            "America/Mexico_City",
	"Israel Standard Time":            "Asia/Jerusalem",
	"Middle East Standard Time":       "Asia/Beirut",
	"West Asia Standard Time":         "Asia/Karachi",
	"Bangladesh Standard Time":        "Asia/Dhaka",
	"SE Asia Standard Time":           "Asia/Bangkok",
	"Taipei Standard Time":            "Asia/Taipei",
	"North Asia Standard Time":        "Asia/Krasnoyarsk",
	"N. Central Asia Standard Time":   "Asia/Novosibirsk",
	"Central Asia Standard Time":      "Asia/Almaty",
	"Azores Standard Time":            "Atlantic/Azores",
	"Cape Verde Standard Time":        "Atlantic/Cape_Verde",
	"Greenland Standard Time":         "America/Godthab",
	"Central Brazilian Standard Time": "America/Cuiaba",
	"E. South America Standard Time":  "America/Sao_Paulo",
	"Central Pacific Standard Time":   "Pacific/Guadalcanal",
	"Fiji Standard Time":              "Pacific/Fiji",
	"Samoa Standard Time":             "Pacific/Apia",
	"UTC-11":                          "Etc/GMT+11",
	"UTC-02":                          "Etc/GMT+2",
	"UTC+12":                          "Etc/GMT-12",
	"UTC+13":                          "Etc/GMT-13",
}

// getSystemTimezone returns the system's IANA timezone.
// On Windows, this reads the registry and maps the Windows timezone to IANA.
func getSystemTimezone() string {
	// Try to read the Windows timezone from the registry
	key, err := registry.OpenKey(
		registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\TimeZoneInformation`,
		registry.QUERY_VALUE,
	)
	if err != nil {
		return fallbackTimezone()
	}
	defer key.Close()

	// Try TimeZoneKeyName first (more reliable, available since Vista)
	tzKeyName, _, err := key.GetStringValue("TimeZoneKeyName")
	if err == nil && tzKeyName != "" {
		if iana, ok := windowsToIANA[tzKeyName]; ok {
			return iana
		}
		// Return the Windows name if we don't have a mapping
		return tzKeyName
	}

	// Fall back to StandardName
	standardName, _, err := key.GetStringValue("StandardName")
	if err == nil && standardName != "" {
		if iana, ok := windowsToIANA[standardName]; ok {
			return iana
		}
		return standardName
	}

	return fallbackTimezone()
}

// fallbackTimezone returns a fallback timezone using Go's local timezone.
func fallbackTimezone() string {
	name, _ := time.Now().Zone()
	if name != "" && name != "Local" {
		return name
	}
	return time.Local.String()
}
