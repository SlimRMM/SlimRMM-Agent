// Package homebrew provides Homebrew cask and formula management for macOS.
package homebrew

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"time"
)

// caskNamePattern validates Homebrew cask names (lowercase alphanumeric with hyphens).
var caskNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$`)

// IsValidCaskName checks if a cask name is valid.
func IsValidCaskName(name string) bool {
	if len(name) == 0 || len(name) > 128 {
		return false
	}
	return caskNamePattern.MatchString(name)
}

const (
	// HomebrewAPIBase is the base URL for Homebrew API.
	HomebrewAPIBase = "https://formulae.brew.sh/api"
	// RequestTimeout is the default timeout for API requests.
	RequestTimeout = 30 * time.Second
)

// CaskInfo represents Homebrew cask metadata from API.
type CaskInfo struct {
	Token     string            `json:"token"`
	Name      []string          `json:"name"`
	Desc      string            `json:"desc"`
	Homepage  string            `json:"homepage"`
	URL       string            `json:"url"`
	Version   string            `json:"version"`
	SHA256    string            `json:"sha256"`
	Artifacts []json.RawMessage `json:"artifacts"`
	DependsOn map[string]any    `json:"depends_on"`
}

// CaskArtifact represents installation artifact.
type CaskArtifact struct {
	App []string `json:"app,omitempty"`
	Pkg []string `json:"pkg,omitempty"`
}

// GetArtifactType returns "app", "pkg", or "unknown".
func (c *CaskInfo) GetArtifactType() string {
	for _, raw := range c.Artifacts {
		var artifact CaskArtifact
		if err := json.Unmarshal(raw, &artifact); err != nil {
			continue
		}
		if len(artifact.App) > 0 {
			return "app"
		}
		if len(artifact.Pkg) > 0 {
			return "pkg"
		}
	}
	return "unknown"
}

// GetAppName extracts .app name from artifacts.
func (c *CaskInfo) GetAppName() string {
	for _, raw := range c.Artifacts {
		var artifact CaskArtifact
		if err := json.Unmarshal(raw, &artifact); err != nil {
			continue
		}
		if len(artifact.App) > 0 {
			return artifact.App[0]
		}
	}
	return ""
}

// FetchCaskInfo retrieves cask metadata from Homebrew API.
func FetchCaskInfo(ctx context.Context, caskName string) (*CaskInfo, error) {
	// Validate cask name to prevent injection attacks
	if !IsValidCaskName(caskName) {
		return nil, fmt.Errorf("invalid cask name: %s", caskName)
	}

	ctx, cancel := context.WithTimeout(ctx, RequestTimeout)
	defer cancel()

	url := fmt.Sprintf("%s/cask/%s.json", HomebrewAPIBase, caskName)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch cask info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("cask not found: %s", caskName)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: status %d", resp.StatusCode)
	}

	var info CaskInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}

	return &info, nil
}
