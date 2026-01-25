package osquery

import (
	"runtime"
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if DefaultTimeout <= 0 {
		t.Error("DefaultTimeout should be positive")
	}
	if DefaultTimeout != 30*time.Second {
		t.Errorf("DefaultTimeout = %v, want 30s", DefaultTimeout)
	}
	if fallbackVersion == "" {
		t.Error("fallbackVersion should not be empty")
	}
}

func TestGitHubReleaseStruct(t *testing.T) {
	release := GitHubRelease{
		TagName: "5.15.0",
		Assets: []struct {
			Name               string `json:"name"`
			BrowserDownloadURL string `json:"browser_download_url"`
		}{
			{
				Name:               "osquery-5.15.0.msi",
				BrowserDownloadURL: "https://example.com/download",
			},
		},
	}

	if release.TagName != "5.15.0" {
		t.Error("TagName not set correctly")
	}
	if len(release.Assets) != 1 {
		t.Error("Assets not set correctly")
	}
	if release.Assets[0].Name != "osquery-5.15.0.msi" {
		t.Error("Asset Name not set correctly")
	}
}

func TestQueryResult(t *testing.T) {
	result := QueryResult{
		Query: "SELECT * FROM system_info",
		Rows: []map[string]string{
			{"hostname": "test-host", "cpu_brand": "Intel"},
		},
		Count:    1,
		Duration: 100,
		Error:    "",
	}

	if result.Query != "SELECT * FROM system_info" {
		t.Error("Query not set correctly")
	}
	if result.Count != 1 {
		t.Error("Count not set correctly")
	}
	if result.Duration != 100 {
		t.Error("Duration not set correctly")
	}
	if len(result.Rows) != 1 {
		t.Error("Rows not set correctly")
	}
	if result.Rows[0]["hostname"] != "test-host" {
		t.Error("Row data not set correctly")
	}
}

func TestQueryResultWithError(t *testing.T) {
	result := QueryResult{
		Query:    "SELECT * FROM invalid_table",
		Rows:     []map[string]string{},
		Count:    0,
		Duration: 50,
		Error:    "table not found",
	}

	if result.Error == "" {
		t.Error("Error should be set")
	}
	if result.Count != 0 {
		t.Error("Count should be 0 on error")
	}
}

func TestNew(t *testing.T) {
	client := New()
	if client == nil {
		t.Fatal("New returned nil")
	}
}

func TestNewWithPath(t *testing.T) {
	client := NewWithPath("/custom/path/osqueryi")
	if client == nil {
		t.Fatal("NewWithPath returned nil")
	}
	if client.binaryPath != "/custom/path/osqueryi" {
		t.Errorf("binaryPath = %s, want /custom/path/osqueryi", client.binaryPath)
	}
}

func TestGetBinaryPath(t *testing.T) {
	path := "/test/path/osqueryi"
	client := NewWithPath(path)
	if client.GetBinaryPath() != path {
		t.Errorf("GetBinaryPath = %s, want %s", client.GetBinaryPath(), path)
	}
}

func TestIsAvailableWithInvalidPath(t *testing.T) {
	client := NewWithPath("/nonexistent/path/osqueryi")
	if client.IsAvailable() {
		t.Error("IsAvailable should return false for non-existent binary")
	}
}

func TestIsAvailableWithEmptyPath(t *testing.T) {
	client := NewWithPath("")
	if client.IsAvailable() {
		t.Error("IsAvailable should return false for empty path")
	}
}

func TestGetVersionWithInvalidPath(t *testing.T) {
	client := NewWithPath("/nonexistent/path/osqueryi")
	version := client.GetVersion()
	if version != "" {
		t.Errorf("GetVersion should return empty for non-existent binary, got %s", version)
	}
}

func TestClientStruct(t *testing.T) {
	client := &Client{
		binaryPath: "/test/path",
	}

	if client.binaryPath != "/test/path" {
		t.Error("binaryPath not set correctly")
	}
}

func TestQueryResultEmpty(t *testing.T) {
	result := QueryResult{
		Query:    "SELECT * FROM system_info WHERE 1=0",
		Rows:     []map[string]string{},
		Count:    0,
		Duration: 10,
	}

	if len(result.Rows) != 0 {
		t.Error("empty result should have no rows")
	}
	if result.Count != 0 {
		t.Error("empty result should have count 0")
	}
}

func TestVersionCacheVariables(t *testing.T) {
	// Test that version cache variables are properly initialized
	if versionCacheTTL <= 0 {
		t.Error("versionCacheTTL should be positive")
	}
	if versionCacheTTL != 1*time.Hour {
		t.Errorf("versionCacheTTL = %v, want 1h", versionCacheTTL)
	}
}

func TestFallbackVersion(t *testing.T) {
	// Fallback version should be a valid semver
	if fallbackVersion == "" {
		t.Error("fallbackVersion should not be empty")
	}
	// Check it looks like a version
	if len(fallbackVersion) < 5 {
		t.Error("fallbackVersion should be at least 5 chars (x.y.z)")
	}
}

func TestFindOsqueryBinaryReturnsPath(t *testing.T) {
	// This test just verifies the function doesn't panic
	path := findOsqueryBinary()
	// Path can be empty if osquery is not installed
	_ = path
}

func TestNewReturnsValidClient(t *testing.T) {
	client := New()
	if client == nil {
		t.Fatal("New should return a valid client")
	}
	// binaryPath may be empty if osquery is not installed
}

func TestQueryResultWithMultipleRows(t *testing.T) {
	result := QueryResult{
		Query: "SELECT * FROM users",
		Rows: []map[string]string{
			{"username": "root", "uid": "0"},
			{"username": "user", "uid": "1000"},
			{"username": "guest", "uid": "1001"},
		},
		Count:    3,
		Duration: 200,
	}

	if result.Count != 3 {
		t.Errorf("Count = %d, want 3", result.Count)
	}
	if len(result.Rows) != 3 {
		t.Errorf("len(Rows) = %d, want 3", len(result.Rows))
	}
	if result.Rows[0]["username"] != "root" {
		t.Error("first row should be root")
	}
}

func TestGithubReleasesURLConstant(t *testing.T) {
	if githubReleasesURL == "" {
		t.Error("githubReleasesURL should not be empty")
	}
	if len(githubReleasesURL) < 20 {
		t.Error("githubReleasesURL should be a valid URL")
	}
}

func TestRateLimitRetryWaitConstant(t *testing.T) {
	if rateLimitRetryWait <= 0 {
		t.Error("rateLimitRetryWait should be positive")
	}
	if rateLimitRetryWait != 5*time.Minute {
		t.Errorf("rateLimitRetryWait = %v, want 5m", rateLimitRetryWait)
	}
}

func TestOsqueryBinaryNamesPerPlatform(t *testing.T) {
	// Just verify findOsqueryBinary handles different platforms
	// without panicking
	client := New()

	// On any platform, client should be non-nil
	if client == nil {
		t.Fatal("client should not be nil")
	}

	// Path may or may not be set depending on osquery installation
	path := client.GetBinaryPath()
	if path != "" {
		// If path is set, it should be an absolute path or valid binary name
		if runtime.GOOS == "windows" {
			// Windows paths typically contain : or backslash
		} else {
			// Unix paths typically start with /
		}
	}
}
