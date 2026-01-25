package installer

import (
	"os"
	"runtime"
	"testing"
	"time"
)

func TestConstants(t *testing.T) {
	if systemdServiceName != "slimrmm-agent" {
		t.Errorf("systemdServiceName = %s, want slimrmm-agent", systemdServiceName)
	}
	if systemdServicePath != "/etc/systemd/system/slimrmm-agent.service" {
		t.Errorf("systemdServicePath = %s, want /etc/systemd/system/slimrmm-agent.service", systemdServicePath)
	}
	if launchdPlistName != "io.slimrmm.agent" {
		t.Errorf("launchdPlistName = %s, want io.slimrmm.agent", launchdPlistName)
	}
	if launchdPlistPath != "/Library/LaunchDaemons/io.slimrmm.agent.plist" {
		t.Errorf("launchdPlistPath = %s, want /Library/LaunchDaemons/io.slimrmm.agent.plist", launchdPlistPath)
	}
}

func TestSystemdServiceTemplate(t *testing.T) {
	if systemdServiceTemplate == "" {
		t.Error("systemdServiceTemplate should not be empty")
	}

	// Verify template has placeholders
	if len(systemdServiceTemplate) < 100 {
		t.Error("systemdServiceTemplate seems too short")
	}

	// Verify template contains key sections
	expectedSections := []string{
		"[Unit]",
		"[Service]",
		"[Install]",
		"Description=SlimRMM Agent",
		"ExecStart=%s",
		"Restart=always",
		"Environment=\"SLIMRMM_SERVICE=1\"",
	}
	for _, section := range expectedSections {
		if !containsString(systemdServiceTemplate, section) {
			t.Errorf("systemdServiceTemplate missing section: %s", section)
		}
	}
}

func TestLaunchdPlistTemplate(t *testing.T) {
	if launchdPlistTemplate == "" {
		t.Error("launchdPlistTemplate should not be empty")
	}

	// Verify template has placeholders
	if len(launchdPlistTemplate) < 100 {
		t.Error("launchdPlistTemplate seems too short")
	}

	// Verify template contains key sections
	expectedSections := []string{
		"<?xml version=\"1.0\"",
		"<plist version=\"1.0\">",
		"<key>Label</key>",
		"io.slimrmm.agent",
		"<key>ProgramArguments</key>",
		"<key>RunAtLoad</key>",
		"<key>KeepAlive</key>",
		"SLIMRMM_SERVICE",
	}
	for _, section := range expectedSections {
		if !containsString(launchdPlistTemplate, section) {
			t.Errorf("launchdPlistTemplate missing section: %s", section)
		}
	}
}

func containsString(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && (s[:len(substr)] == substr || containsString(s[1:], substr)))
}

func TestRegistrationConstants(t *testing.T) {
	if StatusPending != "pending" {
		t.Errorf("StatusPending = %s, want pending", StatusPending)
	}
	if StatusApproved != "approved" {
		t.Errorf("StatusApproved = %s, want approved", StatusApproved)
	}
	if StatusRejected != "rejected" {
		t.Errorf("StatusRejected = %s, want rejected", StatusRejected)
	}
	if InitialPollInterval != 30*time.Second {
		t.Errorf("InitialPollInterval = %v, want 30s", InitialPollInterval)
	}
	if MaxPollInterval != 5*time.Minute {
		t.Errorf("MaxPollInterval = %v, want 5m", MaxPollInterval)
	}
	if PollMultiplier != 1.5 {
		t.Errorf("PollMultiplier = %v, want 1.5", PollMultiplier)
	}
}

func TestErrors(t *testing.T) {
	if ErrRejected == nil {
		t.Error("ErrRejected should not be nil")
	}
	if ErrRejected.Error() != "agent registration was rejected" {
		t.Errorf("ErrRejected = %v, want 'agent registration was rejected'", ErrRejected)
	}
	if ErrApprovalTimeout == nil {
		t.Error("ErrApprovalTimeout should not be nil")
	}
	if ErrApprovalTimeout.Error() != "approval timeout exceeded" {
		t.Errorf("ErrApprovalTimeout = %v, want 'approval timeout exceeded'", ErrApprovalTimeout)
	}
}

func TestRegistrationRequest(t *testing.T) {
	req := RegistrationRequest{
		OS:                   "linux",
		Arch:                 "x86_64",
		Hostname:             "test-host",
		AgentVersion:         "1.0.0",
		Token:                "token123",
		ExistingUUID:         "uuid-123",
		ReregistrationSecret: "secret456",
	}

	if req.OS != "linux" {
		t.Errorf("OS = %s, want linux", req.OS)
	}
	if req.Arch != "x86_64" {
		t.Errorf("Arch = %s, want x86_64", req.Arch)
	}
	if req.Hostname != "test-host" {
		t.Errorf("Hostname = %s, want test-host", req.Hostname)
	}
	if req.AgentVersion != "1.0.0" {
		t.Errorf("AgentVersion = %s, want 1.0.0", req.AgentVersion)
	}
	if req.Token != "token123" {
		t.Errorf("Token = %s, want token123", req.Token)
	}
	if req.ExistingUUID != "uuid-123" {
		t.Errorf("ExistingUUID = %s, want uuid-123", req.ExistingUUID)
	}
	if req.ReregistrationSecret != "secret456" {
		t.Errorf("ReregistrationSecret = %s, want secret456", req.ReregistrationSecret)
	}
}

func TestRegistrationResponse(t *testing.T) {
	resp := RegistrationResponse{
		UUID:                 "uuid-abc",
		Status:               StatusApproved,
		RegistrationToken:    "reg-token",
		ReregistrationSecret: "rereg-secret",
		Message:              "success",
		CACert:               "ca-cert-pem",
		ClientCert:           "client-cert-pem",
		ClientKey:            "client-key-pem",
	}

	if resp.UUID != "uuid-abc" {
		t.Errorf("UUID = %s, want uuid-abc", resp.UUID)
	}
	if resp.Status != StatusApproved {
		t.Errorf("Status = %s, want approved", resp.Status)
	}
	if resp.RegistrationToken != "reg-token" {
		t.Errorf("RegistrationToken = %s, want reg-token", resp.RegistrationToken)
	}
	if resp.CACert != "ca-cert-pem" {
		t.Errorf("CACert = %s, want ca-cert-pem", resp.CACert)
	}
}

func TestRegistrationResponseWithMTLS(t *testing.T) {
	resp := RegistrationResponse{
		UUID:   "uuid-xyz",
		Status: StatusApproved,
		MTLS: &struct {
			CertificatePEM   string `json:"certificate_pem"`
			PrivateKeyPEM    string `json:"private_key_pem"`
			CACertificatePEM string `json:"ca_certificate_pem"`
		}{
			CertificatePEM:   "cert-pem",
			PrivateKeyPEM:    "key-pem",
			CACertificatePEM: "ca-pem",
		},
	}

	if resp.MTLS == nil {
		t.Fatal("MTLS should not be nil")
	}
	if resp.MTLS.CertificatePEM != "cert-pem" {
		t.Errorf("MTLS.CertificatePEM = %s, want cert-pem", resp.MTLS.CertificatePEM)
	}
	if resp.MTLS.PrivateKeyPEM != "key-pem" {
		t.Errorf("MTLS.PrivateKeyPEM = %s, want key-pem", resp.MTLS.PrivateKeyPEM)
	}
	if resp.MTLS.CACertificatePEM != "ca-pem" {
		t.Errorf("MTLS.CACertificatePEM = %s, want ca-pem", resp.MTLS.CACertificatePEM)
	}
}

func TestEnrollmentStatusResponse(t *testing.T) {
	resp := EnrollmentStatusResponse{
		Status:  StatusPending,
		Message: "waiting for approval",
		Error:   "",
	}

	if resp.Status != StatusPending {
		t.Errorf("Status = %s, want pending", resp.Status)
	}
	if resp.Message != "waiting for approval" {
		t.Errorf("Message = %s, want 'waiting for approval'", resp.Message)
	}
	if resp.Error != "" {
		t.Error("Error should be empty")
	}
}

func TestCertificateResponse(t *testing.T) {
	resp := CertificateResponse{
		UUID:                 "uuid-123",
		Status:               StatusApproved,
		ReregistrationSecret: "secret",
	}
	resp.MTLS.CertificatePEM = "cert"
	resp.MTLS.PrivateKeyPEM = "key"
	resp.MTLS.CACertificatePEM = "ca"

	if resp.UUID != "uuid-123" {
		t.Errorf("UUID = %s, want uuid-123", resp.UUID)
	}
	if resp.Status != StatusApproved {
		t.Errorf("Status = %s, want approved", resp.Status)
	}
	if resp.MTLS.CertificatePEM != "cert" {
		t.Errorf("MTLS.CertificatePEM = %s, want cert", resp.MTLS.CertificatePEM)
	}
}

func TestGetArch(t *testing.T) {
	arch := getArch()

	// On amd64, should return x86_64
	if runtime.GOARCH == "amd64" {
		if arch != "x86_64" {
			t.Errorf("getArch() = %s, want x86_64 for amd64", arch)
		}
	} else {
		// On other architectures, should return GOARCH
		if arch != runtime.GOARCH {
			t.Errorf("getArch() = %s, want %s", arch, runtime.GOARCH)
		}
	}
}

func TestIncreasePollInterval(t *testing.T) {
	tests := []struct {
		name     string
		current  time.Duration
		expected time.Duration
	}{
		{"initial", 30 * time.Second, 45 * time.Second},                       // 30 * 1.5 = 45
		{"second", 45 * time.Second, 67500 * time.Millisecond},                // 45 * 1.5 = 67.5
		{"near max", 4 * time.Minute, 5 * time.Minute},                        // 4 * 1.5 = 6, capped to 5
		{"at max", 5 * time.Minute, 5 * time.Minute},                          // Already at max
		{"over max", 6 * time.Minute, 5 * time.Minute},                        // Would be 9, capped to 5
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := increasePollInterval(tt.current)
			if result != tt.expected {
				t.Errorf("increasePollInterval(%v) = %v, want %v", tt.current, result, tt.expected)
			}
		})
	}
}

func TestProgressCallbackType(t *testing.T) {
	var called bool
	var capturedStatus, capturedMessage string

	cb := ProgressCallback(func(status string, message string) {
		called = true
		capturedStatus = status
		capturedMessage = message
	})

	cb(StatusPending, "test message")

	if !called {
		t.Error("callback was not called")
	}
	if capturedStatus != StatusPending {
		t.Errorf("status = %s, want pending", capturedStatus)
	}
	if capturedMessage != "test message" {
		t.Errorf("message = %s, want 'test message'", capturedMessage)
	}
}

func TestRegisterOptions(t *testing.T) {
	opts := RegisterOptions{
		ExistingUUID:         "uuid-existing",
		ReregistrationSecret: "secret-existing",
		ProgressCallback:     func(status string, message string) {},
	}

	if opts.ExistingUUID != "uuid-existing" {
		t.Errorf("ExistingUUID = %s, want uuid-existing", opts.ExistingUUID)
	}
	if opts.ReregistrationSecret != "secret-existing" {
		t.Errorf("ReregistrationSecret = %s, want secret-existing", opts.ReregistrationSecret)
	}
	if opts.ProgressCallback == nil {
		t.Error("ProgressCallback should not be nil")
	}
}

func TestIsRunningAsService(t *testing.T) {
	// Save original value
	origValue := os.Getenv("SLIMRMM_SERVICE")
	defer os.Setenv("SLIMRMM_SERVICE", origValue)

	// Test when not set
	os.Unsetenv("SLIMRMM_SERVICE")
	if IsRunningAsService() {
		t.Error("IsRunningAsService should return false when SLIMRMM_SERVICE is not set")
	}

	// Test when set to 0
	os.Setenv("SLIMRMM_SERVICE", "0")
	if IsRunningAsService() {
		t.Error("IsRunningAsService should return false when SLIMRMM_SERVICE=0")
	}

	// Test when set to 1
	os.Setenv("SLIMRMM_SERVICE", "1")
	if !IsRunningAsService() {
		t.Error("IsRunningAsService should return true when SLIMRMM_SERVICE=1")
	}
}

func TestIsServiceInstalled(t *testing.T) {
	// This test just verifies the function doesn't panic
	// The actual result depends on system state
	result := IsServiceInstalled()
	_ = result // Result can be true or false depending on system
}

func TestIsServiceRunning(t *testing.T) {
	// This test just verifies the function doesn't panic
	// The actual result depends on system state
	running, err := IsServiceRunning()
	_ = running
	if err != nil {
		// Only certain platforms return errors
		t.Logf("IsServiceRunning returned error (expected on unsupported platforms): %v", err)
	}
}

func TestAgentConfigStruct(t *testing.T) {
	cfg := AgentConfig{
		Status:            StatusApproved,
		RegistrationToken: "token123",
	}

	if cfg.Status != StatusApproved {
		t.Errorf("Status = %s, want approved", cfg.Status)
	}
	if cfg.RegistrationToken != "token123" {
		t.Errorf("RegistrationToken = %s, want token123", cfg.RegistrationToken)
	}
}
