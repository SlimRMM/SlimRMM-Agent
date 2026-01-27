// Package installer provides agent registration and installation.
package installer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// Agent status constants matching Python agent.
const (
	StatusPending  = "pending"
	StatusApproved = "approved"
	StatusRejected = "rejected"

	// Polling intervals
	InitialPollInterval = 30 * time.Second
	MaxPollInterval     = 5 * time.Minute
	PollMultiplier      = 1.5
)

var (
	// ErrRejected is returned when the agent is rejected by the server.
	ErrRejected = errors.New("agent registration was rejected")
	// ErrApprovalTimeout is returned when waiting for approval times out.
	ErrApprovalTimeout = errors.New("approval timeout exceeded")
)

// RegistrationRequest matches backend schema.
// Includes optional token for auto-approval and existing_uuid for re-registration.
type RegistrationRequest struct {
	OS                   string `json:"os"`
	Arch                 string `json:"arch"`
	Hostname             string `json:"hostname"`
	AgentVersion         string `json:"agent_version"`
	Token                string `json:"token,omitempty"`
	ExistingUUID         string `json:"existing_uuid,omitempty"`
	ReregistrationSecret string `json:"reregistration_secret,omitempty"`
}

// RegistrationResponse is received from the server after initial registration.
type RegistrationResponse struct {
	UUID                 string `json:"uuid"`
	Status               string `json:"status"`
	RegistrationToken    string `json:"registration_token,omitempty"`
	ReregistrationSecret string `json:"reregistration_secret,omitempty"`
	Message              string `json:"message,omitempty"`
	Error                string `json:"error,omitempty"`
	// Legacy fields for direct registration (no approval workflow)
	CACert     string `json:"ca_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
	// mTLS fields from new registration flow
	MTLS *struct {
		CertificatePEM   string `json:"certificate_pem"`
		PrivateKeyPEM    string `json:"private_key_pem"`
		CACertificatePEM string `json:"ca_certificate_pem"`
	} `json:"mtls,omitempty"`
}

// EnrollmentStatusResponse is returned when polling for approval status.
type EnrollmentStatusResponse struct {
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
	Error   string `json:"error,omitempty"`
}

// CertificateResponse is returned when fetching certificates after approval.
// Matches backend's /api/v1/enrollment/certificate/{uuid} response.
type CertificateResponse struct {
	UUID                 string `json:"uuid"`
	Status               string `json:"status"`
	ReregistrationSecret string `json:"reregistration_secret,omitempty"`
	MTLS                 struct {
		CertificatePEM   string `json:"certificate_pem"`
		PrivateKeyPEM    string `json:"private_key_pem"`
		CACertificatePEM string `json:"ca_certificate_pem"`
	} `json:"mtls"`
	Error string `json:"error,omitempty"`
}

// AgentConfig extends config.Config with enrollment-specific fields.
type AgentConfig struct {
	*config.Config
	Status            string `json:"status"`
	RegistrationToken string `json:"registration_token,omitempty"`
}

// getArch returns architecture in Python's platform.machine() format.
func getArch() string {
	arch := runtime.GOARCH
	// Convert Go's amd64 to Python's x86_64
	if arch == "amd64" {
		return "x86_64"
	}
	return arch
}

// ProgressCallback is called during the approval wait to report status.
type ProgressCallback func(status string, message string)

// RegisterOptions contains optional parameters for registration.
type RegisterOptions struct {
	// ExistingUUID is the UUID from a previous installation.
	// If provided along with ReregistrationSecret, the agent can be auto-approved.
	ExistingUUID string
	// ReregistrationSecret is the secret from the previous approval.
	// Required for secure re-registration to prevent UUID spoofing.
	ReregistrationSecret string
	// ProgressCallback is called to report progress during approval wait.
	ProgressCallback ProgressCallback
}

// Register registers the agent with the server using the enrollment workflow.
// This implements the full 3-step approval process:
// 1. POST /api/v1/enrollment/register - Initial registration
// 2. GET /api/v1/enrollment/status/{uuid} - Poll for approval
// 3. GET /api/v1/enrollment/certificate/{uuid} - Fetch certificates
func Register(serverURL string, regKey string, paths config.Paths) (*config.Config, error) {
	return RegisterWithContext(context.Background(), serverURL, regKey, paths, nil, nil)
}

// RegisterWithProgress registers the agent and calls progressCb during approval wait.
// Use this for interactive installations to show progress to the user.
func RegisterWithProgress(serverURL string, regKey string, paths config.Paths, progressCb ProgressCallback) (*config.Config, error) {
	opts := &RegisterOptions{
		ProgressCallback: progressCb,
	}
	return RegisterWithContext(context.Background(), serverURL, regKey, paths, nil, opts)
}

// RegisterWithExistingUUID registers the agent with an existing UUID for re-registration.
// This allows previously approved agents to be auto-approved after reinstall/update.
// The reregistration secret is loaded from the existing config for secure verification.
func RegisterWithExistingUUID(serverURL string, enrollmentToken string, paths config.Paths, existingUUID string) (*config.Config, error) {
	// Try to load existing config to get the reregistration secret
	existingCfg, err := config.Load(paths.ConfigFile)
	var reregSecret string
	if err == nil && existingCfg != nil {
		reregSecret = existingCfg.GetReregistrationSecret()
	}

	opts := &RegisterOptions{
		ExistingUUID:         existingUUID,
		ReregistrationSecret: reregSecret,
	}
	return RegisterWithContext(context.Background(), serverURL, enrollmentToken, paths, nil, opts)
}

// RegisterWithContext registers the agent with cancellation support.
func RegisterWithContext(ctx context.Context, serverURL string, enrollmentToken string, paths config.Paths, logger *slog.Logger, opts *RegisterOptions) (*config.Config, error) {
	if logger == nil {
		logger = slog.Default()
	}

	// Step 1: Initial registration
	var existingUUID, reregSecret string
	if opts != nil {
		existingUUID = opts.ExistingUUID
		reregSecret = opts.ReregistrationSecret
	}
	regResp, err := registerAgent(ctx, serverURL, enrollmentToken, existingUUID, reregSecret, logger)
	if err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	if regResp.UUID == "" {
		return nil, errors.New("registration response missing UUID")
	}

	// Create initial configuration
	cfg := config.New(serverURL, paths)
	cfg.SetUUID(regResp.UUID)

	// Save reregistration secret if provided
	if regResp.ReregistrationSecret != "" {
		cfg.SetReregistrationSecret(regResp.ReregistrationSecret)
	}

	// Check if we got certificates directly (new approval mode with mTLS in response)
	if regResp.MTLS != nil && regResp.MTLS.CertificatePEM != "" {
		logger.Info("received certificates directly, agent approved")
		return saveCertificatesAndConfig(cfg, regResp.MTLS.CACertificatePEM, regResp.MTLS.CertificatePEM, regResp.MTLS.PrivateKeyPEM, paths)
	}

	// Check if we got certificates directly (legacy/direct approval mode)
	if regResp.CACert != "" && regResp.ClientCert != "" && regResp.ClientKey != "" {
		logger.Info("received certificates directly (legacy), no approval workflow required")
		return saveCertificatesAndConfig(cfg, regResp.CACert, regResp.ClientCert, regResp.ClientKey, paths)
	}

	// Check initial status
	if regResp.Status == StatusApproved {
		logger.Info("agent already approved, fetching certificates")
		return fetchCertificatesAndSave(ctx, cfg, serverURL, regResp.UUID, regResp.RegistrationToken, paths, logger)
	}

	if regResp.Status == StatusRejected {
		return nil, ErrRejected
	}

	// Save pending config
	cfg.MTLSEnabled = false
	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving pending config: %w", err)
	}

	// Step 2: Poll for approval
	logger.Info("waiting for server approval", "uuid", regResp.UUID)
	var progressCb ProgressCallback
	if opts != nil && opts.ProgressCallback != nil {
		progressCb = opts.ProgressCallback
	}
	if err := waitForApproval(ctx, serverURL, regResp.UUID, regResp.RegistrationToken, logger, progressCb); err != nil {
		return nil, err
	}

	// Step 3: Fetch certificates
	logger.Info("agent approved, fetching certificates")
	return fetchCertificatesAndSave(ctx, cfg, serverURL, regResp.UUID, regResp.RegistrationToken, paths, logger)
}

// registerAgent performs the initial registration request.
func registerAgent(ctx context.Context, serverURL string, enrollmentToken string, existingUUID string, reregSecret string, logger *slog.Logger) (*RegistrationResponse, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	req := RegistrationRequest{
		OS:                   runtime.GOOS,
		Arch:                 getArch(),
		Hostname:             hostname,
		AgentVersion:         version.Get().Version,
		Token:                enrollmentToken,
		ExistingUUID:         existingUUID,
		ReregistrationSecret: reregSecret,
	}

	if enrollmentToken != "" {
		logger.Info("registering with enrollment token for auto-approval")
	}

	if existingUUID != "" {
		if reregSecret != "" {
			logger.Info("re-registering with existing UUID and secret", "uuid", existingUUID)
		} else {
			logger.Warn("re-registering with existing UUID but no secret (will require manual approval)", "uuid", existingUUID)
		}
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	// Try enrollment endpoint first (new workflow)
	url := serverURL + "/api/v1/enrollment/register"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if enrollmentToken != "" {
		httpReq.Header.Set("X-Registration-Key", enrollmentToken)
	}

	logger.Debug("sending registration request", "url", url)

	resp, err := client.Do(httpReq)
	if err != nil {
		// Try legacy endpoint as fallback
		return registerAgentLegacy(ctx, serverURL, reqBody, client, logger)
	}
	defer resp.Body.Close()

	// If enrollment endpoint returns 404, try legacy
	if resp.StatusCode == http.StatusNotFound {
		logger.Debug("enrollment endpoint not found, trying legacy registration")
		return registerAgentLegacy(ctx, serverURL, reqBody, client, logger)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if regResp.Error != "" {
		return nil, fmt.Errorf("registration error: %s", regResp.Error)
	}

	return &regResp, nil
}

// registerAgentLegacy uses the old /api/v1/agents/register endpoint.
func registerAgentLegacy(ctx context.Context, serverURL string, reqBody []byte, client *http.Client, logger *slog.Logger) (*RegistrationResponse, error) {
	url := serverURL + "/api/v1/agents/register"
	httpReq, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	logger.Debug("sending legacy registration request", "url", url)

	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("registration failed (status %d): %s", resp.StatusCode, string(body))
	}

	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if regResp.Error != "" {
		return nil, fmt.Errorf("registration error: %s", regResp.Error)
	}

	// Legacy endpoint typically returns approved status immediately
	if regResp.Status == "" {
		regResp.Status = StatusApproved
	}

	return &regResp, nil
}

// waitForApproval polls the server until the agent is approved or rejected.
func waitForApproval(ctx context.Context, serverURL, uuid, regToken string, logger *slog.Logger, progressCb ProgressCallback) error {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	pollInterval := InitialPollInterval
	pollCount := 0

	// Initial progress notification
	if progressCb != nil {
		progressCb(StatusPending, "Waiting for admin approval...")
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(pollInterval):
		}

		pollCount++
		status, err := checkApprovalStatus(ctx, client, serverURL, uuid, regToken)
		if err != nil {
			logger.Warn("error checking approval status", "error", err)
			// Continue polling despite transient errors
			pollInterval = increasePollInterval(pollInterval)
			continue
		}

		switch status {
		case StatusApproved:
			if progressCb != nil {
				progressCb(StatusApproved, "Agent approved!")
			}
			return nil
		case StatusRejected:
			if progressCb != nil {
				progressCb(StatusRejected, "Agent rejected by admin")
			}
			return ErrRejected
		case StatusPending:
			logger.Debug("still waiting for approval", "interval", pollInterval)
			if progressCb != nil {
				nextPollSec := int(pollInterval.Seconds())
				progressCb(StatusPending, fmt.Sprintf("Still waiting... (check %d, next in %ds)", pollCount, nextPollSec))
			}
			pollInterval = increasePollInterval(pollInterval)
		default:
			logger.Warn("unknown status received", "status", status)
			pollInterval = increasePollInterval(pollInterval)
		}
	}
}

// checkApprovalStatus checks the current approval status.
func checkApprovalStatus(ctx context.Context, client *http.Client, serverURL, uuid, regToken string) (string, error) {
	url := serverURL + "/api/v1/enrollment/status/" + uuid
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("creating request: %w", err)
	}

	if regToken != "" {
		req.Header.Set("X-Registration-Token", regToken)
	}
	req.Header.Set("X-Agent-UUID", uuid)

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status check failed (status %d): %s", resp.StatusCode, string(body))
	}

	var statusResp EnrollmentStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&statusResp); err != nil {
		return "", fmt.Errorf("parsing response: %w", err)
	}

	if statusResp.Error != "" {
		return "", fmt.Errorf("status error: %s", statusResp.Error)
	}

	return statusResp.Status, nil
}

// fetchCertificatesAndSave retrieves certificates from the server and saves them.
func fetchCertificatesAndSave(ctx context.Context, cfg *config.Config, serverURL, uuid, regToken string, paths config.Paths, logger *slog.Logger) (*config.Config, error) {
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
			},
		},
	}

	url := serverURL + "/api/v1/enrollment/certificate/" + uuid
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	if regToken != "" {
		req.Header.Set("X-Registration-Token", regToken)
	}
	req.Header.Set("X-Agent-UUID", uuid)

	logger.Debug("fetching certificates", "url", url)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("certificate fetch failed (status %d): %s", resp.StatusCode, string(body))
	}

	var certResp CertificateResponse
	if err := json.NewDecoder(resp.Body).Decode(&certResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if certResp.Error != "" {
		return nil, fmt.Errorf("certificate error: %s", certResp.Error)
	}

	// Validate response has certificate data
	if certResp.MTLS.CACertificatePEM == "" || certResp.MTLS.CertificatePEM == "" || certResp.MTLS.PrivateKeyPEM == "" {
		return nil, errors.New("certificate response missing required certificate data")
	}

	// Save reregistration secret for future reinstalls
	if certResp.ReregistrationSecret != "" {
		cfg.SetReregistrationSecret(certResp.ReregistrationSecret)
		logger.Info("received reregistration secret for future reinstalls")
	}

	return saveCertificatesAndConfig(cfg, certResp.MTLS.CACertificatePEM, certResp.MTLS.CertificatePEM, certResp.MTLS.PrivateKeyPEM, paths)
}

// saveCertificatesAndConfig saves certificates and updates the configuration.
func saveCertificatesAndConfig(cfg *config.Config, caCert, clientCert, clientKey string, paths config.Paths) (*config.Config, error) {
	certPaths := mtls.CertPaths{
		CACert:     paths.CACert,
		ClientCert: paths.ClientCert,
		ClientKey:  paths.ClientKey,
	}

	if err := mtls.SaveCertificates(certPaths,
		[]byte(caCert),
		[]byte(clientCert),
		[]byte(clientKey),
	); err != nil {
		return nil, fmt.Errorf("saving certificates: %w", err)
	}

	cfg.MTLSEnabled = true
	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	return cfg, nil
}

// increasePollInterval increases the polling interval with exponential backoff.
func increasePollInterval(current time.Duration) time.Duration {
	next := time.Duration(float64(current) * PollMultiplier)
	if next > MaxPollInterval {
		return MaxPollInterval
	}
	return next
}

// RenewCertificates requests new certificates from the server.
func RenewCertificates(cfg *config.Config, paths config.Paths) error {
	return RenewCertificatesWithContext(context.Background(), cfg, paths)
}

// RenewCertificatesWithContext requests new certificates with context support.
func RenewCertificatesWithContext(ctx context.Context, cfg *config.Config, paths config.Paths) error {
	// Create HTTP client with existing mTLS certs
	certPaths := &mtls.CertPaths{
		CACert:     paths.CACert,
		ClientCert: paths.ClientCert,
		ClientKey:  paths.ClientKey,
	}

	tlsConfig, err := mtls.NewTLSConfig(certPaths, nil)
	if err != nil {
		return fmt.Errorf("creating TLS config: %w", err)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	// Request certificate renewal
	url := cfg.GetServer() + "/api/v1/agents/" + cfg.GetUUID() + "/renew-cert"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Agent-UUID", cfg.GetUUID())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("renewal failed (status %d): %s", resp.StatusCode, string(body))
	}

	// Parse response
	var renewResp struct {
		CACert     string `json:"ca_cert"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&renewResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	// Save new certificates
	if err := mtls.SaveCertificates(*certPaths,
		[]byte(renewResp.CACert),
		[]byte(renewResp.ClientCert),
		[]byte(renewResp.ClientKey),
	); err != nil {
		return fmt.Errorf("saving certificates: %w", err)
	}

	return nil
}
