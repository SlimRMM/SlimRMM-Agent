// Package installer provides agent registration and installation.
package installer

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/slimrmm/slimrmm-agent/internal/config"
	"github.com/slimrmm/slimrmm-agent/internal/monitor"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"github.com/slimrmm/slimrmm-agent/pkg/version"
)

// RegistrationRequest is sent to the server to register the agent.
type RegistrationRequest struct {
	Hostname        string `json:"hostname"`
	OS              string `json:"os"`
	Platform        string `json:"platform"`
	Kernel          string `json:"kernel"`
	Arch            string `json:"arch"`
	AgentVersion    string `json:"agent_version"`
	ExternalIP      string `json:"external_ip,omitempty"`
	RegistrationKey string `json:"registration_key,omitempty"`
}

// RegistrationResponse is received from the server after registration.
type RegistrationResponse struct {
	UUID       string `json:"uuid"`
	CACert     string `json:"ca_cert,omitempty"`
	ClientCert string `json:"client_cert,omitempty"`
	ClientKey  string `json:"client_key,omitempty"`
	Message    string `json:"message,omitempty"`
	Error      string `json:"error,omitempty"`
}

// Register registers the agent with the server.
func Register(serverURL string, regKey string, paths config.Paths) (*config.Config, error) {
	// Gather system information
	mon := monitor.New()
	stats, err := mon.GetStats(context.Background())
	if err != nil {
		return nil, fmt.Errorf("gathering system info: %w", err)
	}

	// Create registration request
	req := RegistrationRequest{
		Hostname:        stats.Hostname,
		OS:              stats.OS,
		Platform:        stats.Platform,
		Kernel:          stats.Kernel,
		Arch:            version.Get().Arch,
		AgentVersion:    version.Get().Version,
		ExternalIP:      stats.ExternalIP,
		RegistrationKey: regKey,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshaling request: %w", err)
	}

	// Create HTTP client with TLS but without client certs
	client := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
		},
	}

	// Send registration request
	url := serverURL + "/api/v1/agents/register"
	httpReq, err := http.NewRequest("POST", url, bytes.NewReader(reqBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

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

	// Parse response
	var regResp RegistrationResponse
	if err := json.Unmarshal(body, &regResp); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}

	if regResp.Error != "" {
		return nil, fmt.Errorf("registration error: %s", regResp.Error)
	}

	if regResp.UUID == "" {
		return nil, fmt.Errorf("registration response missing UUID")
	}

	// Save certificates if provided
	if regResp.CACert != "" && regResp.ClientCert != "" && regResp.ClientKey != "" {
		certPaths := mtls.CertPaths{
			CACert:     paths.CACert,
			ClientCert: paths.ClientCert,
			ClientKey:  paths.ClientKey,
		}

		if err := mtls.SaveCertificates(certPaths,
			[]byte(regResp.CACert),
			[]byte(regResp.ClientCert),
			[]byte(regResp.ClientKey),
		); err != nil {
			return nil, fmt.Errorf("saving certificates: %w", err)
		}
	}

	// Create and save configuration
	cfg := config.New(serverURL, paths)
	cfg.SetUUID(regResp.UUID)

	if regResp.CACert != "" {
		// Enable mTLS if certificates were provided
		cfg.MTLSEnabled = true
	}

	if err := cfg.Save(); err != nil {
		return nil, fmt.Errorf("saving config: %w", err)
	}

	return cfg, nil
}

// RenewCertificates requests new certificates from the server.
func RenewCertificates(cfg *config.Config, paths config.Paths) error {
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
	req, err := http.NewRequest("POST", url, nil)
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
