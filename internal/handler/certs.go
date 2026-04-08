package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	httppkg "github.com/slimrmm/slimrmm-agent/internal/http"
	"github.com/slimrmm/slimrmm-agent/internal/security/mtls"
	"time"
)

// checkAndRenewCertificates checks if certificates need renewal.
func (h *Handler) checkAndRenewCertificates(ctx context.Context) {
	h.logger.Info("performing periodic certificate check")
	h.lastCertCheck = time.Now()

	// Attempt certificate renewal
	if err := h.renewCertificates(ctx); err != nil {
		h.logger.Warn("certificate renewal check failed", "error", err)
		return
	}

	h.logger.Info("certificate check completed successfully")
}

// renewCertificates attempts to renew certificates from the server.
func (h *Handler) renewCertificates(ctx context.Context) error {
	// Reuse the process-wide shared transport for connection pooling and a
	// TLS 1.2 minimum floor, but clone it so we can swap in our mTLS config
	// without mutating the shared instance used by other callers.
	baseTransport := httppkg.SharedTransport().Clone()
	baseTransport.TLSClientConfig = h.tlsConfig
	client := &http.Client{
		Timeout:   httpClientTimeout,
		Transport: baseTransport,
	}

	url := h.cfg.GetServer() + "/api/v1/agents/" + h.cfg.GetUUID() + "/renew-cert"
	req, err := http.NewRequestWithContext(ctx, "POST", url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}
	req.Header.Set("X-Agent-UUID", h.cfg.GetUUID())

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending request: %w", err)
	}
	defer resp.Body.Close()

	// 304 Not Modified means certificates are still valid
	if resp.StatusCode == http.StatusNotModified {
		h.logger.Debug("certificates are still valid")
		return nil
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("renewal failed with status %d", resp.StatusCode)
	}

	// Parse and save new certificates
	var renewResp struct {
		CACert     string `json:"ca_cert"`
		ClientCert string `json:"client_cert"`
		ClientKey  string `json:"client_key"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&renewResp); err != nil {
		return fmt.Errorf("parsing response: %w", err)
	}

	// Only save if we got new certificates
	if renewResp.CACert != "" && renewResp.ClientCert != "" && renewResp.ClientKey != "" {
		h.logger.Info("received new certificates, saving...")

		certPaths := mtls.CertPaths{
			CACert:     h.paths.CACert,
			ClientCert: h.paths.ClientCert,
			ClientKey:  h.paths.ClientKey,
		}

		if err := mtls.SaveCertificates(certPaths,
			[]byte(renewResp.CACert),
			[]byte(renewResp.ClientCert),
			[]byte(renewResp.ClientKey),
		); err != nil {
			return fmt.Errorf("saving certificates: %w", err)
		}

		// Reload in-memory TLS config so subsequent connections use the new certs
		newTLS, err := mtls.NewTLSConfig(&certPaths, nil)
		if err == nil {
			h.tlsConfig = newTLS
		}

		h.logger.Info("certificates renewed and saved successfully")
	}

	return nil
}
