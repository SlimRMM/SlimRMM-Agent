// Package mtls provides mutual TLS configuration for secure communication.
// It handles loading certificates and creating TLS configurations.
package mtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

const (
	certFileMode = 0644
	keyFileMode  = 0600
)

var (
	ErrCertNotFound   = errors.New("certificate file not found")
	ErrKeyNotFound    = errors.New("private key file not found")
	ErrCANotFound     = errors.New("CA certificate not found")
	ErrInvalidCert    = errors.New("invalid certificate")
	ErrCertLoadFailed = errors.New("failed to load certificate")
)

// CertPaths holds the paths to certificate files.
type CertPaths struct {
	CACert     string
	ClientCert string
	ClientKey  string
}

// Config holds TLS configuration options.
type Config struct {
	InsecureSkipVerify bool
	ServerName         string
}

// NewTLSConfig creates a TLS configuration for mTLS.
// If certPaths is provided, client certificates are loaded for mutual TLS.
// If certPaths is nil, only server verification is performed.
func NewTLSConfig(certPaths *CertPaths, cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if cfg != nil {
		tlsConfig.InsecureSkipVerify = cfg.InsecureSkipVerify
		if cfg.ServerName != "" {
			tlsConfig.ServerName = cfg.ServerName
		}
	}

	// Load CA certificate if available
	if certPaths != nil && certPaths.CACert != "" {
		if err := loadCACert(tlsConfig, certPaths.CACert); err != nil {
			// CA cert is optional, log but continue
			fmt.Printf("Warning: Could not load CA cert: %v\n", err)
		}
	}

	// Load client certificate if available (for mTLS)
	if certPaths != nil && certPaths.ClientCert != "" && certPaths.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(certPaths.ClientCert, certPaths.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrCertLoadFailed, err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}

// loadCACert loads the CA certificate into the TLS config.
func loadCACert(tlsConfig *tls.Config, caPath string) error {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrCANotFound
		}
		return fmt.Errorf("reading CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("%w: failed to parse CA certificate", ErrInvalidCert)
	}

	tlsConfig.RootCAs = caCertPool
	return nil
}

// SaveCertificates saves the certificates to disk with proper permissions.
func SaveCertificates(paths CertPaths, caCert, clientCert, clientKey []byte) error {
	files := []struct {
		path    string
		content []byte
		mode    os.FileMode
	}{
		{paths.CACert, caCert, certFileMode},
		{paths.ClientCert, clientCert, certFileMode},
		{paths.ClientKey, clientKey, keyFileMode},
	}

	for _, f := range files {
		if len(f.content) == 0 {
			continue
		}

		if err := os.WriteFile(f.path, f.content, f.mode); err != nil {
			return fmt.Errorf("writing %s: %w", f.path, err)
		}

		// Ensure correct permissions
		if err := os.Chmod(f.path, f.mode); err != nil {
			return fmt.Errorf("setting permissions on %s: %w", f.path, err)
		}
	}

	return nil
}

// CertificatesExist checks if all required certificate files exist.
func CertificatesExist(paths CertPaths) bool {
	files := []string{paths.CACert, paths.ClientCert, paths.ClientKey}
	for _, f := range files {
		if _, err := os.Stat(f); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// GetCertExpiry returns the expiration time of the client certificate.
func GetCertExpiry(certPath string) (string, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return "", fmt.Errorf("reading certificate: %w", err)
	}

	// Parse the certificate
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return "", errors.New("failed to parse certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("parsing certificate: %w", err)
	}

	return cert.NotAfter.Format("2006-01-02 15:04:05"), nil
}
