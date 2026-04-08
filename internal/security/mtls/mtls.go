// Package mtls provides mutual TLS configuration for secure communication.
// It handles loading certificates and creating TLS configurations.
package mtls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"
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
	// Deprecated: InsecureSkipVerify is ignored for security.
	// Certificate verification is always enabled.
	InsecureSkipVerify bool
	ServerName         string
}

// NewTLSConfig creates a TLS configuration for mTLS.
// If certPaths is provided, client certificates are loaded for mutual TLS.
// If certPaths is nil, only server verification is performed.
func NewTLSConfig(certPaths *CertPaths, cfg *Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg != nil {
		// Note: InsecureSkipVerify is intentionally NOT applied from config.
		// Certificate verification must always be enabled for security.
		if cfg.ServerName != "" {
			tlsConfig.ServerName = cfg.ServerName
		}
	}

	// Load CA certificate if specified
	if certPaths != nil && certPaths.CACert != "" {
		if err := loadCACert(tlsConfig, certPaths.CACert); err != nil {
			return nil, fmt.Errorf("loading CA certificate: %w", err)
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
// It starts with system root CAs and adds the custom CA, so both
// public TLS certs (e.g., Let's Encrypt) and mTLS certs are trusted.
func loadCACert(tlsConfig *tls.Config, caPath string) error {
	caCert, err := os.ReadFile(caPath)
	if err != nil {
		if os.IsNotExist(err) {
			return ErrCANotFound
		}
		return fmt.Errorf("reading CA cert: %w", err)
	}

	// Start with system root CAs (for Let's Encrypt, etc.)
	caCertPool, err := x509.SystemCertPool()
	if err != nil {
		// Fallback to empty pool if system certs unavailable
		caCertPool = x509.NewCertPool()
	}

	// Add our custom mTLS CA
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("%w: failed to parse CA certificate", ErrInvalidCert)
	}

	tlsConfig.RootCAs = caCertPool
	return nil
}

// ValidateCertificateBundle validates that the provided certificate bundle is
// well-formed and consistent: PEM data is valid, the CA certificate has IsCA
// set, the client certificate is not expired, the private key matches the
// client certificate, and the client certificate is signed by the CA.
func ValidateCertificateBundle(caCert, clientCert, clientKey []byte) error {
	// Decode and parse the CA certificate
	caBlock, _ := pem.Decode(caCert)
	if caBlock == nil {
		return fmt.Errorf("%w: CA certificate is not valid PEM", ErrInvalidCert)
	}
	caCertParsed, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse CA certificate: %v", ErrInvalidCert, err)
	}
	if !caCertParsed.IsCA {
		return fmt.Errorf("%w: CA certificate does not have IsCA flag set", ErrInvalidCert)
	}

	// Decode and parse the client certificate
	clientBlock, _ := pem.Decode(clientCert)
	if clientBlock == nil {
		return fmt.Errorf("%w: client certificate is not valid PEM", ErrInvalidCert)
	}
	clientCertParsed, err := x509.ParseCertificate(clientBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse client certificate: %v", ErrInvalidCert, err)
	}
	if !time.Now().Before(clientCertParsed.NotAfter) {
		return fmt.Errorf("%w: client certificate has expired (NotAfter: %v)", ErrInvalidCert, clientCertParsed.NotAfter)
	}

	// Decode and parse the private key
	keyBlock, _ := pem.Decode(clientKey)
	if keyBlock == nil {
		return fmt.Errorf("%w: private key is not valid PEM", ErrInvalidCert)
	}
	privKey, err := parsePrivateKey(keyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("%w: failed to parse private key: %v", ErrInvalidCert, err)
	}

	// Verify the private key matches the client certificate's public key
	if !publicKeysMatch(clientCertParsed, privKey) {
		return fmt.Errorf("%w: private key does not match client certificate public key", ErrInvalidCert)
	}

	// Verify the client certificate is signed by the CA
	caPool := x509.NewCertPool()
	caPool.AddCert(caCertParsed)
	opts := x509.VerifyOptions{
		Roots: caPool,
		KeyUsages: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageAny,
		},
	}
	if _, err := clientCertParsed.Verify(opts); err != nil {
		return fmt.Errorf("%w: client certificate not signed by provided CA: %v", ErrInvalidCert, err)
	}

	return nil
}

// parsePrivateKey attempts to parse a DER-encoded private key as PKCS8, PKCS1
// RSA, or EC private key.
func parsePrivateKey(der []byte) (interface{}, error) {
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, errors.New("unsupported private key type")
}

// publicKeysMatch checks whether the private key corresponds to the public key
// in the certificate.
func publicKeysMatch(cert *x509.Certificate, privKey interface{}) bool {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		priv, ok := privKey.(*rsa.PrivateKey)
		return ok && pub.N.Cmp(priv.N) == 0 && pub.E == priv.E
	case *ecdsa.PublicKey:
		priv, ok := privKey.(*ecdsa.PrivateKey)
		return ok && pub.X.Cmp(priv.X) == 0 && pub.Y.Cmp(priv.Y) == 0
	case ed25519.PublicKey:
		priv, ok := privKey.(ed25519.PrivateKey)
		return ok && pub.Equal(priv.Public())
	default:
		return false
	}
}

// SaveCertificates saves the certificates to disk with proper permissions.
// It validates the certificate bundle before writing any files.
func SaveCertificates(paths CertPaths, caCert, clientCert, clientKey []byte) error {
	// Validate the certificate bundle before writing anything to disk
	if len(caCert) > 0 && len(clientCert) > 0 && len(clientKey) > 0 {
		if err := ValidateCertificateBundle(caCert, clientCert, clientKey); err != nil {
			return fmt.Errorf("certificate validation failed: %w", err)
		}
	}

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
