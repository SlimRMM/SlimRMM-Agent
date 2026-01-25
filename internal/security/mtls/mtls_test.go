package mtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewTLSConfigNilPaths(t *testing.T) {
	// Test with nil paths - should create basic TLS config
	tlsConfig, err := NewTLSConfig(nil, nil)
	if err != nil {
		t.Fatalf("NewTLSConfig failed: %v", err)
	}

	if tlsConfig == nil {
		t.Fatal("tlsConfig should not be nil")
	}
	if tlsConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d", tlsConfig.MinVersion, tls.VersionTLS13)
	}
}

func TestNewTLSConfigWithServerName(t *testing.T) {
	cfg := &Config{
		ServerName: "example.com",
	}

	tlsConfig, err := NewTLSConfig(nil, cfg)
	if err != nil {
		t.Fatalf("NewTLSConfig failed: %v", err)
	}

	if tlsConfig.ServerName != "example.com" {
		t.Errorf("ServerName = %s, want example.com", tlsConfig.ServerName)
	}
}

func TestNewTLSConfigWithCerts(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mtls_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificates
	caCert, caKey := generateTestCA(t)
	clientCert, clientKey := generateTestCert(t, caCert, caKey)

	// Save certificates
	caCertPath := filepath.Join(tmpDir, "ca.crt")
	clientCertPath := filepath.Join(tmpDir, "client.crt")
	clientKeyPath := filepath.Join(tmpDir, "client.key")

	savePEM(t, caCertPath, "CERTIFICATE", caCert)
	savePEM(t, clientCertPath, "CERTIFICATE", clientCert)
	savePEM(t, clientKeyPath, "EC PRIVATE KEY", clientKey)

	paths := &CertPaths{
		CACert:     caCertPath,
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
	}

	tlsConfig, err := NewTLSConfig(paths, nil)
	if err != nil {
		t.Fatalf("NewTLSConfig failed: %v", err)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}
	if tlsConfig.RootCAs == nil {
		t.Error("RootCAs should be set")
	}
}

func TestNewTLSConfigInvalidCert(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "mtls_invalid_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Create invalid certificate files
	clientCertPath := filepath.Join(tmpDir, "client.crt")
	clientKeyPath := filepath.Join(tmpDir, "client.key")

	os.WriteFile(clientCertPath, []byte("invalid cert"), 0644)
	os.WriteFile(clientKeyPath, []byte("invalid key"), 0600)

	paths := &CertPaths{
		ClientCert: clientCertPath,
		ClientKey:  clientKeyPath,
	}

	_, err = NewTLSConfig(paths, nil)
	if err == nil {
		t.Error("NewTLSConfig should fail with invalid certificates")
	}
}

func TestSaveCertificates(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "save_certs_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := CertPaths{
		CACert:     filepath.Join(tmpDir, "ca.crt"),
		ClientCert: filepath.Join(tmpDir, "client.crt"),
		ClientKey:  filepath.Join(tmpDir, "client.key"),
	}

	err = SaveCertificates(paths, []byte("ca"), []byte("cert"), []byte("key"))
	if err != nil {
		t.Fatalf("SaveCertificates failed: %v", err)
	}

	// Verify files exist
	for _, path := range []string{paths.CACert, paths.ClientCert, paths.ClientKey} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("file should exist: %s", path)
		}
	}

	// Verify key file permissions
	info, err := os.Stat(paths.ClientKey)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != keyFileMode {
		t.Errorf("key file permissions = %o, want %o", info.Mode().Perm(), keyFileMode)
	}
}

func TestSaveCertificatesEmpty(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "save_empty_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := CertPaths{
		CACert:     filepath.Join(tmpDir, "ca.crt"),
		ClientCert: filepath.Join(tmpDir, "client.crt"),
		ClientKey:  filepath.Join(tmpDir, "client.key"),
	}

	// Empty content should be skipped
	err = SaveCertificates(paths, nil, nil, nil)
	if err != nil {
		t.Fatalf("SaveCertificates should not fail for empty content: %v", err)
	}

	// Files should not be created
	for _, path := range []string{paths.CACert, paths.ClientCert, paths.ClientKey} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Errorf("file should not exist when content is empty: %s", path)
		}
	}
}

func TestCertificatesExist(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_exist_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := CertPaths{
		CACert:     filepath.Join(tmpDir, "ca.crt"),
		ClientCert: filepath.Join(tmpDir, "client.crt"),
		ClientKey:  filepath.Join(tmpDir, "client.key"),
	}

	// Should return false when files don't exist
	if CertificatesExist(paths) {
		t.Error("CertificatesExist should return false when files don't exist")
	}

	// Create files
	for _, path := range []string{paths.CACert, paths.ClientCert, paths.ClientKey} {
		os.WriteFile(path, []byte("test"), 0644)
	}

	// Should return true when all files exist
	if !CertificatesExist(paths) {
		t.Error("CertificatesExist should return true when all files exist")
	}
}

func TestCertificatesExistPartial(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "certs_partial_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	paths := CertPaths{
		CACert:     filepath.Join(tmpDir, "ca.crt"),
		ClientCert: filepath.Join(tmpDir, "client.crt"),
		ClientKey:  filepath.Join(tmpDir, "client.key"),
	}

	// Create only some files
	os.WriteFile(paths.CACert, []byte("test"), 0644)
	os.WriteFile(paths.ClientCert, []byte("test"), 0644)
	// ClientKey is missing

	if CertificatesExist(paths) {
		t.Error("CertificatesExist should return false when some files are missing")
	}
}

func TestGetCertExpiry(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert_expiry_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Generate test certificate
	caCert, _ := generateTestCA(t)

	certPath := filepath.Join(tmpDir, "cert.crt")
	savePEM(t, certPath, "CERTIFICATE", caCert)

	expiry, err := GetCertExpiry(certPath)
	if err != nil {
		t.Fatalf("GetCertExpiry failed: %v", err)
	}

	if expiry == "" {
		t.Error("expiry should not be empty")
	}
}

func TestGetCertExpiryInvalid(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "cert_expiry_invalid_test")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Invalid cert
	certPath := filepath.Join(tmpDir, "invalid.crt")
	os.WriteFile(certPath, []byte("not a certificate"), 0644)

	_, err = GetCertExpiry(certPath)
	if err == nil {
		t.Error("GetCertExpiry should fail for invalid certificate")
	}
}

func TestGetCertExpiryNotFound(t *testing.T) {
	_, err := GetCertExpiry("/nonexistent/path.crt")
	if err == nil {
		t.Error("GetCertExpiry should fail for nonexistent file")
	}
}

func TestErrors(t *testing.T) {
	errors := []error{
		ErrCertNotFound,
		ErrKeyNotFound,
		ErrCANotFound,
		ErrInvalidCert,
		ErrCertLoadFailed,
	}

	for _, err := range errors {
		if err == nil {
			t.Error("error should not be nil")
		}
		if err.Error() == "" {
			t.Error("error should have a message")
		}
	}
}

func TestConstants(t *testing.T) {
	if certFileMode != 0644 {
		t.Errorf("certFileMode = %o, want 0644", certFileMode)
	}
	if keyFileMode != 0600 {
		t.Errorf("keyFileMode = %o, want 0600", keyFileMode)
	}
}

// Test helpers

func generateTestCA(t *testing.T) ([]byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	return certDER, key
}

func generateTestCert(t *testing.T, caCertDER []byte, caKey *ecdsa.PrivateKey) ([]byte, []byte) {
	t.Helper()

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("failed to parse CA cert: %v", err)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "Test Client",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
		},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	keyBytes, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}

	return certDER, keyBytes
}

func savePEM(t *testing.T, path, pemType string, data []byte) {
	t.Helper()

	block := &pem.Block{
		Type:  pemType,
		Bytes: data,
	}

	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("failed to create file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("failed to encode PEM: %v", err)
	}
}
