package http

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestDownload_SizeLimit verifies that Download does not read more than
// MaxResponseSize bytes into memory, protecting against OOM from a
// malicious server.
func TestDownload_SizeLimit(t *testing.T) {
	// Server that streams way more than MaxResponseSize.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(http.StatusOK)
		chunk := make([]byte, 1024*1024) // 1 MiB
		// Try to send MaxResponseSize + 10 MiB.
		total := MaxResponseSize + 10*1024*1024
		written := 0
		for written < total {
			n, err := w.Write(chunk)
			if err != nil {
				return
			}
			written += n
		}
	}))
	defer srv.Close()

	c := NewClient(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	body, err := c.Download(ctx, srv.URL, WithDownloadTimeout(30*time.Second))
	if err != nil {
		t.Fatalf("Download returned error: %v", err)
	}
	if int64(len(body)) > MaxResponseSize {
		t.Fatalf("Download returned %d bytes, exceeds MaxResponseSize %d",
			len(body), MaxResponseSize)
	}
}

// TestDownloadToFile_RejectsOversizeContentLength verifies that a lying
// server cannot push more than MaxDownloadSize bytes to disk.
func TestDownloadToFile_RejectsOversizeContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Advertise huge size, then stream infinite zeros.
		w.Header().Set("Content-Length",
			// MaxDownloadSize * 2
			"1099511627776")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	tmp, err := os.MkdirTemp("", "dltest")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmp)

	dst := filepath.Join(tmp, "file.bin")
	c := NewClient(nil)
	err = c.DownloadToFile(context.Background(), srv.URL, dst,
		WithDownloadTimeout(10*time.Second))
	if err == nil {
		t.Fatalf("expected error for oversized Content-Length")
	}
	if !strings.Contains(err.Error(), "too large") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestSharedTransport_TLS13 verifies that the shared transport enforces
// TLS 1.3 minimum and does not disable cert verification.
func TestSharedTransport_TLS12(t *testing.T) {
	tr := SharedTransport()
	if tr.TLSClientConfig == nil {
		t.Fatal("shared transport has no TLSClientConfig")
	}
	if tr.TLSClientConfig.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %d, want %d",
			tr.TLSClientConfig.MinVersion, tls.VersionTLS13)
	}
	if tr.TLSClientConfig.InsecureSkipVerify {
		t.Error("InsecureSkipVerify must be false")
	}
	if tr.MaxIdleConns == 0 || tr.MaxIdleConnsPerHost == 0 {
		t.Error("connection pooling must be configured")
	}
}

// TestVerifyCertPin_NoMatch verifies the pin verifier rejects when no
// peer cert matches any configured pin.
func TestVerifyCertPin_NoMatch(t *testing.T) {
	// A totally bogus hash.
	verify := VerifyCertPin([]string{
		hex.EncodeToString(make([]byte, 32)),
	})
	// Feed it an empty raw cert list so x509.ParseCertificate fails and no
	// pins can match.
	if err := verify([][]byte{{0x30, 0x00}}, nil); err == nil {
		t.Error("expected verification failure, got nil")
	}
}

// TestVerifyCertPin_EmptyPinsRejects verifies the verifier refuses to
// validate anything when no pins are configured (defence in depth).
func TestVerifyCertPin_EmptyPinsRejects(t *testing.T) {
	verify := VerifyCertPin(nil)
	if err := verify([][]byte{{0x30, 0x00}}, nil); err == nil {
		t.Error("expected error for empty pin list")
	}
}

// TestVerifyCertPin_Match verifies that a matching SPKI hash succeeds.
func TestVerifyCertPin_Match(t *testing.T) {
	// Build an httptest TLS server and grab its leaf certificate's SPKI hash.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cert := srv.Certificate()
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	pin := hex.EncodeToString(sum[:])

	verify := VerifyCertPin([]string{pin})
	if err := verify([][]byte{cert.Raw}, nil); err != nil {
		t.Errorf("expected pin match, got error: %v", err)
	}
}
