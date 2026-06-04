package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internalca"
)

func resetBackendTr(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { backendTr = nil })
	backendTr = nil
}

func writeCABundle(t *testing.T) string {
	t.Helper()
	ca, err := internalca.Generate("test-ca", time.Hour)
	if err != nil {
		t.Fatalf("ca: %v", err)
	}
	p := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(p, ca.CertPEM(), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

// TestBackendTransportDormant: no bundle env → plain client (system default),
// unchanged behavior.
func TestBackendTransportDormant(t *testing.T) {
	resetBackendTr(t)
	t.Setenv("TLS_BACKEND_CA_FILE", "")
	t.Setenv("TLS_CLIENT_CA_FILE", "")
	if err := initBackendTransport(); err != nil {
		t.Fatalf("dormant init: %v", err)
	}
	if backendTr != nil {
		t.Fatal("dormant must leave backendTr nil")
	}
	if c := backendHTTPClient(time.Second); c.Transport != nil {
		t.Fatal("dormant client must use the default transport")
	}
}

// TestBackendTransportConfigured: a valid internal CA bundle → hardened shared
// transport attached to backend clients.
func TestBackendTransportConfigured(t *testing.T) {
	resetBackendTr(t)
	t.Setenv("TLS_BACKEND_CA_FILE", writeCABundle(t))
	if err := initBackendTransport(); err != nil {
		t.Fatalf("configured init: %v", err)
	}
	if backendTr == nil {
		t.Fatal("configured init must build a transport")
	}
	if c := backendHTTPClient(2 * time.Second); c.Transport == nil || c.Timeout != 2*time.Second {
		t.Fatal("backend client must carry the shared transport + its timeout")
	}
}

// TestBackendTransportFailClosed: a configured-but-unloadable bundle is a fatal
// error — never a silent downgrade to the system pool.
func TestBackendTransportFailClosed(t *testing.T) {
	resetBackendTr(t)
	t.Setenv("TLS_BACKEND_CA_FILE", filepath.Join(t.TempDir(), "missing.pem"))
	if err := initBackendTransport(); err == nil {
		t.Fatal("unloadable CA bundle must error (fail closed)")
	}
}
