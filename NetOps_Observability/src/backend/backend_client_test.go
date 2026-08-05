package backend

import (
	"net/http"
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
	// SEC-010 made the userinfo seam unconditional: dormant means the
	// DEFAULT transport underneath authURLTransport, not a nil Transport
	// (this assertion previously predated the seam and checked for nil).
	c := backendHTTPClient(time.Second)
	at, ok := c.Transport.(authURLTransport)
	if !ok {
		t.Fatalf("dormant client transport is %T, want authURLTransport", c.Transport)
	}
	if at.base != http.DefaultTransport {
		t.Fatal("dormant client must ride the default transport under the auth seam")
	}
}

// TestBackendClientSVIDDeferredOnFirstBoot: with the internal CA enabled and
// the api's own SVID not yet minted (virgin deployment — bootstrapInternalCA
// runs AFTER the first init), the transport must still be built CA-verified,
// just without the client certificate; a missing SVID must not brick boot
// (APP-001 made TLS_BACKEND_CERT_FILE load-bearing for api→correlation).
func TestBackendClientSVIDDeferredOnFirstBoot(t *testing.T) {
	resetBackendTr(t)
	t.Setenv("TLS_BACKEND_CA_FILE", writeCABundle(t))
	t.Setenv("TLS_INTERNAL_CA", "true")
	missing := filepath.Join(t.TempDir(), "api.crt")
	t.Setenv("TLS_BACKEND_CERT_FILE", missing)
	t.Setenv("TLS_BACKEND_KEY_FILE", filepath.Join(t.TempDir(), "api.key"))
	if err := initBackendTransport(); err != nil {
		t.Fatalf("first-boot init with unminted SVID must defer, got: %v", err)
	}
	if backendTr == nil {
		t.Fatal("the CA-verified transport must still be built while the SVID is deferred")
	}
	// Without the internal CA flag, the same missing file is a hard error —
	// the deferral is narrow, never a general silent downgrade.
	resetBackendTr(t)
	t.Setenv("TLS_INTERNAL_CA", "")
	if err := initBackendTransport(); err == nil {
		t.Fatal("missing client SVID without the internal CA must fail closed")
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
