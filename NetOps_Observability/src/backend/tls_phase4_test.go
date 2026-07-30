package backend

import (
	"context"
	"netops/backend/internal/vault"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internalca"
	"netops/backend/tlsconfig"
)

// TestCertValidMargin checks the readiness signal: a cert is "valid" only with
// more than `margin` left before expiry — so a near-expiry cert fails readiness
// and the LB pulls the instance before it serves a dead cert.
func TestCertValidMargin(t *testing.T) {
	// nil tlsServer / no reloader → readiness unaffected by TLS.
	if ok, _ := (&tlsServer{}).certValid(time.Minute); !ok {
		t.Fatal("no-TLS readiness should be ok")
	}

	ca, _ := internalca.Generate("ca", time.Hour)
	dir := t.TempDir()
	certF, keyF := filepath.Join(dir, "s.crt"), filepath.Join(dir, "s.key")
	svid, _ := ca.Issue(internalca.Request{SPIFFEID: "spiffe://netops/sa/api", TTL: 2 * time.Minute, Server: true})
	writeFileAtomic(certF, svid.CertPEM, 0o644)
	writeFileAtomic(keyF, svid.KeyPEM, 0o600)
	rl, err := tlsconfig.NewCertReloader(certF, keyF)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	ts := &tlsServer{reloader: rl}

	if ok, _ := ts.certValid(time.Minute); !ok {
		t.Fatal("cert with ~2m left should pass a 1m margin")
	}
	if ok, reason := ts.certValid(5 * time.Minute); ok {
		t.Fatalf("cert with ~2m left should FAIL a 5m margin, got ok (%s)", reason)
	}
}

// TestProvisionReissuesNewCert proves the rotation loop's unit of work: re-running
// provisionFromEnv mints a fresh cert (new serial) at the same paths — which the
// CertReloader then hot-swaps. No restart needed.
func TestProvisionReissuesNewCert(t *testing.T) {
	withTempCAKeys(t)
	dir := t.TempDir()
	certF, keyF := filepath.Join(dir, "api.crt"), filepath.Join(dir, "api.key")
	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("TLS_CERT_FILE", certF)
	t.Setenv("TLS_KEY_FILE", keyF)
	t.Setenv("TLS_SVID_TTL", "1h")

	v, _ := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	m, err := bootstrapInternalCA(v)
	if err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	serial := func() string {
		rl, err := tlsconfig.NewCertReloader(certF, keyF)
		if err != nil {
			t.Fatalf("reloader: %v", err)
		}
		return rl.Leaf().SerialNumber.String()
	}
	first := serial()
	if err := m.provisionFromEnv(); err != nil { // the loop's per-tick work
		t.Fatalf("reissue: %v", err)
	}
	if serial() == first {
		t.Fatal("re-issue must mint a new certificate (new serial)")
	}
}
