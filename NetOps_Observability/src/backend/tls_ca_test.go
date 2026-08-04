package backend

import (
	"context"
	"crypto/x509"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"netops/backend/tlsconfig"
)

// withTempCAKeys redirects the CA kv blobs to a temp dir so the test doesn't
// touch the repo, and returns that dir.
func withTempCAKeys(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	oc, ok := kvCACertKey, kvCAKeyKey
	kvCACertKey = filepath.Join(dir, "ca.pem")
	kvCAKeyKey = filepath.Join(dir, "ca.key.enc")
	t.Cleanup(func() { kvCACertKey, kvCAKeyKey = oc, ok })
	return dir
}

// TestCAManagerSealsKeyAndIssues proves: (1) the CA private key is vault.Vault-sealed at
// rest (ciphertext, not the EC key PEM); (2) a reload decrypts it and yields a CA
// that issues SVIDs which load via tlsconfig and chain to the CA bundle. End to
// end: secret-custody → internal CA → tlsconfig.
func TestCAManagerSealsKeyAndIssues(t *testing.T) {
	dir := withTempCAKeys(t)
	v, err := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if err != nil {
		t.Fatalf("vault: %v", err)
	}

	if _, err := loadOrCreateCA(v, "netops"); err != nil {
		t.Fatalf("create CA: %v", err)
	}
	// The sealed key blob must be ciphertext, never the raw EC private key.
	raw, err := platformdb.Load(kvCAKeyKey)
	if err != nil {
		t.Fatalf("load sealed key: %v", err)
	}
	if strings.Contains(string(raw), "EC PRIVATE KEY") {
		t.Fatal("CA private key stored in plaintext")
	}
	if !strings.HasPrefix(string(raw), vault.VersionPrefix) {
		t.Fatalf("CA key not vault.Vault-sealed (no %s prefix)", vault.VersionPrefix)
	}

	// Reload decrypts the key and re-instantiates the SAME root.
	m, err := loadOrCreateCA(v, "netops")
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	certF := filepath.Join(dir, "api.crt")
	keyF := filepath.Join(dir, "api.key")
	if err := m.issueService(certF, keyF, "api", time.Hour, []string{"localhost"}, false, true); err != nil {
		t.Fatalf("issue: %v", err)
	}
	bundleF := filepath.Join(dir, "ca-bundle.pem")
	if err := m.writeBundle(bundleF); err != nil {
		t.Fatalf("bundle: %v", err)
	}

	// The issued pair must load through tlsconfig and chain to the bundle.
	rl, err := tlsconfig.NewCertReloader(certF, keyF)
	if err != nil {
		t.Fatalf("reloader: %v", err)
	}
	tb, err := tlsconfig.LoadTrustBundle(bundleF)
	if err != nil {
		t.Fatalf("trust bundle: %v", err)
	}
	if _, err := rl.Leaf().Verify(x509.VerifyOptions{Roots: tb.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("issued SVID does not chain to the CA bundle: %v", err)
	}
}

// TestBootstrapInternalCADormant: without TLS_INTERNAL_CA the bootstrap is a no-op.
func TestBootstrapInternalCADormant(t *testing.T) {
	t.Setenv("TLS_INTERNAL_CA", "")
	m, err := bootstrapInternalCA(vault.Dormant())
	if err != nil || m != nil {
		t.Fatalf("dormant bootstrap: want (nil,nil), got (%v,%v)", m, err)
	}
}

// TestBootstrapInternalCAIssuesCerts drives the full boot flow and checks the
// served cert + bundle land and load.
func TestBootstrapInternalCAIssuesCerts(t *testing.T) {
	withTempCAKeys(t)
	dir := t.TempDir()
	certF := filepath.Join(dir, "api.crt")
	keyF := filepath.Join(dir, "api.key")
	caF := filepath.Join(dir, "ca.pem")
	ngDir := filepath.Join(dir, "nginx")
	vmDir := filepath.Join(dir, "victoria")
	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("TLS_CERT_FILE", certF)
	t.Setenv("TLS_KEY_FILE", keyF)
	t.Setenv("TLS_CLIENT_CA_FILE", caF)
	t.Setenv("TLS_NGINX_CERT_DIR", ngDir)
	t.Setenv("TLS_VICTORIA_CERT_DIR", vmDir)
	t.Setenv("TLS_SVID_TTL", "1h")

	v, _ := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if _, err := bootstrapInternalCA(v); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	if _, err := tlsconfig.NewCertReloader(certF, keyF); err != nil {
		t.Fatalf("api SVID not usable: %v", err)
	}
	if _, err := tlsconfig.LoadTrustBundle(caF); err != nil {
		t.Fatalf("CA bundle not written: %v", err)
	}
	if _, err := tlsconfig.NewCertReloader(filepath.Join(ngDir, "nginx.crt"), filepath.Join(ngDir, "nginx.key")); err != nil {
		t.Fatalf("nginx SVID not usable: %v", err)
	}
	// #149: the metrics scraper's client SVID, so the api:8080 scrape survives
	// the mTLS-only listener.
	if _, err := tlsconfig.NewCertReloader(filepath.Join(vmDir, "victoria.crt"), filepath.Join(vmDir, "victoria.key")); err != nil {
		t.Fatalf("victoria SVID not usable: %v", err)
	}
}
