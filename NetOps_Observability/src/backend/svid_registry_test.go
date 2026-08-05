package backend

// svid_registry_test.go — SEC-003.3 issuance end-to-end: drive the real CA
// over the whole workloadid.Registry and verify each leaf. The registry's own
// completeness/uniqueness guards live with the table
// (internal/workloadid/workloadid_test.go); this file proves the wiring in
// tls_ca.go mints exactly what the table declares.

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"netops/backend/internal/vault"
	"netops/backend/internal/workloadid"
)

func TestRegistryIssuanceMintsEveryRow(t *testing.T) {
	withTempCAKeys(t)
	root := t.TempDir()
	t.Setenv("TLS_INTERNAL_CA", "true")
	t.Setenv("TLS_SERVICE_CERT_ROOT", root)
	t.Setenv("TLS_CERT_FILE", "")
	t.Setenv("TLS_KEY_FILE", "")
	t.Setenv("TLS_CLIENT_CA_FILE", "")
	t.Setenv("TLS_NGINX_CERT_DIR", "")
	t.Setenv("TLS_VICTORIA_CERT_DIR", "")
	t.Setenv("TLS_SVID_TTL", "1h")

	v, _ := vault.NewWithProvider(context.Background(), &memSealing{}, &memVaultStore{data: map[string][]byte{}}, func(string, string, map[string]any) {})
	if _, err := bootstrapInternalCA(v); err != nil {
		t.Fatalf("bootstrap: %v", err)
	}
	for _, e := range workloadid.Registry {
		certPath := filepath.Join(root, e.Service, e.Service+".crt")
		raw, err := os.ReadFile(certPath)
		if err != nil {
			t.Errorf("%s: SVID not minted: %v", e.Service, err)
			continue
		}
		block, _ := pem.Decode(raw)
		if block == nil {
			t.Errorf("%s: not PEM", e.Service)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Errorf("%s: parse: %v", e.Service, err)
			continue
		}
		wantURI := "spiffe://netops/ns/default/sa/" + e.Service
		if len(cert.URIs) != 1 || cert.URIs[0].String() != wantURI {
			t.Errorf("%s: URI SANs = %v, want exactly [%s]", e.Service, cert.URIs, wantURI)
		}
		if got, want := strings.Join(cert.DNSNames, ","), strings.Join(e.DNS, ","); got != want {
			t.Errorf("%s: DNS SANs = %q, want %q", e.Service, got, want)
		}
		hasEKU := func(k x509.ExtKeyUsage) bool {
			for _, u := range cert.ExtKeyUsage {
				if u == k {
					return true
				}
			}
			return false
		}
		if e.Client != hasEKU(x509.ExtKeyUsageClientAuth) {
			t.Errorf("%s: ClientAuth EKU presence = %v, want %v", e.Service, !e.Client, e.Client)
		}
		if e.Server != hasEKU(x509.ExtKeyUsageServerAuth) {
			t.Errorf("%s: ServerAuth EKU presence = %v, want %v", e.Service, !e.Server, e.Server)
		}
		// Self-contained dir: the trust anchor ships beside the leaf so a
		// consumer can mount ONE read-only directory (SEC-008: OpenSearch
		// rejects paths outside its config dir; docker cannot nest a file
		// mount inside a read-only dir mount).
		if _, err := os.Stat(filepath.Join(root, e.Service, "ca.pem")); err != nil {
			t.Errorf("%s: trust bundle missing from the service dir: %v", e.Service, err)
		}
		// 0600 keys: the mount decides who reads them; the file mode must not.
		ki, err := os.Stat(filepath.Join(root, e.Service, e.Service+".key"))
		if err != nil {
			t.Errorf("%s: key missing: %v", e.Service, err)
		} else if ki.Mode().Perm() != 0o600 {
			t.Errorf("%s: key mode %o, want 600", e.Service, ki.Mode().Perm())
		}
	}
}
