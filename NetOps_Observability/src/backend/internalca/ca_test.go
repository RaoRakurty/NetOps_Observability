package internalca

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func parseFirstCert(pemBytes []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(pemBytes)
	if b == nil {
		return nil, errors.New("no PEM block")
	}
	return x509.ParseCertificate(b.Bytes)
}

func mustGenerate(t *testing.T) *CA {
	t.Helper()
	ca, err := Generate("netops-internal-ca", time.Hour)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return ca
}

// verifyLeaf parses an issued cert and checks it chains to the CA with the
// expected EKU — the core "did we mint a usable, trusted SVID" assertion.
func verifyLeaf(t *testing.T, ca *CA, svid *SVID, want x509.ExtKeyUsage) *x509.Certificate {
	t.Helper()
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca.CertPEM()) {
		t.Fatal("append CA cert")
	}
	block := svid.CertPEM
	cert, err := parseFirstCert(block)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{want}}); err != nil {
		t.Fatalf("leaf does not chain to CA for %v: %v", want, err)
	}
	return cert
}

func TestIssueServerSVID(t *testing.T) {
	ca := mustGenerate(t)
	id := "spiffe://netops/ns/default/sa/api"
	svid, err := ca.Issue(Request{SPIFFEID: id, DNSNames: []string{"api.netops"}, TTL: 30 * time.Minute, Server: true})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	cert := verifyLeaf(t, ca, svid, x509.ExtKeyUsageServerAuth)
	if len(cert.URIs) != 1 || cert.URIs[0].String() != id {
		t.Fatalf("URI SAN = %v, want %s", cert.URIs, id)
	}
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != "api.netops" {
		t.Fatalf("DNS SAN = %v", cert.DNSNames)
	}
	// Short-lived: NotAfter ~ now+TTL, not the CA's lifetime.
	if d := time.Until(cert.NotAfter); d > 31*time.Minute || d < 28*time.Minute {
		t.Fatalf("TTL not honored: NotAfter in %v", d)
	}
}

func TestIssueClientSVID(t *testing.T) {
	ca := mustGenerate(t)
	svid, err := ca.Issue(Request{SPIFFEID: "spiffe://netops/ns/default/sa/nginx", TTL: time.Hour, Client: true})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	verifyLeaf(t, ca, svid, x509.ExtKeyUsageClientAuth)
	// A client-only SVID must NOT validate for server auth.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(ca.CertPEM())
	cert, _ := parseFirstCert(svid.CertPEM)
	if _, err := cert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err == nil {
		t.Fatal("client SVID must not satisfy serverAuth")
	}
}

func TestPEMRoundTrip(t *testing.T) {
	ca := mustGenerate(t)
	keyPEM, err := ca.KeyPEM()
	if err != nil {
		t.Fatalf("KeyPEM: %v", err)
	}
	reloaded, err := FromPEM(ca.CertPEM(), keyPEM)
	if err != nil {
		t.Fatalf("FromPEM: %v", err)
	}
	// A reloaded CA must still mint certs that chain to the SAME root.
	svid, err := reloaded.Issue(Request{SPIFFEID: "spiffe://netops/ns/default/sa/x", TTL: time.Hour, Server: true})
	if err != nil {
		t.Fatalf("issue after reload: %v", err)
	}
	verifyLeaf(t, ca, svid, x509.ExtKeyUsageServerAuth) // verified against the ORIGINAL ca cert
}

func TestIssueValidation(t *testing.T) {
	ca := mustGenerate(t)
	if _, err := ca.Issue(Request{TTL: time.Hour, Server: true}); err == nil {
		t.Error("missing SPIFFE ID must error")
	}
	if _, err := ca.Issue(Request{SPIFFEID: "spiffe://x/y", Server: true}); err == nil {
		t.Error("non-positive TTL must error")
	}
	if _, err := Generate("x", 0); err == nil {
		t.Error("non-positive CA validity must error")
	}
	if _, err := FromPEM([]byte("not a pem"), []byte("nope")); err == nil {
		t.Error("garbage PEM must error")
	}
}
