package internalca

// SEC-008: issued SVID keys must be PKCS#8 — the OpenSearch security plugin
// accepts nothing else, and every other consumer (Go tls.X509KeyPair, nginx,
// postgres, clickhouse via OpenSSL) accepts both. Pinned so a future "tidy"
// back to SEC1 fails here instead of at an OpenSearch bootstrap.

import (
	"crypto/tls"
	"encoding/pem"
	"strings"
	"testing"
	"time"
)

func TestIssuedKeysArePKCS8AndLoadable(t *testing.T) {
	ca, err := Generate("test ca", time.Hour)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	svid, err := ca.Issue(Request{SPIFFEID: "spiffe://netops/ns/default/sa/opensearch", DNSNames: []string{"opensearch"}, TTL: time.Hour, Server: true, Client: true})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	blk, _ := pem.Decode(svid.KeyPEM)
	if blk == nil {
		t.Fatal("key is not PEM")
	}
	if blk.Type != "PRIVATE KEY" {
		t.Fatalf("key PEM type = %q, want \"PRIVATE KEY\" (PKCS#8)", blk.Type)
	}
	if strings.Contains(string(svid.KeyPEM), "EC PRIVATE KEY") {
		t.Fatal("key is SEC1 — the OpenSearch security plugin will refuse it")
	}
	// And it must still be a usable keypair for every Go consumer.
	if _, err := tls.X509KeyPair(svid.CertPEM, svid.KeyPEM); err != nil {
		t.Fatalf("PKCS#8 SVID not loadable by tls.X509KeyPair: %v", err)
	}
}
