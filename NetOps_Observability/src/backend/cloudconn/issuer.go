package cloudconn

// issuer.go — the platform workload OIDC issuer's signing-key custody (Wave 4
// #13, extracted P2 RA.11). The platform holds one RSA signing key: generated
// on first boot, private half Vault-sealed at rest (the internal-CA custody
// pattern), kid = RFC 7638 JWK thumbprint. The well-known HTTP endpoints and
// the boot-time wiring stay with the entrypoint; this file owns load-or-create
// and the assertion-source projection the broker's adapters mint with.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"netops/backend/internal/platformdb"
	"netops/backend/internal/vault"
)

const (
	// WorkloadIssuerKeyField is the Vault AAD field-id (platform DEK). PINNED:
	// existing sealed keys decrypt only under this label.
	WorkloadIssuerKeyField = "cloudconn.workload.issuer.key"
	workloadIssuerKeyBits  = 2048 // RS256 interop floor for AWS/Azure/GCP OIDC federation
)

// kv key for the sealed signing key — a var so tests redirect it to a temp
// path (the file backend treats a kv key as a path), via SetIssuerKeyPathForTest.
var workloadIssuerKeyKV = "cloud_workload_issuer_key.enc"

// SetIssuerKeyPathForTest redirects the sealed-key kv path and returns a
// restore func (the *ForTest idiom).
func SetIssuerKeyPathForTest(path string) (restore func()) {
	orig := workloadIssuerKeyKV
	workloadIssuerKeyKV = path
	return func() { workloadIssuerKeyKV = orig }
}

// WorkloadIssuer is the loaded platform issuer identity.
type WorkloadIssuer struct {
	key    *rsa.PrivateKey
	kid    string // RFC 7638 JWK thumbprint of the public key
	issuer string // normalized public issuer URL (no trailing slash)
}

// Issuer returns the normalized public issuer URL.
func (wi *WorkloadIssuer) Issuer() string { return wi.issuer }

// Kid returns the RFC 7638 thumbprint key id.
func (wi *WorkloadIssuer) Kid() string { return wi.kid }

// PublicKey returns the verification half for JWKS rendering.
func (wi *WorkloadIssuer) PublicKey() *rsa.PublicKey { return &wi.key.PublicKey }

// Source returns the assertion source the broker's adapters mint with.
func (wi *WorkloadIssuer) Source() MintedWorkloadAssertionSource {
	return MintedWorkloadAssertionSource{Key: wi.key, Kid: wi.kid, Issuer: wi.issuer}
}

// LoadOrCreateWorkloadIssuer loads the sealed signing key from the kv store
// or, on first run, generates and persists one. issuerURL must be an absolute
// http(s) URL — it becomes the `iss` every relying provider pins.
func LoadOrCreateWorkloadIssuer(v *vault.Vault, issuerURL string) (*WorkloadIssuer, error) {
	u := strings.TrimRight(strings.TrimSpace(issuerURL), "/")
	if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
		return nil, fmt.Errorf("workload issuer: CLOUD_WORKLOAD_ISSUER_URL must be an absolute http(s) URL, got %q", issuerURL)
	}
	if enc, err := platformdb.Load(workloadIssuerKeyKV); err == nil && len(enc) > 0 {
		keyPEM, err := v.Decrypt("", WorkloadIssuerKeyField, string(enc))
		if err != nil {
			return nil, fmt.Errorf("workload issuer: decrypt signing key: %w", err)
		}
		key, err := parseRSAPrivatePEM([]byte(keyPEM))
		if err != nil {
			return nil, fmt.Errorf("workload issuer: parse signing key: %w", err)
		}
		return &WorkloadIssuer{key: key, kid: RSAJWKThumbprintKid(&key.PublicKey), issuer: u}, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, workloadIssuerKeyBits)
	if err != nil {
		return nil, fmt.Errorf("workload issuer: generate signing key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	sealed, err := v.Encrypt("", WorkloadIssuerKeyField, string(keyPEM))
	if err != nil {
		return nil, fmt.Errorf("workload issuer: seal signing key: %w", err)
	}
	if err := platformdb.Save(workloadIssuerKeyKV, []byte(sealed)); err != nil {
		return nil, fmt.Errorf("workload issuer: persist signing key: %w", err)
	}
	return &WorkloadIssuer{key: key, kid: RSAJWKThumbprintKid(&key.PublicKey), issuer: u}, nil
}

// parseRSAPrivatePEM decodes a PKCS#8 (or legacy PKCS#1) RSA private key PEM.
func parseRSAPrivatePEM(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}
	if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rk, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA key")
		}
		return rk, nil
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
