// Package internalca is a small, stdlib-only certificate authority for the
// internal service mesh (#18 phase 2). It issues SHORT-LIVED leaf certs ("SVIDs")
// carrying a SPIFFE URI SAN, all chaining to a private root that is NEVER a public
// CA — so internal mTLS trusts only identities this platform minted.
//
// It is deliberately minimal (no CRL/OCSP server): revocation is by short TTL +
// fast rotation, the SPIFFE model. The issued cert+key feed a
// tlsconfig.CertReloader; the CA cert feeds a tlsconfig.TrustBundle. The CA
// private key is sealed at rest by the #17 Vault (see the caller, tls_ca.go).
package internalca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

const (
	pemCertType = "CERTIFICATE"
	pemKeyType  = "EC PRIVATE KEY"
)

// CA is an internal certificate authority (ECDSA P-256 root).
type CA struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
}

// Generate creates a new self-signed CA root valid for the given lifetime. The
// root is constrained (IsCA, KeyUsageCertSign) and pathlen 0 — it signs leaves
// only, not sub-CAs.
func Generate(commonName string, validity time.Duration) (*CA, error) {
	if validity <= 0 {
		return nil, errors.New("internalca: validity must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(validity),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, key: key, certPEM: encodePEM(pemCertType, der)}, nil
}

// FromPEM reconstructs a CA from its cert + key PEM (e.g. after the key is
// Vault-decrypted on boot).
func FromPEM(certPEM, keyPEM []byte) (*CA, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != pemCertType {
		return nil, errors.New("internalca: invalid CA certificate PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("internalca: parse CA cert: %w", err)
	}
	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != pemKeyType {
		return nil, errors.New("internalca: invalid CA key PEM")
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("internalca: parse CA key: %w", err)
	}
	if !cert.IsCA {
		return nil, errors.New("internalca: certificate is not a CA")
	}
	return &CA{cert: cert, key: key, certPEM: certPEM}, nil
}

// CertPEM returns the CA certificate PEM (the trust anchor — safe to distribute).
func (ca *CA) CertPEM() []byte { return ca.certPEM }

// KeyPEM returns the CA private key PEM. SENSITIVE — the caller must seal it at
// rest (Vault) and never log or distribute it.
func (ca *CA) KeyPEM() ([]byte, error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, err
	}
	return encodePEM(pemKeyType, der), nil
}

// NotAfter is the CA root's expiry (for rotation scheduling / metrics).
func (ca *CA) NotAfter() time.Time { return ca.cert.NotAfter }

// Request describes a leaf to mint.
type Request struct {
	// SPIFFEID becomes the URI SAN, e.g. spiffe://netops/ns/default/sa/api. The
	// authoritative service identity; required.
	SPIFFEID string
	// DNSNames are additional DNS SANs (service hostnames for SNI/hostname checks).
	DNSNames []string
	// TTL is the leaf lifetime; short by design (hours–days).
	TTL time.Duration
	// Client mints a clientAuth leaf (a service proving identity TO a peer);
	// otherwise serverAuth. Both EKUs are set when a service is both.
	Client bool
	Server bool
}

// SVID is an issued identity (cert + key PEM) plus its expiry.
type SVID struct {
	CertPEM  []byte
	KeyPEM   []byte
	NotAfter time.Time
}

// Issue mints a short-lived leaf signed by the CA. Fail-closed: a missing SPIFFE
// ID or non-positive TTL is rejected.
func (ca *CA) Issue(req Request) (*SVID, error) {
	if req.SPIFFEID == "" {
		return nil, errors.New("internalca: SPIFFEID required")
	}
	uri, err := url.Parse(req.SPIFFEID)
	if err != nil {
		return nil, fmt.Errorf("internalca: invalid SPIFFE ID %q: %w", req.SPIFFEID, err)
	}
	if uri.Scheme == "" {
		// Parsed, but not a URI (no scheme) — a different operator/caller mistake
		// from an unparseable string, and both must stay fail-closed.
		return nil, fmt.Errorf("internalca: invalid SPIFFE ID %q: missing scheme (want spiffe://…)", req.SPIFFEID)
	}
	if req.TTL <= 0 {
		return nil, errors.New("internalca: TTL must be positive")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randSerial()
	if err != nil {
		return nil, err
	}
	var eku []x509.ExtKeyUsage
	if req.Server || !req.Client {
		eku = append(eku, x509.ExtKeyUsageServerAuth)
	}
	if req.Client {
		eku = append(eku, x509.ExtKeyUsageClientAuth)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: req.SPIFFEID},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(req.TTL),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  eku,
		DNSNames:     req.DNSNames,
		URIs:         []*url.URL{uri},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &SVID{
		CertPEM:  encodePEM(pemCertType, der),
		KeyPEM:   encodePEM(pemKeyType, kder),
		NotAfter: tmpl.NotAfter,
	}, nil
}

func randSerial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
}

func encodePEM(typ string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der})
}
