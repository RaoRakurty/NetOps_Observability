// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// exchange_azure_cert.go — Azure Entra certificate credential (Wave 4 #13).
//
// Entra's certificate flow is the client-credentials grant where, instead of a
// client_secret, the client presents a client_assertion: a short-lived JWT
// signed with the app certificate's RSA private key. Entra matches the signing
// certificate by thumbprint (the x5t JWT header) against the certificates
// uploaded to the app registration.
//
// Correlix stores the customer-uploaded certificate + private key as ONE PEM
// bundle, Vault-encrypted via the standard connector-secret path (the broker
// decrypts it only at exchange time, into req.LegacySecret). Zero-trust checks
// before anything touches the wire:
//   - the private key must match the certificate's public key,
//   - the certificate must not be expired / not yet valid,
//   - if the connector config carries a thumbprint, the bundle must match it
//     (a swapped or mis-pasted bundle is refused, not sent to Entra).

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- x5t is DEFINED as the SHA-1 certificate thumbprint (RFC 7515 §4.1.7); not an integrity mechanism
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"strings"
	"time"
)

// azureCertAssertionLifetime bounds the client assertion's validity. Entra only
// needs it to survive the token call; 5 minutes absorbs clock skew.
const azureCertAssertionLifetime = 5 * time.Minute

// azureCertMaterial is the parsed, cross-checked content of the uploaded
// certificate PEM bundle. Never logged; never serialized.
type azureCertMaterial struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
	x5t  string // base64url(SHA-1(cert DER)) — the JWT header value
}

// parseAzureCertBundle parses a PEM bundle holding exactly one certificate and
// one RSA private key (any block order; PKCS#8 or PKCS#1 keys). It verifies the
// key matches the certificate and the certificate is within its validity window.
func parseAzureCertBundle(bundle string, now time.Time) (azureCertMaterial, error) {
	var (
		key  *rsa.PrivateKey
		cert *x509.Certificate
	)
	rest := []byte(bundle)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		switch block.Type {
		case "CERTIFICATE":
			c, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate PEM block is not parseable"}
			}
			if cert != nil {
				// A chain is tolerated: keep the leaf (the one whose key we hold);
				// resolution happens after the loop via the key match.
				if c.IsCA {
					continue
				}
			}
			cert = c
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			if k, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
				rk, ok := k.(*rsa.PrivateKey)
				if !ok {
					return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "private key is not RSA"}
				}
				key = rk
				continue
			}
			rk, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "private key PEM block is not parseable"}
			}
			key = rk
		}
	}
	if cert == nil || key == nil {
		return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate bundle must contain one CERTIFICATE and one private key PEM block"}
	}
	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok {
		return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate public key is not RSA"}
	}
	if pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "private key does not match the certificate"}
	}
	if now.Before(cert.NotBefore) {
		return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate is not yet valid"}
	}
	if now.After(cert.NotAfter) {
		return azureCertMaterial{}, &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "certificate has expired — rotate the connector credential"}
	}
	sum := sha1.Sum(cert.Raw) // #nosec G401 -- x5t thumbprint per RFC 7515 §4.1.7, not integrity
	return azureCertMaterial{
		key:  key,
		cert: cert,
		x5t:  base64.RawURLEncoding.EncodeToString(sum[:]),
	}, nil
}

// NormalizeAzureThumbprint canonicalizes a portal-pasted thumbprint (uppercase
// hex, sometimes colon/space separated) to lowercase bare hex for comparison.
func NormalizeAzureThumbprint(s string) string {
	return strings.NewReplacer(":", "", " ", "").Replace(strings.ToLower(strings.TrimSpace(s)))
}

// azureThumbprintMatches compares a configured thumbprint against the parsed
// certificate. Empty configured value = nothing to check.
func azureThumbprintMatches(configured string, m azureCertMaterial) bool {
	c := NormalizeAzureThumbprint(configured)
	if c == "" {
		return true
	}
	sum := sha1.Sum(m.cert.Raw) // #nosec G401 -- thumbprint comparison, not integrity
	return c == hex.EncodeToString(sum[:])
}

// azureCertClientAssertion mints the signed client-assertion JWT for the Entra
// token endpoint: aud = the token endpoint URL, iss = sub = the app client id,
// x5t header = the certificate thumbprint, short-lived, unique jti.
func azureCertClientAssertion(m azureCertMaterial, clientID, tokenEndpoint string, now time.Time) (string, error) {
	jti, err := randomToken128()
	if err != nil {
		return "", &ExchangeError{Provider: ProviderAzure, Code: "request_invalid", Msg: "unable to mint assertion id"}
	}
	claims := map[string]any{
		"aud": tokenEndpoint,
		"iss": clientID,
		"sub": clientID,
		"jti": jti,
		"iat": now.Unix(),
		"nbf": now.Unix(),
		"exp": now.Add(azureCertAssertionLifetime).Unix(),
	}
	return signRS256JWTHeader(m.key, map[string]any{"x5t": m.x5t}, claims)
}

// randomToken128 returns 128 bits of crypto/rand as lowercase hex.
func randomToken128() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// AzureCertBundleThumbprint is the upload-time structural check the handler
// runs before encrypting the bundle: parseable, key-matches-cert, within
// validity. Returns the lowercase hex SHA-1 thumbprint for the non-secret
// key-hint / config cross-check.
func AzureCertBundleThumbprint(bundle string, now time.Time) (string, error) {
	m, err := parseAzureCertBundle(bundle, now)
	if err != nil {
		return "", err
	}
	sum := sha1.Sum(m.cert.Raw) // #nosec G401 -- thumbprint display value
	return hex.EncodeToString(sum[:]), nil
}
