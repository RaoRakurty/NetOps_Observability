// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package jwks

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
)

// jwks.go — OIDC discovery + JWKS-based RS256 verification, pure stdlib.
//
// This is what lets the Go API validate the ID tokens Keycloak issues at the
// OIDC callback (and, optionally, Keycloak-signed Bearer tokens presented by
// service-account API clients) WITHOUT pulling a JWT/JOSE library:
//
//   - discovery is a JSON GET of /.well-known/openid-configuration
//   - JWKS is JSON; an RSA public key is rebuilt from its (n, e) parameters
//   - RS256 verification is crypto/rsa.VerifyPKCS1v15 + crypto/sha256
//
// Keeping this in stdlib is the whole reason the design pushes federation out
// to Keycloak (see docs/IDENTITY_ACCESS.md): the backend "only learns to verify
// RS256 against a JWKS URL".

type Discovery struct {
	Issuer        string `json:"issuer"`
	AuthEndpoint  string `json:"authorization_endpoint"`
	TokenEndpoint string `json:"token_endpoint"`
	JWKSURI       string `json:"jwks_uri"`
	UserInfo      string `json:"userinfo_endpoint"`
	EndSession    string `json:"end_session_endpoint"`
}

type jwk struct {
	Kid string `json:"kid"`
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// Claims are the subset of standard + Keycloak claims we consume. Aud is
// kept raw because the spec allows either a string or an array.
type Claims struct {
	Sub               string          `json:"sub"`
	Email             string          `json:"email"`
	EmailVerified     bool            `json:"email_verified"`
	PreferredUsername string          `json:"preferred_username"`
	Name              string          `json:"name"`
	Iss               string          `json:"iss"`
	Aud               json.RawMessage `json:"aud"`
	Azp               string          `json:"azp"`
	Exp               int64           `json:"exp"`
	Iat               int64           `json:"iat"`
	RealmAccess       struct {
		Roles []string `json:"roles"`
	} `json:"realm_access"`
	Groups []string `json:"groups"`
	// Authentication assurance (OIDC): amr = methods used (e.g. pwd, otp, mfa, hwk,
	// sms, webauthn), acr = assurance class. Used to verify the IdP performed MFA
	// when the SSO config requires it.
	Amr []string `json:"amr"`
	Acr string   `json:"acr"`
	// Nonce echoes the value the RP sent on the authorization request (OIDC Core
	// §3.1.3.7 #11): the SSO callback compares it against the server-side login
	// transaction so a captured/substituted ID token cannot complete a login it
	// was not minted for.
	Nonce string `json:"nonce"`
}

func (c Claims) Audiences() []string {
	if len(c.Aud) == 0 {
		return nil
	}
	var one string
	if err := json.Unmarshal(c.Aud, &one); err == nil {
		return []string{one}
	}
	var many []string
	_ = json.Unmarshal(c.Aud, &many) // best-effort: aud may be a bare string (handled above); malformed yields empty
	return many
}

// Cache fetches and caches an issuer's discovery doc and signing keys.
// Keys are refreshed on a TTL and on a cache miss (Keycloak rotates kids).
//
// H10 (fetch-amplification guard): an unknown `kid` used to trigger one
// outbound IdP fetch PER verification — unauthenticated callers could aim a
// firehose of made-up kids at us and we would relay it to the IdP. Refreshes
// are now single-flighted (refreshMu — concurrent verifications share one
// fetch) and rate-floored (minRefreshInterval between kid-miss fetches);
// within the floor an unknown kid fails from cache — the negative-cache
// effect: a kid the last fetch didn't know stays unknown until the floor
// elapses. A real Keycloak rotation is still picked up on the first miss
// after the floor.
type Cache struct {
	issuer string
	client *http.Client
	ttl    time.Duration

	// refreshMu single-flights the JWKS fetch: one holder performs it, every
	// concurrent kid-miss waits and re-checks the refreshed cache (stdlib-only
	// per §6 — no x/sync singleflight).
	refreshMu sync.Mutex

	mu        sync.RWMutex
	disc      *Discovery
	keys      map[string]*rsa.PublicKey // kid -> key
	fetchedAt time.Time
	// attemptedAt is the last refresh ATTEMPT (success or failure) — the
	// floor between kid-miss fetches. Failure counts too: a down IdP must not
	// be hammered by every bad token.
	attemptedAt time.Time
}

// minRefreshInterval is the floor between kid-miss-driven JWKS fetches: an
// unknown kid within the floor is answered from cache (i.e. refused) instead
// of relayed to the IdP. 30s keeps rotation pickup prompt while capping the
// amplification an attacker gets to ~2 fetches/min regardless of volume.
const minRefreshInterval = 30 * time.Second

// New builds a cache for one issuer. ttl is how long signing keys are cached
// before a refresh (the IdP cert-rollover interval; the integrator reads it
// from config — see jwksTTL in the entrypoint package). Keys are additionally
// refreshed on an unknown-kid miss, so a rotation is picked up immediately
// regardless. A non-positive ttl falls back to 10 minutes.
func New(issuer string, ttl time.Duration) *Cache {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &Cache{
		issuer: strings.TrimRight(issuer, "/"),
		client: &http.Client{Timeout: 10 * time.Second},
		ttl:    ttl,
		keys:   make(map[string]*rsa.PublicKey),
	}
}

func (c *Cache) Discovery() (*Discovery, error) {
	c.mu.RLock()
	d := c.disc
	c.mu.RUnlock()
	if d != nil {
		return d, nil
	}
	url := c.issuer + "/.well-known/openid-configuration"
	var got Discovery
	if err := c.getJSON(url, &got); err != nil {
		return nil, fmt.Errorf("oidc discovery: %w", err)
	}
	if got.JWKSURI == "" || got.TokenEndpoint == "" {
		return nil, errors.New("oidc discovery incomplete")
	}
	c.mu.Lock()
	c.disc = &got
	c.mu.Unlock()
	return &got, nil
}

// keyFor returns the signing key for kid, refreshing the JWKS if it's unknown
// or the cache has gone stale — at most once per minRefreshInterval, shared
// across concurrent callers (H10).
func (c *Cache) keyFor(kid string) (*rsa.PublicKey, error) {
	c.mu.RLock()
	k, ok := c.keys[kid]
	fresh := time.Since(c.fetchedAt) < c.ttl
	c.mu.RUnlock()
	if ok && fresh {
		return k, nil
	}
	// Single-flight: the first miss fetches; everyone else queues here and
	// re-checks the cache the winner just refreshed.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	c.mu.RLock()
	k2, ok2 := c.keys[kid]
	fresh2 := time.Since(c.fetchedAt) < c.ttl
	floored := time.Since(c.attemptedAt) < minRefreshInterval
	c.mu.RUnlock()
	if ok2 && fresh2 {
		return k2, nil // a concurrent verification already refreshed
	}
	if floored {
		// Negative cache: a fetch within the floor already didn't know this
		// kid (or already failed). Serve the stale key if we hold one; refuse
		// the unknown kid WITHOUT another outbound call.
		if ok2 {
			return k2, nil
		}
		return nil, fmt.Errorf("no JWKS key for kid %q", kid)
	}
	if err := c.refresh(); err != nil {
		// Serve a stale key rather than fail if we have one.
		if ok2 {
			return k2, nil
		}
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	if kid == "" && len(c.keys) == 1 {
		for _, only := range c.keys {
			return only, nil
		}
	}
	return nil, fmt.Errorf("no JWKS key for kid %q", kid)
}

// Refresh eagerly fetches the discovery document and signing keys — useful to
// pre-warm the cache or probe a live IdP; VerifyRS256 refreshes on demand.
func (c *Cache) Refresh() error {
	// Explicit refreshes (boot pre-warm, admin probe) bypass the kid-miss
	// floor but still single-flight against concurrent verifications.
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()
	return c.refresh()
}

// KeyCount reports how many signing keys are currently cached.
func (c *Cache) KeyCount() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.keys)
}

func (c *Cache) refresh() error {
	// Stamp the ATTEMPT before any network IO, success or not: the floor in
	// keyFor must hold even (especially) when the IdP is down or slow —
	// otherwise every bad token still produces an outbound connection.
	c.mu.Lock()
	c.attemptedAt = time.Now()
	c.mu.Unlock()
	disc, err := c.Discovery()
	if err != nil {
		return err
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := c.getJSON(disc.JWKSURI, &doc); err != nil {
		return fmt.Errorf("fetch jwks: %w", err)
	}
	next := make(map[string]*rsa.PublicKey, len(doc.Keys))
	for _, k := range doc.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := rsaKeyFromJWK(k)
		if err != nil {
			continue
		}
		next[k.Kid] = pub
	}
	if len(next) == 0 {
		return errors.New("jwks contained no usable RSA keys")
	}
	c.mu.Lock()
	c.keys = next
	c.fetchedAt = time.Now()
	c.mu.Unlock()
	return nil
}

func (c *Cache) getJSON(url string, out any) error {
	resp, err := c.client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("%s returned %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, out)
}

// rsaKeyFromJWK rebuilds an *rsa.PublicKey from the base64url (n, e) JWK params.
func rsaKeyFromJWK(k jwk) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.N, "="))
	if err != nil {
		return nil, err
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.E, "="))
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(nBytes)
	// e is a big-endian integer, usually 65537. Left-pad to 8 bytes for Uint64.
	var eb [8]byte
	copy(eb[8-len(eBytes):], eBytes)
	e := int(binary.BigEndian.Uint64(eb[:])) // #nosec G115 -- RSA exponent (tiny, e.g. 65537); the e<=0 guard below rejects any wrap
	if e <= 0 {
		return nil, errors.New("invalid RSA exponent")
	}
	return &rsa.PublicKey{N: n, E: e}, nil
}

// VerifyRS256 validates a compact JWT's signature against the issuer's JWKS and
// checks exp/iss/aud. It returns the decoded claims on success.
func (c *Cache) VerifyRS256(token, wantIssuer, wantAudience string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("malformed jwt")
	}
	var hdr struct {
		Alg string `json:"alg"`
		Kid string `json:"kid"`
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, errors.New("bad jwt header")
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return Claims{}, errors.New("bad jwt header")
	}
	if hdr.Alg != "RS256" {
		return Claims{}, fmt.Errorf("unexpected jwt alg %q", hdr.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, errors.New("bad jwt signature encoding")
	}
	// H10: decode + structurally validate the claims BEFORE the key lookup —
	// keyFor can trigger an outbound IdP fetch on an unknown kid, and a
	// malformed/expired/wrong-issuer token must be refused without ever
	// costing a network call. Nothing here TRUSTS the claims yet: every
	// checked value is re-covered by the signature verified below, and the
	// claims are only returned after that verification passes.
	cb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, errors.New("bad jwt claims encoding")
	}
	var claims Claims
	if err := json.Unmarshal(cb, &claims); err != nil {
		return Claims{}, errors.New("bad jwt claims")
	}
	if claims.Exp != 0 && time.Now().Unix() > claims.Exp {
		return Claims{}, errors.New("token expired")
	}
	if wantIssuer != "" && strings.TrimRight(claims.Iss, "/") != strings.TrimRight(wantIssuer, "/") {
		return Claims{}, fmt.Errorf("issuer mismatch: %s", claims.Iss)
	}
	pub, err := c.keyFor(hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	signed := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, signed[:], sig); err != nil {
		return Claims{}, errors.New("jwt signature invalid")
	}
	if wantAudience != "" {
		ok := claims.Azp == wantAudience
		for _, a := range claims.Audiences() {
			if a == wantAudience {
				ok = true
			}
		}
		if !ok {
			return Claims{}, errors.New("audience mismatch")
		}
	}
	return claims, nil
}
