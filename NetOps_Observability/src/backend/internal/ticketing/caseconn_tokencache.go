// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ticketing

// caseconn_tokencache.go — the keyed, bounded OAuth token cache the vendor case
// connectors share.
//
// WHY THIS EXISTS (§3a TENANT ISOLATION). DefaultCaseConnectorRegistry builds
// exactly ONE CiscoSmartBondingConnector and ONE JuniperConnector for the whole
// server, and every tenant's case is filed through that one object with its own
// configuration handed in per call. A bearer cached in a plain field on such a
// connector therefore belongs to no tenant in particular: the first tenant to
// open a case mints one, and the next tenant is handed it. That is a
// cross-tenant credential leak — tenant B's case, serial number, problem text
// and evidence bundle filed under tenant A's vendor account and against A's
// quota, and B able to read A's case back with the same bearer.
//
// The rule is the one mailbox_auth.go already states for the mailbox
// connectors, and this is the same pattern: the cache is keyed by the
// CREDENTIAL, never by the connector. Two tenants cannot collide on a key, and
// no tenant can be handed a bearer minted from another's credential.
//
// SECRETS (§8). The key carries a DIGEST of the client secret and the plaintext
// identity fields around it, never the secret itself. So the key is safe to
// hold in memory beside the token, and a rotated secret produces a different
// key rather than letting the old bearer outlive it.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"sync"
	"time"
)

// maxVendorTokenCache bounds the cache so a deployment with many tenants, or a
// tenant rotating credentials in a loop, cannot grow it without limit (§9: all
// queues bounded).
const maxVendorTokenCache = 256

type cachedVendorToken struct {
	token   string
	expires time.Time
}

// vendorTokenCache holds one bearer per credential. Its zero value is usable:
// the map is created on the first store, so a connector needs no constructor
// change to get one.
type vendorTokenCache struct {
	mu      sync.Mutex
	entries map[string]cachedVendorToken
}

// lookup returns a cached bearer for one credential, and only while it is still
// more than a minute from expiry — the same refresh margin the mailbox cache
// uses, so a token cannot expire in flight.
func (c *vendorTokenCache) lookup(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit, ok := c.entries[key]
	if !ok || !time.Now().Before(hit.expires.Add(-time.Minute)) {
		return "", false
	}
	return hit.token, true
}

// store caches one bearer and keeps the cache bounded: expired entries go
// first, and a cache still at its ceiling after that is dropped wholesale
// rather than grown. Losing a cached token costs one extra mint, never a wrong
// answer.
func (c *vendorTokenCache) store(key, tok string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil {
		c.entries = map[string]cachedVendorToken{}
	}
	if len(c.entries) >= maxVendorTokenCache {
		now := time.Now()
		for k, v := range c.entries {
			if !now.Before(v.expires) {
				delete(c.entries, k)
			}
		}
		if len(c.entries) >= maxVendorTokenCache {
			c.entries = map[string]cachedVendorToken{}
		}
	}
	c.entries[key] = cachedVendorToken{token: tok, expires: time.Now().Add(ttl)}
}

// size reports how many entries are cached. Tests use it to prove the bound.
func (c *vendorTokenCache) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.entries)
}

// vendorTokenCacheKey builds a cache key that identifies a credential WITHOUT
// carrying it: the secret contributes only a digest, the identity fields are
// plaintext because they are not secrets and a readable key is a debuggable
// one. Callers pass every field that changes which bearer the vendor mints —
// identity AND environment — because two configurations that differ in any of
// them must never share an entry.
func vendorTokenCacheKey(secret string, identity ...string) string {
	sum := sha256.Sum256([]byte(secret))
	return strings.Join(append(identity, hex.EncodeToString(sum[:8])), "|")
}
