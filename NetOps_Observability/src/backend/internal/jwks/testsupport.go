// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package jwks

// SeedDiscoveryForTest pre-populates the cached discovery document so tests can
// exercise OIDC flows hermetically (no network fetch). TEST SUPPORT ONLY: in
// production discovery always comes from the issuer's well-known endpoint. If a
// static-endpoint mode ever becomes a real feature (IdPs without discovery),
// promote this into a constructor option instead.
func (c *Cache) SeedDiscoveryForTest(d *Discovery) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.disc = d
}
