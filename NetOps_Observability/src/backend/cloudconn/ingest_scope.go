// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// ingest_scope.go — the default-scope derivation for the poller-facing ingest
// surface (extracted P2 RA.16): the same account/region precedence the
// validate handler's live trust check uses.

// DefaultScope derives the default provider account + region from the
// connector's declared scopes.
func DefaultScope(c Connector) (account, region string) {
	for _, sc := range c.Scopes {
		if sc.Type == ScopeRegion && region == "" {
			region = sc.Ref
			continue
		}
		if account == "" {
			account = sc.Ref
			if len(sc.Regions) > 0 && region == "" {
				region = sc.Regions[0]
			}
		}
	}
	return account, region
}
