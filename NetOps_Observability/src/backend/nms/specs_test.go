// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import "testing"

// TestAuthPolicy enforces the owner's auth policy across every connector:
// (1) a simple credential path exists for testing — Basic where the vendor has
// username/password, API key for Meraki; (2) OAuth is PreferredAuth wherever
// the vendor supports it.
func TestAuthPolicy(t *testing.T) {
	// Vendors that genuinely offer OAuth (verified 2026).
	oauthVendors := map[string]bool{"meraki": true, "versa_director": true, "versa_concerto": true, "generic": true}

	for vendor, spec := range Specs() {
		if len(spec.SupportedAuth) == 0 {
			t.Errorf("%s: no supported auth", vendor)
		}
		// (1) Every connector has a simple test credential: Basic, or API key
		// for the vendors without a username/password concept (Meraki).
		hasTestPath := spec.SupportsAuth(AuthBasic) || spec.SupportsAuth(AuthAPIKey)
		if !hasTestPath {
			t.Errorf("%s: must support Basic (or API key) for testing; has %v", vendor, spec.SupportedAuth)
		}
		// Meraki specifically: API key is its test path (no Basic exists there).
		if vendor == "meraki" && !spec.SupportsAuth(AuthAPIKey) {
			t.Errorf("meraki must support API key")
		}
		// Every non-Meraki Cisco/Versa/generic connector supports Basic.
		if vendor != "meraki" && !spec.SupportsAuth(AuthBasic) {
			t.Errorf("%s: must support Basic auth for testing", vendor)
		}
		// (2) OAuth vendors implement it AND prefer it.
		if oauthVendors[vendor] {
			if !spec.SupportsAuth(AuthOAuth) {
				t.Errorf("%s: supports OAuth per vendor — must implement it", vendor)
			}
			if vendor != "generic" && spec.PreferredAuth != AuthOAuth {
				t.Errorf("%s: OAuth-capable vendor should prefer OAuth, got %s", vendor, spec.PreferredAuth)
			}
		}
		// (3) Non-OAuth Cisco platforms must NOT claim OAuth (verified absent).
		if !oauthVendors[vendor] && spec.SupportsAuth(AuthOAuth) {
			t.Errorf("%s: does not offer OAuth (verified) — must not claim it", vendor)
		}
		// PreferredAuth must be in the supported set.
		if !spec.SupportsAuth(spec.PreferredAuth) {
			t.Errorf("%s: preferred auth %s not in supported set %v", vendor, spec.PreferredAuth, spec.SupportedAuth)
		}
	}
}

func TestSpecsCoverAllVendors(t *testing.T) {
	want := []string{"meraki", "catalyst_center", "vmanage", "ndfc", "prime", "versa_director", "versa_concerto", "generic"}
	s := Specs()
	for _, v := range want {
		if _, ok := s[v]; !ok {
			t.Errorf("missing spec for %s", v)
		}
	}
	// Meraki rate limit is the verified 10/s.
	if s["meraki"].RatePerSec != 10 {
		t.Errorf("meraki rate = %v, want 10", s["meraki"].RatePerSec)
	}
}
