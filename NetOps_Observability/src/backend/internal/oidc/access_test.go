// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package oidc

import "testing"

// access_test.go — the ACCESS segment of the provider string (elevation
// providers, 2026-09-07). The property that matters most is the one about what
// the segment does NOT change: every provider string written before it existed
// must still parse to exactly the same standing button.

func TestParseProvidersKeepsThreeSegmentEntriesStanding(t *testing.T) {
	got := ParseProviders("okta:Okta:saml,corp")
	if len(got) != 2 {
		t.Fatalf("parsed %d buttons, want 2", len(got))
	}
	for _, p := range got {
		if p.Access != AccessStanding || p.IsElevation() {
			t.Errorf("%q parsed as access=%q; a legacy entry must stay standing", p.ID, p.Access)
		}
	}
	if got[0].Kind != "saml" || got[0].Name != "Okta" {
		t.Errorf("legacy parse drifted: %+v", got[0])
	}
	if got[1].Kind != "oidc" || got[1].Name != "corp" {
		t.Errorf("bare id parse drifted: %+v", got[1])
	}
}

func TestParseProvidersReadsTheElevationSegment(t *testing.T) {
	got := ParseProviders("corp:Corp:oidc,elev:Break Glass:oidc:elevation")
	if len(got) != 2 {
		t.Fatalf("parsed %d buttons", len(got))
	}
	if got[0].IsElevation() {
		t.Error("the standing button was marked as an elevation door")
	}
	if !got[1].IsElevation() {
		t.Fatalf("the elevation button parsed as %q", got[1].Access)
	}
	if got[1].Name != "Break Glass" {
		t.Errorf("label %q — the access segment must not eat the label", got[1].Name)
	}
}

// Fail-closed: a typo must leave a door STANDING (which merely provisions as
// before), never turn a working front door into one that refuses new users.
func TestParseProvidersTreatsAMisspeltAccessSegmentAsStanding(t *testing.T) {
	for _, csv := range []string{"a:A:oidc:elevate", "a:A:oidc:elevation-", "a:A:oidc: ", "a:A:oidc:standing"} {
		got := ParseProviders(csv)
		if len(got) != 1 || got[0].IsElevation() {
			t.Errorf("%q parsed as an elevation door", csv)
		}
	}
}

func TestElevationProvidersAndLookup(t *testing.T) {
	p := NewProviderFromConfig(Config{
		Enabled: true, Issuer: "https://idp.example.test", ClientID: "x",
		Providers: "corp:Corp:oidc,elev:Break Glass:oidc:elevation,two:Two:saml:elevation",
	}, 0)
	elev := p.ElevationProviders()
	if len(elev) != 2 || elev[0].ID != "elev" || elev[1].ID != "two" {
		t.Fatalf("elevation doors: %+v", elev)
	}
	if pi, ok := p.ProviderByID("corp"); !ok || pi.IsElevation() {
		t.Errorf("ProviderByID(corp) = %+v ok=%v", pi, ok)
	}
	if _, ok := p.ProviderByID("nope"); ok {
		t.Error("ProviderByID invented a provider the operator never configured")
	}
}

// The realm-default button (no OIDC_PROVIDERS set) is the door that provisions,
// so it must never be an elevation door — otherwise a plain OIDC deployment
// would suddenly refuse every first-time sign-in.
func TestRealmDefaultButtonIsStanding(t *testing.T) {
	p := NewProviderFromConfig(Config{Enabled: true, Issuer: "https://idp.example.test", ClientID: "x"}, 0)
	if len(p.Providers()) != 1 || p.Providers()[0].IsElevation() {
		t.Fatalf("realm default button: %+v", p.Providers())
	}
	if len(p.ElevationProviders()) != 0 {
		t.Error("a plain deployment reported an elevation door")
	}
}
