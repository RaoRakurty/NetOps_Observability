// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

// registry_test.go — Wave 5 #17 slice 1: the provider registry is the ONE
// source of provider truth. The core proof: registering a NEW provider
// descriptor makes every provider-neutral surface (Valid/Parse, method offer,
// scope types, adapter resolution, identity ref, catalog enumeration) serve it
// with ZERO edits to provider.go / scope.go / identityprovider.go — adapter
// work, not framework surgery.

import (
	"context"
	"testing"
)

// fakeProviderAdapter is a minimal CloudIdentityProvider for the registered
// test provider.
type fakeProviderAdapter struct{ id Provider }

func (f fakeProviderAdapter) Provider() Provider { return f.id }
func (f fakeProviderAdapter) ValidateConfiguration(_ IdentityConfig) ValidationResult {
	return ValidationResult{OK: true}
}
func (f fakeProviderAdapter) SetupInstructions(_ IdentityConfig, _ CapabilityPack) (SetupBundle, error) {
	return SetupBundle{Provider: f.id, Summary: "fake setup"}, nil
}
func (f fakeProviderAdapter) ExchangeCredential(_ context.Context, _ ExchangeRequest) (ScopedToken, error) {
	return ScopedToken{}, ErrProviderExchangeDeferred
}
func (f fakeProviderAdapter) DiscoverScopes(_ context.Context, _ DiscoverRequest) ([]Scope, error) {
	return nil, ErrProviderExchangeDeferred
}
func (f fakeProviderAdapter) ValidateCapabilities(_ context.Context, _ CapabilityCheckRequest) (CapabilityReport, error) {
	return CapabilityReport{}, ErrProviderExchangeDeferred
}
func (f fakeProviderAdapter) Revoke(_ context.Context, _ RevokeRequest) error {
	return ErrProviderExchangeDeferred
}

// registerTestProvider registers a fake 4th provider and removes it again at
// cleanup so the rest of the package suite sees only the built-ins.
func registerTestProvider(t *testing.T) ProviderDescriptor {
	t.Helper()
	d := ProviderDescriptor{
		ID:              Provider("testcloud"),
		DisplayName:     "Test Cloud",
		ShortLabel:      "TC",
		AuthMethods:     []AuthMethod{AuthMethodWorkloadFederation, AuthMethodStaticKey},
		ScopeTypes:      []ScopeType{ScopeOrg, ScopeAccount, ScopeRegion, ScopeExplicit},
		OrgScopeTypes:   []ScopeType{ScopeOrg},
		MemberScopeType: ScopeAccount,
		SetupDocKey:     "cloud-connector-testcloud",
		HasFlowLogs:     false,
		IdentityRef:     func(cfg IdentityConfig) string { return cfg.RoleARN },
		NewAdapter:      func() CloudIdentityProvider { return fakeProviderAdapter{id: "testcloud"} },
	}
	RegisterProvider(d)
	t.Cleanup(func() { delete(providerRegistry, d.ID) })
	return d
}

func TestBuiltinProvidersRegistered(t *testing.T) {
	for _, p := range []Provider{ProviderAWS, ProviderAzure, ProviderGCP} {
		d, ok := Descriptor(p)
		if !ok {
			t.Fatalf("built-in provider %s not registered", p)
		}
		if d.DisplayName == "" || d.ShortLabel == "" || d.SetupDocKey == "" {
			t.Fatalf("%s descriptor missing display metadata: %+v", p, d)
		}
		if len(d.AuthMethods) == 0 || d.AuthMethods[0] != AuthMethodWorkloadFederation {
			t.Fatalf("%s must offer federation first, got %v", p, d.AuthMethods)
		}
		if len(d.OrgScopeTypes) == 0 || d.MemberScopeType == "" {
			t.Fatalf("%s descriptor missing org-onboarding shape", p)
		}
		if d.NewAdapter == nil || d.NewAdapter() == nil {
			t.Fatalf("%s live adapter constructor broken", p)
		}
		if got := d.NewAdapter().Provider(); got != p {
			t.Fatalf("%s adapter reports provider %s", p, got)
		}
	}
	// Honest capability flags: flow logs exist for AWS+GCP packs, not Azure;
	// only AWS has a provider-health lane today.
	if d, _ := Descriptor(ProviderAWS); !d.HasFlowLogs || !d.HasHealthLane {
		t.Fatalf("aws flags wrong: %+v", d)
	}
	if d, _ := Descriptor(ProviderAzure); d.HasFlowLogs || d.HasHealthLane {
		t.Fatalf("azure flags must be honest-false: %+v", d)
	}
	if d, _ := Descriptor(ProviderGCP); !d.HasFlowLogs || d.HasHealthLane {
		t.Fatalf("gcp flags wrong: %+v", d)
	}
}

// TestRegistryPreservesLegacySurfaces pins the pre-registry behavior of the
// refactored switches: same method offers, same scope-type order.
func TestRegistryPreservesLegacySurfaces(t *testing.T) {
	wantMethods := map[Provider][]AuthMethod{
		ProviderAWS:   {AuthMethodWorkloadFederation, AuthMethodCloudRole, AuthMethodStaticKey},
		ProviderAzure: {AuthMethodWorkloadFederation, AuthMethodCertificate, AuthMethodClientSecret},
		ProviderGCP:   {AuthMethodWorkloadFederation, AuthMethodStaticKey},
	}
	for p, want := range wantMethods {
		got := ProviderMethods(p)
		if len(got) != len(want) {
			t.Fatalf("%s methods = %v want %v", p, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s methods = %v want %v", p, got, want)
			}
		}
	}
	wantScopes := map[Provider][]ScopeType{
		ProviderAWS:   {ScopeOrg, ScopeOU, ScopeAccount, ScopeVPC, ScopeRegion, ScopeExplicit},
		ProviderAzure: {ScopeOrg, ScopeMgmtGroup, ScopeSubscription, ScopeResourceGrp, ScopeVNet, ScopeRegion, ScopeExplicit},
		ProviderGCP:   {ScopeOrg, ScopeFolder, ScopeProject, ScopeVPC, ScopeRegion, ScopeExplicit},
	}
	for p, want := range wantScopes {
		got := ScopeTypesForProvider(p)
		if len(got) != len(want) {
			t.Fatalf("%s scope types = %v want %v", p, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s scope types = %v want %v", p, got, want)
			}
		}
	}
	if ProviderMethods(Provider("nope")) != nil {
		t.Fatal("unknown provider must have no method offer")
	}
	if AdapterFor(Provider("nope")) != nil {
		t.Fatal("unknown provider must have no adapter")
	}
}

// TestFourthProviderIsAdapterWorkOnly — the slice-1 success criterion: a new
// provider registered through the registry is served by EVERY provider-neutral
// surface without editing any of them.
func TestFourthProviderIsAdapterWorkOnly(t *testing.T) {
	d := registerTestProvider(t)

	// Parse/valid surface.
	p, ok := ParseProvider("  TestCloud ")
	if !ok || p != d.ID {
		t.Fatalf("ParseProvider = %q,%v — registered provider not recognized", p, ok)
	}
	if !d.ID.Valid() {
		t.Fatal("registered provider must be Valid()")
	}

	// Method offer + gating.
	ms := ProviderMethods(d.ID)
	if len(ms) != 2 || ms[0] != AuthMethodWorkloadFederation {
		t.Fatalf("methods = %v", ms)
	}
	if !MethodAllowed(d.ID, AuthMethodStaticKey) || MethodAllowed(d.ID, AuthMethodCloudRole) {
		t.Fatal("MethodAllowed must follow the descriptor offer")
	}

	// Scope surface.
	if !ScopeOrg.ValidForProvider(d.ID) || ScopeProject.ValidForProvider(d.ID) {
		t.Fatal("scope validity must follow the descriptor")
	}
	if err := ValidateScopes(d.ID, []Scope{{Type: ScopeAccount, Ref: "tc-123"}}); err != nil {
		t.Fatalf("ValidateScopes: %v", err)
	}

	// Adapter seam.
	a := AdapterFor(d.ID)
	if a == nil || a.Provider() != d.ID {
		t.Fatalf("AdapterFor did not resolve the registered adapter: %v", a)
	}
	if NewAdapterWithExchanger(d.ID, nil) != nil {
		t.Fatal("descriptor without exchanger hook must yield nil injected adapter")
	}
	if aa := AdapterForWithAssertions(d.ID, nil); aa == nil || aa.Provider() != d.ID {
		t.Fatal("assertion wiring must fall back to the live adapter")
	}

	// Identity-ref (broker cache key) surface.
	if got := IdentityRefFor(d.ID, IdentityConfig{RoleARN: "arn:tc:role/x"}); got != "arn:tc:role/x" {
		t.Fatalf("IdentityRefFor = %q", got)
	}

	// Catalog enumeration includes the 4th provider exactly once, sorted.
	seen := 0
	for _, dd := range Descriptors() {
		if dd.ID == d.ID {
			seen++
			if dd.DisplayName != "Test Cloud" || dd.MemberScopeType != ScopeAccount {
				t.Fatalf("descriptor round-trip lost fields: %+v", dd)
			}
		}
	}
	if seen != 1 {
		t.Fatalf("Descriptors() contains the test provider %d times", seen)
	}
}

// TestRegisterProviderRejectsInvalid — half-declared providers fail fast.
func TestRegisterProviderRejectsInvalid(t *testing.T) {
	cases := map[string]ProviderDescriptor{
		"empty id":        {DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"uppercase id":    {ID: "Bad", DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"duplicate":       {ID: ProviderAWS, DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"no methods":      {ID: "x1", DisplayName: "X", ShortLabel: "X", ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"prohibited":      {ID: "x2", DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodProhibited}, ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"no scopes":       {ID: "x3", DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"org not subset":  {ID: "x4", DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}, OrgScopeTypes: []ScopeType{ScopeFolder}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
		"no constructor":  {ID: "x5", DisplayName: "X", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}},
		"no display name": {ID: "x6", ShortLabel: "X", AuthMethods: []AuthMethod{AuthMethodStaticKey}, ScopeTypes: []ScopeType{ScopeAccount}, NewAdapter: func() CloudIdentityProvider { return fakeProviderAdapter{} }},
	}
	for name, d := range cases {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: RegisterProvider did not panic", name)
				}
			}()
			RegisterProvider(d)
		}()
		if d.ID != "" && d.ID != ProviderAWS {
			if _, leaked := Descriptor(d.ID); leaked {
				t.Errorf("%s: invalid descriptor leaked into the registry", name)
			}
		}
	}
}
