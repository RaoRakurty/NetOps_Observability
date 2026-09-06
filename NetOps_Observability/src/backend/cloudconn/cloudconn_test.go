// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package cloudconn

import (
	"strings"
	"testing"
)

func TestAuthMethodOrderingAndClass(t *testing.T) {
	// Preference order is strict and federated < legacy < prohibited.
	if AuthMethodWorkloadFederation.Rank() >= AuthMethodCloudRole.Rank() {
		t.Fatal("workload federation must be preferred over cloud role")
	}
	if AuthMethodStaticKey.Rank() >= AuthMethodProhibited.Rank() {
		t.Fatal("static key must rank ahead of prohibited")
	}
	if !AuthMethodWorkloadFederation.IsFederated() {
		t.Fatal("workload federation must be federated")
	}
	if AuthMethodStaticKey.IsFederated() {
		t.Fatal("static key is not federated")
	}
	for _, m := range []AuthMethod{AuthMethodClientSecret, AuthMethodStaticKey} {
		if !m.IsLegacy() || !m.HoldsStoredSecret() {
			t.Fatalf("%s must be legacy + hold a stored secret", m)
		}
	}
	if AuthMethodWorkloadFederation.HoldsStoredSecret() {
		t.Fatal("federated method must not hold a stored secret")
	}
	if !AuthMethodProhibited.IsProhibited() {
		t.Fatal("admin password must be prohibited")
	}
}

func TestProviderMethodsFederatedFirst(t *testing.T) {
	for _, p := range []Provider{ProviderAWS, ProviderAzure, ProviderGCP} {
		ms := ProviderMethods(p)
		if len(ms) == 0 {
			t.Fatalf("%s has no methods", p)
		}
		if !ms[0].IsFederated() {
			t.Fatalf("%s must offer a federated method first, got %s", p, ms[0])
		}
		for _, m := range ms {
			if m.IsProhibited() {
				t.Fatalf("%s must never offer a prohibited method", p)
			}
		}
	}
}

func TestExternalIDUniqueUnpredictableValid(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 2000; i++ {
		id := NewExternalID()
		if !ValidExternalID(id) {
			t.Fatalf("minted ExternalId failed its own validator: %q", id)
		}
		if seen[id] {
			t.Fatalf("ExternalId collision at %d: %q", i, id)
		}
		seen[id] = true
		if !strings.HasPrefix(id, "correlix-") {
			t.Fatalf("ExternalId missing label prefix: %q", id)
		}
	}
	// Derived/guessable values must be rejected.
	for _, bad := range []string{"", "acme", "correlix-", "correlix-short", "arn:aws:iam::1:root", "tenant-acme-connector-1"} {
		if ValidExternalID(bad) {
			t.Fatalf("weak/derived ExternalId accepted: %q", bad)
		}
	}
}

func TestCapabilityPacksImmutableReadOnlyLeastPriv(t *testing.T) {
	for _, full := range []string{"aws-observer-v1", "azure-observer-v1", "gcp-observer-v1"} {
		p, ok := Pack(full)
		if !ok {
			t.Fatalf("missing built-in pack %s", full)
		}
		if p.FullID() != full {
			t.Fatalf("pack full id mismatch: %s vs %s", p.FullID(), full)
		}
		if !p.ReadOnly {
			t.Fatalf("observer pack %s must be read-only", full)
		}
		if len(p.AllPermissions()) == 0 {
			t.Fatalf("pack %s declares no permissions", full)
		}
		for _, c := range p.Capabilities {
			if !c.ReadOnly {
				t.Fatalf("pack %s capability %s must be read-only", full, c.Key)
			}
			if len(c.Permissions) == 0 {
				t.Fatalf("pack %s capability %s declares no permissions", full, c.Key)
			}
		}
	}
	// AllPermissions is sorted + deduped.
	perms := mustPack(t, "aws-observer-v1").AllPermissions()
	for i := 1; i < len(perms); i++ {
		if perms[i-1] >= perms[i] {
			t.Fatalf("AllPermissions not strictly sorted/deduped: %v", perms)
		}
	}
}

func TestLifecycleStateMachine(t *testing.T) {
	// A connector cannot jump straight to ACTIVE without validation.
	if CanTransition(StateDraft, StateActive) {
		t.Fatal("DRAFT must not transition directly to ACTIVE")
	}
	if !CanTransition(StateValidating, StateActive) {
		t.Fatal("VALIDATING must be able to reach ACTIVE")
	}
	// Only ACTIVE/DEGRADED collect.
	for s, want := range map[LifecycleState]bool{
		StateActive: true, StateDegraded: true,
		StateDraft: false, StateDisabled: false, StateRevoked: false, StateDeleted: false,
	} {
		if s.Collecting() != want {
			t.Fatalf("Collecting(%s)=%v want %v", s, s.Collecting(), want)
		}
	}
	// Disabled/revoked/deleted cannot mint tokens.
	for _, s := range []LifecycleState{StateDisabled, StateRevoked, StateDeleting, StateDeleted, StateDraft} {
		if s.CanExchangeToken() {
			t.Fatalf("%s must not be allowed to exchange tokens", s)
		}
	}
	if !StateActive.CanExchangeToken() {
		t.Fatal("ACTIVE must be allowed to exchange tokens")
	}
	if !StateDeleted.Terminal() {
		t.Fatal("DELETED must be terminal")
	}
}

func TestScopeValidation(t *testing.T) {
	if err := ValidateScopes(ProviderAWS, nil); err == nil {
		t.Fatal("empty scope set must be rejected")
	}
	if err := ValidateScopes(ProviderAWS, []Scope{{Type: ScopeSubscription, Ref: "x"}}); err == nil {
		t.Fatal("azure subscription scope must be invalid for AWS")
	}
	if err := ValidateScopes(ProviderAWS, []Scope{{Type: ScopeAccount, Ref: ""}}); err == nil {
		t.Fatal("scope without ref must be rejected")
	}
	if err := ValidateScopes(ProviderAWS, []Scope{{Type: ScopeAccount, Ref: "123456789012"}}); err != nil {
		t.Fatalf("valid AWS account scope rejected: %v", err)
	}
}

func mustPack(t *testing.T, full string) CapabilityPack {
	t.Helper()
	p, ok := Pack(full)
	if !ok {
		t.Fatalf("pack %s missing", full)
	}
	return p
}
