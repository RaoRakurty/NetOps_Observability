// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

import (
	"context"
	"testing"
)

func TestPolicyNormalizeValidatesAndBounds(t *testing.T) {
	good := TenantPolicy{
		Default:  PolicyConfig{ExpectedOrigins: []uint32{64496, 64496, 0}, Upstreams: []uint32{64500}, MinVisibility: 0.6, MinVantages: 2},
		Prefixes: map[string]PolicyConfig{"193.0.0.0/21": {ExpectedOrigins: []uint32{64496}}},
	}
	norm, err := good.Normalize()
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	if len(norm.Default.ExpectedOrigins) != 1 {
		t.Fatalf("duplicates and AS0 must be dropped: %+v", norm.Default.ExpectedOrigins)
	}
	if _, ok := norm.Prefixes["193.0.0.0/21"]; !ok {
		t.Fatalf("the prefix key must be canonicalized: %+v", norm.Prefixes)
	}

	// A prefix key that is not a prefix is an ERROR, never a dropped entry: a
	// silently dropped policy would change what gets alerted on.
	bad := TenantPolicy{Prefixes: map[string]PolicyConfig{"nope": {}}}
	if _, err := bad.Normalize(); err == nil {
		t.Fatal("an unparsable prefix key must be refused")
	}
	tooMany := TenantPolicy{Default: PolicyConfig{ExpectedOrigins: make([]uint32, MaxDeclaredASNs+1)}}
	if _, err := tooMany.Normalize(); err == nil {
		t.Fatal("an oversized ASN set must be refused")
	}
	badVis := TenantPolicy{Default: PolicyConfig{MinVisibility: 2}}
	if _, err := badVis.Normalize(); err == nil {
		t.Fatal("min_visibility outside 0..1 must be refused")
	}
}

func TestFileStoreIsTenantScopedAndFailsClosed(t *testing.T) {
	s := NewFileStore("")
	ctx := context.Background()
	if err := s.SetPolicy(ctx, "acme", "u1", TenantPolicy{Default: PolicyConfig{ExpectedOrigins: []uint32{64496}}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := s.Policy(ctx, "acme")
	if err != nil || len(got.Default.ExpectedOrigins) != 1 {
		t.Fatalf("acme policy: %+v %v", got, err)
	}
	other, err := s.Policy(ctx, "globex")
	if err != nil {
		t.Fatalf("globex policy: %v", err)
	}
	if len(other.Default.ExpectedOrigins) != 0 {
		t.Fatalf("globex read acme's policy: %+v", other)
	}
	// "" and "*" are refused at the store, so a mis-scoped caller reads and
	// writes NOTHING rather than everything (§3a rule 4).
	for _, bad := range []string{"", "*", "   "} {
		if _, err := s.Policy(ctx, bad); err == nil {
			t.Fatalf("Policy(%q) must be refused", bad)
		}
		if err := s.SetPolicy(ctx, bad, "u1", TenantPolicy{}); err == nil {
			t.Fatalf("SetPolicy(%q) must be refused", bad)
		}
	}
	// The returned policy is a COPY: mutating it must not reach the store.
	got.Default.ExpectedOrigins[0] = 1
	if again, _ := s.Policy(ctx, "acme"); again.Default.ExpectedOrigins[0] != 64496 {
		t.Fatal("the store handed out a live reference")
	}
}

func TestParseASN(t *testing.T) {
	for _, in := range []string{"AS64500", "as64500", "64500", " AS64500 "} {
		n, err := ParseASN(in)
		if err != nil || n != 64500 {
			t.Fatalf("ParseASN(%q) = %d, %v", in, n, err)
		}
	}
	for _, in := range []string{"", "AS0", "0", "ASxyz", "4294967296"} {
		if _, err := ParseASN(in); err == nil {
			t.Fatalf("ParseASN(%q) must fail", in)
		}
	}
}
