// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import (
	"testing"

	"netops/backend/cloud"
)

// the cloud identity-map now feeds the SAME resolver, so a flow/log to a tagged
// cloud private IP names its app instead of resolving "unknown" (#81 P3F+1).
func TestBuildCloudKeyMap(t *testing.T) {
	maps := []cloud.CloudIdentityMapping{
		{TenantID: "acme", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.1.10", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: "acme", MatchKeyType: cloud.MatchENI, MatchKey: "eni-abc", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: "globex", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.9.9.9", AppName: "payroll", Source: cloud.SrcCloudGraph, Confidence: cloud.Strong},
		// unknown attribution must NOT assert an app
		{TenantID: "acme", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.6.6", AppName: "", Source: cloud.SrcUnknown, Confidence: cloud.Unknown},
	}
	m := buildCloudKeyMap(maps)
	if got := m["acme"]["10.0.1.10"].app; got != "billing" {
		t.Fatalf("acme 10.0.1.10 → %q, want billing", got)
	}
	if got := m["acme"]["10.0.1.10"].source; got != SrcCloudTag {
		t.Fatalf("source → %q, want cloud_tag", got)
	}
	if _, ok := m["acme"]["10.0.6.6"]; ok {
		t.Fatalf("unknown attribution must be skipped, not indexed")
	}
	if _, ok := m["acme"]["10.9.9.9"]; ok {
		t.Fatalf("cross-tenant leak: acme must not hold globex's key")
	}
}

func TestCloudAppResolverSignalFor_TenantIsolation(t *testing.T) {
	r := NewCloudResolver(nil)
	m := buildCloudKeyMap([]cloud.CloudIdentityMapping{
		{TenantID: "acme", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.1.10", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
		{TenantID: "globex", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.9.9.9", AppName: "payroll", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
	})
	r.cur.Store(&m)

	// scoped acme sees its own key, NOT globex's
	if sig, ok := r.SignalFor("acme", false, "10.0.1.10"); !ok || sig.App != "billing" {
		t.Fatalf("acme own key: ok=%v app=%q", ok, sig.App)
	}
	if _, ok := r.SignalFor("acme", false, "10.9.9.9"); ok {
		t.Fatalf("acme must NOT resolve globex's key (cross-tenant leak)")
	}
	// platform owner (cross) may match across buckets
	if sig, ok := r.SignalFor("", true, "10.9.9.9"); !ok || sig.App != "payroll" {
		t.Fatalf("cross resolve: ok=%v app=%q", ok, sig.App)
	}
	// unknown key → no signal
	if _, ok := r.SignalFor("acme", false, "203.0.113.1"); ok {
		t.Fatalf("unindexed key must not resolve")
	}
}

// the bridge signal fuses to a CONFIRMED app verdict — proving the cloud private
// IP, previously "unknown", now names its app through the shared resolver.
func TestCloudSignalFusesToConfirmed(t *testing.T) {
	r := NewCloudResolver(nil)
	m := buildCloudKeyMap([]cloud.CloudIdentityMapping{
		{TenantID: "acme", MatchKeyType: cloud.MatchPrivateIP, MatchKey: "10.0.1.10", AppName: "billing", Source: cloud.SrcCloudTag, Confidence: cloud.Confirmed},
	})
	r.cur.Store(&m)
	sig, ok := r.SignalFor("acme", false, "10.0.1.10")
	if !ok {
		t.Fatal("expected a cloud signal")
	}
	v := Fuse([]Signal{sig})
	if v.App != "billing" || v.Tier != Confirmed {
		t.Fatalf("fused verdict = %q/%s, want billing/confirmed", v.App, v.Tier)
	}
}
