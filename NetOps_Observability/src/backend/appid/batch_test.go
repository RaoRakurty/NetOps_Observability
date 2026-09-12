// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

func TestFuseBatch_GroupsByConversation(t *testing.T) {
	ctx := BatchContext{Now: fuseNow, CatalogVersion: 1}
	obs := []ApplicationObservation{
		// conversation A (session s1) — two sources corroborate.
		ob(SrcNGFWAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" }),
		ob(SrcIPFIXAppID, "Microsoft Teams", func(o *ApplicationObservation) { o.SessionID = "s1" }),
		// conversation B (session s2) — different scope.
		ob(SrcNGFWAppID, "Zoom", func(o *ApplicationObservation) { o.SessionID = "s2" }),
	}
	got := FuseBatch(obs, ctx)
	if len(got) != 2 {
		t.Fatalf("want 2 fused identities (one per session), got %d", len(got))
	}
	// the s1 group fused two sources.
	var teams *FusedIdentity
	for i := range got {
		if got[i].App == "Microsoft Teams" {
			teams = &got[i]
		}
	}
	if teams == nil || teams.State != StateFused {
		t.Fatalf("s1 should fuse two sources → fused; got %+v", teams)
	}
}

func TestFuseBatch_SkipsUngroupable(t *testing.T) {
	// no session/flow/dst → ungroupable, skipped.
	obs := []ApplicationObservation{{Source: SrcNGFWAppID, VendorAppName: "X"}}
	if got := FuseBatch(obs, BatchContext{Now: fuseNow}); len(got) != 0 {
		t.Errorf("ungroupable observation should be skipped, got %d", len(got))
	}
}

func TestFuseBatch_AmbiguityHooks(t *testing.T) {
	// a shared-CDN hook excludes ip-only evidence → unknown for that conversation.
	obs := []ApplicationObservation{ob(SrcIPCatalog, "SomeSaaS", func(o *ApplicationObservation) { o.DstIP = "203.0.113.9"; o.DstPort = 443 })}
	ctx := BatchContext{Now: fuseNow, CatalogVersion: 1, SharedCDN: func(ip string) bool { return ip == "203.0.113.9" }}
	got := FuseBatch(obs, ctx)
	if len(got) != 1 || got[0].App != "unknown" {
		t.Fatalf("shared-CDN ip-only should resolve unknown, got %+v", got)
	}
}

func TestFuseBatch_Deterministic(t *testing.T) {
	obs := []ApplicationObservation{ob(SrcNGFWAppID, "Slack", func(o *ApplicationObservation) { o.SessionID = "s9" })}
	a := FuseBatch(obs, BatchContext{Now: fuseNow, CatalogVersion: 3})
	b := FuseBatch(obs, BatchContext{Now: fuseNow, CatalogVersion: 3})
	if len(a) != 1 || len(b) != 1 || a[0].FusionID != b[0].FusionID {
		t.Fatal("FuseBatch must be deterministic")
	}
}
