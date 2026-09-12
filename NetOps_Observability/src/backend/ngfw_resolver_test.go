// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"testing"

	"netops/backend/appid"
)

func TestBuildNgfwAppMap(t *testing.T) {
	// docs arrive newest-first; first-seen per (tenant,dst) wins.
	docs := []ngfwDoc{
		{TenantID: "org-a", AppID: "Zoom", AppDst: "1.2.3.4"},
		{TenantID: "org-a", AppID: "ZoomOld", AppDst: "1.2.3.4"}, // older, ignored
		{TenantID: "org-b", AppID: "Slack", AppDst: "1.2.3.4"},   // different tenant, same dst
		{TenantID: "", AppID: "GitHub", AppDst: "5.6.7.8"},
		{TenantID: "org-a", AppID: "", AppDst: "9.9.9.9"}, // no app → skipped
		{TenantID: "org-a", AppID: "X", AppDst: ""},       // no dst → skipped
	}
	m := buildNgfwAppMap(docs)
	if m["org-a"]["1.2.3.4"] != "Zoom" {
		t.Fatalf("org-a newest should be Zoom, got %q", m["org-a"]["1.2.3.4"])
	}
	if m["org-b"]["1.2.3.4"] != "Slack" {
		t.Fatalf("org-b should isolate to Slack, got %q", m["org-b"]["1.2.3.4"])
	}
	if m[""]["5.6.7.8"] != "GitHub" {
		t.Fatalf("untagged bucket wrong: %q", m[""]["5.6.7.8"])
	}
	if _, ok := m["org-a"]["9.9.9.9"]; ok {
		t.Fatal("empty app should be skipped")
	}
}

func TestNgfwSignalForScoping(t *testing.T) {
	r := newNgfwAppResolver()
	m := buildNgfwAppMap([]ngfwDoc{
		{TenantID: "org-a", AppID: "Zoom", AppDst: "1.2.3.4"},
		{TenantID: "org-b", AppID: "Slack", AppDst: "1.2.3.4"},
		{TenantID: "", AppID: "GitHub", AppDst: "5.6.7.8"},
	})
	r.cur.Store(&m)

	// scoped org-a sees only its own attribution, tagged as the authoritative source
	if sig, ok := r.signalFor("org-a", false, "1.2.3.4"); !ok || sig.App != "Zoom" || sig.Source != appid.SrcNGFWAppID {
		t.Fatalf("org-a should resolve Zoom, got %+v ok=%v", sig, ok)
	}
	// org-a must NOT see org-b's Slack for the same dst (no cross-tenant mixing)
	if sig, _ := r.signalFor("org-a", false, "1.2.3.4"); sig.App == "Slack" {
		t.Fatal("cross-tenant NGFW leak: org-a saw org-b's Slack")
	}
	// a tenant with no firewall data → miss
	if _, ok := r.signalFor("org-c", false, "1.2.3.4"); ok {
		t.Fatal("org-c has no firewall attributions, must miss")
	}
	// platform owner (cross) reads the untagged/global bucket
	if sig, ok := r.signalFor("", true, "5.6.7.8"); !ok || sig.App != "GitHub" {
		t.Fatalf("cross caller should read untagged GitHub, got %+v ok=%v", sig, ok)
	}
	// unknown dst → miss
	if _, ok := r.signalFor("org-a", false, "10.0.0.1"); ok {
		t.Fatal("unknown dst must miss")
	}
}

func TestNgfwNilSafe(t *testing.T) {
	var r *ngfwAppResolver
	if _, ok := r.signalFor("org-a", false, "1.2.3.4"); ok {
		t.Fatal("nil resolver must be safe and miss")
	}
}
