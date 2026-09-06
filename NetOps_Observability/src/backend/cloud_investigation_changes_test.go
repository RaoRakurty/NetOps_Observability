// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_investigation_changes_test.go — Wave 4 #12 slice 3: the change→incident
// correlation read is tenant-scoped, bounded, and scoped to the object's OWN
// blast radius; the relative-to-onset math is exact.

import (
	"strings"
	"testing"
	"time"
)

// Every query the endpoint issues carries the caller's tenant scope, a LIMIT,
// and a bounded window; named columns only (mirrors TestCloudSignalQueriesAreTenantScoped).
func TestInvestigationChangeQueriesAreTenantScopedAndBounded(t *testing.T) {
	for _, scope := range []string{"acme", "__none__"} {
		queries := []string{
			investigationObjectSQL("11111111-2222-3333-4444-555555555555", scope),
			investigationChangesSQL("2026-07-18 00:00:00", " AND (entity_id IN ('r1'))", 50, scope),
		}
		for _, q := range queries {
			if !strings.Contains(q, "SETTINGS tenant_scope = '"+scope+"'") {
				t.Fatalf("query is not scoped to %q:\n%s", scope, q)
			}
			if !strings.Contains(q, "LIMIT") {
				t.Fatalf("query is unbounded:\n%s", q)
			}
			if strings.Contains(q, "SELECT *") {
				t.Fatalf("query must name its columns (#100):\n%s", q)
			}
		}
	}
	// The signal read carries BOTH the absolute guard and the onset anchor,
	// and only ever the change kinds.
	q := investigationChangesSQL("2026-07-18 00:00:00", "", 50, "acme")
	for _, want := range []string{
		"INTERVAL 168 HOUR",
		"toDateTime('2026-07-18 00:00:00','UTC') - INTERVAL 6 HOUR",
		"ts <= now()",
		"kind IN ('cloud_change','cloud_audit','security_policy_change')",
		"source = 'cloud'",
	} {
		if !strings.Contains(q, want) {
			t.Fatalf("changes SQL missing %q:\n%s", want, q)
		}
	}
	// The object lookup uses the hot projection.
	if !strings.Contains(investigationObjectSQL("11111111-2222-3333-4444-555555555555", "acme"),
		"netops.corr_current FINAL") {
		t.Fatal("object lookup must use corr_current FINAL")
	}
}

// The scope predicate binds to the signal's OWN identity fields, drops unsafe
// values (sqlList), and is EMPTY when the object recorded no blast radius —
// the handler then answers honestly instead of querying unscoped.
func TestInvestigationScopeSQL(t *testing.T) {
	p := investigationScopeSQL([]string{"i-abc123"}, []string{"store-api"})
	for _, want := range []string{
		"entity_id IN ('i-abc123')",
		"JSONExtractString(attrs,'resource_id') IN ('i-abc123')",
		"JSONExtractString(attrs,'app') IN ('store-api')",
		"JSONExtractString(attrs,'app_id') IN ('store-api')",
	} {
		if !strings.Contains(p, want) {
			t.Fatalf("scope predicate missing %q: %s", want, p)
		}
	}
	if strings.Contains(p, "LIKE") {
		t.Fatalf("scope predicate must not fuzzy-match: %s", p)
	}
	if investigationScopeSQL(nil, nil) != "" {
		t.Fatal("no affected scope ⇒ no predicate (honest empty, never unscoped)")
	}
	// injection-shaped values are dropped by sqlList, not quoted through
	if p := investigationScopeSQL([]string{"x' OR 1=1 --"}, nil); p != "" {
		t.Fatalf("unsafe resource id must be dropped, got %s", p)
	}
}

func TestAffectedCloudResources(t *testing.T) {
	raw := `{"apps":["store-api"],"cloud_resources":["i-abc","vm-1"],"devices":["r1"]}`
	got := affectedCloudResources(raw)
	if len(got) != 2 || got[0] != "i-abc" || got[1] != "vm-1" {
		t.Fatalf("affectedCloudResources = %v", got)
	}
	if len(affectedCloudResources("")) != 0 || len(affectedCloudResources("{}")) != 0 {
		t.Fatal("no cloud_resources ⇒ empty, never nil-panic or invention")
	}
}

// "14m before onset" must be exact: negative = before onset, positive = after.
func TestOffsetFromOnset(t *testing.T) {
	onset := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	if off := offsetFromOnset(onset.Add(-14*time.Minute), onset); off != -840 {
		t.Fatalf("14m before onset = %d, want -840", off)
	}
	if off := offsetFromOnset(onset.Add(90*time.Second), onset); off != 90 {
		t.Fatalf("90s after onset = %d, want 90", off)
	}
	if off := offsetFromOnset(onset, onset); off != 0 {
		t.Fatalf("at onset = %d, want 0", off)
	}
}
