// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rumsources

import (
	"strings"
	"testing"
)

func TestQueryIsForOneTenantOnly(t *testing.T) {
	q, ok := Query(" Acme ")
	if !ok {
		t.Fatal("a platform-shaped tenant id was refused")
	}
	if !strings.Contains(q, "tenant_id = 'acme'") || !strings.Contains(q, "FROM netops.experience_events") {
		t.Fatalf("query does not filter the tenant: %s", q)
	}
	if !strings.Contains(q, "LIMIT 501") {
		t.Fatalf("query must ask for one more than the cap to detect truncation: %s", q)
	}
}

func TestQueryRefusesATenantThatIsNotOurShape(t *testing.T) {
	for _, bad := range []string{"", "*", "a' OR 1=1 --", "acme\nx", strings.Repeat("a", 200), "Ünïcode"} {
		if _, ok := Query(bad); ok {
			t.Fatalf("tenant %q was embedded", bad)
		}
	}
}

func TestFromRowsSaysWhichAppsReportAndWhichWentQuiet(t *testing.T) {
	r := FromRows("acme", []map[string]any{
		{"tenant_id": "acme", "app": "checkout", "app_source": "attribute", "events_24h": "120", "page_views_24h": "40", "errors_24h": "3", "last_seen_ms": "1800000000000"},
		{"tenant_id": "acme", "app": "shop.example.com", "app_source": "hostname", "events_24h": "0", "page_views_24h": "0", "errors_24h": "0", "last_seen_ms": "1799000000000"},
	})
	if r.Status != "ok" || r.Reporting != 1 || r.Quiet != 1 || len(r.Sources) != 2 {
		t.Fatalf("fold: %+v", r)
	}
	if r.Sources[0].App != "shop.example.com" || r.Sources[0].State != StateQuiet {
		t.Fatalf("a quiet app must come first, it needs a look: %+v", r.Sources)
	}
	if r.Sources[1].State != StateReporting || r.Sources[1].Events24h != 120 || r.Sources[1].Errors24h != 3 {
		t.Fatalf("reporting app: %+v", r.Sources[1])
	}
	if r.Sources[0].AppSource != "hostname" || r.Sources[1].AppSource != "attribute" {
		t.Fatalf("app_source lost: %+v", r.Sources)
	}
}

func TestFromRowsSkipsMalformedRowsAndUnknownSources(t *testing.T) {
	r := FromRows("acme", []map[string]any{
		{"tenant_id": "acme", "app": "", "last_seen_ms": "1"},
		{"tenant_id": "acme", "app": "x", "last_seen_ms": "not-a-number"},
		{"tenant_id": "acme", "app": "y", "app_source": "made-up", "events_24h": "-5", "last_seen_ms": "1800000000000"},
	})
	if len(r.Sources) != 1 || r.Sources[0].App != "y" {
		t.Fatalf("malformed rows were guessed at: %+v", r.Sources)
	}
	if r.Sources[0].AppSource != "" || r.Sources[0].Events24h != 0 || r.Sources[0].State != StateQuiet {
		t.Fatalf("an unknown source or a negative count leaked: %+v", r.Sources[0])
	}
}

func TestFromRowsDropsAnotherTenantsRowEvenIfTheStoreReturnsIt(t *testing.T) {
	r := FromRows("acme", []map[string]any{
		{"tenant_id": "globex", "app": "globex-portal", "events_24h": "9", "last_seen_ms": "1800000000000"},
		{"tenant_id": "", "app": "untagged", "events_24h": "9", "last_seen_ms": "1800000000000"},
		{"tenant_id": "ACME", "app": "checkout", "events_24h": "1", "last_seen_ms": "1800000000000"},
	})
	if len(r.Sources) != 1 || r.Sources[0].App != "checkout" {
		t.Fatalf("a foreign or untagged row reached acme: %+v", r.Sources)
	}
	if got := FromRows("", []map[string]any{{"tenant_id": "", "app": "x", "last_seen_ms": "1"}}); len(got.Sources) != 0 {
		t.Fatalf("an empty tenant matched untagged rows: %+v", got.Sources)
	}
}

func TestFromRowsTruncatesAndSaysSo(t *testing.T) {
	rows := make([]map[string]any, 0, MaxSources+1)
	for i := 0; i <= MaxSources; i++ {
		rows = append(rows, map[string]any{"tenant_id": "acme", "app": "a" + strings.Repeat("x", i%7) + string(rune('a'+i%26)), "events_24h": "1", "last_seen_ms": "1800000000000"})
	}
	r := FromRows("acme", rows)
	if !r.Truncated || len(r.Sources) != MaxSources {
		t.Fatalf("truncation: %v %d", r.Truncated, len(r.Sources))
	}
}

func TestUnavailableAndRestrictedAreNeverAnEmptyOK(t *testing.T) {
	if u := Unavailable(); u.Status != "unavailable" || u.Sources == nil {
		t.Fatalf("unavailable: %+v", u)
	}
	if r := Restricted(); r.Status != "ok" || !r.Restricted || len(r.Sources) != 0 {
		t.Fatalf("restricted: %+v", r)
	}
}
