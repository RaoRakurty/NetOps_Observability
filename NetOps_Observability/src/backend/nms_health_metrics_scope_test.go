// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"netops/backend/nms"
)

// TestTenantMetricsScopeNeverMatchesNMSHealthSeries: the connector-health
// series (nms/health.go) are platform plumbing. They carry tenant_id /
// integration_id / vendor and NEVER device / hostname / source — the labels a
// scoped tenant's extra_filters[] match on — so no tenant scope admits them,
// not even one whose device ids and names are chosen to equal the label
// values the series DO carry.
func TestTenantMetricsScopeNeverMatchesNMSHealthSeries(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("[]")) // test server
	}))
	defer srv.Close()
	store := nms.NewMemStore()
	ic := nms.Integration{Tenant: "t_acme", ID: "nmsi-1", Vendor: "generic", Product: "generic",
		DisplayName: "acme generic", BaseURL: srv.URL, Enabled: true, PollIntervalS: 60}
	if err := store.Upsert(context.Background(), ic); err != nil {
		t.Fatal(err)
	}
	rt := nms.NewRuntime(store, nms.Sinks{}, 0)
	if rec := rt.PollIntegration(context.Background(), ic); rec.Status != nms.RunStatusOK {
		t.Fatalf("poll: %+v", rec)
	}
	var b bytes.Buffer
	rt.WriteMetrics(&b)

	series := parseExposition(t, b.String())
	if len(series) == 0 {
		t.Fatal("no NMS health series rendered — the test would pass vacuously")
	}
	// Adversarial scopes: device ids / names equal to every label value the
	// NMS series carry, plus an ordinary tenant and the empty namespace.
	scopes := map[string][]string{
		"adversarial": metricsScopeFilters(
			[]string{"t_acme", "nmsi-1", "generic", "events", "ok"},
			[]string{"t_acme", "nmsi-1", "generic", "events", "ok"}, false),
		"ordinary": metricsScopeFilters([]string{"core-1"}, []string{"core-1.acme"}, false),
		"empty":    metricsScopeFilters(nil, nil, false),
	}
	for name, filters := range scopes {
		for _, s := range series {
			if !strings.HasPrefix(s["__name__"], "netops_nms_") {
				continue
			}
			if admitted(filters, s) {
				t.Errorf("TENANT SCOPE LEAK (%s scope): %v admits platform series %v", name, filters, s)
			}
		}
	}
}

var expoLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)\{(.*)\} \S+$`)
var expoLabel = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="((?:[^"\\]|\\.)*)"`)

// parseExposition reads name{labels} value lines into label maps.
func parseExposition(t *testing.T, text string) []map[string]string {
	t.Helper()
	var out []map[string]string
	for _, line := range strings.Split(text, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		m := expoLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("unparseable exposition line %q", line)
		}
		s := map[string]string{"__name__": m[1]}
		for _, l := range expoLabel.FindAllStringSubmatch(m[2], -1) {
			s[l[1]] = l[2]
		}
		out = append(out, s)
	}
	return out
}
