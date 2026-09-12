// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"netops/backend/internal/discovery"
	"sort"
	"strings"
	"testing"

	"netops/backend/models"
)

// metricsServerWithDevices builds a server whose inventory spans two tenants
// plus a platform-owned (untagged) device, to exercise metrics scoping.
func metricsServerWithDevices() *server {
	d := discovery.NewDiscoveryAggregator()
	d.Upsert(models.Device{ID: "core-1", Name: "core-1.acme", Address: "10.1.0.1", TenantID: "acme"})
	d.Upsert(models.Device{ID: "edge-2", Name: "edge-2.globex", Address: "10.2.0.1", TenantID: "globex"})
	d.Upsert(models.Device{ID: "shared", Name: "shared", Address: "10.9.0.1"}) // platform-owned
	return &server{discovery: d}
}

// TestMetricsScopeFiltersCrossTenant: the platform owner gets NO filter — the
// query stays a raw pass-through.
func TestMetricsScopeFiltersCrossTenant(t *testing.T) {
	got := metricsScopeFilters([]string{"core-1"}, []string{"core-1.acme"}, true)
	if got != nil {
		t.Fatalf("cross-tenant must inject no extra_filters[]; got %v", got)
	}
}

// TestMetricsScopeFiltersScopedWithDevices: a scoped tenant with visible devices
// gets OR-combined matchers on device / hostname / source carrying exactly its
// own device id + name set.
func TestMetricsScopeFiltersScopedWithDevices(t *testing.T) {
	got := metricsScopeFilters([]string{"core-1"}, []string{"core-1.acme"}, false)
	if len(got) != 3 {
		t.Fatalf("expected 3 filters (device,hostname,source); got %d: %v", len(got), got)
	}
	joined := strings.Join(got, " ")
	for _, want := range []string{
		`{device=~"core-1"}`,
		`{hostname=~"core-1\.acme"}`, // regex metachars escaped
		`{source=~"core-1\.acme"}`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing filter %q in %v", want, got)
		}
	}
	// Must NOT leak another tenant's identifiers.
	if strings.Contains(joined, "edge-2") || strings.Contains(joined, "globex") {
		t.Errorf("TENANT LEAK: foreign device in filters %v", got)
	}
}

// TestMetricsScopeFiltersScopedNoDevices: a scoped tenant with zero visible
// devices gets a single match-nothing filter, so the result is empty (never
// unfiltered).
func TestMetricsScopeFiltersScopedNoDevices(t *testing.T) {
	got := metricsScopeFilters(nil, nil, false)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 match-nothing filter; got %v", got)
	}
	if !strings.Contains(got[0], "__netops_no_visible_device__") {
		t.Errorf("expected an impossible-value match-nothing filter; got %q", got[0])
	}
}

// TestMetricsScopeFiltersIdsOnly: when devices have ids but no names, only the
// device matcher is emitted (no empty hostname/source matchers).
func TestMetricsScopeFiltersIdsOnly(t *testing.T) {
	got := metricsScopeFilters([]string{"a", "b"}, nil, false)
	if len(got) != 1 || got[0] != `{device=~"a|b"}` {
		t.Fatalf(`expected single {device=~"a|b"}; got %v`, got)
	}
}

// TestRegexAlternationEscaping: values are regex-quoted and joined with |.
func TestRegexAlternationEscaping(t *testing.T) {
	cases := []struct {
		in   []string
		want string
	}{
		{nil, ""},
		{[]string{"core-1"}, "core-1"},
		{[]string{"a.b", "c+d"}, `a\.b|c\+d`},
	}
	for _, c := range cases {
		if got := regexAlternation(c.in); got != c.want {
			t.Errorf("regexAlternation(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestMetricsUpstreamIsVictoria: VM (default + explicit) is detected; an explicit
// Prometheus URL is not (so scoping fails closed there).
func TestMetricsUpstreamIsVictoria(t *testing.T) {
	cases := []struct {
		base string
		want bool
	}{
		{"http://victoria:8428", true},
		{"http://vmselect:8481/select/0/prometheus", true}, // VM cluster select path
		{"", true}, // default => VM
		{"http://prometheus:9090", false},
		{"http://metrics:9090", false},
	}
	for _, c := range cases {
		if got := metricsUpstreamIsVictoria(c.base); got != c.want {
			t.Errorf("metricsUpstreamIsVictoria(%q) = %v, want %v", c.base, got, c.want)
		}
	}
}

// TestVisibleDeviceMetricLabelsTenantIsolation: the tenancy helper feeding the
// scoper returns only the caller's own devices' ids/names — never a foreign
// tenant's or the platform-owned device's.
func TestVisibleDeviceMetricLabelsTenantIsolation(t *testing.T) {
	s := metricsServerWithDevices()
	ids, names, cross := s.visibleDeviceMetricLabels(jwtClaims{Role: RoleOperator, Tenant: "acme"})
	if cross {
		t.Fatal("scoped acme operator must not be cross-tenant")
	}
	sort.Strings(ids)
	sort.Strings(names)
	if strings.Join(ids, ",") != "core-1" {
		t.Errorf("acme ids = %v, want [core-1]", ids)
	}
	if strings.Join(names, ",") != "core-1.acme" {
		t.Errorf("acme names = %v, want [core-1.acme]", names)
	}
	all := strings.Join(append(ids, names...), " ")
	if strings.Contains(all, "edge-2") || strings.Contains(all, "globex") {
		t.Error("TENANT LEAK: acme must not see globex device labels")
	}
	if strings.Contains(all, "shared") {
		t.Error("strict isolation: platform-owned device must not be visible to a scoped tenant")
	}
}

// TestVisibleDeviceMetricLabelsCrossTenant: the platform owner is cross-tenant
// (nil sets, no restriction).
func TestVisibleDeviceMetricLabelsCrossTenant(t *testing.T) {
	s := metricsServerWithDevices()
	ids, names, cross := s.visibleDeviceMetricLabels(jwtClaims{Role: RoleSuperAdmin, Tenant: TenantGlobal})
	if !cross {
		t.Fatal("platform super-admin must be cross-tenant")
	}
	if ids != nil || names != nil {
		t.Errorf("cross-tenant must return nil sets; got ids=%v names=%v", ids, names)
	}
}
