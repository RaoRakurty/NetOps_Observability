// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// metrics_unresolved_device_isolation_test.go — CLAUDE.md §3a rule 5 isolation
// test for controller series of UNRESOLVED devices (NMS-first plan F1).
//
// A controller (vManage, …) labels a device it cannot map to inventory by its
// native key, e.g. device="10.255.255.40", and stamps tenant_id with the
// integration's tenant. The metric scope used to match on the device label
// alone, and a tenant may create a device with any id. So tenant A, by
// creating a device "10.255.255.40", read tenant B's controller series for
// B's unresolved device. System-ips are low-entropy; the same happens by
// accident when an operator names a device by its system-ip.
//
// The assertions evaluate the filters that actually went on the wire with
// VictoriaMetrics semantics (a series is admitted when ANY extra_filter's
// matchers ALL hold; =~ and !~ are anchored RE2), not by string inspection.

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"netops/backend/models"
)

var vmMatcherRe = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)(=~|!~|!=|=)"((?:[^"\\]|\\.)*)"`)

// vmAdmits reports whether VictoriaMetrics would return series under the
// given extra_filters[]. No filters means unfiltered.
func vmAdmits(t *testing.T, filters []string, series map[string]string) bool {
	t.Helper()
	if len(filters) == 0 {
		return true
	}
	for _, f := range filters {
		body := strings.TrimSuffix(strings.TrimPrefix(f, "{"), "}")
		ms := vmMatcherRe.FindAllStringSubmatch(body, -1)
		if len(ms) == 0 {
			t.Fatalf("unparseable filter %q", f)
		}
		ok := true
		for _, m := range ms {
			label, op := m[1], m[2]
			// Decode the PromQL string literal first, as VictoriaMetrics does:
			// its escapes (\\, \", \n, \xNN) are Go's.
			val, err := strconv.Unquote(`"` + m[3] + `"`)
			if err != nil {
				t.Fatalf("filter %q: matcher value %q is not a valid PromQL string: %v", f, m[3], err)
			}
			got := series[label]
			switch op {
			case "=":
				ok = ok && got == val
			case "!=":
				ok = ok && got != val
			case "=~", "!~":
				re, err := regexp.Compile("^(?:" + val + ")$")
				if err != nil {
					t.Fatalf("filter %q: bad regex %q: %v", f, val, err)
				}
				ok = ok && (re.MatchString(got) == (op == "=~"))
			}
		}
		if ok {
			return true
		}
	}
	return false
}

func TestMetricsScopeNeverAdmitsAnotherTenantsUnresolvedControllerSeries(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	mkTenant := func(name, slug string) string {
		t.Helper()
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org: %d %s", st, b)
		}
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": name, "org_id": idOf(t, b), "slug": slug})
		if st != 201 {
			t.Fatalf("create tenant: %d %s", st, b)
		}
		return idOf(t, b)
	}
	acme, globex := mkTenant("Acme", "acme"), mkTenant("Globex", "globex")
	s.discovery.Upsert(models.Device{ID: "acme-core", Name: "acme-core", Address: "10.1.0.1", TenantID: acme})
	s.discovery.Upsert(models.Device{ID: "globex-core", Name: "globex-core", Address: "10.2.0.1", TenantID: globex})

	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op-acme", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	acmeTok := login(t, srv, "op-acme", "Passw0rd!2345").Token

	// The attack: acme names a device after globex's unresolved system-ip.
	st, b = do(t, srv, "POST", "/api/devices", acmeTok, map[string]any{"id": "10.255.255.40", "name": "10.255.255.40", "address": "10.255.255.40"})
	if st != 201 && st != 200 {
		t.Fatalf("acme create device: %d %s", st, b)
	}

	globexUnresolved := map[string]string{"__name__": "controller_metric_bfd_sessions_up", "device": "10.255.255.40",
		"tenant_id": globex, "integration_id": "nmsi-00000000000000bb", "source_system": "vmanage"}
	acmeUnresolved := map[string]string{"__name__": "controller_metric_bfd_sessions_up", "device": "10.255.255.40",
		"tenant_id": acme, "integration_id": "nmsi-00000000000000aa", "source_system": "vmanage"}
	acmeSNMP := map[string]string{"__name__": "device_cpu_percent", "device": "acme-core"}
	globexSNMP := map[string]string{"__name__": "device_cpu_percent", "device": "globex-core"}

	query := func(t *testing.T, token, asTenant string) [][]string {
		t.Helper()
		vm := &captureVM{}
		vm.start(t)
		req, err := http.NewRequest("GET", srv.URL+"/api/metrics/query?query=up", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		if asTenant != "" {
			req.Header.Set("X-Acting-Tenant", asTenant)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		got := vm.all()
		if len(got) == 0 {
			t.Fatal("no VictoriaMetrics query was issued — this fixture proves nothing")
		}
		out := make([][]string, 0, len(got))
		for _, q := range got {
			out = append(out, q["extra_filters[]"])
		}
		return out
	}

	t.Run("scoped tenant reads its own series and never another tenant's unresolved device", func(t *testing.T) {
		for i, f := range query(t, acmeTok, "") {
			if vmAdmits(t, f, globexUnresolved) {
				t.Fatalf("TENANT LEAK: query %d admitted globex's unresolved controller series via a device acme named 10.255.255.40: %q", i, f)
			}
			if vmAdmits(t, f, globexSNMP) {
				t.Fatalf("TENANT LEAK: query %d admitted globex's device series: %q", i, f)
			}
			if !vmAdmits(t, f, acmeSNMP) || !vmAdmits(t, f, acmeUnresolved) {
				t.Fatalf("query %d lost acme's own series: %q", i, f)
			}
		}
	})

	t.Run("as_tenant into another org is ignored for a scoped caller", func(t *testing.T) {
		for i, f := range query(t, acmeTok, globex) {
			if vmAdmits(t, f, globexUnresolved) || vmAdmits(t, f, globexSNMP) {
				t.Fatalf("TENANT LEAK: acme's caller acting as globex read globex's series (query %d): %q", i, f)
			}
		}
	})

	t.Run("platform owner scoped into a tenant reads only that tenant", func(t *testing.T) {
		for i, f := range query(t, admin, globex) {
			// globex's unresolved series is on no globex inventory device, so
			// the device bound hides it in a scoped view; only its own device's
			// series must be there.
			if !vmAdmits(t, f, globexSNMP) {
				t.Fatalf("query %d lost globex's own series: %q", i, f)
			}
			if vmAdmits(t, f, acmeUnresolved) || vmAdmits(t, f, acmeSNMP) {
				t.Fatalf("TENANT LEAK: owner acting as globex read acme's series (query %d): %q", i, f)
			}
		}
	})

	t.Run("a restricted tenant's unresolved series are excluded from the Global view", func(t *testing.T) {
		if _, err := s.tenants.SetOperatorRestricted("globex", true); err != nil {
			t.Fatalf("restrict globex: %v", err)
		}
		for i, f := range query(t, admin, "") {
			if vmAdmits(t, f, globexUnresolved) {
				t.Fatalf("RESTRICTION LEAK: query %d admitted restricted globex's unresolved controller series: %q", i, f)
			}
			if vmAdmits(t, f, globexSNMP) {
				t.Fatalf("RESTRICTION LEAK: query %d admitted restricted globex's device series: %q", i, f)
			}
			if !vmAdmits(t, f, acmeUnresolved) || !vmAdmits(t, f, acmeSNMP) {
				t.Fatalf("query %d over-excluded unrestricted acme: %q", i, f)
			}
		}
	})
}

// The pure builders, without the router: a tenant's scope keeps device-less
// series of its own named devices and the match-nothing sentinel intact.
func TestMetricsTenantScopedKeepsSentinelAndNameMatchers(t *testing.T) {
	if got := metricsTenantScoped([]string{metricsNoVisibleDeviceFilter}, "t_a"); len(got) != 1 || got[0] != metricsNoVisibleDeviceFilter {
		t.Fatalf("sentinel must pass through untouched, got %v", got)
	}
	f := metricsTenantScoped(metricsScopeFilters([]string{"a-core"}, []string{"a-core"}, false), "T_A")
	telegraf := map[string]string{"__name__": "cpu_usage", "hostname": "a-core"}
	foreignCtl := map[string]string{"__name__": "controller_metric_x", "hostname": "a-core", "tenant_id": "t_b"}
	ownCtlUpper := map[string]string{"__name__": "controller_metric_x", "device": "a-core", "tenant_id": "T_a"}
	if !vmAdmits(t, f, telegraf) {
		t.Errorf("a device-less series of the caller's own device was dropped: %v", f)
	}
	if vmAdmits(t, f, foreignCtl) {
		t.Errorf("another tenant's series admitted by name: %v", f)
	}
	if !vmAdmits(t, f, ownCtlUpper) {
		t.Errorf("tenant_id must match case-insensitively: %v", f)
	}
}

// Dotted ids and names are the common case (IPs, FQDN sysNames). They must
// reach VictoriaMetrics as a parseable string that still matches literally.
func TestRegexAlternationIsAValidPromQLStringThatMatchesLiterally(t *testing.T) {
	f := metricsScopeFilters([]string{"10.255.255.40"}, []string{"core-1.acme.example"}, false)
	if !vmAdmits(t, f, map[string]string{"device": "10.255.255.40"}) {
		t.Fatalf("dotted device id no longer matches itself: %v", f)
	}
	if vmAdmits(t, f, map[string]string{"device": "10x255x255x40"}) {
		t.Fatalf("a dot matched any character — not literal: %v", f)
	}
	if !vmAdmits(t, f, map[string]string{"hostname": "core-1.acme.example"}) {
		t.Fatalf("dotted name no longer matches itself: %v", f)
	}
	for _, flt := range f {
		if strings.Contains(flt, `\.`) && !strings.Contains(flt, `\\.`) {
			t.Fatalf("single-backslash regex escape inside a PromQL string (VictoriaMetrics rejects it): %q", flt)
		}
	}
}

// A device sets its own sysName. A name that tries to close the string and add
// its own selector must stay one literal value, never widen the scope.
func TestADeviceNameCannotInjectMatchersIntoTheScope(t *testing.T) {
	evil := `x"}|{device=~".*`
	f := metricsTenantScoped(metricsScopeFilters([]string{"a-core"}, []string{evil, "a\\b", "nl\nx"}, false), "t_a")
	for _, flt := range f {
		if n := len(vmMatcherRe.FindAllStringSubmatch(strings.Trim(flt, "{}"), -1)); n > 3 {
			t.Fatalf("injected matchers: %d matchers in %q", n, flt)
		}
	}
	if vmAdmits(t, f, map[string]string{"device": "b-core", "tenant_id": "t_b"}) {
		t.Fatalf("TENANT LEAK: an injected name widened the scope: %v", f)
	}
	if !vmAdmits(t, f, map[string]string{"hostname": evil}) {
		t.Fatalf("the hostile name must still match itself literally: %v", f)
	}
	if !vmAdmits(t, f, map[string]string{"hostname": "a\\b"}) || !vmAdmits(t, f, map[string]string{"hostname": "nl\nx"}) {
		t.Fatalf("backslash / newline names must round-trip: %v", f)
	}
}
