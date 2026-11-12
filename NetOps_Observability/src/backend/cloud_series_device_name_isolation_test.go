// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// cloud_series_device_name_isolation_test.go — CLAUDE.md §3a rule 5 isolation
// test for the CLOUD metric lane read through the device-scoped metric lanes
// (tracker 392).
//
// The cloud poller's MetricEvent carries no tenant. Vector's metrics_normalized
// lane looks the event's `device` (the resource NAME) up in device_tenant, which
// holds network devices, and stamps whatever it finds — normally nothing, so
// the series lands as
//
//	cloud_cpu_util{device="globex-web-01", resource_id="i-…", provider="aws", tenant_id=""}
//
// The device-scoped lanes bound a tenant by {device=~"<its device ids>"} plus a
// tenant_id that may be EMPTY (SNMP, gNMI and probe series carry none). So a
// tenant that created a device whose id is another tenant's cloud resource name
// read that resource's series. Worse, once the device exists Vector resolves the
// name to the attacker and stamps tenant_id=<attacker> on the victim's series,
// which the empty-or-own tenant clause then admits outright.
//
// The assertions evaluate the filters that actually went on the wire with
// VictoriaMetrics semantics (vmAdmits), not by string inspection.

import (
	"net/http"
	"testing"

	"netops/backend/models"
)

func TestMetricsScopeNeverAdmitsAnotherTenantsCloudSeriesByDeviceName(t *testing.T) {
	srv, s := newTestServerState(t)
	s.cloud = newCloudStore()
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

	// globex OWNS the cloud resource: its integration discovered it.
	seedCloudResource(t, s, globex, "i-0globex00000001", "globex-web-01")
	seedCloudResource(t, s, acme, "i-0acme0000000001", "acme-web-01")

	st, b := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op-acme-cloud", "password": "Passw0rd!2345", "role": "operator", "tenant_id": acme,
	})
	if st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	acmeTok := login(t, srv, "op-acme-cloud", "Passw0rd!2345").Token

	// The attack: acme creates a device whose id is globex's cloud resource NAME.
	st, b = do(t, srv, "POST", "/api/devices", acmeTok, map[string]any{"id": "globex-web-01", "name": "globex-web-01", "address": "10.9.9.9"})
	if st != 201 && st != 200 {
		t.Fatalf("acme create device: %d %s", st, b)
	}

	cloudSeries := func(name, rid, tenant string) map[string]string {
		return map[string]string{"__name__": "cloud_cpu_util", "device": name, "resource_id": rid, "provider": "aws", "tenant_id": tenant}
	}
	// As Vector writes it before acme's device exists: no tenant.
	globexCloudUnstamped := cloudSeries("globex-web-01", "i-0globex00000001", "")
	// As Vector writes it once acme's device exists: the name resolves to acme.
	globexCloudStampedAcme := cloudSeries("globex-web-01", "i-0globex00000001", acme)
	acmeSNMP := map[string]string{"__name__": "device_cpu_percent", "device": "acme-core"}
	acmeTelegraf := map[string]string{"__name__": "snmp_ifHCInOctets", "hostname": "acme-core"}
	globexSNMP := map[string]string{"__name__": "device_cpu_percent", "device": "globex-core"}

	query := func(t *testing.T, token, asTenant string) [][]string {
		t.Helper()
		vm := &captureVM{}
		vm.start(t)
		req, err := http.NewRequest("GET", srv.URL+"/api/metrics/query?query=cloud_cpu_util", nil)
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
		if err := resp.Body.Close(); err != nil {
			t.Fatal(err)
		}
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

	t.Run("scoped tenant never reads another tenant's cloud series through a colliding device id", func(t *testing.T) {
		for i, f := range query(t, acmeTok, "") {
			if len(f) == 0 {
				t.Fatalf("query %d went out UNFILTERED for a scoped caller", i)
			}
			if vmAdmits(t, f, globexCloudUnstamped) {
				t.Fatalf("TENANT LEAK: query %d admitted globex's cloud series (tenant_id empty) via acme's device named after it: %q", i, f)
			}
			if vmAdmits(t, f, globexCloudStampedAcme) {
				t.Fatalf("TENANT LEAK: query %d admitted globex's cloud series that Vector stamped with acme's tenant by name: %q", i, f)
			}
			if vmAdmits(t, f, globexSNMP) {
				t.Fatalf("TENANT LEAK: query %d admitted globex's device series: %q", i, f)
			}
			if !vmAdmits(t, f, acmeSNMP) || !vmAdmits(t, f, acmeTelegraf) {
				t.Fatalf("query %d lost acme's own device series: %q", i, f)
			}
		}
	})

	t.Run("as_tenant into another org is ignored for a scoped caller", func(t *testing.T) {
		for i, f := range query(t, acmeTok, globex) {
			if vmAdmits(t, f, globexCloudUnstamped) || vmAdmits(t, f, globexCloudStampedAcme) || vmAdmits(t, f, globexSNMP) {
				t.Fatalf("TENANT LEAK: acme's caller acting as globex read globex's series (query %d): %q", i, f)
			}
		}
	})

	t.Run("platform owner scoped into acme does not read globex's cloud series either", func(t *testing.T) {
		for i, f := range query(t, admin, acme) {
			if vmAdmits(t, f, globexCloudUnstamped) || vmAdmits(t, f, globexCloudStampedAcme) {
				t.Fatalf("TENANT LEAK: owner acting as acme read globex's cloud series (query %d): %q", i, f)
			}
			if !vmAdmits(t, f, acmeSNMP) {
				t.Fatalf("query %d lost acme's own device series: %q", i, f)
			}
		}
	})

	t.Run("unrestricted platform owner keeps the whole cloud lane", func(t *testing.T) {
		for i, f := range query(t, admin, "") {
			if !vmAdmits(t, f, globexCloudUnstamped) || !vmAdmits(t, f, globexSNMP) {
				t.Fatalf("query %d: the platform owner lost fleet series: %q", i, f)
			}
		}
	})
}

// The pure builders: a device-scoped filter set never admits a series that
// carries a resource_id, whatever its device label or tenant_id says, and still
// admits every device-lane shape it admitted before.
func TestMetricsScopeFiltersExcludeCloudLaneSeries(t *testing.T) {
	f := metricsTenantScoped(metricsScopeFilters([]string{"web-01"}, []string{"web-01"}, false), "t_a")
	for _, tenant := range []string{"", "t_a", "T_A"} {
		cloud := map[string]string{"__name__": "cloud_cpu_util", "device": "web-01", "resource_id": "i-0123", "tenant_id": tenant}
		if vmAdmits(t, f, cloud) {
			t.Fatalf("a cloud-lane series (tenant_id=%q) was admitted by a device-name match: %q", tenant, f)
		}
		hostnameCloud := map[string]string{"__name__": "cloud_cpu_util", "hostname": "web-01", "resource_id": "i-0123", "tenant_id": tenant}
		if vmAdmits(t, f, hostnameCloud) {
			t.Fatalf("a cloud-lane series carrying a hostname was admitted by a name match: %q", f)
		}
	}
	for _, own := range []map[string]string{
		{"__name__": "device_cpu_percent", "device": "web-01"},
		{"__name__": "controller_metric_x", "device": "web-01", "tenant_id": "t_a"},
		{"__name__": "snmp_ifHCInOctets", "hostname": "web-01"},
		{"__name__": "gnmi_x", "source": "web-01"},
	} {
		if !vmAdmits(t, f, own) {
			t.Fatalf("own device-lane series %v lost: %q", own, f)
		}
	}
}
