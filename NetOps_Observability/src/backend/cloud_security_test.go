package backend

// cloud_security_test.go — Wave 5 #16 isolation + read-contract tests
// (CLAUDE.md §3a.5). The three new cloud read surfaces are ClickHouse-backed:
// the isolation contract IS the tenant_scope literal every query must carry
// (the corr_signals FORCE row policy enforces on it), plus fail-closed scope
// derivation — the same contract cloud_signals_test.go pins for health/changes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"netops/backend/cloud"
)

// §3a: every Wave 5 #16 query carries the CALLER's scope; no claims fails
// closed; a scoped caller's query can never name another tenant.
func TestCloudSecurityQueriesAreTenantScoped(t *testing.T) {
	scopeFor := func(c *jwtClaims) string {
		r := httptest.NewRequest(http.MethodGet, "/api/cloud/security", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
		}
		return cloud.SafeScopeLiteral(chTenantScope(r))
	}
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		{"no claims fails closed", nil, "__none__"},
		{"tenantless viewer fails closed", &jwtClaims{Role: "viewer", Tenant: ""}, "__none__"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scope := scopeFor(tc.claim)
			if scope != tc.want {
				t.Fatalf("scope = %q, want %q", scope, tc.want)
			}
			queries := []string{
				cloudSecuritySQL(24, "", 100, scope),
				cloudProviderEventsSQL(24, 100, scope),
				cloudSeamTelemetrySQL(24, 100, scope),
			}
			for _, q := range queries {
				if !strings.Contains(q, "SETTINGS tenant_scope = '"+tc.want+"'") {
					t.Fatalf("query is not scoped to %q:\n%s", tc.want, q)
				}
				if tc.want == "acme" && strings.Contains(q, "globex") {
					t.Fatalf("query leaked another tenant:\n%s", q)
				}
				// bounded by construction (§9 / #100 read budgets)
				if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "INTERVAL") {
					t.Fatalf("query is unbounded:\n%s", q)
				}
				if strings.Contains(q, "SELECT *") {
					t.Fatalf("query must name its columns:\n%s", q)
				}
			}
		})
	}
}

// The window parameterizes every #16 query (no hardwired 24h).
func TestCloudSecurityQueriesCarryWindow(t *testing.T) {
	for _, q := range []string{
		cloudSecuritySQL(168, "", 100, "acme"),
		cloudProviderEventsSQL(168, 100, "acme"),
		cloudSeamTelemetrySQL(168, 100, "acme"),
	} {
		if !strings.Contains(q, "INTERVAL 168 HOUR") {
			t.Fatalf("query does not honor the requested window:\n%s", q)
		}
	}
}

// The security read covers exactly the built rollup lanes — WAF blocks, the
// LB plane (rollup + normalized), DNS failures — and each kind maps back to
// its lane for the UI's coverage note.
func TestSecurityKindsCoverTheBuiltLanes(t *testing.T) {
	q := cloudSecuritySQL(24, "", 100, "acme")
	for _, kind := range []string{"cloud_waf_log", "cloud_lb_log", "lb_5xx", "cloud_dns_log"} {
		if !strings.Contains(q, "'"+kind+"'") {
			t.Fatalf("security query missing kind %q:\n%s", kind, q)
		}
	}
	cases := map[string]string{
		"cloud_waf_log": "waf", "cloud_lb_log": "lb", "lb_5xx": "lb",
		"cloud_dns_log": "dns", "cloud_change": "other",
	}
	for kind, want := range cases {
		if got := securityLaneOf(kind); got != want {
			t.Errorf("securityLaneOf(%q) = %q, want %q", kind, got, want)
		}
	}
}

// Provider events show the CURRENT state of each incident: one row per
// signal_id with the LATEST observation winning (an update open→closed must
// replace the stale open row, the inverse of cloudChangesSQL).
func TestProviderEventsSQLKeepsLatestObservation(t *testing.T) {
	q := cloudProviderEventsSQL(24, 100, "acme")
	if !strings.Contains(q, "GROUP BY signal_id") {
		t.Fatalf("provider events must collapse re-emissions per signal_id:\n%s", q)
	}
	if !strings.Contains(q, "argMax(attrs, ts)") || !strings.Contains(q, "argMax(severity, ts)") {
		t.Fatalf("provider events must keep the LATEST observation (argMax):\n%s", q)
	}
	if !strings.Contains(q, "'provider_event'") {
		t.Fatalf("provider events must read kind=provider_event:\n%s", q)
	}
}

// The seam read folds to the latest state per seam endpoint and counts window
// churn — and the state mapping is default-closed (unknown, never "up").
func TestSeamTelemetryContract(t *testing.T) {
	q := cloudSeamTelemetrySQL(24, 100, "acme")
	if !strings.Contains(q, "GROUP BY entity_id") || !strings.Contains(q, "count()") {
		t.Fatalf("seam telemetry must fold per seam with churn count:\n%s", q)
	}
	for _, kind := range []string{"cloud_vpn_tunnel_down", "cloud_bgp_session_up",
		"cloud_gateway_blackhole_drop", "cloud_state_unknown", "ipsec_tunnel_status"} {
		if !strings.Contains(q, "'"+kind+"'") {
			t.Fatalf("seam query missing kind %q:\n%s", kind, q)
		}
	}
	cases := []struct {
		kind  string
		value float64
		want  string
	}{
		{"cloud_vpn_tunnel_up", 1, "up"},
		{"cloud_vpn_tunnel_down", 1, "down"},
		{"cloud_bgp_flap", 1, "degraded"},
		{"cloud_nat_port_exhaustion", 42, "degraded"},
		{"cloud_physical_link_down", 1, "down"},
		{"ipsec_tunnel_status", 1, "up"},
		{"ipsec_tunnel_status", 0, "down"},
		{"cloud_state_unknown", 1, "unknown"},
		{"some_future_kind", 1, "unknown"}, // default-closed: never green
	}
	for _, tc := range cases {
		if got := seamStateOf(tc.kind, tc.value); got != tc.want {
			t.Errorf("seamStateOf(%q, %v) = %q, want %q", tc.kind, tc.value, got, tc.want)
		}
	}
}

// Lane detail renders only what the producer measured — absence stays absent.
func TestSecurityDetailRendersMeasuredFactsOnly(t *testing.T) {
	waf := securityDetail("cloud_waf_log", signalAttrs{Rule: "rate-limit", Action: "BLOCK", Host: "shop.example"})
	for _, want := range []string{"rule rate-limit", "BLOCK", "host shop.example"} {
		if !strings.Contains(waf, want) {
			t.Errorf("waf detail missing %q: %s", want, waf)
		}
	}
	dns := securityDetail("cloud_dns_log", signalAttrs{Rcode: "NXDOMAIN", QueryType: "A"})
	if dns != "rcode NXDOMAIN · A" {
		t.Errorf("dns detail = %q", dns)
	}
	if securityDetail("cloud_lb_log", signalAttrs{}) != "" {
		t.Error("no measured facts must render as empty, never invented")
	}
}
