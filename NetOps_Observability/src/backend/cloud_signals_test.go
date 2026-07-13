package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ── Tenant isolation (CLAUDE.md §3a) ─────────────────────────────────────────
// Every cloud read surface is scoped by the CALLER's principal. The scope literal
// is what the corr_signals / corr_signals_archive / corr_objects FORCE row policies
// enforce on, so these assertions are the isolation contract: a tenant caller's
// query can only ever carry ITS OWN scope, a request without claims fails closed,
// and no query may reach ClickHouse without a scope at all.
func TestCloudSignalQueriesAreTenantScoped(t *testing.T) {
	scopeFor := func(c *jwtClaims) string {
		r := httptest.NewRequest(http.MethodGet, "/api/cloud/health", nil)
		if c != nil {
			r = r.WithContext(context.WithValue(r.Context(), userCtxKey, *c))
		}
		return safeScopeLiteral(chTenantScope(r))
	}
	cases := []struct {
		name  string
		claim *jwtClaims
		want  string
	}{
		{"platform owner", &jwtClaims{Role: RoleSuperAdmin, Tenant: ""}, "__all__"},
		{"tenant admin", &jwtClaims{Role: "admin", Tenant: "acme"}, "acme"},
		{"tenant super-admin is NOT cross-tenant", &jwtClaims{Role: RoleSuperAdmin, Tenant: "acme"}, "acme"},
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
				cloudHealthSQL("", 100, scope),
				cloudChangesSQL("", 100, scope),
				cloudEvidenceObjectsSQL("", scope),
				cloudEvidenceSignalsSQL("'id'", 100, scope),
			}
			for _, q := range queries {
				if !strings.Contains(q, "SETTINGS tenant_scope = '"+tc.want+"'") {
					t.Fatalf("query is not scoped to %q:\n%s", tc.want, q)
				}
				// another tenant's id must never appear in a scoped caller's query
				if tc.want == "acme" && strings.Contains(q, "globex") {
					t.Fatalf("query leaked another tenant:\n%s", q)
				}
				// bounded by construction (§9 / #100 read budgets)
				if !strings.Contains(q, "LIMIT") || !strings.Contains(q, "INTERVAL") {
					t.Fatalf("query is unbounded:\n%s", q)
				}
				if strings.Contains(q, "SELECT *") {
					t.Fatalf("query must name its columns (#100 contract):\n%s", q)
				}
			}
		})
	}
}

// The evidence read must use the HOT projection (never the raw hypotheses/objects
// table) and must prefilter the archive by the picked object ids — the #100 contract.
func TestCloudEvidenceQueriesFollowHotReadContract(t *testing.T) {
	obj := cloudEvidenceObjectsSQL("", "acme")
	if !strings.Contains(obj, "netops.corr_current FINAL") {
		t.Fatalf("object read must use corr_current FINAL:\n%s", obj)
	}
	if strings.Contains(obj, "netops.hypotheses") {
		t.Fatalf("object read must never touch hypotheses near a fold:\n%s", obj)
	}
	sig := cloudEvidenceSignalsSQL("'a','b'", 50, "acme")
	if !strings.Contains(sig, "archived_for IN ('a','b')") {
		t.Fatalf("archive read must be prefiltered by the picked ids:\n%s", sig)
	}
}

// The app filter must bind the app to the signal's OWN identity fields — never a
// LIKE/contains match that could pull in a neighbouring app's rows.
func TestAppFilterSQLBindsExactly(t *testing.T) {
	f := appFilterSQL("store-api")
	for _, want := range []string{"entity_id = 'store-api'", "JSONExtractString(attrs,'app') = 'store-api'"} {
		if !strings.Contains(f, want) {
			t.Fatalf("appFilterSQL missing %q: %s", want, f)
		}
	}
	if strings.Contains(f, "LIKE") {
		t.Fatalf("appFilterSQL must not fuzzy-match: %s", f)
	}
	if appFilterSQL("") != "" {
		t.Fatal("no app ⇒ no predicate")
	}
}

func TestClampSignalLimit(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", cloudSignalDefaultLim},
		{"0", cloudSignalDefaultLim},
		{"-5", cloudSignalDefaultLim},
		{"abc", cloudSignalDefaultLim},
		{"50", 50},
		{"1000000", cloudSignalMaxLim},
	}
	for _, tc := range cases {
		if got := clampSignalLimit(tc.in); got != tc.want {
			t.Fatalf("clampSignalLimit(%q) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

// A tenant scope reaches a SQL literal — anything that is not an opaque id token
// must fail CLOSED to the non-matching sentinel, never widen the query.
func TestSafeScopeLiteralFailsClosed(t *testing.T) {
	ok := []string{"__all__", "t_9f3a", "global", "acme-prod", "a.b"}
	for _, s := range ok {
		if got := safeScopeLiteral(s); got != s {
			t.Fatalf("safeScopeLiteral(%q) = %q, want passthrough", s, got)
		}
	}
	bad := []string{"", "' OR 1=1 --", `t_1' UNION SELECT`, "a\\b", "a b", "t\n"}
	for _, s := range bad {
		if got := safeScopeLiteral(s); got != "__none__" {
			t.Fatalf("safeScopeLiteral(%q) = %q, want __none__ (fail closed)", s, got)
		}
	}
}

func TestCloudHealthStateAndSeverity(t *testing.T) {
	cases := []struct{ sev, state, sevOut string }{
		{"crit", "down", "critical"},
		{"high", "degraded", "warning"},
		{"warn", "degraded", "warning"},
		{"info", "healthy", "info"},
		{"", "unknown", "info"},
	}
	for _, tc := range cases {
		if got := cloudHealthState(tc.sev); got != tc.state {
			t.Fatalf("cloudHealthState(%q) = %q, want %q", tc.sev, got, tc.state)
		}
		if got := cloudHealthSeverity(tc.sev); got != tc.sevOut {
			t.Fatalf("cloudHealthSeverity(%q) = %q, want %q", tc.sev, got, tc.sevOut)
		}
	}
}

// Classification is on the provider's OWN event name — these are the real event
// names observed on the AWS/Azure lane. An empty name stays "unknown": we never
// classify a change we cannot name.
func TestCloudChangeType(t *testing.T) {
	cases := []struct{ kind, event, want string }{
		{"cloud_change", "RevokeSecurityGroupIngress", "security_policy_change"},
		{"cloud_change", "AuthorizeSecurityGroupIngress", "security_policy_change"},
		{"cloud_change", "PutBucketPublicAccessBlock", "security_policy_change"},
		{"cloud_change", "PutBucketPolicy", "security_policy_change"},
		{"security_policy_change", "whatever", "security_policy_change"},
		{"cloud_change", "CreateRoute", "route_change"},
		{"cloud_change", "ReplaceRoute", "route_change"},
		{"cloud_change", "AssociateAddress", "route_change"},
		{"cloud_change", "vif_state", "route_change"},
		{"cloud_change", "connection_state", "route_change"},
		{"cloud_change", "StartInstances", "scale_change"},
		{"cloud_change", "StopInstances", "scale_change"},
		{"cloud_change", "AttachRolePolicy", "iam_change"},
		{"cloud_change", "ChangeResourceRecordSets", "dns_change"},
		{"cloud_change", "ImportCertificate", "cert_change"},
		{"cloud_change", "UpdateFunctionCode", "deploy"},
		// an SSM agent heartbeat is NOT a scale change — it stays the honest
		// catch-all for a mutating management-plane call.
		{"cloud_audit", "UpdateInstanceInformation", "config_change"},
		{"cloud_change", "PutBucketLifecycle", "config_change"},
		{"cloud_change", "", "unknown"},
	}
	for _, tc := range cases {
		if got := cloudChangeType(tc.kind, tc.event); got != tc.want {
			t.Fatalf("cloudChangeType(%q, %q) = %q, want %q", tc.kind, tc.event, got, tc.want)
		}
	}
}

func TestShortActor(t *testing.T) {
	cases := []struct{ in, want string }{
		{"arn:aws:iam::945714973156:user/correlix", "iam:user/correlix"},
		{"arn:aws:sts::945714973156:assumed-role/deploy/i-01", "sts:assumed-role/deploy/i-01"},
		{"svc-principal@example", "svc-principal@example"},
		{"", "—"},
	}
	for _, tc := range cases {
		if got := shortActor(tc.in); got != tc.want {
			t.Fatalf("shortActor(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	// the account number must not survive into the UI
	if got := shortActor("arn:aws:iam::945714973156:user/correlix"); strings.Contains(got, "945714973156") {
		t.Fatalf("shortActor leaked the account id: %q", got)
	}
}

func TestCloudChangeConfidence(t *testing.T) {
	if got := cloudChangeConfidence("arn:...:user/x", "ec2.amazonaws.com", "req-1"); got != "confirmed" {
		t.Fatalf("full provenance = %q, want confirmed", got)
	}
	if got := cloudChangeConfidence("", "ec2.amazonaws.com", ""); got != "strong" {
		t.Fatalf("no actor = %q, want strong", got)
	}
	if got := cloudChangeConfidence("actor", "", ""); got != "strong" {
		t.Fatalf("no emitting service = %q, want strong", got)
	}
}

// "undetermined" must never be promoted into a confidence we did not earn.
func TestVerdictConfidence(t *testing.T) {
	for in, want := range map[string]string{
		"confirmed": "confirmed", "suspected": "suspected",
		"undetermined": "unknown", "": "unknown", "recovered": "unknown",
	} {
		if got := verdictConfidence(in); got != want {
			t.Fatalf("verdictConfidence(%q) = %q, want %q", in, got, want)
		}
	}
}

// A baseline the engine never computed reads "—", never a fabricated 0.
func TestFmtBaselineNotMeasured(t *testing.T) {
	if got := fmtBaseline(0, 0); got != "—" {
		t.Fatalf("fmtBaseline(0,0) = %q, want —", got)
	}
	if got := fmtBaseline(0.2, 6.2); got != "0.2" {
		t.Fatalf("fmtBaseline(0.2, 6.2) = %q, want 0.2", got)
	}
	if got := fmtSignalValue(6.4); got != "6.4" {
		t.Fatalf("fmtSignalValue(6.4) = %q", got)
	}
}

func TestAppAndResourceResolution(t *testing.T) {
	// app-centric health signal: entity IS the app
	row := chSignalRow{EntityType: "app", EntityID: "booking-service"}
	a := parseAttrs(`{"app":"booking-service","provider":"azure","host":"azure-host-01"}`)
	if got := appOf(row, a); got != "booking-service" {
		t.Fatalf("appOf = %q", got)
	}
	if got := resourceOf(row, a); got != "azure-host-01" {
		t.Fatalf("resourceOf = %q, want the host it was measured on", got)
	}
	// resource-centric change: no app in attrs and the entity is a resource →
	// unattributed, which must stay EMPTY (the caller renders "—"), never guessed.
	row = chSignalRow{EntityType: "cloud_resource", EntityID: "i-025bac7de4e6be0a6"}
	a = parseAttrs(`{"account":"945714973156","provider":"aws","resource_id":"i-025bac7de4e6be0a6"}`)
	if got := appOf(row, a); got != "" {
		t.Fatalf("appOf on an unattributed resource = %q, want \"\"", got)
	}
	if got := resourceOf(row, a); got != "i-025bac7de4e6be0a6" {
		t.Fatalf("resourceOf = %q", got)
	}
	if got := providerOf(a); got != "aws" {
		t.Fatalf("providerOf = %q", got)
	}
	if got := providerOf(signalAttrs{}); got != "cloud" {
		t.Fatalf("providerOf(empty) = %q, want cloud", got)
	}
}

func TestAffectedAppsAndMissingEvidence(t *testing.T) {
	apps := affectedApps(`{"apps":["booking-service","journey"]}`)
	if len(apps) != 2 || apps[0] != "booking-service" {
		t.Fatalf("affectedApps = %v", apps)
	}
	if got := affectedApps(""); len(got) != 0 {
		t.Fatalf("affectedApps(empty) = %v, want []", got)
	}
	if got := affectedApps(`{"interfaces":["x"]}`); len(got) != 0 {
		t.Fatalf("affectedApps(no apps) = %v, want []", got)
	}
	gaps := missingEvidence(`["sig.x: single observer (cloud:a:b); need ≥2"]`)
	if len(gaps) != 1 || !strings.Contains(gaps[0], "single observer") {
		t.Fatalf("missingEvidence = %v", gaps)
	}
	if got := missingEvidence("[]"); len(got) != 0 {
		t.Fatalf("missingEvidence([]) = %v", got)
	}
}

// A value that could break out of the SQL literal list must be dropped, not quoted.
func TestSQLListDropsUnsafeValues(t *testing.T) {
	got := sqlList([]string{"0ad5e1ec-60ac-5832-8ffd-31cc6b798c16", "x'; DROP TABLE netops.corr_signals; --", ""})
	if got != "'0ad5e1ec-60ac-5832-8ffd-31cc6b798c16'" {
		t.Fatalf("sqlList = %q", got)
	}
	if sqlList(nil) != "" {
		t.Fatal("sqlList(nil) must be empty so the caller skips the query")
	}
}

func TestISOTS(t *testing.T) {
	if got := isoTS("2026-07-12 13:49:00.000"); got != "2026-07-12T13:49:00.000Z" {
		t.Fatalf("isoTS = %q", got)
	}
	if got := isoTS(""); got != "" {
		t.Fatalf("isoTS(empty) = %q", got)
	}
}

// The evidence ledger speaks OPERATOR language: what was observed, on which
// named resource, how serious, and what it supports. Schema kinds, signature
// ids and raw machine handles must never be the operator's text (owner
// directive 2026-07-13); the raw ids live in cloud_ref for console pivot.
func TestEvidenceReasonIsOperatorReadable(t *testing.T) {
	namer := func(id string) string {
		if id == "eni-007542c1d61f44947" {
			return "correlix-app-host-01"
		}
		return ""
	}
	got := evidenceReason("cloud_flow_log", "rejected_flow", "eni-007542c1d61f44947", "warn",
		"sig.ent.app.saas-experience-degraded", "suspected", namer)

	for _, want := range []string{
		"Traffic was rejected by a cloud security rule", // the observation, in words
		"correlix-app-host-01",                          // the resource, by NAME
		"minor",                                         // severity, in words
		"supporting the suspected",                      // what it feeds
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("evidenceReason %q missing %q", got, want)
		}
	}
	// BANNED: schema kinds, signature ids, bare severity tokens.
	for _, banned := range []string{"cloud_flow_log", "sig.ent.", "severity warn", "grounded into"} {
		if strings.Contains(got, banned) {
			t.Fatalf("evidenceReason %q leaks developer language %q", got, banned)
		}
	}
	// The raw id may still appear as a parenthetical for the engineer.
	if !strings.Contains(got, "(eni-007542c1d61f44947)") {
		t.Fatalf("evidenceReason %q must keep the raw handle for console pivot", got)
	}
}
