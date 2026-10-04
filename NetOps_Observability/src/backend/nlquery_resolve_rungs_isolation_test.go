// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// nlquery_resolve_rungs_isolation_test.go — the N-C2 remainder rungs end to
// end through /api/ai/entities/resolve and the NL scope, §3a: tenant A's
// adjacency, application seeds and aliases never resolve for tenant B (and
// vice versa); an as_tenant walk changes nothing; a foreign application is
// invisible exactly like a missing one; a carrier seed is visible to everyone
// (public) but never mapped, so it is refused precisely; and a model
// suggestion asked for where no model exists is said, not faked.

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"netops/backend/collectors"
	"netops/backend/internal/dem/experience"
	nlqast "netops/backend/internal/nlquery/ast"
	"netops/backend/internal/nlquery/resolve"
	"netops/backend/internal/nlquery/validate"
	"netops/backend/models"
)

func rungsFixture(t *testing.T) (*server, jwtClaims, jwtClaims) {
	t.Helper()
	s, a, b := aliasFixture(t) // dev-a "edge-a" (t-a), dev-b "edge-b" (t-b)
	for _, d := range []models.Device{
		{ID: "core-a", Name: "core-a", TenantID: "t-a", Labels: map[string]string{"site": "dfw-hq", "role": "core-switch"}},
		{ID: "dev-a", Name: "edge-a", TenantID: "t-a", Labels: map[string]string{"site": "dfw-hq", "role": "router"}},
		{ID: "core-b", Name: "core-b", TenantID: "t-b", Labels: map[string]string{"site": "dfw-hq", "role": "core-switch"}},
		{ID: "dev-b", Name: "edge-b", TenantID: "t-b", Labels: map[string]string{"site": "dfw-hq", "role": "router"}},
	} {
		if err := s.discovery.Upsert(d); err != nil {
			t.Fatal(err)
		}
	}
	// core-a's collector also reports tenant B's edge-b as a neighbour (a
	// shared segment) — the trap: it must never be offered to tenant A.
	s.topoLinks = func(context.Context) ([]collectors.LLDPNeighbor, error) {
		return []collectors.LLDPNeighbor{
			{LocalDevice: "core-a", LocalName: "core-a", LocalPort: "Ethernet1", RemSysName: "edge-a", RemPort: "Ethernet2", Proto: "lldp"},
			{LocalDevice: "core-a", LocalName: "core-a", LocalPort: "Ethernet9", RemSysName: "edge-b", RemPort: "Ethernet2", Proto: "lldp"},
			{LocalDevice: "core-b", LocalName: "core-b", LocalPort: "Ethernet1", RemSysName: "edge-b", RemPort: "Ethernet2", Proto: "lldp"},
		}, nil
	}
	s.experienceStore = experience.NewFileStore("")
	now := time.Now().UTC()
	for _, c := range []experience.ChangeEvent{
		{TenantID: "t-a", ID: "chg-a", Type: experience.ChangeConfig, App: "salesforce", Object: "dev-a", ObjectKind: "device", Summary: "a"},
		{TenantID: "t-a", ID: "chg-a2", Type: experience.ChangeConfig, App: "Payroll Portal", Object: "dev-a", ObjectKind: "device", Summary: "a2"},
		{TenantID: "t-b", ID: "chg-b", Type: experience.ChangeConfig, App: "globex-crm", Object: "dev-b", ObjectKind: "device", Summary: "b"},
	} {
		c.Provenance = experience.Provenance{Source: experience.SourceConfigDrift, Producer: "test", EventAt: now.Add(-time.Hour),
			ObservedAt: now.Add(-time.Hour), Observation: experience.ObservationObserved, DataClass: experience.DataClassCustomerMetadata}
		if _, err := s.experienceStore.RecordChange(context.Background(), c); err != nil {
			t.Fatal(err)
		}
	}
	return s, a, b
}

func resolveCall(t *testing.T, s *server, c jwtClaims, body string) (int, resolve.Result) {
	t.Helper()
	code, raw := aliasCall(t, s, c, http.MethodPost, "/api/ai/entities/resolve", body)
	var r resolve.Result
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(raw), &r); err != nil {
			t.Fatalf("decode %s: %v", raw, err)
		}
	}
	return code, r
}

func refIDs(r resolve.Result) string {
	var out []string
	for _, x := range r.Refs {
		out = append(out, x.EntityID+"@"+x.Method)
	}
	return strings.Join(out, ",")
}

func TestTopologyRungNeverCrossesTenants(t *testing.T) {
	s, a, b := rungsFixture(t)
	_, r := resolveCall(t, s, a, `{"text":"routers next to core-a"}`)
	if !r.Set || refIDs(r) != "device:dev-a@"+resolve.MethodTopology {
		t.Fatalf("tenant A's routers next to core-a = %+v — tenant B's edge-b on the same segment must not appear", r)
	}
	// Tenant B cannot anchor on tenant A's device, and an as_tenant walk
	// into A changes nothing.
	walker := b
	walker.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{"tenant B": b, "as_tenant walk": walker} {
		if _, r := resolveCall(t, s, c, `{"text":"routers next to core-a"}`); len(r.Refs) != 0 {
			t.Errorf("%s resolved tenant A's adjacency: %+v", name, r)
		}
	}
	// Tenant B's own adjacency works for tenant B only.
	if _, r := resolveCall(t, s, b, `{"text":"the router next to core-b"}`); refIDs(r) != "device:dev-b@"+resolve.MethodTopology {
		t.Fatalf("tenant B's router next to core-b = %+v", r)
	}
	if _, r := resolveCall(t, s, a, `{"text":"the router next to core-b"}`); len(r.Refs) != 0 {
		t.Fatalf("tenant A resolved tenant B's adjacency: %+v", r)
	}
}

func TestApplicationSeedsAreTheTenantsOwn(t *testing.T) {
	s, a, b := rungsFixture(t)
	if _, r := resolveCall(t, s, a, `{"text":"salesforce","types":["application"]}`); refIDs(r) != "app:salesforce@"+resolve.MethodInventoryName {
		t.Fatalf("tenant A's own application = %+v", r)
	}
	// A public synonym reaches the caller's OWN application.
	if _, r := resolveCall(t, s, a, `{"text":"SFDC","types":["application"]}`); refIDs(r) != "app:salesforce@"+resolve.MethodCatalogSynonym {
		t.Fatalf("SFDC for tenant A = %+v", r)
	}
	walker := b
	walker.ActingTenant = a.Tenant
	for name, c := range map[string]jwtClaims{"tenant B": b, "as_tenant walk": walker} {
		for _, text := range []string{"salesforce", "SFDC"} {
			if _, r := resolveCall(t, s, c, `{"text":"`+text+`","types":["application"]}`); len(r.Refs) != 0 {
				t.Errorf("%s resolved tenant A's application via %q: %+v", name, text, r)
			}
		}
	}
	if _, r := resolveCall(t, s, a, `{"text":"globex-crm","types":["application"]}`); len(r.Refs) != 0 {
		t.Fatalf("tenant A resolved tenant B's application: %+v", r)
	}
	// Visible: own → true; foreign ≡ missing → false.
	ctx := context.Background()
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	for id, want := range map[string]bool{"app:salesforce": true, "app:globex-crm": false, "app:no-such-app": false, "app:Payroll Portal": false} {
		if got, err := h.Visible(ctx, nlqast.EntityRef{Type: "application", ID: id}); err != nil || got != want {
			t.Errorf("tenant A Visible(%s) = %v %v, want %v", id, got, err, want)
		}
	}
	hb := s.nlqScopeFor(newAITestRequest(t, b), b)
	if got, _ := hb.Visible(ctx, nlqast.EntityRef{Type: "application", ID: "app:salesforce"}); got {
		t.Fatal("tenant B sees tenant A's seeded application")
	}
	// An alias makes an application visible to its own tenant only.
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"application","entity_id":"app:payroll","alias":"Payroll"}`); code != 200 {
		t.Fatalf("alias: %d %s", code, body)
	}
	if got, _ := h.Visible(ctx, nlqast.EntityRef{Type: "application", ID: "app:payroll"}); !got {
		t.Fatal("an aliased application must be visible to its tenant")
	}
	if got, _ := hb.Visible(ctx, nlqast.EntityRef{Type: "application", ID: "app:payroll"}); got {
		t.Fatal("tenant B sees tenant A's aliased application")
	}
}

func TestProviderSeedsAreNamedButRefusedUntilMapped(t *testing.T) {
	s, a, b := rungsFixture(t)
	for _, c := range []jwtClaims{a, b} {
		if _, r := resolveCall(t, s, c, `{"text":"CenturyLink"}`); refIDs(r) != "provider:lumen@"+resolve.MethodCatalogSeed {
			t.Fatalf("a public carrier seed must resolve for every tenant: %+v", r)
		}
	}
	ctx := context.Background()
	h := s.nlqScopeFor(newAITestRequest(t, a), a)
	if got, _ := h.Visible(ctx, nlqast.EntityRef{Type: "provider", ID: "provider:lumen"}); !got {
		t.Fatal("a catalog seed must be visible")
	}
	if got, _ := h.Visible(ctx, nlqast.EntityRef{Type: "provider", ID: "provider:acme-private-isp"}); got {
		t.Fatal("an unseeded, unaliased provider must not be visible")
	}
	// Named, but no circuit is attributed to it: refused precisely, never
	// answered as "nothing wrong with this carrier".
	q := &nlqast.AST{V: 1, Type: nlqast.MetricSeries, Target: "device", Metric: "cpu_util_pct",
		Refs: []nlqast.EntityRef{{Type: "provider", ID: "provider:lumen"}}, Time: nlqast.TimeRange{Kind: nlqast.TimeRelative, Last: "1h"}}
	_, vr := validate.Validate(ctx, s.nlqCatalog, h, q)
	found := false
	for _, e := range vr.Errors {
		found = found || e.Code == validate.CodeUnmappedProvider
	}
	if vr.Valid || !found {
		t.Fatalf("a named but unmapped provider must be unmapped_provider: %+v", vr)
	}
	// A provider aliased by tenant A is A's alone.
	if code, body := aliasCall(t, s, a, http.MethodPut, "/api/ai/aliases", `{"entity_type":"provider","entity_id":"provider:acme-isp","alias":"Acme Fiber"}`); code != 200 {
		t.Fatalf("alias: %d %s", code, body)
	}
	hb := s.nlqScopeFor(newAITestRequest(t, b), b)
	if got, _ := hb.Visible(ctx, nlqast.EntityRef{Type: "provider", ID: "provider:acme-isp"}); got {
		t.Fatal("tenant B sees tenant A's aliased provider")
	}
	if _, r := resolveCall(t, s, b, `{"text":"Acme Fiber"}`); len(r.Refs) != 0 {
		t.Fatalf("tenant B resolved tenant A's provider alias: %+v", r)
	}
}

func TestModelSuggestionWithoutAModelIsSaid(t *testing.T) {
	s, a, _ := rungsFixture(t)
	t.Setenv("IRIS_NLQ_MODEL_FALLBACK", "false")
	code, r := resolveCall(t, s, a, `{"text":"dalas","suggest":true}`)
	if code != 200 || len(r.Refs) != 0 || r.SuggestionError != resolve.SuggestionUnavailable {
		t.Fatalf("suggest with no model = %d %+v", code, r)
	}
	// Not asked: no model rung at all.
	if _, r := resolveCall(t, s, a, `{"text":"dalas"}`); r.SuggestionError != "" || len(r.Refs) != 0 {
		t.Fatalf("no suggest = %+v", r)
	}
	// A deterministic match never consults the model.
	if _, r := resolveCall(t, s, a, `{"text":"edge-a","suggest":true}`); r.SuggestionError != "" || refIDs(r) != "device:dev-a@"+resolve.MethodInventoryName {
		t.Fatalf("deterministic + suggest = %+v", r)
	}
	if code, _ := resolveCall(t, s, a, `{"text":"dalas","suggest":"yes"}`); code != http.StatusBadRequest {
		t.Fatalf("a non-boolean suggest must be refused, got %d", code)
	}
}
