// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"netops/backend/internal/sealedfields"
	"netops/backend/processors"
	"netops/backend/sealing"
)

// TestRouterConfigSecretScopesAreServable is the round trip the edge-key
// tenant guard (7f4f40f1) broke: every SECRET[cxseal.X]/SECRET[cxmac.X] the
// generated router config references is fetched by the router's secret backend
// as `edge-keys?tenant=X`; if the REAL server-side scope resolver refuses any
// of them, Vector refuses the whole config (exit 78) and the log pipeline is
// down. The quarantine scope is not a tenant, so a "real tenants only" guard
// 404s it — this test pins that the wired resolver serves every referenced
// scope, using the production closure rather than an injected predicate.
func TestRouterConfigSecretScopesAreServable(t *testing.T) {
	ts, s, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	tenantID := createTenantFor(t, ts, admin, "acme")

	out, err := processors.GenerateRouterConfig([]processors.Rule{{
		ID: "p-1", TenantID: tenantID, Lane: "applogs", Type: processors.TypeSeal,
		Enabled: true, Field: "card", DataType: "card", Order: 10,
	}})
	if err != nil {
		t.Fatalf("GenerateRouterConfig: %v", err)
	}
	re := regexp.MustCompile(`SECRET\[(` + sealing.EdgeSealBackend + `|` + sealing.EdgeMACBackend + `)\.([^\]]+)\]`)
	scopes := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(out, -1) {
		scopes[m[2]] = true
	}
	if !scopes[processors.QuarantineScope] {
		t.Fatalf("generated config no longer references the quarantine scope; scopes=%v", scopes)
	}
	if !scopes[tenantID] {
		t.Fatalf("generated config does not reference the tenant's own scope %q; scopes=%v", tenantID, scopes)
	}

	t.Setenv("INGEST_TOKEN", "tok")
	h := sealedfields.EdgeKeyHandler(
		func() sealing.CryptoProvider { return s.sealProvider },
		s.sealingEdgeCaller, s.edgeKeyScopeResolver(), nil)
	for scope := range scopes {
		req := httptest.NewRequest(http.MethodGet, sealedfields.EdgeKeyPath+"?tenant="+scope, nil)
		req.SetBasicAuth("netops-ingest", "tok")
		rec := httptest.NewRecorder()
		h(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("scope %q referenced by the router config is refused by the edge-key endpoint: %d %s — Vector would refuse the config",
				scope, rec.Code, rec.Body.String())
		}
	}
}

// TestEdgeKeyScopeResolverCanonicalisesAndBounds pins the resolver's contract:
// reserved engine scopes pass verbatim; a real tenant resolves to its canonical
// ID from ANY spelling (id, slug, case, whitespace) so custody holds one DEK per
// tenant; everything else is refused.
func TestEdgeKeyScopeResolverCanonicalisesAndBounds(t *testing.T) {
	ts, s, _ := sealTestServer(t)
	admin := login(t, ts, "admin", "Passw0rd!2345").Token
	tenantID := createTenantFor(t, ts, admin, "acme")
	tn, ok := s.tenants.Resolve(tenantID)
	if !ok {
		t.Fatalf("tenant %q must resolve", tenantID)
	}
	resolve := s.edgeKeyScopeResolver()

	if got, ok := resolve(processors.QuarantineScope); !ok || got != processors.QuarantineScope {
		t.Fatalf("reserved scope: got (%q,%v), want (%q,true)", got, ok, processors.QuarantineScope)
	}
	for _, spelling := range []string{tenantID, strings.ToUpper(tenantID), " " + tenantID + " ", tn.Slug, strings.ToUpper(tn.Slug)} {
		got, ok := resolve(spelling)
		if !ok || got != tenantID {
			t.Errorf("spelling %q: got (%q,%v), want (%q,true)", spelling, got, ok, tenantID)
		}
	}
	for _, bad := range []string{"", "made-up", "Quarantine", "t_ffffffffffffffffffffffffffffffff"} {
		if got, ok := resolve(bad); ok {
			t.Errorf("%q must be refused, resolved to %q", bad, got)
		}
	}
}
