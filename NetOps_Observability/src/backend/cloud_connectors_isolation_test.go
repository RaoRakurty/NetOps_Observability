package backend

import (
	"encoding/json"
	"testing"

	"netops/backend/cloudconn"
)

// cloud_connectors_isolation_test.go — the MANDATED two-tenant negative tests for
// the Cloud Connector framework (CLAUDE.md §3a step 5 + spec §26). Two tenants
// build connectors with the SAME provider account display name, SAME role name,
// SAME client id and SAME capability pack. We assert, through the REAL router +
// auth middleware, that cross-tenant read / delete / update / secret-ref / audit
// access all FAIL CLOSED, that ExternalIds are unique + unpredictable, and that
// an `as_tenant` override can never widen a non-owner's view.

type ccnFixture struct {
	orgID, tenantID, user, token string
	connID, externalID           string
}

func TestCloudConnectorCrossTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	// The shared harness doesn't wire the connector store/broker; the handlers
	// read them at request time, so setting them on the live *server is enough.
	s.cloudConn = cloudconn.NewMemStore()
	s.cloudBroker = cloudconn.NewIdentityBroker(s.cloudConn, s.vault, func(event, tenant, connectorID, provider, decision, detail string) {
		if s.audit != nil {
			s.audit.Record(AuditEvent{Actor: "broker", Tenant: tenant, Method: event,
				Path: "/cloudconn/broker/" + connectorID, Status: 200, Decision: decision,
				Detail: map[string]any{"event": event, "connector": connectorID, "provider": provider, "info": detail}})
		}
	})

	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Two tenants A and B, each with a tenant-scoped operator.
	fix := map[string]*ccnFixture{}
	for _, name := range []string{"A", "B"} {
		st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
		if st != 201 {
			t.Fatalf("create org %s: %d %s", name, st, b)
		}
		orgID := idOf(t, b)
		st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
		if st != 201 {
			t.Fatalf("create tenant %s: %d %s", name, st, b)
		}
		tid := idOf(t, b)
		user := "op-" + name
		st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": user, "password": "Passw0rd!2345", "role": "operator", "tenant_id": tid,
		})
		if st != 201 {
			t.Fatalf("create user %s: %d %s", name, st, b)
		}
		fix[name] = &ccnFixture{orgID: orgID, tenantID: tid, user: user, token: login(t, srv, user, "Passw0rd!2345").Token}
	}

	// Each tenant builds an AWS connector with IDENTICAL display name, role ARN,
	// capability pack — a collision the framework must keep tenant-isolated.
	const sameRole = "arn:aws:iam::123456789012:role/correlix-observer"
	for _, name := range []string{"A", "B"} {
		f := fix[name]
		st, b := do(t, srv, "POST", "/api/cloud/connectors", f.token, map[string]any{
			"provider": "aws", "display_name": "Prod Account",
		})
		if st != 201 {
			t.Fatalf("%s create connector: %d %s", name, st, b)
		}
		var v cloudconn.ConnectorView
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode connector: %v", err)
		}
		f.connID = v.ID
		// select auth → same role ARN for both tenants
		st, b = do(t, srv, "POST", "/api/cloud/connectors/"+f.connID+"/auth", f.token, map[string]any{
			"method": "cloud_role", "role_arn": sameRole,
		})
		if st != 200 {
			t.Fatalf("%s select auth: %d %s", name, st, b)
		}
		if err := json.Unmarshal(b, &v); err != nil {
			t.Fatalf("decode auth: %v", err)
		}
		f.externalID = v.Identity.ExternalID
		if f.externalID == "" || !cloudconn.ValidExternalID(f.externalID) {
			t.Fatalf("%s connector missing/weak ExternalId: %q", name, f.externalID)
		}
	}

	a, b := fix["A"], fix["B"]

	// (1) ExternalId uniqueness across tenants despite identical role/name/pack.
	if a.externalID == b.externalID {
		t.Fatal("ExternalId collided across tenants — confused-deputy protection broken")
	}

	// (2) Own-only list: each operator sees exactly its own connector.
	for _, name := range []string{"A", "B"} {
		f := fix[name]
		st, body := do(t, srv, "GET", "/api/cloud/connectors", f.token, nil)
		if st != 200 {
			t.Fatalf("%s list: %d %s", name, st, body)
		}
		var r struct {
			Connectors []cloudconn.ConnectorView `json:"connectors"`
		}
		if err := json.Unmarshal(body, &r); err != nil {
			t.Fatalf("decode list: %v", err)
		}
		if len(r.Connectors) != 1 || r.Connectors[0].ID != f.connID {
			t.Fatalf("%s must see ONLY its own connector, got %d", name, len(r.Connectors))
		}
	}

	// (3) Cross-tenant GET by id → 404 (never reveal another tenant's connector).
	if st, _ := do(t, srv, "GET", "/api/cloud/connectors/"+b.connID, a.token, nil); st != 404 {
		t.Fatalf("cross-tenant GET must be 404, got %d", st)
	}

	// (4) Cross-tenant DELETE → 404 and B's connector survives.
	if st, _ := do(t, srv, "DELETE", "/api/cloud/connectors/"+b.connID, a.token, nil); st != 404 {
		t.Fatalf("cross-tenant DELETE must be 404, got %d", st)
	}
	if st, _ := do(t, srv, "GET", "/api/cloud/connectors/"+b.connID, b.token, nil); st != 200 {
		t.Fatalf("B's connector must survive A's delete attempt, got %d", st)
	}

	// (5) Cross-tenant mutation (select auth / scopes) → 404, no hijack.
	if st, _ := do(t, srv, "POST", "/api/cloud/connectors/"+b.connID+"/auth", a.token, map[string]any{"method": "static_key"}); st != 404 {
		t.Fatalf("cross-tenant auth mutation must be 404, got %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/cloud/connectors/"+b.connID+"/scopes", a.token,
		map[string]any{"scopes": []map[string]any{{"type": "account", "ref": "123"}}}); st != 404 {
		t.Fatalf("cross-tenant scope mutation must be 404, got %d", st)
	}

	// (6) as_tenant override cannot widen a non-owner's view.
	st, body := do(t, srv, "GET", "/api/cloud/connectors?as_tenant="+b.tenantID, a.token, nil)
	if st != 200 {
		t.Fatalf("list with as_tenant: %d %s", st, body)
	}
	var widened struct {
		Connectors []cloudconn.ConnectorView `json:"connectors"`
	}
	_ = json.Unmarshal(body, &widened)
	if len(widened.Connectors) != 1 || widened.Connectors[0].ID != a.connID {
		t.Fatal("as_tenant override widened a non-owner's connector view — must be ignored")
	}

	// (7) Cross-tenant secret-ref access fails closed at the store/broker layer.
	//     Store a legacy secret on B (switch B to static_key first).
	if st, bb := do(t, srv, "POST", "/api/cloud/connectors/"+b.connID+"/auth", b.token, map[string]any{"method": "static_key"}); st != 200 {
		t.Fatalf("B switch to static_key: %d %s", st, bb)
	}
	ref, err := s.cloudBroker.StoreSecret(t.Context(), b.tenantID, b.connID, cloudconn.ProviderAWS, "aws_secret_access_key", "AKIAB", "s3cr3t-B")
	if err != nil {
		t.Fatalf("store B secret: %v", err)
	}
	// Tenant A must not resolve B's secret ref.
	if _, found, _ := s.cloudConn.GetSecretRef(t.Context(), a.tenantID, false, ref); found {
		t.Fatal("tenant A resolved tenant B's secret reference — cross-tenant secret leak")
	}
	// Owner (cross) can see it exists (platform scope), proving the ref is real.
	if _, found, _ := s.cloudConn.GetSecretRef(t.Context(), "", true, ref); !found {
		t.Fatal("platform owner should see the secret ref exists")
	}

	// (8) EXCHANGE PATH isolation: with both connectors forced collectable and a
	//     fake provider, tenant A can neither mint a token for B's connector nor
	//     ever be served B's cached credential.
	fakeEx := &fakeAdapter{provider: cloudconn.ProviderAWS}
	s.cloudBroker.SetAdapter(func(cloudconn.Provider) cloudconn.CloudIdentityProvider { return fakeEx })
	for _, f := range []*ccnFixture{a, b} {
		c, found, err := s.cloudConn.Get(t.Context(), f.tenantID, false, f.connID)
		if err != nil || !found {
			t.Fatalf("reload %s: found=%v err=%v", f.connID, found, err)
		}
		c.State = cloudconn.StateActive
		// (7) switched B to static_key; force both back onto the secretless role
		// path for the exchange assertions.
		c.AuthMethod = cloudconn.AuthMethodCloudRole
		c.Identity.Method = cloudconn.AuthMethodCloudRole
		if _, _, err := s.cloudConn.Update(t.Context(), c, 0); err != nil {
			t.Fatal(err)
		}
	}
	// B warms the cache first.
	tokB, err := s.cloudBroker.TokenFor(t.Context(), cloudconn.ScopedTokenRequest{Tenant: b.tenantID, ConnectorID: b.connID, ProviderAccount: "123456789012"})
	if err != nil {
		t.Fatalf("B mint: %v", err)
	}
	// A asking for B's connector id fails closed (404-equivalent, no mint).
	if _, err := s.cloudBroker.TokenFor(t.Context(), cloudconn.ScopedTokenRequest{Tenant: a.tenantID, ConnectorID: b.connID, ProviderAccount: "123456789012"}); err == nil {
		t.Fatal("tenant A minted a token for tenant B's connector — cross-tenant exchange leak")
	}
	// A's own otherwise-identical request gets A's OWN credential, never B's.
	tokA, err := s.cloudBroker.TokenFor(t.Context(), cloudconn.ScopedTokenRequest{Tenant: a.tenantID, ConnectorID: a.connID, ProviderAccount: "123456789012"})
	if err != nil {
		t.Fatalf("A mint: %v", err)
	}
	if tokA.Value == tokB.Value {
		t.Fatal("tenant A received tenant B's cached credential — cross-tenant cache leak")
	}

	// (9) Cross-tenant AUDIT access fails closed: A's audit view excludes B's
	//     connector events (and vice-versa).
	aEvents := auditList(t, s, a.tenantID, false, auditQuery{Limit: 500})
	for _, e := range aEvents {
		if detailConnector(e) == b.connID {
			t.Fatal("tenant A audit view contains tenant B's connector event — cross-tenant audit leak")
		}
	}
	bEvents := auditList(t, s, b.tenantID, false, auditQuery{Limit: 500})
	sawB := false
	for _, e := range bEvents {
		if detailConnector(e) == b.connID {
			sawB = true
		}
		if detailConnector(e) == a.connID {
			t.Fatal("tenant B audit view contains tenant A's connector event — cross-tenant audit leak")
		}
	}
	if !sawB {
		t.Fatal("tenant B audit view is missing its own connector events")
	}
}

func detailConnector(e AuditEvent) string {
	if e.Detail == nil {
		return ""
	}
	if v, ok := e.Detail["connector"].(string); ok {
		return v
	}
	return ""
}
