package main

// cloud_ingest_service_test.go — Wave 1 #2 per-tenant ingestion: the poller-
// facing ingest-service surface. Includes the MANDATED cross-tenant isolation
// coverage (CLAUDE.md §3a.5, org_isolation_test.go template): the connector
// list / credentials / inventory endpoints must NEVER be reachable with a
// tenant-bound credential, and the tenant stamped onto ingested data comes
// from the CONNECTOR ROW, never from the poller's payload.

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/cloud"
	"netops/backend/cloudconn"
)

// newIngestTestServer wires the connector store, a fake-adapter broker, the
// cloud inventory store and the ingest snapshot registry onto the shared test
// harness (the handlers read them at request time).
func newIngestTestServer(t *testing.T) (srv *httptest.Server, s *server, fake *fakeAdapter) {
	t.Helper()
	hs, st := newTestServerState(t)
	st.cloudConn = newMemCloudConnStore()
	fake = &fakeAdapter{provider: cloudconn.ProviderAWS}
	st.cloudBroker = newCloudIdentityBroker(st.cloudConn, nil, nil)
	st.cloudBroker.adapter = func(cloudconn.Provider) cloudconn.CloudIdentityProvider { return fake }
	st.cloud = &memCloudStore{
		res:   map[string][]cloud.CloudResource{},
		maps:  map[string][]cloud.CloudIdentityMapping{},
		conns: map[string][]cloud.ConnectorInfo{},
	}
	st.cloudIngestInv = newCloudIngestInventory()
	return hs, st, fake
}

// mintIngestKey creates an API key via the REAL /api/apikeys surface. tenantID
// "" = platform realm (what the poller must use); non-empty = tenant-bound.
func mintIngestKey(t *testing.T, srv *httptest.Server, admin, tenantID string, scopes []string) string {
	t.Helper()
	stCode, body := do(t, srv, "POST", "/api/apikeys", admin, map[string]any{
		"label": "cloud-ingest-poller", "tenant_id": tenantID, "scopes": scopes,
	})
	if stCode != 201 {
		t.Fatalf("create api key: %d %s", stCode, body)
	}
	var out struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(body, &out); err != nil || out.Secret == "" {
		t.Fatalf("api key secret missing: %v %s", err, body)
	}
	return out.Secret
}

func mkIngestTenant(t *testing.T, srv *httptest.Server, admin, name string) string {
	t.Helper()
	stCode, body := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + name})
	if stCode != 201 {
		t.Fatalf("create org: %d %s", stCode, body)
	}
	orgID := idOf(t, body)
	stCode, body = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + name, "org_id": orgID})
	if stCode != 201 {
		t.Fatalf("create tenant: %d %s", stCode, body)
	}
	return idOf(t, body)
}

func TestCloudIngestServiceAuthFailsClosed(t *testing.T) {
	srv, s, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/x")

	// No credential → 401 (middleware).
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors", "", nil); st != 401 {
		t.Fatalf("unauthenticated must be 401, got %d", st)
	}
	// A tenant-bound key WITH the ingest scope must still fail closed: the
	// surface enumerates every tenant's connectors, so only the platform realm
	// may hold the credential (§3a.3 — a tenant admin's key is never enough).
	tenantKey := mintIngestKey(t, srv, admin, tidA, []string{cloudIngestScope})
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors", tenantKey, nil); st != 403 {
		t.Fatalf("tenant-bound ingest key must be 403, got %d", st)
	}
	// A tenant-scoped human (even an admin-role one) fails closed too.
	if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "op-a", "password": "Passw0rd!2345", "role": "admin", "tenant_id": tidA,
	}); st != 201 {
		t.Fatalf("create tenant admin failed: %d", st)
	}
	opTok := login(t, srv, "op-a", "Passw0rd!2345").Token
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors", opTok, nil); st != 403 {
		t.Fatalf("tenant admin must be 403, got %d", st)
	}
	// A platform-realm key WITHOUT the scope fails closed.
	noScope := mintIngestKey(t, srv, admin, "", []string{"read:metrics"})
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors", noScope, nil); st != 403 {
		t.Fatalf("platform key without ingest scope must be 403, got %d", st)
	}
	// The real service credential: platform realm + ingest:cloud → 200.
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})
	if st, body := do(t, srv, "GET", "/api/cloud/ingest/connectors", svcKey, nil); st != 200 {
		t.Fatalf("platform ingest key must be 200, got %d %s", st, body)
	}
	// as_tenant can never WIDEN: a tenant-bound key aiming at the global realm
	// keeps its own tenant (override ignored) and stays locked out.
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors?as_tenant=global", tenantKey, nil); st != 403 {
		t.Fatalf("tenant key with as_tenant=global must stay 403, got %d", st)
	}
	// For the platform service key the override is ignored for machine
	// principals (no binding reaches the target), so the surface still serves —
	// and it serves the same platform-wide view, nothing tenant-elevated.
	if st, _ := do(t, srv, "GET", "/api/cloud/ingest/connectors?as_tenant="+tidA, svcKey, nil); st != 200 {
		t.Fatalf("service key with ignored as_tenant must remain 200, got %d", st)
	}
}

func TestCloudIngestConnectorListCrossTenantAndSecretFree(t *testing.T) {
	srv, s, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	tidB := mkIngestTenant(t, srv, admin, "B")
	ca := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::123456789012:role/correlix-observer")
	cb := mkActiveConnector(t, s.cloudConn, tidB, "arn:aws:iam::123456789012:role/correlix-observer")
	// A draft connector is NOT pollable and must not be listed.
	draft := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/draft")
	draft.State = cloudconn.StateDraft
	if _, _, err := s.cloudConn.Update(context.Background(), draft, 0); err != nil {
		t.Fatal(err)
	}

	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})
	st, body := do(t, srv, "GET", "/api/cloud/ingest/connectors", svcKey, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, body)
	}
	var out struct {
		Connectors []ingestConnectorView `json:"connectors"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Connectors) != 2 {
		t.Fatalf("expected the 2 ACTIVE connectors, got %d", len(out.Connectors))
	}
	byID := map[string]ingestConnectorView{}
	for _, v := range out.Connectors {
		byID[v.ID] = v
	}
	if byID[ca.ConnectorID].Tenant != tidA || byID[cb.ConnectorID].Tenant != tidB {
		t.Fatalf("connector tenants not derived from rows: %+v", byID)
	}
	// The list is a polling plan, not a trust dump: no identity metadata, no
	// secrets, no external ids may appear in the wire body.
	for _, needle := range []string{"role_arn", "external_id", "client_id", "secret", "ciphertext"} {
		if strings.Contains(string(body), needle) {
			t.Fatalf("connector list leaks %q: %s", needle, body)
		}
	}
}

func TestCloudIngestCredentialsServerDerivedTenant(t *testing.T) {
	srv, s, fake := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	ca := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/x")
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	st, body := do(t, srv, "POST", "/api/cloud/ingest/connectors/"+ca.ConnectorID+"/credentials", svcKey,
		map[string]any{"tenant": "tenant-evil"}) // unknown fields are ignored; tenant is NEVER accepted
	if st != 200 {
		t.Fatalf("credentials: %d %s", st, body)
	}
	var resp ingestCredentialsResp
	if err := json.Unmarshal(body, &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Tenant != tidA {
		t.Fatalf("credential tenant must come from the connector row (%s), got %q", tidA, resp.Tenant)
	}
	if resp.Token == "" && resp.AWSAccessKeyID == "" {
		t.Fatal("no credential material returned")
	}
	if !resp.Expiry.After(time.Now()) {
		t.Fatalf("credential must be short-lived but future-dated, got %v", resp.Expiry)
	}
	if fake.issued != 1 {
		t.Fatalf("expected exactly one exchange, got %d", fake.issued)
	}

	// Unknown connector id → 404 (no existence oracle beyond the id namespace).
	if st, _ := do(t, srv, "POST", "/api/cloud/ingest/connectors/ccn_doesnotexist/credentials", svcKey, nil); st != 404 {
		t.Fatalf("unknown connector must be 404, got %d", st)
	}
	// A disabled connector fails closed with 409 (and no exchange happens).
	ca.State = cloudconn.StateDisabled
	if _, _, err := s.cloudConn.Update(context.Background(), ca, 0); err != nil {
		t.Fatal(err)
	}
	before := fake.issued
	if st, _ := do(t, srv, "POST", "/api/cloud/ingest/connectors/"+ca.ConnectorID+"/credentials", svcKey, nil); st != 409 {
		t.Fatalf("disabled connector must be 409, got %d", st)
	}
	if fake.issued != before {
		t.Fatal("no token may be minted for a disabled connector")
	}
}

func TestCloudIngestInventoryTenantStampedFromConnectorRow(t *testing.T) {
	srv, s, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	tidB := mkIngestTenant(t, srv, admin, "B")
	ca := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/a")
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	// The payload LIES about its tenant — the row's tenant must win.
	doc := map[string]any{
		"provider": "aws", "account_id": "111111111111",
		"collection": map[string]any{"mode": "live_poller", "collected_at": time.Now().UTC()},
		"resources": []map[string]any{{
			"tenant_id": tidB, // hostile/buggy stamp — MUST be ignored
			"region":    "us-west-2", "resource_id": "i-0abc", "resource_type": "ec2:instance",
			"resource_name": "web-1", "private_ips": []string{"10.0.0.5"},
			"tags": map[string]string{"app": "shop"}, "source": "cloud_api", "confidence": "confirmed",
		}},
	}
	st, body := do(t, srv, "PUT", "/api/cloud/ingest/connectors/"+ca.ConnectorID+"/inventory", svcKey, doc)
	if st != 200 {
		t.Fatalf("inventory put: %d %s", st, body)
	}
	resA, err := s.cloud.ListResources(context.Background(), tidA, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resA) != 1 || resA[0].TenantID != normTenant(tidA) || resA[0].ResourceID != "i-0abc" {
		t.Fatalf("resource must land under the CONNECTOR's tenant %s: %+v", tidA, resA)
	}
	resB, err := s.cloud.ListResources(context.Background(), tidB, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(resB) != 0 {
		t.Fatalf("payload-claimed tenant %s must receive NOTHING, got %+v", tidB, resB)
	}

	// Provider mismatch is refused: an aws connector can never write azure rows.
	doc["provider"] = "azure"
	if st, _ := do(t, srv, "PUT", "/api/cloud/ingest/connectors/"+ca.ConnectorID+"/inventory", svcKey, doc); st != 400 {
		t.Fatalf("provider mismatch must be 400, got %d", st)
	}

	// Telemetry health flipped to healthy (measured proof of flow).
	got, found, err := s.cloudConn.Get(context.Background(), tidA, false, ca.ConnectorID)
	if err != nil || !found {
		t.Fatalf("reload connector: %v %v", found, err)
	}
	if got.TelemetryHealth.State != "healthy" {
		t.Fatalf("telemetry health must be healthy after ingest, got %q", got.TelemetryHealth.State)
	}
}

// TestCloudIngestInventoryMultiConnectorMerge: two connectors in ONE tenant —
// one connector's PUT must never clobber its sibling's resources, and a
// re-PUT replaces only its own slice.
func TestCloudIngestInventoryMultiConnectorMerge(t *testing.T) {
	srv, s, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	c1 := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/one")
	c2 := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::2:role/two")
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	put := func(connID, rid string) {
		t.Helper()
		doc := map[string]any{
			"provider": "aws", "account_id": "1",
			"resources": []map[string]any{{
				"region": "us-west-2", "resource_id": rid, "resource_type": "ec2:instance",
			}},
		}
		if st, body := do(t, srv, "PUT", "/api/cloud/ingest/connectors/"+connID+"/inventory", svcKey, doc); st != 200 {
			t.Fatalf("put %s: %d %s", connID, st, body)
		}
	}
	put(c1.ConnectorID, "i-one")
	put(c2.ConnectorID, "i-two")
	res, err := s.cloud.ListResources(context.Background(), tidA, false)
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]bool{}
	for _, r := range res {
		ids[r.ResourceID] = true
	}
	if !ids["i-one"] || !ids["i-two"] || len(res) != 2 {
		t.Fatalf("both connectors' resources must coexist, got %+v", ids)
	}
	// Re-PUT of connector 1 replaces ONLY its slice.
	put(c1.ConnectorID, "i-one-v2")
	res, _ = s.cloud.ListResources(context.Background(), tidA, false)
	ids = map[string]bool{}
	for _, r := range res {
		ids[r.ResourceID] = true
	}
	if !ids["i-one-v2"] || !ids["i-two"] || ids["i-one"] || len(res) != 2 {
		t.Fatalf("re-PUT must replace only its own connector's slice, got %+v", ids)
	}
}
