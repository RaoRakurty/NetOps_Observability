package backend

// cloud_source_status_test.go — Wave 2 #4: poller-reported permission_denied /
// misconfigured source states. Covers the store semantics (full-set replace,
// first-failure preservation, expiry), the platform-only gate (§3a.3), the
// connector-row owner stamping (§3a.2), and the MANDATED cross-tenant isolation
// (§3a.5): tenant A's IAM-failure details must never reach tenant B through
// GET /api/cloud/ingestion.

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ── store unit tests ──────────────────────────────────────────────────────────

func TestSourceStatusStoreSincePreservedAcrossReplace(t *testing.T) {
	st := newCloudSourceStatusStore()
	day1 := time.Date(2026, 7, 14, 9, 0, 0, 0, time.UTC)
	day2 := day1.Add(24 * time.Hour)
	rec := cloudSourceStatusRecord{
		Tenant: "t_a", Provider: "aws", AccountID: "1", Region: "us-west-2",
		SourceType: "flow_logs", Status: "permission_denied", Since: day1,
	}
	st.Replace([]cloudSourceStatusRecord{rec}, day1)
	// The poller re-reports the SAME failure a day later with a fresh since —
	// the stored first-failure time must not move forward.
	rec.Since = day2
	st.Replace([]cloudSourceStatusRecord{rec}, day2)
	got := st.ForTenant("t_a", false, day2)
	if len(got) != 1 || !got[0].Since.Equal(day1) {
		t.Fatalf("first-failure time must be preserved (want %v): %+v", day1, got)
	}
	// Full-set replace: a lane that recovered stops being reported → gone.
	st.Replace(nil, day2)
	if got := st.ForTenant("t_a", false, day2); len(got) != 0 {
		t.Fatalf("cleared set must be empty, got %+v", got)
	}
}

func TestSourceStatusStoreExpiryAndTenantScope(t *testing.T) {
	st := newCloudSourceStatusStore()
	now := time.Date(2026, 7, 16, 12, 0, 0, 0, time.UTC)
	st.Replace([]cloudSourceStatusRecord{
		{Tenant: "t_a", Provider: "aws", SourceType: "flow_logs", Status: "permission_denied"},
		{Tenant: "t_b", Provider: "gcp", SourceType: "metrics", Status: "misconfigured"},
	}, now)
	// Default-closed: a non-cross caller only sees its own tenant.
	if got := st.ForTenant("t_a", false, now); len(got) != 1 || got[0].Tenant != "t_a" {
		t.Fatalf("tenant scope leak: %+v", got)
	}
	if got := st.ForTenant("", true, now); len(got) != 2 {
		t.Fatalf("cross caller sees all: %+v", got)
	}
	// A record not refreshed within the stale horizon expires on read: the
	// poller that observed it is gone, and unknown must not read as broken.
	late := now.Add(ingestStaleWindow + time.Minute)
	if got := st.ForTenant("t_a", false, late); len(got) != 0 {
		t.Fatalf("stale record must expire, got %+v", got)
	}
}

// ── overlay unit test ─────────────────────────────────────────────────────────

func TestOverlaySourceStatusPrecedenceAndProviderMatch(t *testing.T) {
	rows := []cloudSourceStatus{
		{SourceType: "flow_logs", Status: "flowing", Volume: 10, Capability: "available"},
		{SourceType: "metrics", Status: "off", Capability: "available"},
	}
	since := time.Date(2026, 7, 14, 8, 0, 0, 0, time.UTC)
	recs := []cloudSourceStatusRecord{
		{Tenant: "t", Provider: "aws", SourceType: "flow_logs", Status: "misconfigured", Detail: "bucket missing", Since: since},
		{Tenant: "t", Provider: "aws", AccountID: "2", SourceType: "flow_logs", Status: "permission_denied", Detail: "IAM denied s3:GetObject", Since: since},
		{Tenant: "t", Provider: "azure", SourceType: "metrics", Status: "permission_denied", Detail: "role missing", Since: since},
	}
	// Provider row: only ITS records apply; permission_denied outranks
	// misconfigured when both hit one source. Measured volume is kept.
	got := overlaySourceStatus(append([]cloudSourceStatus{}, rows...), recs, "aws")
	if got[0].Status != "permission_denied" || got[0].Detail != "IAM denied s3:GetObject" {
		t.Fatalf("aws flow_logs must be permission_denied w/ detail: %+v", got[0])
	}
	if got[0].Volume != 10 || got[0].SinceISO == "" {
		t.Fatalf("volume kept + since stamped: %+v", got[0])
	}
	if got[1].Status != "off" {
		t.Fatalf("azure record must not touch the aws metrics row: %+v", got[1])
	}
	// Global row ("" provider): any of the tenant's providers apply.
	got = overlaySourceStatus(append([]cloudSourceStatus{}, rows...), recs, "")
	if got[1].Status != "permission_denied" || got[1].Detail != "role missing" {
		t.Fatalf("global metrics row must carry the azure denial: %+v", got[1])
	}
}

// ── handler + isolation tests (real HTTP surface) ────────────────────────────

func putSourceStatus(t *testing.T, srv *httptest.Server, key string, records []map[string]any) (int, []byte) {
	t.Helper()
	return do(t, srv, "PUT", "/api/cloud/ingest/source-status", key, map[string]any{"records": records})
}

func TestSourceStatusAuthFailsClosed(t *testing.T) {
	srv, _, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")

	rec := []map[string]any{{
		"provider": "aws", "source_type": "flow_logs", "status": "permission_denied",
	}}
	if st, _ := putSourceStatus(t, srv, "", rec); st != 401 {
		t.Fatalf("unauthenticated must be 401, got %d", st)
	}
	tenantKey := mintIngestKey(t, srv, admin, tidA, []string{cloudIngestScope})
	if st, _ := putSourceStatus(t, srv, tenantKey, rec); st != 403 {
		t.Fatalf("tenant-bound key must be 403, got %d", st)
	}
	noScope := mintIngestKey(t, srv, admin, "", []string{"read:metrics"})
	if st, _ := putSourceStatus(t, srv, noScope, rec); st != 403 {
		t.Fatalf("platform key without scope must be 403, got %d", st)
	}
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})
	if st, body := putSourceStatus(t, srv, svcKey, rec); st != 200 {
		t.Fatalf("service key must be 200, got %d %s", st, body)
	}
}

func TestSourceStatusValidation(t *testing.T) {
	srv, _, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	// A poller may only report WHY a lane fails — never that it is healthy.
	if st, _ := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"provider": "aws", "source_type": "flow_logs", "status": "flowing",
	}}); st != 400 {
		t.Fatalf("poller-claimed 'flowing' must be 400, got %d", st)
	}
	if st, _ := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"provider": "aws", "source_type": "not_a_source", "status": "permission_denied",
	}}); st != 400 {
		t.Fatalf("unknown source_type must be 400, got %d", st)
	}
	if st, _ := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"source_type": "flow_logs", "status": "permission_denied",
	}}); st != 400 {
		t.Fatalf("missing provider must be 400, got %d", st)
	}
	big := make([]map[string]any, srcStatusRecordsMax+1)
	for i := range big {
		big[i] = map[string]any{"provider": "aws", "source_type": "flow_logs",
			"status": "permission_denied", "account_id": fmt.Sprintf("%d", i)}
	}
	if st, _ := putSourceStatus(t, srv, svcKey, big); st != 413 {
		t.Fatalf("record cap must be 413, got %d", st)
	}
}

func TestSourceStatusConnectorRowStampsOwner(t *testing.T) {
	srv, s, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	tidB := mkIngestTenant(t, srv, admin, "B")
	ca := mkActiveConnector(t, s.cloudConn, tidA, "arn:aws:iam::1:role/a")
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	// The payload LIES about tenant and provider — the connector row must win.
	st, body := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"connector_id": ca.ConnectorID, "tenant": tidB, "provider": "azure",
		"source_type": "inventory", "status": "permission_denied",
		"detail": "provider denied the discovery role",
	}})
	if st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}
	now := time.Now().UTC()
	recs := s.cloudSourceStatus.ForTenant(tidA, false, now)
	if len(recs) != 1 || recs[0].Provider != "aws" {
		t.Fatalf("record must land under the connector's tenant/provider: %+v", recs)
	}
	if leak := s.cloudSourceStatus.ForTenant(tidB, false, now); len(leak) != 0 {
		t.Fatalf("payload-claimed tenant must receive NOTHING: %+v", leak)
	}
	// Unknown connector id → 404 (no cross-connector guessing).
	if st, _ := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"connector_id": "ccn_doesnotexist", "provider": "aws",
		"source_type": "inventory", "status": "permission_denied",
	}}); st != 404 {
		t.Fatalf("unknown connector must be 404, got %d", st)
	}
}

// TestIngestionSurfacesPermissionErrorsTenantScoped is the org/tenant isolation
// test required by §3a.5 for this feature: the record shows on the OWNING
// tenant's /api/cloud/ingestion (matrix row + detail + since), forces its
// provider into the matrix even with zero landed data (the fully-dark-account
// case the page exists for), and is INVISIBLE to another tenant.
func TestIngestionSurfacesPermissionErrorsTenantScoped(t *testing.T) {
	srv, _, _ := newIngestTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	tidA := mkIngestTenant(t, srv, admin, "A")
	tidB := mkIngestTenant(t, srv, admin, "B")
	svcKey := mintIngestKey(t, srv, admin, "", []string{cloudIngestScope})

	for name, tid := range map[string]string{"op-a": tidA, "op-b": tidB} {
		if st, _ := do(t, srv, "POST", "/api/users", admin, map[string]any{
			"username": name, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tid,
		}); st != 201 {
			t.Fatalf("create %s failed: %d", name, st)
		}
	}
	since := time.Now().UTC().Add(-48 * time.Hour).Format(time.RFC3339)
	if st, body := putSourceStatus(t, srv, svcKey, []map[string]any{{
		"tenant": tidA, "provider": "aws", "account_id": "111111111111",
		"source_type": "flow_logs", "status": "permission_denied",
		"detail": "IAM denied logs:FilterLogEvents", "since_iso": since,
	}}); st != 200 {
		t.Fatalf("put: %d %s", st, body)
	}

	type ingResp struct {
		Sources   []cloudSourceStatus            `json:"sources"`
		Providers map[string][]cloudSourceStatus `json:"providers"`
	}
	fetch := func(user string) ingResp {
		t.Helper()
		tok := login(t, srv, user, "Passw0rd!2345").Token
		st, body := do(t, srv, "GET", "/api/cloud/ingestion", tok, nil)
		if st != 200 {
			t.Fatalf("ingestion as %s: %d %s", user, st, body)
		}
		var out ingResp
		if err := json.Unmarshal(body, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	find := func(rows []cloudSourceStatus, src string) cloudSourceStatus {
		for _, r := range rows {
			if r.SourceType == src {
				return r
			}
		}
		return cloudSourceStatus{}
	}

	a := fetch("op-a")
	awsRows, ok := a.Providers["aws"]
	if !ok {
		t.Fatalf("the failing provider must appear in the matrix even with zero landed data: %+v", a.Providers)
	}
	row := find(awsRows, "flow_logs")
	if row.Status != "permission_denied" || !strings.Contains(row.Detail, "FilterLogEvents") {
		t.Fatalf("aws flow_logs must be permission_denied with the IAM detail: %+v", row)
	}
	if row.SinceISO == "" {
		t.Fatalf("since must be carried for 'denied since <time>': %+v", row)
	}
	if g := find(a.Sources, "flow_logs"); g.Status != "permission_denied" {
		t.Fatalf("global row must surface the denial too: %+v", g)
	}

	// Tenant B must see NOTHING of it — not the status, not the detail.
	b := fetch("op-b")
	all := append(append([]cloudSourceStatus{}, b.Sources...), b.Providers["aws"]...)
	for _, r := range all {
		if r.Status == "permission_denied" || strings.Contains(r.Detail, "FilterLogEvents") {
			t.Fatalf("cross-tenant leak into tenant B: %+v", r)
		}
	}

	// Recovery: the poller stops reporting the record → the denial clears.
	if st, _ := putSourceStatus(t, srv, svcKey, nil); st != 200 {
		t.Fatalf("clearing put failed: %d", st)
	}
	a = fetch("op-a")
	if row := find(a.Providers["aws"], "flow_logs"); row.Status == "permission_denied" {
		t.Fatalf("cleared record must not linger: %+v", row)
	}
}
