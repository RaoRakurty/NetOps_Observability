package main

// incidents_filter_test.go — regression guards for audit F-74 (and the paging
// half of the same class on /api/incidents).
//
// The measured defect: `?severity=warning`, `?severity=bogus` and
// `?severity=WARN` all returned byte-identical 47,521-byte responses — the
// `info` bucket. incident.SeverityRank maps every unrecognised string to 0, and
// 0 is not "no match", it is `info`; incidents_pg.go then applied that as a real
// SQL predicate. A client filtering for warnings received INFO incidents
// presented as warnings. Confidently wrong is worse than ignoring.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"netops/backend/internal/incident"
	"sort"
	"testing"
	"time"

	"netops/backend/internal/httppage"
)

// ── the substitution itself ──────────────────────────────────────────────────

func TestIncidentsHandlerRejectsBadFilters(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	for _, tc := range []struct{ name, query, wantIn string }{
		{"the audit's probe", "?severity=warning", "severity"},
		{"uppercase off-ladder", "?severity=WARN", "severity"},
		{"nonsense", "?severity=bogus", "severity"},
		{"unknown status", "?status=in-progress", "status"},
		{"unknown parameter", "?priority=p1", "priority"},
		{"limit garbage", "?limit=5x", "limit"},
		{"limit above the cap", "?limit=100000", "limit"},
		{"before not RFC3339", "?before=last%20tuesday", "before"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, b := do(t, srv, "GET", "/api/incidents"+tc.query, admin, nil)
			if st != http.StatusBadRequest {
				t.Fatalf("GET /api/incidents%s = %d, want 400: %s", tc.query, st, truncBody(b))
			}
			if !bytesContain(b, tc.wantIn) {
				t.Errorf("400 body %s does not name %q", truncBody(b), tc.wantIn)
			}
		})
	}
	// A severity ON the ladder must reach the store (409 here = "no store
	// wired", i.e. it got past validation) rather than being refused.
	for _, good := range []string{"info", "low", "medium", "high", "critical"} {
		st, b := do(t, srv, "GET", "/api/incidents?severity="+good, admin, nil)
		if st == http.StatusBadRequest {
			t.Errorf("a valid severity %q was refused: %s", good, truncBody(b))
		}
	}
}

// ── paging + isolation over an in-memory repo ────────────────────────────────

// fakeIncidents is a minimal in-memory incidentsRepo so the paging and
// isolation contract can be exercised without Postgres. Only the read path is
// implemented; every write method is an explicit "not used by this test".
type fakeIncidents struct{ rows []Incident }

var errFakeUnused = fmt.Errorf("fakeIncidents: write path not exercised by this test")

func (f *fakeIncidents) visible(tenant string, cross bool, q IncidentQuery) ([]Incident, error) {
	if q.Severity != "" && !incident.ValidSeverity(q.Severity) {
		return nil, fmt.Errorf("unknown incident severity %q", q.Severity)
	}
	if q.Status != "" && !incident.ValidStatus(q.Status) {
		return nil, fmt.Errorf("unknown incident status %q", q.Status)
	}
	var out []Incident
	for _, r := range f.rows {
		if !cross && r.TenantID != tenant {
			continue // the RLS equivalent
		}
		if q.Severity != "" && r.Severity != incident.CanonicalSeverity(q.Severity) {
			continue
		}
		if q.Status != "" && r.Status != q.Status {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (f *fakeIncidents) List(_ context.Context, tenant string, cross bool, q IncidentQuery) ([]Incident, error) {
	rows, err := f.visible(tenant, cross, q)
	if err != nil {
		return nil, err
	}
	limit := incident.ClampLimit(q.Limit)
	if q.Offset >= len(rows) {
		return nil, nil
	}
	end := q.Offset + limit
	if end > len(rows) {
		end = len(rows)
	}
	return rows[q.Offset:end], nil
}

func (f *fakeIncidents) Count(_ context.Context, tenant string, cross bool, q IncidentQuery) (int, error) {
	rows, err := f.visible(tenant, cross, q)
	return len(rows), err
}

func (f *fakeIncidents) Ingest(context.Context, IncidentInput) (Incident, bool, error) {
	return Incident{}, false, errFakeUnused
}
func (f *fakeIncidents) Get(_ context.Context, tenant string, cross bool, id string) (Incident, []IncidentEvent, bool, error) {
	for _, r := range f.rows {
		if r.ID == id && (cross || r.TenantID == tenant) {
			return r, nil, true, nil
		}
	}
	return Incident{}, nil, false, nil
}
func (f *fakeIncidents) Transition(context.Context, string, bool, string, string, string, string) (Incident, error) {
	return Incident{}, errFakeUnused
}
func (f *fakeIncidents) AddNote(context.Context, string, bool, string, string, string) (Incident, error) {
	return Incident{}, errFakeUnused
}
func (f *fakeIncidents) Assign(context.Context, string, bool, string, string, string) (Incident, error) {
	return Incident{}, errFakeUnused
}
func (f *fakeIncidents) MarkSync(context.Context, string, string, string, string, string, time.Time) error {
	return errFakeUnused
}
func (f *fakeIncidents) MarkNotified(context.Context, string, string) error { return errFakeUnused }
func (f *fakeIncidents) FindByExternalTicket(context.Context, string, string, string) (Incident, bool, error) {
	return Incident{}, false, errFakeUnused
}

var _ incidentsRepo = (*fakeIncidents)(nil)

func TestIncidentsPagingWalksEveryRowAndReportsTheTrueTotal(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// Seed PAST the page size on purpose.
	const total = 113
	fake := &fakeIncidents{}
	for i := 0; i < total; i++ {
		fake.rows = append(fake.rows, Incident{
			ID: fmt.Sprintf("inc-%04d", i), TenantID: "", Severity: "high", Status: incident.StatusOpen,
		})
	}
	s.incidents = fake

	seen := map[string]int{}
	const limit = 25
	for offset := 0; offset < total+limit; offset += limit {
		st, b, h := doHead(t, srv, "GET", fmt.Sprintf("/api/incidents?limit=%d&offset=%d", limit, offset), admin)
		if st != 200 {
			t.Fatalf("offset %d: status %d: %s", offset, st, truncBody(b))
		}
		if got := headerInt(t, h, httppage.HeaderTotalCount); got != total {
			t.Fatalf("offset %d: X-Total-Count = %d, want %d", offset, got, total)
		}
		var rows []Incident
		if err := json.Unmarshal(b, &rows); err != nil {
			t.Fatalf("decode: %v (%s)", err, truncBody(b))
		}
		if offset >= total {
			if len(rows) != 0 {
				t.Fatalf("offset %d past %d rows returned %d, want an empty page", offset, total, len(rows))
			}
			continue
		}
		for _, r := range rows {
			seen[r.ID]++
		}
	}
	if len(seen) != total {
		t.Fatalf("walk reached %d incidents, want %d", len(seen), total)
	}
	for id, n := range seen {
		if n != 1 {
			t.Fatalf("incident %s returned %d times", id, n)
		}
	}
}

// TestIncidentsFilterAndTotalAgree: the total must be the total OF THE FILTER,
// not of the table — otherwise a filtered page still cannot be told from a
// filtered whole.
func TestIncidentsFilterAndTotalAgree(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	fake := &fakeIncidents{}
	for i := 0; i < 30; i++ {
		sev := "high"
		if i%3 == 0 {
			sev = "critical"
		}
		fake.rows = append(fake.rows, Incident{
			ID: fmt.Sprintf("inc-%04d", i), Severity: sev, Status: incident.StatusOpen})
	}
	s.incidents = fake

	_, b, h := doHead(t, srv, "GET", "/api/incidents?severity=critical&limit=5", admin)
	if got := headerInt(t, h, httppage.HeaderTotalCount); got != 10 {
		t.Fatalf("X-Total-Count = %d for severity=critical, want 10 (the filter's total, not the table's)", got)
	}
	var rows []Incident
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Severity != "critical" {
			t.Fatalf("severity=critical returned a %q incident — the filter was substituted (F-74)", r.Severity)
		}
	}
}

// TestIncidentsTenantIsolation (§3a.5).
func TestIncidentsTenantIsolation(t *testing.T) {
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Alpha"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Bravo"}, 201))
	tenantA := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Alpha", "org_id": orgA}, 201))
	tenantB := idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Bravo", "org_id": orgB}, 201))
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "inc-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": tenantA}, 201)
	tokA := login(t, srv, "inc-a", "Passw0rd!2345").Token

	fake := &fakeIncidents{}
	for i := 0; i < 8; i++ {
		fake.rows = append(fake.rows, Incident{
			ID: fmt.Sprintf("a-%02d", i), TenantID: tenantA, Severity: "high", Status: incident.StatusOpen})
	}
	for i := 0; i < 20; i++ {
		fake.rows = append(fake.rows, Incident{
			ID: fmt.Sprintf("b-%02d", i), TenantID: tenantB, Severity: "high", Status: incident.StatusOpen})
	}
	s.incidents = fake

	// own-only list + the caller's own total
	_, b, h := doHead(t, srv, "GET", "/api/incidents?limit=500", tokA)
	if got := headerInt(t, h, httppage.HeaderTotalCount); got != 8 {
		t.Fatalf("tenant A total = %d, want its own 8 — the total must be scoped like the rows", got)
	}
	var rows []Incident
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.TenantID != tenantA {
			t.Fatalf("CROSS-TENANT LEAK: tenant A received an incident owned by %q", r.TenantID)
		}
	}
	// paging must not become a way around the scope
	for offset := 0; offset < 40; offset += 4 {
		_, b, _ := doHead(t, srv, "GET", fmt.Sprintf("/api/incidents?limit=4&offset=%d", offset), tokA)
		var page []Incident
		if err := json.Unmarshal(b, &page); err != nil {
			t.Fatal(err)
		}
		for _, r := range page {
			if r.TenantID != tenantA {
				t.Fatalf("offset %d leaked an incident owned by %q", offset, r.TenantID)
			}
		}
	}
	// as_tenant into another org must be ignored
	_, _, h = doHead(t, srv, "GET", "/api/incidents?limit=500&as_tenant="+tenantB, tokA)
	if got := headerInt(t, h, httppage.HeaderTotalCount); got != 8 {
		t.Fatalf("as_tenant into org B changed tenant A's total to %d — narrowing must never WIDEN", got)
	}
	// cross-tenant get by id is a 404, never a 403 that confirms the id exists
	st, _ := do(t, srv, "GET", "/api/incidents/b-00", tokA, nil)
	if st != http.StatusNotFound {
		t.Fatalf("cross-tenant incident GET = %d, want 404", st)
	}
}
