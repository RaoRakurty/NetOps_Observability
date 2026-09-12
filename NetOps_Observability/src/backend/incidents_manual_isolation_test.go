// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// incidents_manual_isolation_test.go — §3a isolation + zero-trust guards for
// POST /api/incidents, the Troubleshooting page's one way in.
//
// The route exists because the page used to carry a second surface where an
// operator could DESCRIBE a problem and then do nothing with it (owner,
// 2026-09-06). A described symptom is now a record through the same seam an
// alert-born incident uses, so every action works on it. That makes it a WRITE
// on tenant-owned data, and the four properties below are what keep it safe:
//
//   · the owning tenant is stamped from the TOKEN — never from the body
//   · a tenant_id in the body is REFUSED by name (400), not silently ignored:
//     a client that believes it can choose an owner must learn otherwise
//   · a cross-tenant (platform) principal owns no tenant and cannot open one
//   · another tenant's record is a 404 on read, never a 403 that confirms it
//
// The route path is written literally here so the scoped-route coverage guard
// (route_isolation_coverage_test.go) can see /api/incidents is exercised.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/incident"
)

// ── an in-memory incidents repo whose WRITE path is real ─────────────────────

// manualIncidentStore implements just enough of incidentsRepo to observe what
// the handler actually wrote. It reproduces the store's two load-bearing rules:
// the row is stamped with Input.TenantID, and an open row with the same dedup
// key folds instead of minting a second record.
type manualIncidentStore struct {
	rows []Incident
	seen []IncidentInput
}

var errManualUnused = fmt.Errorf("manualIncidentStore: path not exercised by this test")

func (m *manualIncidentStore) Ingest(_ context.Context, in IncidentInput) (Incident, bool, error) {
	m.seen = append(m.seen, in)
	dk := incident.DedupKeyFor(in)
	for i := range m.rows {
		if m.rows[i].DedupKey == dk && m.rows[i].TenantID == in.TenantID && m.rows[i].Status == incident.StatusOpen {
			m.rows[i].Occurrences++
			return m.rows[i], false, nil
		}
	}
	inc := Incident{
		ID: fmt.Sprintf("m-%02d", len(m.rows)), TenantID: in.TenantID,
		Title: in.Title, Description: in.Description, Severity: incident.CanonicalSeverity(in.Severity),
		Status: incident.StatusOpen, SourceType: in.SourceType, DedupKey: dk, Occurrences: 1,
	}
	m.rows = append(m.rows, inc)
	return inc, true, nil
}

func (m *manualIncidentStore) Get(_ context.Context, tenant string, cross bool, id string) (Incident, []IncidentEvent, bool, error) {
	for _, r := range m.rows {
		if r.ID == id && (cross || r.TenantID == tenant) {
			return r, nil, true, nil
		}
	}
	return Incident{}, nil, false, nil
}

func (m *manualIncidentStore) List(_ context.Context, tenant string, cross bool, _ IncidentQuery) ([]Incident, error) {
	var out []Incident
	for _, r := range m.rows {
		if cross || r.TenantID == tenant {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *manualIncidentStore) Count(ctx context.Context, tenant string, cross bool, q IncidentQuery) (int, error) {
	rows, err := m.List(ctx, tenant, cross, q)
	return len(rows), err
}

func (m *manualIncidentStore) Transition(context.Context, string, bool, string, string, string, string) (Incident, error) {
	return Incident{}, errManualUnused
}
func (m *manualIncidentStore) AddNote(context.Context, string, bool, string, string, string) (Incident, error) {
	return Incident{}, errManualUnused
}
func (m *manualIncidentStore) Assign(context.Context, string, bool, string, string, string) (Incident, error) {
	return Incident{}, errManualUnused
}
func (m *manualIncidentStore) MarkSync(context.Context, string, string, string, string, string, time.Time) error {
	return errManualUnused
}
func (m *manualIncidentStore) MarkNotified(context.Context, string, string) error {
	return errManualUnused
}
func (m *manualIncidentStore) FindByExternalTicket(context.Context, string, string, string) (Incident, bool, error) {
	return Incident{}, false, errManualUnused
}

var _ incidentsRepo = (*manualIncidentStore)(nil)

// ── fixtures: two orgs, one tenant each, one operator each ───────────────────

type manualIncidentFixture struct {
	tenantA, tenantB string
	tokA, tokB       string
	viewer           string
	store            *manualIncidentStore
}

func manualIncidentFixtures(t *testing.T) (*httptest.Server, manualIncidentFixture) {
	t.Helper()
	srv, s := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	orgA := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Manual A"}, 201))
	orgB := idOf(t, mustDo(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org Manual B"}, 201))
	f := manualIncidentFixture{
		tenantA: idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Manual A", "org_id": orgA}, 201)),
		tenantB: idOf(t, mustDo(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant Manual B", "org_id": orgB}, 201)),
	}
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "man-a", "password": "Passw0rd!2345", "role": "operator", "tenant_id": f.tenantA}, 201)
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "man-b", "password": "Passw0rd!2345", "role": "operator", "tenant_id": f.tenantB}, 201)
	mustDo(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "man-v", "password": "Passw0rd!2345", "role": "viewer", "tenant_id": f.tenantA}, 201)
	f.tokA = login(t, srv, "man-a", "Passw0rd!2345").Token
	f.tokB = login(t, srv, "man-b", "Passw0rd!2345").Token
	f.viewer = login(t, srv, "man-v", "Passw0rd!2345").Token
	f.store = &manualIncidentStore{}
	s.incidents = f.store
	return srv, f
}

func describedIncident(t *testing.T, b []byte) Incident {
	t.Helper()
	var out struct {
		Incident Incident `json:"incident"`
		Created  bool     `json:"created"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("decode POST /api/incidents response: %v (%s)", err, truncBody(b))
	}
	return out.Incident
}

// ── the guards ───────────────────────────────────────────────────────────────

func TestManualIncidentStampsTheOwnerFromTheToken(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	st, b := do(t, srv, "POST", "/api/incidents", f.tokA, map[string]any{
		"title": "  Branch  users   cannot reach the CRM  ", "severity": "high"})
	if st != http.StatusCreated {
		t.Fatalf("POST /api/incidents = %d, want 201: %s", st, truncBody(b))
	}
	inc := describedIncident(t, b)
	if inc.TenantID != f.tenantA {
		t.Fatalf("incident owned by %q, want the token's tenant %q", inc.TenantID, f.tenantA)
	}
	if inc.SourceType != incident.SourceManual {
		t.Fatalf("source_type = %q, want %q", inc.SourceType, incident.SourceManual)
	}
	// The operator's own words, whitespace-normalised and nothing invented.
	if inc.Title != "Branch users cannot reach the CRM" {
		t.Fatalf("title = %q, want the collapsed operator text", inc.Title)
	}
	if len(f.store.seen) != 1 || f.store.seen[0].Actor == "" {
		t.Fatalf("the ingest recorded no actor: %+v", f.store.seen)
	}
}

func TestManualIncidentRefusesATenantInTheBody(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	st, b := do(t, srv, "POST", "/api/incidents", f.tokA, map[string]any{
		"title": "Site B is dark", "tenant_id": f.tenantB})
	if st != http.StatusBadRequest {
		t.Fatalf("a tenant_id in the body = %d, want 400: %s", st, truncBody(b))
	}
	if !bytesContain(b, "tenant_id") {
		t.Errorf("the 400 does not name tenant_id: %s", truncBody(b))
	}
	if len(f.store.rows) != 0 {
		t.Fatalf("a refused request still wrote %d incident(s)", len(f.store.rows))
	}
}

func TestManualIncidentIsBehindTheWriteGate(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	st, b := do(t, srv, "POST", "/api/incidents", f.viewer, map[string]any{"title": "Wi-Fi is slow"})
	if st != http.StatusForbidden {
		t.Fatalf("a read-only principal POST /api/incidents = %d, want 403: %s", st, truncBody(b))
	}
	// It is the WRITE gate, not a lockout: the same principal still reads.
	if st, b = do(t, srv, "GET", "/api/incidents", f.viewer, nil); st != http.StatusOK {
		t.Fatalf("the same read-only principal GET /api/incidents = %d, want 200: %s", st, truncBody(b))
	}
}

func TestManualIncidentRefusesTheCrossTenantPlatformPrincipal(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	st, b := do(t, srv, "POST", "/api/incidents", admin, map[string]any{"title": "Everything is down"})
	if st == http.StatusCreated || st == http.StatusOK {
		t.Fatalf("a platform principal opened an unowned incident (%d): %s", st, truncBody(b))
	}
	if st != http.StatusBadRequest {
		t.Fatalf("platform principal POST = %d, want 400: %s", st, truncBody(b))
	}
	if len(f.store.rows) != 0 {
		t.Fatalf("a refused platform write still created %d incident(s)", len(f.store.rows))
	}
}

func TestManualIncidentIsInvisibleToAnotherTenant(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	inc := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents", f.tokA,
		map[string]any{"title": "Core uplink flapping"}, 201))

	// cross-tenant read by id → 404, never a 403 that confirms the id exists
	if st, b := do(t, srv, "GET", "/api/incidents/"+inc.ID, f.tokB, nil); st != http.StatusNotFound {
		t.Fatalf("tenant B GET tenant A's incident = %d, want 404: %s", st, truncBody(b))
	}
	// own-only list
	st, b := do(t, srv, "GET", "/api/incidents?limit=500", f.tokB, nil)
	if st != http.StatusOK {
		t.Fatalf("tenant B list = %d: %s", st, truncBody(b))
	}
	var rows []Incident
	if err := json.Unmarshal(b, &rows); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.TenantID != f.tenantB {
			t.Fatalf("CROSS-TENANT LEAK: tenant B received an incident owned by %q", r.TenantID)
		}
	}
	// ?as_tenant into another org is IGNORED — the selector narrows, it never
	// re-points a write at a tenant the caller does not own.
	steered := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents?as_tenant="+f.tenantB, f.tokA,
		map[string]any{"title": "Second look"}, 201))
	if steered.TenantID != f.tenantA {
		t.Fatalf("as_tenant steered the write to %q, want the token's own %q", steered.TenantID, f.tenantA)
	}
}

func TestManualIncidentRefusesAnUnusableDescription(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	for _, tc := range []struct {
		name, wantIn string
		body         any
	}{
		{"no title at all", "title", map[string]any{"severity": "high"}},
		{"whitespace only", "title", map[string]any{"title": "   \t  "}},
		{"off-ladder severity", "severity", map[string]any{"title": "x", "severity": "urgent"}},
		{"an unknown field", "", map[string]any{"title": "x", "assignee": "me"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			st, b := do(t, srv, "POST", "/api/incidents", f.tokA, tc.body)
			if st != http.StatusBadRequest {
				t.Fatalf("POST %v = %d, want 400: %s", tc.body, st, truncBody(b))
			}
			if tc.wantIn != "" && !bytesContain(b, tc.wantIn) {
				t.Errorf("the 400 does not name %q: %s", tc.wantIn, truncBody(b))
			}
		})
	}
	if len(f.store.rows) != 0 {
		t.Fatalf("a refused request still wrote %d incident(s)", len(f.store.rows))
	}
}

func TestManualIncidentFoldsARepeatedDescription(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	first := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents", f.tokA,
		map[string]any{"title": "VPN drops every ten minutes"}, 201))
	// The same words while the first is still open fold into it — describing a
	// problem twice must not leave two investigations of the same thing.
	again := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents", f.tokA,
		map[string]any{"title": "VPN   drops every  ten minutes"}, 200))
	if again.ID != first.ID {
		t.Fatalf("a repeated description minted %q, want the open %q", again.ID, first.ID)
	}
	// Another tenant describing the SAME words gets its OWN record.
	other := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents", f.tokB,
		map[string]any{"title": "VPN drops every ten minutes"}, 201))
	if other.ID == first.ID || other.TenantID != f.tenantB {
		t.Fatalf("tenant B folded into tenant A's record (%q/%q)", other.ID, other.TenantID)
	}
}

func TestManualIncidentBoundsTheOperatorText(t *testing.T) {
	srv, f := manualIncidentFixtures(t)
	long := strings.Repeat("é", MaxManualIncidentTitle+50)
	inc := describedIncident(t, mustDo(t, srv, "POST", "/api/incidents", f.tokA,
		map[string]any{"title": long, "description": strings.Repeat("d", MaxManualIncidentDescription+100)}, 201))
	if n := len([]rune(inc.Title)); n != MaxManualIncidentTitle {
		t.Fatalf("title kept %d runes, want it bounded to %d", n, MaxManualIncidentTitle)
	}
	if n := len([]rune(inc.Description)); n != MaxManualIncidentDescription {
		t.Fatalf("description kept %d runes, want it bounded to %d", n, MaxManualIncidentDescription)
	}
	_ = f
}
