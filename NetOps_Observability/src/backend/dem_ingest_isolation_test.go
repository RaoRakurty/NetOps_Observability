package backend

// dem_ingest_isolation_test.go — the CLAUDE.md §3a rule-5 cross-org test for the
// Digital Experience INGEST lane (tracker 254), exercised through the REAL
// router, the REAL auth middleware and the REAL s.demIngestAuthz gate mapping.
//
// The route templates this file covers, written literally so the isolation
// COVERAGE guard (route_isolation_coverage_test.go) can see that each scoped
// route is actually exercised:
//
//	/api/dem/events
//	/api/dem/business-events
//
// Proven here:
//   - the owner is stamped from the CREDENTIAL: an ingest key minted for org A
//     produces rows owned by A's tenant no matter what the body says;
//   - a `tenant_id` in the body is a 400, not a silently-ignored attempt;
//   - an `as_tenant` selector into ANOTHER org is ignored — it can only narrow;
//   - the platform owner in the Global (cross-tenant) view is REFUSED rather
//     than allowed to write rows no tenant could own;
//   - the ingest scope grants NO READ: the same key that may POST a beacon is
//     403 on every /api/dem read surface, which is what makes it safe to paste
//     into a public page;
//   - an unauthenticated POST is 401 — there is no anonymous ingest.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"netops/backend/internal/apikey"
	"netops/backend/internal/dem"
	"netops/backend/internal/dem/expbus"
	"netops/backend/internal/dem/experience"
)

// captureSink records what the ingest routes hand the lane, so the test can
// assert on the OWNER of each row rather than on an HTTP status alone.
type captureSink struct {
	events   []experience.ExperienceEvent
	business []experience.BusinessEvent
}

func (c *captureSink) WriteEvents(_ context.Context, evs []experience.ExperienceEvent) error {
	c.events = append(c.events, evs...)
	return nil
}

func (c *captureSink) WriteBusinessEvents(_ context.Context, evs []experience.BusinessEvent) error {
	c.business = append(c.business, evs...)
	return nil
}

func ingestFixtures(t *testing.T) (*httptest.Server, *server, *captureSink, *orgFixture, *orgFixture) {
	t.Helper()
	hs, st, fa, fb := demFixtures(t)
	st.demExperienceMetrics = experience.NewCounters()
	st.experienceStore = experience.NewFileStore(filepath.Join(t.TempDir(), "dem_experience.json"))
	sink := &captureSink{}
	st.experienceEvents = nil
	api, err := experience.NewAPI(experience.Deps{
		Authz:      st.demAuthz,
		Store:      st.experienceStore,
		Targets:    st.demTargets,
		Events:     sink,
		Policy:     experienceScorePolicy(),
		Enabled:    true,
		Now:        func() time.Time { return time.Now().UTC() },
		WriteJSON:  writeJSON,
		WriteError: writeError,
		LogWarn:    func(string, map[string]any) {},
		Counters:   st.demExperienceMetrics,
	})
	if err != nil {
		t.Fatalf("experience.NewAPI: %v", err)
	}
	st.experienceAPI = api
	return hs, st, sink, fa, fb
}

// rawJSON hands `do` a body it will emit VERBATIM, so a test can send a field
// the wire type does not declare — which is the whole point of the
// tenant_id-in-the-body case.
func rawJSON(t *testing.T, s string) json.RawMessage {
	t.Helper()
	if !json.Valid([]byte(s)) {
		t.Fatalf("test fixture is not valid JSON: %s", s)
	}
	return json.RawMessage(s)
}

const ingestBody = `{"events":[{"id":"ev-1","app":"checkout","type":"page_view","success":true,"route":"/pay"}]}`

func TestDEMIngestStampsTheOwnerFromTheCredentialAcrossOrgs(t *testing.T) {
	srv, _, sink, a, b := ingestFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	keyA := mintIngestKey(t, srv, admin, a.tenantID, []string{apikey.ScopeIngestExperience})
	keyB := mintIngestKey(t, srv, admin, b.tenantID, []string{apikey.ScopeIngestExperience})

	for _, tc := range []struct{ key, tenant string }{{keyA, a.tenantID}, {keyB, b.tenantID}} {
		code, body := do(t, srv, "POST", "/api/dem/events", tc.key, rawJSON(t, ingestBody))
		if code != http.StatusAccepted {
			t.Fatalf("POST /api/dem/events: %d %s", code, body)
		}
	}
	if len(sink.events) != 2 {
		t.Fatalf("sink holds %d events, want 2", len(sink.events))
	}
	owners := map[string]bool{}
	for _, e := range sink.events {
		owners[e.TenantID] = true
	}
	if !owners[a.tenantID] || !owners[b.tenantID] || len(owners) != 2 {
		t.Fatalf("owners = %v; each key's events must be owned by ITS tenant", owners)
	}
}

func TestDEMIngestRefusesATenantInTheBodyAndNarrowsAsTenantOnly(t *testing.T) {
	srv, _, sink, a, b := ingestFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	keyA := mintIngestKey(t, srv, admin, a.tenantID, []string{apikey.ScopeIngestExperience})

	// A tenant_id in the body: refused outright, never silently re-owned.
	body := `{"events":[{"id":"ev-x","app":"checkout","type":"page_view","tenant_id":"` + b.tenantID + `"}]}`
	code, resp := do(t, srv, "POST", "/api/dem/events", keyA, rawJSON(t, body))
	if code != http.StatusBadRequest {
		t.Fatalf("a cross-tenant tenant_id returned %d %s, want 400", code, resp)
	}

	// as_tenant into ANOTHER org: the selector can only NARROW, so A's key
	// either writes as A or is refused — never as B.
	code, resp = do(t, srv, "POST", "/api/dem/events?as_tenant="+b.tenantID, keyA, rawJSON(t, ingestBody))
	if code == http.StatusAccepted {
		for _, e := range sink.events {
			if e.TenantID == b.tenantID {
				t.Fatalf("as_tenant let org A's key write a row owned by org B (%s)", b.tenantID)
			}
		}
	}
	for _, e := range sink.events {
		if e.TenantID != a.tenantID {
			t.Fatalf("an event was owned by %q, want only %q", e.TenantID, a.tenantID)
		}
	}
}

func TestDEMIngestKeyGrantsNoReadAtAll(t *testing.T) {
	srv, _, _, a, _ := ingestFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	keyA := mintIngestKey(t, srv, admin, a.tenantID, []string{apikey.ScopeIngestExperience})

	// The credential is served to the public in a page. Any read it could do is
	// a read anyone who views source can do.
	for _, path := range []string{
		"/api/dem/overview", "/api/dem/incidents", "/api/dem/journeys",
		"/api/dem/synthetics/coverage", "/api/dem/changes", "/api/dem/data-health",
		"/api/dem/targets",
	} {
		code, body := do(t, srv, "GET", path, keyA, nil)
		if code == http.StatusOK {
			t.Fatalf("the ingest key READ %s (%d) — a public credential must not be able to read a single row: %s", path, code, body)
		}
	}
}

func TestDEMIngestRefusesTheCrossTenantPlatformViewAndAnonymousCallers(t *testing.T) {
	srv, _, sink, _, _ := ingestFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token

	// The platform owner in the Global view has no concrete tenant to own the
	// rows, so the write is refused rather than filed under nobody.
	code, body := do(t, srv, "POST", "/api/dem/events", admin, rawJSON(t, ingestBody))
	if code == http.StatusAccepted {
		t.Fatalf("the cross-tenant platform view was allowed to ingest: %d %s", code, body)
	}
	if len(sink.events) != 0 {
		t.Fatalf("a cross-tenant write reached the lane: %+v", sink.events)
	}

	// No anonymous ingest: the route is behind the auth middleware like every
	// other one.
	code, body = do(t, srv, "POST", "/api/dem/events", "", rawJSON(t, ingestBody))
	if code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated POST returned %d %s, want 401", code, body)
	}
}

func TestDEMIngestBusinessEventsAreScopedTheSameWay(t *testing.T) {
	srv, _, sink, a, b := ingestFixtures(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	keyA := mintIngestKey(t, srv, admin, a.tenantID, []string{apikey.ScopeIngestExperience})

	body := `{"events":[{"id":"b1","business_event_type":"purchase","success":true,"value":40,"currency":"USD"}]}`
	code, resp := do(t, srv, "POST", "/api/dem/business-events", keyA, rawJSON(t, body))
	if code != http.StatusAccepted {
		t.Fatalf("POST /api/dem/business-events: %d %s", code, resp)
	}
	if len(sink.business) != 1 || sink.business[0].TenantID != a.tenantID {
		t.Fatalf("business owner = %+v, want %s", sink.business, a.tenantID)
	}
	if sink.business[0].TenantID == b.tenantID {
		t.Fatal("a business event was owned by the wrong org")
	}
}

func TestDEMIngestRouteLiteralsMatchTheModuleConstants(t *testing.T) {
	// main.go registers LITERALS so the route-isolation ledger's scanner can
	// see them; this is what keeps those literals and the module's exported
	// constants from drifting into a documented route that 404s.
	if experience.EventsPath != "/api/dem/events" {
		t.Fatalf("EventsPath drifted: %q", experience.EventsPath)
	}
	if experience.BusinessEventPath != "/api/dem/business-events" {
		t.Fatalf("BusinessEventPath drifted: %q", experience.BusinessEventPath)
	}
	if expbus.Topic != "netops.experience" {
		t.Fatalf("the bus topic drifted from the one kafka-init creates and the router consumes: %q", expbus.Topic)
	}
	// The gate must be the INGEST one, not the operator write gate.
	if dem.GateIngest == dem.GateWrite || dem.GateIngest == dem.GateRead {
		t.Fatal("GateIngest collides with an existing gate")
	}
}
