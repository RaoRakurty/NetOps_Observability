package backend

// bgp_watchlist_isolation_test.go — the §3a rule-5 proof for the BGP watchlist,
// and the cross-BACKEND contract that keeps its two implementations honest.
//
// Two things are asserted here, in this order:
//
//  1. CONTRACT — bgpWatchStore has two implementations (Postgres FORCE-RLS and
//     bgpwatch.WatchFileStore). The same table of assertions runs against every
//     one the environment can construct, so the file backend that single-box
//     installs actually run cannot drift from the Postgres one that is
//     integration-tested. The Postgres leg needs DATABASE_URL_TEST and SKIPS
//     without it; the file leg always runs.
//  2. ISOLATION — the HTTP surface, driven the way the router drives it
//     (org_isolation_test.go lineage): own-only list, another tenant's resource
//     is a 404 on delete, a non-owner's as_tenant into another org is ignored,
//     and a cross-tenant principal cannot write at all.
//
// The route this covers is /api/bgp/watchlist, classified `scoped` in
// route_isolation_test.go.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"netops/backend/internal/bgpdepth"
	"netops/backend/internal/bgpwatch"
	"netops/backend/internal/platformdb"
)

// ── 1. the contract, run against EVERY constructible backend ────────────────

type bgpWatchBackend struct {
	name  string
	store bgpWatchStore
}

// bgpWatchBackends builds one entry per implementation the environment allows.
// The file store is always present; Postgres joins only with DATABASE_URL_TEST.
func bgpWatchBackends(t *testing.T) []bgpWatchBackend {
	t.Helper()
	out := []bgpWatchBackend{{
		name:  "file",
		store: bgpwatch.NewWatchFileStore(filepath.Join(t.TempDir(), "bgp_watchlist.json")),
	}}
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Log("DATABASE_URL_TEST unset — the Postgres leg of the watchlist contract is SKIPPED (the file leg still runs)")
		return out
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	t.Cleanup(ps.DB().Close)
	pg := newBGPWatchStore(ps.DB())
	t.Cleanup(func() {
		for _, tenant := range []string{"acme", "globex"} {
			for _, res := range []string{"AS64500", "AS64501", "203.0.113.0/24"} {
				_, _ = pg.Delete(context.Background(), tenant, res)
			}
		}
	})
	return append(out, bgpWatchBackend{name: "postgres", store: pg})
}

func bgpWatchResources(rows []bgpWatchEntry) []string {
	out := make([]string, 0, len(rows))
	for _, e := range rows {
		out = append(out, e.Resource)
	}
	return out
}

func bgpWatchHas(rows []bgpWatchEntry, resource string) bool {
	for _, e := range rows {
		if e.Resource == resource {
			return true
		}
	}
	return false
}

// Every backend answers the SAME way on the isolation-critical operations. A
// divergence here is the bug class this file exists to catch: the file backend
// is what a single-box install runs, and it was not tested at all before.
func TestBGPWatchStoreContractAcrossBackends(t *testing.T) {
	ctx := context.Background()
	for _, b := range bgpWatchBackends(t) {
		t.Run(b.name, func(t *testing.T) {
			st := b.store
			if err := st.Add(ctx, "acme", bgpWatchEntry{Resource: "AS64500", Kind: "asn", Note: "acme peering", AddedBy: "a@acme"}); err != nil {
				t.Fatalf("acme add: %v", err)
			}
			if err := st.Add(ctx, "globex", bgpWatchEntry{Resource: "AS64501", Kind: "asn", AddedBy: "g@globex"}); err != nil {
				t.Fatalf("globex add: %v", err)
			}

			// Own-only list.
			acme, err := st.List(ctx, "acme", false)
			if err != nil {
				t.Fatalf("acme list: %v", err)
			}
			if !bgpWatchHas(acme, "AS64500") {
				t.Fatalf("acme cannot see its own row: %v", bgpWatchResources(acme))
			}
			if bgpWatchHas(acme, "AS64501") {
				t.Fatalf("CROSS-TENANT LEAK: acme sees globex's row: %v", bgpWatchResources(acme))
			}

			// A write with no concrete tenant is refused by the STORE, not only
			// by the handler — no future caller can reintroduce a wildcard.
			for _, tenant := range []string{"", "  ", "*", " * "} {
				if err := st.Add(ctx, tenant, bgpWatchEntry{Resource: "203.0.113.0/24", Kind: "prefix"}); err == nil {
					t.Errorf("Add(%q) accepted a non-concrete tenant", tenant)
				}
				if _, err := st.Delete(ctx, tenant, "AS64500"); err == nil {
					t.Errorf("Delete(%q) accepted a non-concrete tenant", tenant)
				}
			}

			// Deleting a resource ANOTHER tenant watches is "not found".
			found, err := st.Delete(ctx, "globex", "AS64500")
			if err != nil {
				t.Fatalf("cross-tenant delete errored: %v", err)
			}
			if found {
				t.Fatal("CROSS-TENANT DELETE: globex removed acme's row")
			}
			if rows, _ := st.List(ctx, "acme", false); !bgpWatchHas(rows, "AS64500") {
				t.Fatal("acme's row disappeared after a foreign delete")
			}

			// Own delete works, and is idempotent-honest (second call: false).
			if found, err := st.Delete(ctx, "acme", "AS64500"); err != nil || !found {
				t.Fatalf("acme deleting its own row: found=%v err=%v", found, err)
			}
			if found, err := st.Delete(ctx, "acme", "AS64500"); err != nil || found {
				t.Fatalf("second delete reported found=%v err=%v, want false/nil", found, err)
			}
			if rows, _ := st.List(ctx, "globex", false); !bgpWatchHas(rows, "AS64501") {
				t.Fatal("acme's delete reached globex's row")
			}
			if _, err := st.Delete(ctx, "globex", "AS64501"); err != nil {
				t.Fatalf("globex cleanup: %v", err)
			}
		})
	}
}

// ── 2. the HTTP surface, on the FILE backend ────────────────────────────────

// bgpWatchFileServer is the single-box shape: no DATABASE_URL, so main.go wires
// the file register. Before it existed this server answered 503 on every call.
func bgpWatchFileServer(t *testing.T) *server {
	t.Helper()
	s := bgpServer(t, "")
	s.bgpWatch = bgpwatch.NewWatchFileStore(filepath.Join(t.TempDir(), "bgp_watchlist.json"))
	return s
}

func bgpWatchListVia(t *testing.T, s *server, claims jwtClaims) []string {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("GET", "/api/bgp/watchlist", "", claims))
	if w.Code != http.StatusOK {
		t.Fatalf("GET watchlist as %s: want 200, got %d: %s", claims.Sub, w.Code, w.Body.String())
	}
	var out struct {
		Watchlist []bgpWatchEntry `json:"watchlist"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode watchlist: %v (%s)", err, w.Body.String())
	}
	return bgpWatchResources(out.Watchlist)
}

func bgpWatchAddVia(t *testing.T, s *server, claims jwtClaims, resource string) {
	t.Helper()
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", `{"resource":"`+resource+`","note":"x"}`, claims))
	if w.Code != http.StatusOK {
		t.Fatalf("POST %s as %s: want 200, got %d: %s", resource, claims.Sub, w.Code, w.Body.String())
	}
}

// The single-box regression this whole change exists for: with no Postgres the
// watchlist SERVES instead of answering "requires the relational store".
func TestBGPWatchlistWorksOnTheFileBackend(t *testing.T) {
	s := bgpWatchFileServer(t)
	bgpWatchAddVia(t, s, acme(), "AS64500")
	if got := bgpWatchListVia(t, s, acme()); len(got) != 1 || got[0] != "AS64500" {
		t.Fatalf("acme's own watchlist = %v, want [AS64500]", got)
	}
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("DELETE", "/api/bgp/watchlist?resource=AS64500", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme DELETE own resource: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if got := bgpWatchListVia(t, s, acme()); len(got) != 0 {
		t.Fatalf("after delete acme still sees %v", got)
	}
}

// Own-only list; another org's resource is a 404 on delete (existence hidden);
// a non-owner's as_tenant into another org is IGNORED.
func TestBGPWatchlistCrossOrgIsolationFileBackend(t *testing.T) {
	s := bgpWatchFileServer(t)
	bgpWatchAddVia(t, s, acme(), "AS64500")
	bgpWatchAddVia(t, s, globex(), "AS64501")

	if got := bgpWatchListVia(t, s, acme()); len(got) != 1 || got[0] != "AS64500" {
		t.Fatalf("CROSS-TENANT LEAK: acme's list = %v, want [AS64500]", got)
	}
	if got := bgpWatchListVia(t, s, globex()); len(got) != 1 || got[0] != "AS64501" {
		t.Fatalf("CROSS-TENANT LEAK: globex's list = %v, want [AS64501]", got)
	}

	// Cross-tenant delete: 404, and the row survives.
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("DELETE", "/api/bgp/watchlist?resource=AS64500", "", globex()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("globex deleting acme's resource: want 404, got %d: %s", w.Code, w.Body.String())
	}
	if got := bgpWatchListVia(t, s, acme()); len(got) != 1 {
		t.Fatalf("acme's row did not survive a foreign delete: %v", got)
	}

	// as_tenant into another org is ignored for a NON-OWNER: the claim's own
	// tenant is the scope, on both read and write.
	intruder := globex()
	intruder.ActingTenant = "acme"
	if got := bgpWatchListVia(t, s, intruder); len(got) != 1 || got[0] != "AS64501" {
		t.Fatalf("as_tenant honoured for a non-owner: globex-as-acme saw %v", got)
	}
	bgpWatchAddVia(t, s, intruder, "203.0.113.0/24")
	if got := bgpWatchListVia(t, s, acme()); len(got) != 1 || got[0] != "AS64500" {
		t.Fatalf("as_tenant write landed in acme's watchlist: %v", got)
	}
	w = httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("DELETE", "/api/bgp/watchlist?resource=AS64500", "", intruder))
	if w.Code != http.StatusNotFound {
		t.Fatalf("as_tenant delete into acme: want 404, got %d: %s", w.Code, w.Body.String())
	}
}

// The platform owner: refused in the Global (cross-tenant) view on writes, and
// scoped into a concrete tenant by the switcher — same rule as on Postgres.
func TestBGPWatchlistPlatformOwnerScopeFileBackend(t *testing.T) {
	s := bgpWatchFileServer(t)
	bgpWatchAddVia(t, s, acme(), "AS64500")
	bgpWatchAddVia(t, s, globex(), "AS64501")

	for _, method := range []string{"POST", "DELETE"} {
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, req(method, "/api/bgp/watchlist?resource=AS64500", `{"resource":"AS64500"}`, superA()))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("cross-tenant %s: want 400, got %d: %s", method, w.Code, w.Body.String())
		}
	}
	// The Global READ view is cross-tenant by design (the '*' RLS scope's
	// mirror): the owner sees every tenant's watched resources.
	if got := bgpWatchListVia(t, s, superA()); len(got) != 2 {
		t.Fatalf("platform-owner Global view = %v, want both tenants' rows", got)
	}
	// Scoped in by the switcher, the owner writes into THAT tenant only.
	scoped := superA()
	scoped.ActingTenant = "globex"
	bgpWatchAddVia(t, s, scoped, "203.0.113.0/24")
	if got := bgpWatchListVia(t, s, acme()); len(got) != 1 || got[0] != "AS64500" {
		t.Fatalf("owner's scoped write leaked into acme: %v", got)
	}
	if got := bgpWatchListVia(t, s, globex()); len(got) != 2 {
		t.Fatalf("owner's scoped write did not land in globex: %v", got)
	}
}

// The evaluator's own reader (the path the alerting worker walks) is tenant
// scoped on the file backend too — it never performs a cross-tenant read.
func TestBGPWatchPrefixesIsTenantScopedOnFileBackend(t *testing.T) {
	s := bgpWatchFileServer(t)
	bgpWatchAddVia(t, s, acme(), "203.0.113.0/24")
	bgpWatchAddVia(t, s, globex(), "198.51.100.0/24")
	bgpWatchAddVia(t, s, acme(), "AS64500") // an ASN is not a prefix — filtered out

	got, err := s.bgpWatchPrefixes(context.Background(), "acme")
	if err != nil {
		t.Fatalf("bgpWatchPrefixes(acme): %v", err)
	}
	if len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("evaluator saw %v for acme, want only its own prefix", got)
	}
	if gx, err := s.bgpWatchPrefixes(context.Background(), "globex"); err != nil || len(gx) != 1 || gx[0] != "198.51.100.0/24" {
		t.Fatalf("evaluator saw %v (err %v) for globex", gx, err)
	}
}

// bgpTenantResources (the RPKI-over-watchlist and feed views' reader) is
// scoped by the same store on the file backend.
func TestBGPTenantResourcesScopedOnFileBackend(t *testing.T) {
	s := bgpWatchFileServer(t)
	bgpWatchAddVia(t, s, acme(), "203.0.113.0/24")
	bgpWatchAddVia(t, s, globex(), "198.51.100.0/24")

	got := s.bgpTenantResources(context.Background(), "acme", false, "prefix")
	if len(got) != 1 || got[0] != "203.0.113.0/24" {
		t.Fatalf("bgpTenantResources(acme) = %v, want only acme's prefix", got)
	}
}

// ── /api/bgp/feed: the body's counters are the CALLER'S ─────────────────────
//
// The feed handler used to embed bgpdepth's process-wide snapshot, whose
// `rings` key is the number of tenants using the feed. A per-tenant body must
// carry per-tenant facts (internal/bmp/http.go's handleStats is the precedent).
func TestBGPFeedMetricsAreTenantScoped(t *testing.T) {
	s := bgpWatchFileServer(t)
	s.bgpFeed = bgpdepth.NewRuntime(nil, bgpdepth.Options{}) // disabled: no poller, no network

	body := func(claims jwtClaims) map[string]int64 {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleBGPFeed(w, req(http.MethodGet, "/api/bgp/feed", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("GET feed as %s: %d %s", claims.Sub, w.Code, w.Body.String())
		}
		var out struct {
			Metrics map[string]int64 `json:"metrics"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return out.Metrics
	}

	m := body(acme())
	if m == nil {
		t.Fatal("no metrics block in the feed body")
	}
	for _, leaked := range []string{"rings", "pollers_active", "poller_slots_free",
		"pollers_started_total", "pollers_stopped_total", "pollers_capped_total"} {
		if _, ok := m[leaked]; ok {
			t.Errorf("%q is a process-wide fact (it counts OTHER tenants) and must not ride in a tenant body", leaked)
		}
	}
	for k, v := range m {
		if k == "ring_size" {
			continue
		}
		if v != 0 {
			t.Errorf("a tenant that has never used the feed sees %s = %d", k, v)
		}
	}
	// A second tenant sees the same zeros — nothing about the first.
	for k, v := range body(globex()) {
		if k != "ring_size" && v != 0 {
			t.Errorf("globex's feed body carries %s = %d", k, v)
		}
	}
}

// ── L-05: deleting a watch clears its verdict, end to end ──────────────────
//
// Live proof, 2026-09-03: the row was deleted and the Prefixes view kept
// rendering its `incidents` entry — a hijack/leak class for a resource nothing
// was measuring any more. This drives the REAL handler against the REAL
// evaluator, which is where the two halves have to agree.
func TestDeletingAWatchClearsItsIncident(t *testing.T) {
	s := bgpWatchTestServer(t, true) // evaluator has run once; globex watches a bogon
	s.bgpWatch = bgpwatch.NewWatchFileStore(filepath.Join(t.TempDir(), "bgp_watchlist.json"))

	const bogon = "10.9.0.0/16"
	bgpWatchAddVia(t, s, globex(), bogon)

	incidentsFor := func(claims jwtClaims) map[string]bgpwatch.Incident {
		t.Helper()
		w := httptest.NewRecorder()
		s.handleBGPWatchlist(w, req(http.MethodGet, "/api/bgp/watchlist", "", claims))
		if w.Code != http.StatusOK {
			t.Fatalf("GET watchlist: %d %s", w.Code, w.Body.String())
		}
		var out struct {
			Incidents map[string]bgpwatch.Incident `json:"incidents"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatalf("decode: %v (%s)", err, w.Body.String())
		}
		return out.Incidents
	}

	before := incidentsFor(globex())
	inc, ok := before[bogon]
	if !ok || inc.Class == "" {
		t.Fatalf("the fixture produced no verdict to clear: %+v", before)
	}

	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req(http.MethodDelete, "/api/bgp/watchlist?resource="+bogon, "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("DELETE: %d %s", w.Code, w.Body.String())
	}

	if got := bgpWatchListVia(t, s, globex()); len(got) != 0 {
		t.Fatalf("the row survived the delete: %v", got)
	}
	if after := incidentsFor(globex()); len(after) != 0 {
		t.Fatalf("the verdict outlived the row it described: %+v", after)
	}
}

// Deleting an ASN touches no verdict (verdicts are per-prefix), and one tenant's
// delete never reaches another tenant's evaluator state.
func TestDeletingAWatchDoesNotReachAnotherTenantsIncidents(t *testing.T) {
	s := bgpWatchTestServer(t, true)
	s.bgpWatch = bgpwatch.NewWatchFileStore(filepath.Join(t.TempDir(), "bgp_watchlist.json"))

	// acme deletes the SAME prefix globex has a verdict for. acme never watched
	// it, so the delete is a 404 and globex's verdict must be untouched.
	bgpWatchAddVia(t, s, acme(), "AS64500")
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req(http.MethodDelete, "/api/bgp/watchlist?resource=10.9.0.0/16", "", acme()))
	if w.Code != http.StatusNotFound {
		t.Fatalf("acme deleting a resource it does not watch: want 404, got %d", w.Code)
	}
	gx, err := s.bgpWatchEval.Incidents("globex")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, inc := range gx {
		if inc.Prefix == "10.9.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatal("CROSS-TENANT: acme's delete cleared globex's verdict")
	}

	// An ASN delete is a normal success and clears nothing (no per-prefix state).
	w = httptest.NewRecorder()
	s.handleBGPWatchlist(w, req(http.MethodDelete, "/api/bgp/watchlist?resource=AS64500", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme deleting its own ASN: %d %s", w.Code, w.Body.String())
	}
	if gx2, _ := s.bgpWatchEval.Incidents("globex"); len(gx2) != len(gx) {
		t.Fatal("an ASN delete disturbed another tenant's verdicts")
	}
}
