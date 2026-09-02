package backend

// bgp_depth_test.go — the HTTP boundary for the BGP depth panels (item 10):
// RPKI, ASPA, geofeed, the AS-path graph and the near-live feed.
//
// Everything here is OFFLINE (§11): the upstream is an httptest server, and the
// watchlist is a fake pgx tx. The tests that matter most are the isolation ones
// — the RPKI sweep and the feed are per-tenant surfaces, and the graph must be
// tenant-INVARIANT apart from its "my ASN" highlight.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/bgpdepth"
)

// ── a watchlist the handlers can actually read ──────────────────────────────

// bgpFakeRows is the minimal pgx.Rows a watchlist List needs. Every other
// method is inherited nil and would panic — correct for a read-path probe.
type bgpFakeRows struct {
	pgx.Rows
	rows []bgpWatchEntry
	i    int
}

func (r *bgpFakeRows) Next() bool { r.i++; return r.i <= len(r.rows) }
func (r *bgpFakeRows) Close()     {}
func (r *bgpFakeRows) Err() error { return nil }
func (r *bgpFakeRows) Scan(dest ...any) error {
	e := r.rows[r.i-1]
	vals := []any{e.Resource, e.Kind, e.Note, e.AddedBy, e.CreatedAt}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = vals[i].(string)
		default:
			// created_at — the handlers never read it, so leaving it zero is fine.
		}
	}
	return nil
}

type bgpListTx struct {
	pgx.Tx
	rows []bgpWatchEntry
}

func (t *bgpListTx) Query(_ context.Context, _ string, _ ...any) (pgx.Rows, error) {
	return &bgpFakeRows{rows: t.rows}, nil
}

type bgpListDB struct {
	perTenant map[string][]bgpWatchEntry
	seen      []string
	crosses   []bool
}

func (d *bgpListDB) WithTenant(_ context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	d.seen = append(d.seen, tenant)
	d.crosses = append(d.crosses, cross)
	return fn(&bgpListTx{rows: d.perTenant[tenant]})
}

// depthServer builds a server with a scripted upstream and a two-tenant
// watchlist, so cross-tenant reads are actually observable.
func depthServer(t *testing.T, upstream string) (*server, *bgpListDB) {
	t.Helper()
	s := bgpServer(t, upstream)
	db := &bgpListDB{perTenant: map[string][]bgpWatchEntry{
		"acme": {
			{Resource: "193.0.0.0/21", Kind: "prefix", AddedBy: "a@acme"},
			{Resource: "AS3333", Kind: "asn", AddedBy: "a@acme"},
		},
		"globex": {
			{Resource: "198.51.100.0/24", Kind: "prefix", AddedBy: "g@globex"},
			{Resource: "AS64500", Kind: "asn", AddedBy: "g@globex"},
		},
	}}
	s.bgpWatch = newBGPWatchStore(db)
	s.bgpASPA = bgpdepth.NoASPAProvider{}
	return s, db
}

func decodeBody(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return out
}

// ── unknown parameters are refused everywhere ──────────────────────────────

// A typo'd or injected query parameter that is silently IGNORED is how a
// "filter" that never filtered ships. Every depth route fails closed.
func TestBGPDepthRefusesUnknownQueryParams(t *testing.T) {
	s, _ := depthServer(t, "")
	cases := []struct {
		path string
		h    func(http.ResponseWriter, *http.Request)
	}{
		{"/api/bgp/rpki?tenant=globex", s.handleBGPRPKI},
		{"/api/bgp/aspa?resource=AS1&tenant=globex", s.handleBGPASPA},
		{"/api/bgp/geofeed?resource=AS1&all=true", s.handleBGPGeofeed},
		{"/api/bgp/aspath-graph?prefix=193.0.0.0/21&limit=99999", s.handleBGPASPathGraph},
		{"/api/bgp/feed?since=0&cross=true", s.handleBGPFeed},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		c.h(w, req("GET", c.path, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400 for an unknown parameter, got %d: %s", c.path, w.Code, w.Body.String())
		}
	}
	// as_tenant is the platform-wide switcher and stays legal on every route.
	w := httptest.NewRecorder()
	s.handleBGPASPA(w, req("GET", "/api/bgp/aspa?resource=AS3333&as_tenant=acme", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("as_tenant must remain accepted: %d %s", w.Code, w.Body.String())
	}
}

func TestBGPDepthMethodAndPermGates(t *testing.T) {
	s, _ := depthServer(t, "")
	handlers := map[string]func(http.ResponseWriter, *http.Request){
		"rpki": s.handleBGPRPKI, "aspa": s.handleBGPASPA, "geofeed": s.handleBGPGeofeed,
		"aspath-graph": s.handleBGPASPathGraph, "feed": s.handleBGPFeed,
	}
	for name, h := range handlers {
		w := httptest.NewRecorder()
		h(w, req("POST", "/api/bgp/"+name, "", acme()))
		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s POST: want 405, got %d", name, w.Code)
		}
		// No claims in the context at all — the unauthenticated path. Every depth
		// route must refuse it before it looks at a parameter or an upstream.
		w = httptest.NewRecorder()
		h(w, httptest.NewRequest("GET", "/api/bgp/"+name, nil))
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s unauthenticated: want 401, got %d", name, w.Code)
		}
	}
}

// ── RPKI: watchlist-scoped (the ledger's `scoped` claim) ───────────────────

func TestBGPDepthRPKIIsWatchlistScoped(t *testing.T) {
	// The sweep validates prefixes CONCURRENTLY, so the recorder needs a lock —
	// without one this test would be the race, not the code.
	var askedMu sync.Mutex
	var asked []string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		askedMu.Lock()
		asked = append(asked, r.URL.String())
		askedMu.Unlock()
		switch {
		case strings.Contains(r.URL.Path, "rpki-validation"):
			fmt.Fprint(w, ripestatOK(`{"status":"valid","validating_roas":[{"origin":"3333","prefix":"193.0.0.0/21","validity":"valid","max_length":21}]}`))
		default: // routing-status, for the origin resolver
			fmt.Fprint(w, ripestatOK(`{"last_seen":{"origin":"3333"}}`))
		}
	}))
	defer up.Close()
	s, db := depthServer(t, up.URL)

	w := httptest.NewRecorder()
	s.handleBGPRPKI(w, req("GET", "/api/bgp/rpki", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if out["from_watchlist"] != true {
		t.Fatal("a bare sweep must declare that it came from the watchlist")
	}
	results, _ := out["results"].([]any)
	if len(results) != 1 {
		t.Fatalf("acme has ONE watched prefix; got %d results: %v", len(results), results)
	}
	got := results[0].(map[string]any)
	if got["prefix"] != "193.0.0.0/21" {
		t.Fatalf("result = %v", got)
	}
	// The leak symptom: globex's prefix or identity appearing in acme's sweep.
	blob := w.Body.String()
	if strings.Contains(blob, "198.51.100.0/24") || strings.Contains(blob, "globex") {
		t.Fatalf("CROSS-TENANT LEAK: acme's RPKI sweep carries globex data: %s", blob)
	}
	if len(db.seen) == 0 || db.seen[0] != "acme" {
		t.Fatalf("the watchlist was read as %v, want acme", db.seen)
	}
	askedMu.Lock()
	askedSnapshot := append([]string(nil), asked...)
	askedMu.Unlock()
	for _, u := range askedSnapshot {
		if strings.Contains(u, "198.51.100") {
			t.Fatalf("acme's sweep validated globex's prefix upstream: %s", u)
		}
	}

	// The other tenant sees only its own — the mirror half of the proof. The
	// assertion is on the RESULT prefixes, not the raw body: a ROA object
	// legitimately names whatever prefix the (shared, public) validator returned,
	// and asserting on the body would fail on that rather than on a real leak.
	w = httptest.NewRecorder()
	s.handleBGPRPKI(w, req("GET", "/api/bgp/rpki", "", globex()))
	if w.Code != http.StatusOK {
		t.Fatalf("globex sweep: want 200, got %d: %s", w.Code, w.Body.String())
	}
	gxResults, _ := decodeBody(t, w)["results"].([]any)
	if len(gxResults) != 1 {
		t.Fatalf("globex has ONE watched prefix; got %d", len(gxResults))
	}
	if p := gxResults[0].(map[string]any)["prefix"]; p != "198.51.100.0/24" {
		t.Fatalf("CROSS-TENANT LEAK: globex's sweep validated %v", p)
	}
}

func TestBGPDepthRPKIRejectsAnASNAndGarbageBeforeAnyFetch(t *testing.T) {
	var calls int64
	up := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt64(&calls, 1) }))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	for _, res := range []string{"AS3333", "%3Brm+-rf", "not-a-prefix"} {
		w := httptest.NewRecorder()
		s.handleBGPRPKI(w, req("GET", "/api/bgp/rpki?resource="+res, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("resource=%s: want 400, got %d", res, w.Code)
		}
	}
	if atomic.LoadInt64(&calls) != 0 {
		t.Fatal("an invalid resource reached the upstream")
	}
}

// ── ASPA: the honesty contract at the HTTP boundary ────────────────────────

func TestBGPDepthASPAIsHonestWhenUnconfigured(t *testing.T) {
	s, _ := depthServer(t, "")
	w := httptest.NewRecorder()
	s.handleBGPASPA(w, req("GET", "/api/bgp/aspa?resource=AS3333", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if _, fabricated := out["aspa"]; fabricated {
		t.Fatalf("an ASPA verdict was returned with NO data source configured: %v", out)
	}
	st, _ := out["status"].(map[string]any)
	if st["configured"] != false {
		t.Fatalf("status = %v", st)
	}
	if !strings.Contains(fmt.Sprint(st["how_to"]), bgpdepth.EnvASPAProviderURL) {
		t.Fatalf("the operator is not told how to configure a source: %v", st)
	}
}

func TestBGPDepthASPARequiresAnASN(t *testing.T) {
	s, _ := depthServer(t, "")
	for _, res := range []string{"", "193.0.0.0/21", "junk"} {
		w := httptest.NewRecorder()
		s.handleBGPASPA(w, req("GET", "/api/bgp/aspa?resource="+res, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("resource=%q: want 400, got %d", res, w.Code)
		}
	}
}

// ── geofeed ────────────────────────────────────────────────────────────────

func TestBGPDepthGeofeedNotPublishedIsAFactNotAnError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, ripestatOK(`{"records":[[{"key":"descr","value":"nothing"}]],"irr_records":[]}`))
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPGeofeed(w, req("GET", "/api/bgp/geofeed?resource=193.0.0.0/21", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	if out["published"] != false || out["error"] != nil {
		t.Fatalf("out = %v", out)
	}
	if _, ok := out["entries"].([]any); !ok {
		t.Fatalf("entries must serialize as an array, got %T", out["entries"])
	}
}

// The geofeed URL comes from a third party's whois remark: pointing it at
// localhost must NOT produce a request. This is the SSRF regression test.
func TestBGPDepthGeofeedRefusesAnSSRFURLFromWhois(t *testing.T) {
	var victim int64
	loop := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { atomic.AddInt64(&victim, 1) }))
	defer loop.Close()
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, ripestatOK(`{"records":[[{"key":"Comment","value":"Geofeed: %s/secret.csv"}]]}`), loop.URL)
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPGeofeed(w, req("GET", "/api/bgp/geofeed?resource=193.0.0.0/21", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if n := atomic.LoadInt64(&victim); n != 0 {
		t.Fatalf("SSRF: the server fetched a loopback URL published in whois (%d hits)", n)
	}
	if out := decodeBody(t, w); out["published"] == true {
		t.Fatalf("an unsafe URL was treated as a published geofeed: %v", out)
	}
}

// The fetcher's own gate, exercised directly: no http, no private address, no
// odd port — the three shapes an attacker would try.
func TestBGPFetcherGetRefusesUnsafeURLs(t *testing.T) {
	f := newBGPFetcher()
	for _, u := range []string{
		"http://example.com/x.csv", "https://127.0.0.1/x.csv",
		"https://10.0.0.1/x.csv", "https://example.com:9000/x.csv",
		"https://169.254.169.254/latest/meta-data/",
	} {
		if _, err := f.Get(t.Context(), u, 1024); err == nil {
			t.Errorf("Get(%q) was allowed", u)
		}
	}
}

// ── AS-path graph ──────────────────────────────────────────────────────────

func TestBGPDepthASPathGraphBuildsFromBGPState(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "bgp-state") {
			http.Error(w, "no", http.StatusNotFound)
			return
		}
		fmt.Fprint(w, ripestatOK(`{"bgp_state":[{"path":[7018,1299,1273,3333]},{"path":[852,2914,1136,3333]},{"path":[55720,6939,3333]}]}`))
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPASPathGraph(w, req("GET", "/api/bgp/aspath-graph?prefix=193.0.0.0/21", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var g bgpdepth.ASPathGraph
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Source != "bgp-state" || g.Paths != 3 {
		t.Fatalf("g = %+v", g)
	}
	if len(g.Origins) != 1 || g.Origins[0] != 3333 {
		t.Fatalf("origins = %v", g.Origins)
	}
	if g.MaxEdges != bgpdepth.MaxGraphEdges {
		t.Fatalf("the edge cap is not declared: %d", g.MaxEdges)
	}
	// acme watches AS3333 — its own AS must be MARKED.
	var marked bool
	for _, n := range g.Nodes {
		if n.ASN == 3333 && n.Tenant {
			marked = true
		}
	}
	if !marked {
		t.Fatalf("the tenant's own ASN was not marked: %+v", g.Nodes)
	}
}

// The graph is PUBLIC data (the ledger's `globalRef` claim). The only thing a
// tenant changes is which nodes are highlighted — never which nodes exist.
func TestBGPDepthASPathGraphTenantOnlyMarks(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bgp-state") {
			fmt.Fprint(w, ripestatOK(`{"bgp_state":[{"path":[7018,1299,3333]},{"path":[6939,64500]}]}`))
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)

	load := func(c jwtClaims) bgpdepth.ASPathGraph {
		w := httptest.NewRecorder()
		s.handleBGPASPathGraph(w, req("GET", "/api/bgp/aspath-graph?prefix=193.0.0.0/21", "", c))
		if w.Code != http.StatusOK {
			t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
		}
		var g bgpdepth.ASPathGraph
		if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
			t.Fatal(err)
		}
		return g
	}
	a, gx := load(acme()), load(globex())
	if len(a.Nodes) != len(gx.Nodes) || len(a.Edges) != len(gx.Edges) {
		t.Fatalf("the graph's SHAPE differs by tenant (%d/%d vs %d/%d) — it is public data",
			len(a.Nodes), len(a.Edges), len(gx.Nodes), len(gx.Edges))
	}
	mark := func(g bgpdepth.ASPathGraph, asn uint32) bool {
		for _, n := range g.Nodes {
			if n.ASN == asn {
				return n.Tenant
			}
		}
		return false
	}
	// acme watches AS3333, globex watches AS64500 — each sees only its own mark.
	if !mark(a, 3333) || mark(a, 64500) {
		t.Fatalf("acme's marks are wrong: %+v", a.Nodes)
	}
	if !mark(gx, 64500) || mark(gx, 3333) {
		t.Fatalf("globex's marks are wrong: %+v", gx.Nodes)
	}
}

func TestBGPDepthASPathGraphFallsBackToLookingGlass(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "bgp-state") {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		if strings.Contains(r.URL.Path, "looking-glass") {
			fmt.Fprint(w, ripestatOK(`{"rrcs":[{"peers":[{"as_path":"7018 1299 3333"}]}]}`))
			return
		}
		http.Error(w, "no", http.StatusNotFound)
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPASPathGraph(w, req("GET", "/api/bgp/aspath-graph?prefix=193.0.0.0/21", "", acme()))
	var g bgpdepth.ASPathGraph
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Source != "looking-glass" || g.Paths != 1 {
		t.Fatalf("the fallback did not engage: %+v", g)
	}
}

func TestBGPDepthASPathGraphBothSourcesDownIsExplained(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "down", http.StatusBadGateway)
	}))
	defer up.Close()
	s, _ := depthServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPASPathGraph(w, req("GET", "/api/bgp/aspath-graph?prefix=193.0.0.0/21", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("a failed panel must still answer 200 with an explanation, got %d", w.Code)
	}
	var g bgpdepth.ASPathGraph
	if err := json.Unmarshal(w.Body.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	if g.Error == "" {
		t.Fatal("an empty graph with no error is indistinguishable from 'no paths exist'")
	}
}

func TestBGPDepthASPathGraphRequiresAPrefix(t *testing.T) {
	s, _ := depthServer(t, "")
	for _, p := range []string{"", "AS3333", "junk"} {
		w := httptest.NewRecorder()
		s.handleBGPASPathGraph(w, req("GET", "/api/bgp/aspath-graph?prefix="+p, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("prefix=%q: want 400, got %d", p, w.Code)
		}
	}
}

// ── near-live feed ─────────────────────────────────────────────────────────

func TestBGPDepthFeedFlagOffIsHonest(t *testing.T) {
	s, _ := depthServer(t, "")
	s.bgpFeed = nil // the flag-off shape
	w := httptest.NewRecorder()
	s.handleBGPFeed(w, req("GET", "/api/bgp/feed", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	out := decodeBody(t, w)
	st, _ := out["status"].(map[string]any)
	if st["enabled"] != false || !strings.Contains(fmt.Sprint(st["note"]), bgpdepth.EnvFeatureFlag) {
		t.Fatalf("the off-state does not name the flag: %v", st)
	}
	if ups, ok := out["updates"].([]any); !ok || len(ups) != 0 {
		t.Fatalf("updates = %v", out["updates"])
	}
}

func TestBGPDepthFeedIsPerTenantAndRefusesCross(t *testing.T) {
	s, _ := depthServer(t, "")
	s.bgpFeed = bgpdepth.NewRuntime(s.bgpFetch, bgpdepth.Options{Enabled: true})
	defer s.bgpFeed.Stop()

	// A cross-tenant principal (platform owner in the Global view) is refused:
	// the ring is keyed by tenant and must never be read under a wildcard.
	w := httptest.NewRecorder()
	s.handleBGPFeed(w, req("GET", "/api/bgp/feed", "", superA()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant feed read: want 400, got %d: %s", w.Code, w.Body.String())
	}

	// Scoped into a tenant is the sanctioned path.
	scoped := superA()
	scoped.ActingTenant = "acme"
	w = httptest.NewRecorder()
	s.handleBGPFeed(w, req("GET", "/api/bgp/feed", "", scoped))
	if w.Code != http.StatusOK {
		t.Fatalf("scoped read: want 200, got %d: %s", w.Code, w.Body.String())
	}
	out := decodeBody(t, w)
	st, _ := out["status"].(map[string]any)
	res, _ := st["resources"].([]any)
	if len(res) != 2 {
		t.Fatalf("the feed follows acme's 2 watched resources, got %v", res)
	}
	for _, r := range res {
		if fmt.Sprint(r) == "198.51.100.0/24" || fmt.Sprint(r) == "AS64500" {
			t.Fatalf("CROSS-TENANT LEAK: acme's feed follows globex's resources: %v", res)
		}
	}
	if out["metrics"] == nil {
		t.Fatal("the feed must expose its counters (§10)")
	}
}

func TestBGPDepthFeedValidatesCursorAndLimit(t *testing.T) {
	s, _ := depthServer(t, "")
	s.bgpFeed = bgpdepth.NewRuntime(s.bgpFetch, bgpdepth.Options{Enabled: true})
	defer s.bgpFeed.Stop()
	for _, q := range []string{"since=-1", "since=abc", "limit=0", "limit=99999", "limit=-3"} {
		w := httptest.NewRecorder()
		s.handleBGPFeed(w, req("GET", "/api/bgp/feed?"+q, "", acme()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d", q, w.Code)
		}
	}
}
