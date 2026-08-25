package backend

// bgp_ops_test.go — BGP Operations (item 10): boundary validation, fetcher
// cache/retry/cap behavior against a scripted upstream, handler authz and
// failure isolation, and the §3a cross-tenant isolation proof for the
// watchlist (PG-gated, org_isolation_test.go lineage).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"netops/backend/internal/platformdb"
)

// ── resource validation ─────────────────────────────────────────────────────

func TestBGPNormalizeResource(t *testing.T) {
	cases := []struct{ in, wantRes, wantKind string }{
		{"193.0.0.0/21", "193.0.0.0/21", "prefix"},
		{" 193.0.0.0/21 ", "193.0.0.0/21", "prefix"},
		{"193.0.7.7/21", "193.0.0.0/21", "prefix"}, // canonicalized to the masked network
		{"2001:db8::/32", "2001:db8::/32", "prefix"},
		{"203.0.113.9", "203.0.113.9/32", "prefix"}, // bare address → host prefix
		{"2001:db8::1", "2001:db8::1/128", "prefix"},
		{"AS3333", "AS3333", "asn"},
		{"as64500", "AS64500", "asn"},
		{"AS0", "", ""},           // ASN zero is reserved
		{"AS99999999999", "", ""}, // > 32 bit
		{"3333", "", ""},          // bare number is ambiguous — refused
		{"evil.example/../../x", "", ""},
		{"193.0.0.0/33", "", ""},
		{"'; DROP TABLE bgp_watchlist;--", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		res, kind := bgpNormalizeResource(c.in)
		if res != c.wantRes || kind != c.wantKind {
			t.Errorf("normalize(%q) = (%q,%q), want (%q,%q)", c.in, res, kind, c.wantRes, c.wantKind)
		}
	}
}

// ── fetcher ─────────────────────────────────────────────────────────────────

func ripestatOK(data string) string {
	return `{"status":"ok","data":` + data + `}`
}

func testFetcher(upstream string) *bgpFetcher {
	f := newBGPFetcher()
	f.ripestatBase = upstream
	f.rdapBase = upstream + "/registry"
	return f
}

func TestBGPFetcherCachesWithinTTL(t *testing.T) {
	var calls int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		fmt.Fprint(w, ripestatOK(`{"announced":true}`))
	}))
	defer up.Close()
	f := testFetcher(up.URL)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		if _, err := f.ripestat(ctx, "routing-status", "193.0.0.0/21", "", time.Minute); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("expected 1 upstream call (TTL cache), got %d", got)
	}
}

func TestBGPFetcherRetriesOn5xxThenSucceeds(t *testing.T) {
	var calls int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if atomic.AddInt64(&calls, 1) == 1 {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, ripestatOK(`{"announced":true}`))
	}))
	defer up.Close()
	f := testFetcher(up.URL)
	if _, err := f.ripestat(context.Background(), "routing-status", "193.0.0.0/21", "", time.Minute); err != nil {
		t.Fatalf("expected retry to recover: %v", err)
	}
	if got := atomic.LoadInt64(&calls); got != 2 {
		t.Fatalf("expected exactly 2 upstream calls, got %d", got)
	}
}

func TestBGPFetcherNonOKEnvelopeIsAnError(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"status":"error","data":{}}`)
	}))
	defer up.Close()
	f := testFetcher(up.URL)
	if _, err := f.ripestat(context.Background(), "routing-status", "x", "", time.Minute); err == nil {
		t.Fatal("non-ok envelope must surface as an error, never as data")
	}
}

func TestBGPFetcher404IsTerminalNotRetried(t *testing.T) {
	var calls int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
		http.NotFound(w, r)
	}))
	defer up.Close()
	f := testFetcher(up.URL)
	if _, err := f.rdap(context.Background(), "asn", "AS64500"); err == nil {
		t.Fatal("404 must be an error")
	}
	if got := atomic.LoadInt64(&calls); got != 1 {
		t.Fatalf("4xx is terminal — expected 1 call, got %d", got)
	}
}

func TestBGPFetcherCacheCapEvicts(t *testing.T) {
	f := testFetcher("http://unused.invalid")
	for i := 0; i < bgpCacheCap+10; i++ {
		f.store(fmt.Sprintf("k%d", i), time.Minute, []byte("x"))
	}
	f.mu.Lock()
	n := len(f.cache)
	f.mu.Unlock()
	if n > bgpCacheCap {
		t.Fatalf("cache grew past its cap: %d > %d", n, bgpCacheCap)
	}
}

func TestBGPAnnouncedOriginParsesSetNotation(t *testing.T) {
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, ripestatOK(`{"last_seen":{"origin":"{3333,64500}"}}`))
	}))
	defer up.Close()
	f := testFetcher(up.URL)
	if got := bgpAnnouncedOrigin(context.Background(), f, "193.0.0.0/21"); got != "3333" {
		t.Fatalf("origin = %q, want 3333", got)
	}
}

// ── handlers ────────────────────────────────────────────────────────────────

func bgpServer(t *testing.T, upstream string) *server {
	t.Helper()
	dir := t.TempDir()
	roles, err := newRoleStore(dir + "/roles.json")
	if err != nil {
		t.Fatal(err)
	}
	s := &server{roles: roles}
	if upstream != "" {
		s.bgpFetch = testFetcher(upstream)
	}
	return s
}

func TestBGPResourceRejectsGarbageBeforeAnyFetch(t *testing.T) {
	var calls int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&calls, 1)
	}))
	defer up.Close()
	s := bgpServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPResource(w, req("GET", "/api/bgp/resource?resource=%3Brm+-rf", "", acme()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", w.Code)
	}
	if atomic.LoadInt64(&calls) != 0 {
		t.Fatal("invalid resource must never reach the upstream")
	}
}

func TestBGPResourcePartialFailureStaysHonest(t *testing.T) {
	// routing-status answers; looking-glass fails — the response must carry
	// the good part AND name the failed part (never blank, never fake).
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "looking-glass") {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, ripestatOK(`{"announced":true,"last_seen":{"origin":"3333"}}`))
	}))
	defer up.Close()
	s := bgpServer(t, up.URL)
	w := httptest.NewRecorder()
	s.handleBGPResource(w, req("GET", "/api/bgp/resource?resource=193.0.0.0/21", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d: %s", w.Code, w.Body.String())
	}
	var out map[string]any
	if err := json.NewDecoder(w.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out["routing_status"] == nil {
		t.Error("routing_status missing despite healthy upstream")
	}
	if out["paths_error"] == nil {
		t.Error("failed looking-glass must be DECLARED via paths_error")
	}
}

func TestBGPWatchlistWithoutPGAnswers503NotPanic(t *testing.T) {
	s := bgpServer(t, "")
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("GET", "/api/bgp/watchlist", "", acme()))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("want 503 on missing store, got %d", w.Code)
	}
}

func TestBGPWatchlistWriteNeedsWritePerm(t *testing.T) {
	s := bgpServer(t, "")
	viewer := jwtClaims{Sub: "v@acme", Role: RoleReadOnly, Tenant: "acme"}
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", `{"resource":"AS3333"}`, viewer))
	if w.Code != http.StatusForbidden {
		t.Fatalf("viewer POST: want 403, got %d", w.Code)
	}
}

// ── §3a isolation proof (PG-gated, org_isolation_test.go lineage) ───────────

func TestBGPWatchlistTenantIsolationPG(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the watchlist RLS isolation test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	st := newBGPWatchStore(ps.DB())

	// Each tenant writes its own entry (same resource on purpose: the PK is
	// (tenant_id, resource), so collision would be the leak symptom).
	if err := st.Add(ctx, "acme", false, bgpWatchEntry{Resource: "AS3333", Kind: "asn", AddedBy: "a@acme"}); err != nil {
		t.Fatalf("acme add: %v", err)
	}
	if err := st.Add(ctx, "globex", false, bgpWatchEntry{Resource: "AS3333", Kind: "asn", AddedBy: "g@globex"}); err != nil {
		t.Fatalf("globex add: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.Delete(ctx, "acme", false, "AS3333")
		_, _ = st.Delete(ctx, "globex", false, "AS3333")
	})

	// Own-only list.
	acmeList, err := st.List(ctx, "acme", false)
	if err != nil {
		t.Fatalf("acme list: %v", err)
	}
	for _, e := range acmeList {
		if e.AddedBy == "g@globex" {
			t.Fatal("CROSS-TENANT LEAK: acme sees globex's watchlist row")
		}
	}

	// Cross-tenant delete must not reach the other tenant's row.
	if found, err := st.Delete(ctx, "acme", false, "AS3333"); err != nil || !found {
		t.Fatalf("acme deleting its own row: found=%v err=%v", found, err)
	}
	gx, err := st.List(ctx, "globex", false)
	if err != nil {
		t.Fatalf("globex list: %v", err)
	}
	stillThere := false
	for _, e := range gx {
		if e.Resource == "AS3333" && e.AddedBy == "g@globex" {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("acme's delete removed globex's row — RLS write scope broken")
	}
}
