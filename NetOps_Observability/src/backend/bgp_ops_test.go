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
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

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
		f.cachePut(fmt.Sprintf("k%d", i), time.Minute, []byte("x"))
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
	// (tenant_id, resource), so collision would be the leak symptom). The acme
	// note carries a rune-boundary truncation product — PG must accept it
	// (invalid UTF-8 would be SQLSTATE 22021).
	straddled := truncateUTF8(strings.Repeat("a", 299)+"🌍", bgpNoteMaxBytes)
	if err := st.Add(ctx, "acme", bgpWatchEntry{Resource: "AS3333", Kind: "asn", Note: straddled, AddedBy: "a@acme"}); err != nil {
		t.Fatalf("acme add (rune-truncated note): %v", err)
	}
	if err := st.Add(ctx, "globex", bgpWatchEntry{Resource: "AS3333", Kind: "asn", AddedBy: "g@globex"}); err != nil {
		t.Fatalf("globex add: %v", err)
	}
	t.Cleanup(func() {
		_, _ = st.Delete(ctx, "acme", "AS3333")
		_, _ = st.Delete(ctx, "globex", "AS3333")
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
		if e.Resource == "AS3333" && !utf8.ValidString(e.Note) {
			t.Fatal("stored note is not valid UTF-8 — truncation corrupted it")
		}
	}

	// Cross-tenant delete must not reach the other tenant's row.
	if found, err := st.Delete(ctx, "acme", "AS3333"); err != nil || !found {
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

// ── §3a write-scope proofs (no PG needed: a fake tx records the SQL) ────────

type bgpRecordedExec struct {
	sql  string
	args []any
}

// bgpFakeTx embeds pgx.Tx for interface satisfaction; only Exec is scripted —
// any other method panics, which is exactly right for a write-path probe.
type bgpFakeTx struct {
	pgx.Tx
	execs []bgpRecordedExec
}

func (f *bgpFakeTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	f.execs = append(f.execs, bgpRecordedExec{sql: sql, args: args})
	if strings.HasPrefix(strings.TrimSpace(sql), "DELETE") {
		return pgconn.NewCommandTag("DELETE 1"), nil
	}
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

type bgpFakeDB struct {
	tenants []string
	crosses []bool
	tx      bgpFakeTx
}

func (d *bgpFakeDB) WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	d.tenants = append(d.tenants, tenant)
	d.crosses = append(d.crosses, cross)
	return fn(&d.tx)
}

func bgpWatchServer(t *testing.T) (*server, *bgpFakeDB) {
	t.Helper()
	s := bgpServer(t, "")
	db := &bgpFakeDB{}
	s.bgpWatch = newBGPWatchStore(db)
	return s, db
}

// A cross-tenant principal (platform owner, Global view) must be REFUSED on
// write/delete — the ultra finding: the old path ran the delete under the '*'
// RLS GUC and removed EVERY tenant's row for the resource.
func TestBGPWatchlistCrossTenantWriteRefused(t *testing.T) {
	s, db := bgpWatchServer(t)

	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", `{"resource":"AS3333","note":"x"}`, superA()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross POST: want 400, got %d: %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("DELETE", "/api/bgp/watchlist?resource=AS3333", "", superA()))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("cross DELETE: want 400, got %d: %s", w.Code, w.Body.String())
	}
	if len(db.tenants) != 0 {
		t.Fatalf("refused cross-tenant write still reached the store: %v", db.tenants)
	}

	// The tenant switcher is the sanctioned path: the platform owner scoped
	// into a concrete tenant (cross=false) writes into THAT tenant only.
	scoped := superA()
	scoped.ActingTenant = "acme"
	w = httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", `{"resource":"AS3333"}`, scoped))
	if w.Code != http.StatusOK {
		t.Fatalf("owner scoped into acme: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(db.tenants) != 1 || db.tenants[0] != "acme" || db.crosses[0] {
		t.Fatalf("scoped write ran as (%v cross=%v), want (acme cross=false)", db.tenants, db.crosses)
	}
}

// Delete carries an explicit tenant_id predicate bound to the principal's
// tenant — defense-in-depth on top of RLS. Killing the predicate (the original
// bug) fails this test.
func TestBGPWatchlistDeleteIsTenantScopedSQL(t *testing.T) {
	s, db := bgpWatchServer(t)
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("DELETE", "/api/bgp/watchlist?resource=AS3333", "", acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme DELETE own resource: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(db.tenants) != 1 || db.tenants[0] != "acme" || db.crosses[0] {
		t.Fatalf("delete ran as (%v cross=%v), want (acme cross=false)", db.tenants, db.crosses)
	}
	if len(db.tx.execs) != 1 {
		t.Fatalf("want exactly 1 statement, got %d", len(db.tx.execs))
	}
	ex := db.tx.execs[0]
	if !strings.Contains(ex.sql, "tenant_id = $1") {
		t.Fatalf("DELETE lost its tenant predicate: %q", ex.sql)
	}
	if len(ex.args) != 2 || ex.args[0] != "acme" || ex.args[1] != "AS3333" {
		t.Fatalf("DELETE args = %v, want [acme AS3333]", ex.args)
	}
}

// Add stamps tenant_id from the PRINCIPAL as a bound parameter — never the
// RLS GUC, never '*'.
func TestBGPWatchlistAddStampsPrincipalTenantNeverWildcard(t *testing.T) {
	s, db := bgpWatchServer(t)
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", `{"resource":"AS3333","note":"peering"}`, acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("acme POST: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(db.tx.execs) != 1 {
		t.Fatalf("want exactly 1 statement, got %d", len(db.tx.execs))
	}
	ex := db.tx.execs[0]
	if strings.Contains(ex.sql, "current_setting") {
		t.Fatalf("INSERT stamps tenant from the GUC again (can become '*'): %q", ex.sql)
	}
	if len(ex.args) == 0 || ex.args[0] != "acme" {
		t.Fatalf("INSERT tenant arg = %v, want acme first", ex.args)
	}
	for _, a := range ex.args {
		if a == "*" {
			t.Fatalf("INSERT carries the cross-tenant wildcard: %v", ex.args)
		}
	}
}

// The store itself is fail-closed: no concrete tenant, no write (§3a) — even
// if a future handler forgets the boundary check.
func TestBGPWatchStoreRefusesWildcardOrEmptyTenant(t *testing.T) {
	db := &bgpFakeDB{}
	st := newBGPWatchStore(db)
	ctx := context.Background()
	for _, tenant := range []string{"", "  ", "*", " * "} {
		if err := st.Add(ctx, tenant, bgpWatchEntry{Resource: "AS1", Kind: "asn"}); err == nil {
			t.Errorf("Add(%q) accepted a non-concrete tenant", tenant)
		}
		if _, err := st.Delete(ctx, tenant, "AS1"); err == nil {
			t.Errorf("Delete(%q) accepted a non-concrete tenant", tenant)
		}
	}
	if len(db.tenants) != 0 {
		t.Fatalf("refused writes still reached the DB: %v", db.tenants)
	}
}

// ── rune-safe note truncation (ultra finding 1) ─────────────────────────────

func TestTruncateUTF8(t *testing.T) {
	cases := []struct{ in, want string }{
		{strings.Repeat("a", 300), strings.Repeat("a", 300)},               // at the cap: untouched
		{strings.Repeat("a", 301), strings.Repeat("a", 300)},               // ASCII overflow: plain cut
		{strings.Repeat("a", 299) + "é", strings.Repeat("a", 299)},         // 2-byte rune straddles byte 300
		{strings.Repeat("a", 298) + "€€", strings.Repeat("a", 298)},        // 3-byte rune straddles
		{strings.Repeat("a", 299) + "🌍", strings.Repeat("a", 299)},         // 4-byte rune straddles
		{strings.Repeat("a", 296) + "🌍", strings.Repeat("a", 296) + "🌍"},   // 4-byte rune ends exactly at 300
		{"", ""},
	}
	for i, c := range cases {
		got := truncateUTF8(c.in, bgpNoteMaxBytes)
		if got != c.want {
			t.Errorf("case %d: got %d bytes %q…, want %d bytes", i, len(got), got[:min(20, len(got))], len(c.want))
		}
		if !utf8.ValidString(got) {
			t.Errorf("case %d: truncation produced invalid UTF-8", i)
		}
		if len(got) > bgpNoteMaxBytes {
			t.Errorf("case %d: %d bytes exceeds the cap", i, len(got))
		}
	}
}

// End-to-end through the handler: a note whose multi-byte rune straddles byte
// 300 must reach the store as valid UTF-8 (the old byte slice sent PG invalid
// UTF-8 → SQLSTATE 22021 → 500 on a legitimate add).
func TestBGPWatchlistNoteRuneStraddleInsertsValidUTF8(t *testing.T) {
	s, db := bgpWatchServer(t)
	note := strings.Repeat("a", 299) + "🌍"
	body, err := json.Marshal(map[string]string{"resource": "AS3333", "note": note})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	s.handleBGPWatchlist(w, req("POST", "/api/bgp/watchlist", string(body), acme()))
	if w.Code != http.StatusOK {
		t.Fatalf("add with straddling note: want 200, got %d: %s", w.Code, w.Body.String())
	}
	if len(db.tx.execs) != 1 {
		t.Fatalf("want exactly 1 statement, got %d", len(db.tx.execs))
	}
	stored, ok := db.tx.execs[0].args[3].(string) // (tenant, resource, kind, note, added_by)
	if !ok {
		t.Fatalf("note arg is %T, want string", db.tx.execs[0].args[3])
	}
	if !utf8.ValidString(stored) {
		t.Fatal("stored note is invalid UTF-8 — truncation split a rune")
	}
	if len(stored) > bgpNoteMaxBytes {
		t.Fatalf("stored note is %d bytes, cap is %d", len(stored), bgpNoteMaxBytes)
	}
	if stored != strings.Repeat("a", 299) {
		t.Fatalf("stored note = %d bytes %q…, want the 299 a's", len(stored), stored[:min(20, len(stored))])
	}
}
