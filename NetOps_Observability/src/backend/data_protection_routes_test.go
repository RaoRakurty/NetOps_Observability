package backend

// data_protection_routes_test.go — the Data Protection surface AS REGISTERED.
//
// The domain itself lives in internal/dataprotect and is tested there. What is
// under test HERE is the wiring only, and specifically the three things the
// package cannot prove about itself:
//
//  1. THE GATE. Every route is platform-GLOBAL config behind
//     requirePlatformAdmin. A tenant admin holds full administration:admin, so
//     a scope-blind gate would hand every tenant the platform's backup posture
//     AND the ability to delete its restore points (§3a rule 3). Every route is
//     asserted against a real tenant admin and an unauthenticated caller, and
//     the refusal is asserted to happen BEFORE any OpenSearch call.
//
//  2. THE MUX. The EXACT pattern /api/system/backup/snapshots must keep serving
//     the #150 policy GET/PUT while the trailing-slash pattern owns the verbs
//     beneath it; an unknown verb and a deeper path must both 404.
//
//  3. THE PLATFORM SEAMS. The type-to-confirm refusals and the accepted
//     operations must land in the REAL audit store, the 202/404/409 statuses
//     must survive the real router + middleware, and the restorability series
//     must appear in the real /metrics exporter.
//
// There is deliberately NO org-isolation test: this is platform-global
// plumbing, not tenant data (CLAUDE.md §3a rule 3 — the isolation-test
// requirement in rule 5 attaches to per-tenant DATA surfaces). Nothing on these
// routes is scoped by tenant because nothing on them belongs to one.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/alerts"
	"netops/backend/internal/dataprotect"
)

// ── the OpenSearch double ───────────────────────────────────────────────────

// osStub is a canned OpenSearch. It pattern-matches on method+path and records
// every request, so a test can assert not only the RESPONSE but that the api
// actually issued the upstream call it claims to have issued — and, for the
// gate tests, that it issued NONE.
type osStub struct {
	mu sync.Mutex
	// requests is every (method, path?query) the api sent, in order.
	requests []string

	snapshots []map[string]any
	// liveDocs is the _cat/indices answer.
	liveDocs map[string]int64
	// probeCount is what /probe-<idx>/_count returns.
	probeCount int64
	// blockRestore, when non-nil, holds the restore until it is closed (used to
	// pin an operation in `running` for the 409 test).
	blockRestore chan struct{}
	// repoLocation is the repository path the registration reports.
	repoLocation string
	hits         int
}

func newOSStub() *osStub {
	return &osStub{
		snapshots: []map[string]any{
			{
				"snapshot": "netops-daily-2026-09-02", "state": "SUCCESS",
				"indices":              []string{"netops-flows-2026.09.02", "netops-syslog-2026.09.02"},
				"start_time_in_millis": int64(1788000000000),
				"end_time_in_millis":   int64(1788000180000),
				"duration_in_millis":   int64(180000),
				"shards":               map[string]any{"total": 4, "successful": 4, "failed": 0},
				"failures":             []any{},
			},
			{
				"snapshot": "netops-daily-2026-09-01", "state": "PARTIAL",
				"indices":              []string{"netops-flows-2026.09.01"},
				"start_time_in_millis": int64(1787913600000),
				"end_time_in_millis":   int64(1787913700000),
				"duration_in_millis":   int64(100000),
				"shards":               map[string]any{"total": 2, "successful": 1, "failed": 1},
				"failures": []any{map[string]any{
					"index": "netops-flows-2026.09.01", "shard_id": 1,
					"reason": "NoSuchFileException[/snapshots/indices/xyz/__0]",
				}},
			},
		},
		liveDocs:     map[string]int64{"netops-flows-2026.09.02": 900, "netops-syslog-2026.09.02": 42},
		probeCount:   42,
		repoLocation: "/mnt/snapshots",
	}
}

func (st *osStub) record(r *http.Request) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.hits++
	key := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	st.requests = append(st.requests, key)
}

func (st *osStub) sent(substr string) bool {
	st.mu.Lock()
	defer st.mu.Unlock()
	for _, req := range st.requests {
		if strings.Contains(req, substr) {
			return true
		}
	}
	return false
}

func (st *osStub) hitCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hits
}

func (st *osStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		st.record(r)
		p := r.URL.Path
		switch {
		// repository registration
		case r.Method == http.MethodGet && p == "/_snapshot/netops-fs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"netops-fs": map[string]any{
					"type":     "fs",
					"settings": map[string]string{"location": st.repoLocation, "compress": "true"},
				},
			})
		// inventory
		case r.Method == http.MethodGet && p == "/_snapshot/netops-fs/_all":
			st.mu.Lock()
			snaps := st.snapshots
			st.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"snapshots": snaps})
		// node filesystem stats — 403 like a role without cluster:monitor
		case r.Method == http.MethodGet && p == "/_nodes/stats/fs":
			http.Error(w, `{"error":"no permissions for [cluster:monitor/nodes/stats]"}`, http.StatusForbidden)
		// per-snapshot status (sizes + the no-live-index fallback)
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/_status"):
			_ = json.NewEncoder(w).Encode(map[string]any{"snapshots": []map[string]any{{
				"stats": map[string]any{"total": map[string]any{"size_in_bytes": 12345}},
				"indices": map[string]any{
					"netops-syslog-2026.09.02": map[string]any{
						"stats": map[string]any{"total": map[string]any{"size_in_bytes": 10}}},
				},
			}}})
		// live doc counts
		case r.Method == http.MethodGet && p == "/_cat/indices":
			st.mu.Lock()
			rows := make([]map[string]string, 0, len(st.liveDocs))
			for idx, n := range st.liveDocs {
				rows = append(rows, map[string]string{"index": idx, "docs.count": strconv.FormatInt(n, 10)})
			}
			st.mu.Unlock()
			_ = json.NewEncoder(w).Encode(rows)
		// restore
		case r.Method == http.MethodPost && strings.HasSuffix(p, "/_restore"):
			if st.blockRestore != nil {
				<-st.blockRestore
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"accepted": true})
		// health wait on the probe index
		case r.Method == http.MethodGet && strings.HasPrefix(p, "/_cluster/health/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "yellow"})
		// count on the probe index
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/_count"):
			st.mu.Lock()
			n := st.probeCount
			st.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"count": n})
		// delete an index (the probe cleanup)
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/probe-"):
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// create / delete a snapshot
		case r.Method == http.MethodPut && strings.HasPrefix(p, "/_snapshot/netops-fs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"snapshot": map[string]any{"state": "SUCCESS"}})
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/_snapshot/netops-fs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// close / open (in_place)
		case r.Method == http.MethodPost && (strings.HasSuffix(p, "/_close") || strings.HasSuffix(p, "/_open")):
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// the #150 SM policy plumbing (the policy route + the coverage row read it)
		case strings.Contains(p, "/_sm/policies/netops-daily"):
			if strings.HasSuffix(p, "/_explain") {
				_ = json.NewEncoder(w).Encode(map[string]any{"policies": []map[string]any{{"name": "netops-daily"}}})
				return
			}
			if r.Method == http.MethodPut {
				if !strings.Contains(r.URL.RawQuery, "if_seq_no=") || !strings.Contains(r.URL.RawQuery, "if_primary_term=") {
					// SM's real behaviour: a PUT without the concurrency token is a 400.
					http.Error(w, "seq_no must be provided when updating", http.StatusBadRequest)
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"_id": "netops-daily"})
				return
			}
			if r.Method == http.MethodPost { // _start / _stop
				_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"_seq_no": 1, "_primary_term": 1,
				"sm_policy": map[string]any{
					"enabled":           true,
					"last_updated_time": float64(1786066432336),
					"creation": map[string]any{"schedule": map[string]any{
						"cron": map[string]any{"expression": "30 1 * * *", "timezone": "UTC"}}},
					"deletion": map[string]any{"condition": map[string]any{"max_count": float64(14)}},
				},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// backupTestServer stands up the api against the stub, with writable paths for
// the intent store, the operation ring and the probe-verdict file. The env is
// set BEFORE newTestServerState so the module's Deps — which main.go resolves
// from exactly these variables — point inside the test's temp dir.
func backupTestServer(t *testing.T, stub *osStub) (*httptest.Server, *server, string) {
	t.Helper()
	osrv := stub.server(t) // not `os`: this file uses the os package
	t.Setenv("OPENSEARCH_URL", osrv.URL)
	dir := t.TempDir()
	t.Setenv("SYSTEM_BACKUP_FILE", dir+"/system_backup.json")
	t.Setenv("SNAPSHOT_VERIFY_FILE", dir+"/snapshot_verify.json")
	t.Setenv("SNAPSHOT_OPS_FILE", dir+"/snapshot_operations.json")
	t.Setenv("BACKUP_REPORT", dir+"/backup-report.json")
	srv, s := newTestServerState(t)
	return srv, s, dir
}

func platformToken(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	return login(t, srv, "admin", "Passw0rd!2345").Token
}

// tenantAdminToken mints an admin INSIDE a tenant — full administration:admin,
// the exact identity a scope-blind gate would wrongly admit.
func tenantAdminToken(t *testing.T, srv *httptest.Server, admin, suffix string) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/orgs", admin, map[string]any{"name": "Org " + suffix})
	if st != 201 {
		t.Fatalf("create org: %d %s", st, b)
	}
	orgID := idOf(t, b)
	st, b = do(t, srv, "POST", "/api/tenants", admin, map[string]any{"name": "Tenant " + suffix, "org_id": orgID})
	if st != 201 {
		t.Fatalf("create tenant: %d %s", st, b)
	}
	tenantID := idOf(t, b)
	if st, b = do(t, srv, "POST", "/api/users", admin, map[string]any{
		"username": "dpadm" + suffix, "password": "Passw0rd!2345", "role": "admin", "tenant_id": tenantID,
	}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	return login(t, srv, "dpadm"+suffix, "Passw0rd!2345").Token
}

// ── 1. the gate ─────────────────────────────────────────────────────────────

func TestSystemBackupOpsGate(t *testing.T) {
	stub := newOSStub()
	srv, _, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)
	tenantAdmin := tenantAdminToken(t, srv, admin, "A")

	routes := []struct {
		method, path string
		body         any
	}{
		{"GET", "/api/system/backup", nil},
		{"PUT", "/api/system/backup", map[string]any{"remote_url": "/mnt/x"}},
		{"GET", "/api/system/backup/snapshots", nil},
		{"PUT", "/api/system/backup/snapshots", map[string]any{"enabled": false}},
		{"GET", "/api/system/backup/coverage", nil},
		{"GET", "/api/system/backup/snapshots/list", nil},
		{"POST", "/api/system/backup/snapshots/create", map[string]any{}},
		{"POST", "/api/system/backup/snapshots/delete", map[string]any{"snapshot": "x", "confirm": "x"}},
		{"POST", "/api/system/backup/snapshots/restore", map[string]any{"snapshot": "x"}},
		{"POST", "/api/system/backup/snapshots/verify", map[string]any{}},
		{"GET", "/api/system/backup/operations", nil},
		{"GET", "/api/system/backup/operations/op-0011223344556677", nil},
	}

	before := stub.hitCount()
	for _, rt := range routes {
		st, b := do(t, srv, rt.method, rt.path, tenantAdmin, rt.body)
		if st != 403 {
			t.Errorf("%s %s as tenant admin: got %d, want 403 (%s)", rt.method, rt.path, st, b)
		}
		if st, b = do(t, srv, rt.method, rt.path, "", rt.body); st != 401 {
			t.Errorf("%s %s unauthenticated: got %d, want 401 (%s)", rt.method, rt.path, st, b)
		}
	}
	if got := stub.hitCount(); got != before {
		t.Errorf("refused requests still reached OpenSearch (%d -> %d hits) — the gate must run BEFORE the plumbing",
			before, got)
	}

	// The platform admin gets through on every read.
	for _, path := range []string{
		"/api/system/backup", "/api/system/backup/snapshots", "/api/system/backup/coverage",
		"/api/system/backup/snapshots/list", "/api/system/backup/operations",
	} {
		if st, b := do(t, srv, "GET", path, admin, nil); st != 200 {
			t.Errorf("platform admin GET %s: %d %s", path, st, b)
		}
	}
}

// ── 2. the mux ──────────────────────────────────────────────────────────────

func TestSnapshotOpsUnknownVerbAndMethod(t *testing.T) {
	stub := newOSStub()
	srv, _, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)

	if st, _ := do(t, srv, "GET", "/api/system/backup/snapshots/nope", admin, nil); st != 404 {
		t.Errorf("unknown verb: got %d, want 404", st)
	}
	// A further path segment must not be treated as a verb by prefix.
	if st, _ := do(t, srv, "GET", "/api/system/backup/snapshots/list/extra", admin, nil); st != 404 {
		t.Errorf("deeper path: got %d, want 404", st)
	}
	if st, _ := do(t, srv, "POST", "/api/system/backup/snapshots/list", admin, map[string]any{}); st != 405 {
		t.Errorf("POST to list: got %d, want 405", st)
	}
	if st, _ := do(t, srv, "GET", "/api/system/backup/snapshots/create", admin, nil); st != 405 {
		t.Errorf("GET on create: got %d, want 405", st)
	}
	if st, _ := do(t, srv, "POST", "/api/system/backup/coverage", admin, map[string]any{}); st != 405 {
		t.Errorf("POST to coverage: got %d, want 405", st)
	}
	// The #150 policy route must still work through the EXACT pattern.
	if st, b := do(t, srv, "GET", "/api/system/backup/snapshots", admin, nil); st != 200 {
		t.Fatalf("the existing policy GET broke: %d %s", st, b)
	}
}

// ── 3. the platform seams ───────────────────────────────────────────────────

// TestConfirmTokensAreReValidatedOverTheRoutes — the type-to-confirm guard must
// live on the ROUTE, not only in a helper, and whitespace must not pass for
// equality (a padded paste is not a confirmation).
func TestConfirmTokensAreReValidatedOverTheRoutes(t *testing.T) {
	stub := newOSStub()
	srv, _, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)
	const name = "netops-daily-2026-09-02"

	for _, tc := range []struct {
		name    string
		confirm any
		want    int
	}{
		{"missing", nil, 400},
		{"empty", "", 400},
		{"wrong", name + "-x", 400},
		{"leading whitespace", " " + name, 400},
		{"trailing whitespace", name + " ", 400},
		{"case-shifted", strings.ToUpper(name), 400},
		{"correct", name, 202},
	} {
		t.Run("delete/"+tc.name, func(t *testing.T) {
			body := map[string]any{"snapshot": name}
			if tc.confirm != nil {
				body["confirm"] = tc.confirm
			}
			st, b := do(t, srv, "POST", "/api/system/backup/snapshots/delete", admin, body)
			if st != tc.want {
				t.Fatalf("got %d, want %d (%s)", st, tc.want, b)
			}
			if st == 202 {
				waitForOperation(t, srv, admin, operationFrom(t, b).ID)
			}
		})
		t.Run("in_place/"+tc.name, func(t *testing.T) {
			body := map[string]any{"snapshot": name, "mode": "in_place"}
			if tc.confirm != nil {
				body["confirm"] = tc.confirm
			}
			st, b := do(t, srv, "POST", "/api/system/backup/snapshots/restore", admin, body)
			if st != tc.want {
				t.Fatalf("got %d, want %d (%s)", st, tc.want, b)
			}
			if st == 202 {
				waitForOperation(t, srv, admin, operationFrom(t, b).ID)
			}
		})
	}
	// A confirmed delete really did reach the cluster.
	if !stub.sent("DELETE /_snapshot/netops-fs/" + name) {
		t.Error("the confirmed delete never issued the upstream DELETE")
	}
}

// TestOperationsPollableOverTheRoutesAndUnknownIs404 — the 202 → poll contract
// through the real router, including the id grammar's 404.
func TestOperationsPollableOverTheRoutesAndUnknownIs404(t *testing.T) {
	stub := newOSStub()
	srv, _, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)

	st, b := do(t, srv, "POST", "/api/system/backup/snapshots/create", admin, map[string]any{})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	op := operationFrom(t, b)
	if !dataprotect.ValidOperationID(op.ID) {
		t.Fatalf("operation id %q does not match its own grammar", op.ID)
	}
	final := waitForOperation(t, srv, admin, op.ID)
	if final.State != dataprotect.OpStateSucceeded {
		t.Fatalf("create state %s: %s", final.State, final.Error)
	}
	for _, bad := range []string{"op-zzzz", "../../etc/passwd", "op-00112233445566778899", ""} {
		if st, _ = do(t, srv, "GET", "/api/system/backup/operations/"+bad, admin, nil); st != 404 {
			t.Errorf("unknown id %q: got %d, want 404", bad, st)
		}
	}
	// The list carries the ring capacity and the restart caveat.
	st, b = do(t, srv, "GET", "/api/system/backup/operations", admin, nil)
	if st != 200 {
		t.Fatalf("list: %d %s", st, b)
	}
	var list dataprotect.OperationListView
	if err := json.Unmarshal(b, &list); err != nil {
		t.Fatalf("list decode: %v", err)
	}
	if list.Capacity != dataprotect.OperationsCapacity || len(list.Operations) == 0 {
		t.Errorf("list: capacity %d, %d operations", list.Capacity, len(list.Operations))
	}
	if !strings.Contains(list.Detail, "survive an api restart") {
		t.Errorf("the list must state what survives a restart: %q", list.Detail)
	}
}

// TestSecondOperationWhileOneRunsIs409 — the single-slot policy, over the real
// routes: two writers must never race the same repository.
func TestSecondOperationWhileOneRunsIs409(t *testing.T) {
	stub := newOSStub()
	stub.blockRestore = make(chan struct{})
	srv, _, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)
	const name = "netops-daily-2026-09-02"

	st, b := do(t, srv, "POST", "/api/system/backup/snapshots/restore", admin, map[string]any{"snapshot": name})
	if st != 202 {
		t.Fatalf("first restore: %d %s", st, b)
	}
	first := operationFrom(t, b)

	// A second long operation while the first holds the slot.
	st, b = do(t, srv, "POST", "/api/system/backup/snapshots/verify", admin, map[string]any{})
	if st != 409 {
		t.Fatalf("second operation: got %d, want 409 (%s)", st, b)
	}
	if !strings.Contains(string(b), first.ID) {
		t.Errorf("the 409 must name the operation holding the slot: %s", b)
	}
	close(stub.blockRestore)
	waitForOperation(t, srv, admin, first.ID)

	// The slot is released once it ends.
	st, b = do(t, srv, "POST", "/api/system/backup/snapshots/create", admin, map[string]any{})
	if st != 202 {
		t.Fatalf("after release: %d %s", st, b)
	}
	waitForOperation(t, srv, admin, operationFrom(t, b).ID)
}

// TestSnapshotWritesReachTheRealAuditStore — the module records both outcomes
// through the injected Auditor; this asserts the ADAPTER lands them in the
// platform's own audit repo, attributed to the authenticated subject.
func TestSnapshotWritesReachTheRealAuditStore(t *testing.T) {
	stub := newOSStub()
	srv, s, _ := backupTestServer(t, stub)
	admin := platformToken(t, srv)

	// DENY: a delete without the confirm token.
	if st, _ := do(t, srv, "POST", "/api/system/backup/snapshots/delete", admin,
		map[string]any{"snapshot": "netops-daily-2026-09-02"}); st != 400 {
		t.Fatal("expected the unconfirmed delete to be refused")
	}
	// ALLOW: a create.
	st, b := do(t, srv, "POST", "/api/system/backup/snapshots/create", admin, map[string]any{"note": "pre-upgrade"})
	if st != 202 {
		t.Fatalf("create: %d %s", st, b)
	}
	waitForOperation(t, srv, admin, operationFrom(t, b).ID)

	events, err := s.audit.List(TenantGlobal, true, auditQuery{Limit: 200})
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	var sawDeny, sawAllow bool
	for _, e := range events {
		if e.Detail == nil {
			continue
		}
		action, _ := e.Detail["action"].(string)
		if action == "snapshot_delete" && e.Decision == "deny" {
			sawDeny = true
			if e.Path != "/api/system/backup/snapshots/delete" || e.Method != http.MethodPost {
				t.Errorf("the adapter must fill the request envelope: %s %s", e.Method, e.Path)
			}
		}
		if action == "snapshot_create" && e.Decision == "allow" {
			sawAllow = true
			if e.Actor != "admin" {
				t.Errorf("audited actor = %q, want the authenticated subject", e.Actor)
			}
			if _, ok := e.Detail["operation"]; !ok {
				t.Error("an accepted operation must be attributable to its id in the audit trail")
			}
		}
	}
	if !sawDeny {
		t.Error("a REFUSED snapshot write was not audited — an unrecorded refusal is indistinguishable from one that never happened")
	}
	if !sawAllow {
		t.Error("an ACCEPTED snapshot write was not audited")
	}
}

// TestPromMetricsCarriesTheRestorabilitySeries — the exporter renders the
// module's cached DR proof. 0 means NOT PROVEN restorable, which includes
// "never probed"; the vmalert rule is aimed at exactly that series.
func TestPromMetricsCarriesTheRestorabilitySeries(t *testing.T) {
	stub := newOSStub()
	_, s, _ := backupTestServer(t, stub)
	s.alerts = alerts.NewEngine("", nil) // the exporter reads it; the harness leaves it nil
	w := httptest.NewRecorder()
	s.handlePromMetrics(w, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	body := w.Body.String()
	for _, want := range []string{
		`netops_opensearch_snapshot_restorable{repo="netops-fs"} 0`,
		"netops_opensearch_snapshot_probe_enabled{",
		"netops_opensearch_snapshot_last_success_timestamp_seconds{",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the exporter does not carry %q", want)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

func operationFrom(t *testing.T, b []byte) dataprotect.Operation {
	t.Helper()
	var wrap struct {
		Operation dataprotect.Operation `json:"operation"`
	}
	if err := json.Unmarshal(b, &wrap); err != nil {
		t.Fatalf("decode operation: %v (%s)", err, b)
	}
	if wrap.Operation.ID == "" {
		t.Fatalf("202 body carried no operation: %s", b)
	}
	return wrap.Operation
}

// waitForOperation polls until the operation leaves `running`. Bounded: a test
// that hangs is a test that tells you nothing.
func waitForOperation(t *testing.T, srv *httptest.Server, token, id string) dataprotect.Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, b := do(t, srv, "GET", "/api/system/backup/operations/"+id, token, nil)
		if st != 200 {
			t.Fatalf("poll %s: %d %s", id, st, b)
		}
		var op dataprotect.Operation
		if err := json.Unmarshal(b, &op); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if op.State != dataprotect.OpStateRunning {
			return op
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("operation %s never finished", id)
	return dataprotect.Operation{}
}
