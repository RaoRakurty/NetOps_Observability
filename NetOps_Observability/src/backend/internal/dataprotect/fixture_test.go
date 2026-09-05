package dataprotect

// fixture_test.go — the Data Protection test harness.
//
// The OpenSearch double is a real httptest server rather than a hand-rolled
// map: the module's ONLY route to the cluster is the injected OpenSearch
// interface, and driving that interface over real HTTP keeps the JSON encoding,
// the status handling and the bounded error snippet under test too. `httpOS`
// below is the same shape the integrator's adapter has, which is what makes
// these tests evidence about production and not about a stub.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// ── the OpenSearch double ───────────────────────────────────────────────────

// osStub is a canned OpenSearch. It pattern-matches on method+path and records
// every request, so a test can assert not only the RESPONSE but that the module
// actually issued the upstream call it claims to have issued.
type osStub struct {
	mu sync.Mutex
	// requests is every (method, path?query) the module sent, in order.
	requests []string
	// bodies is the decoded JSON body of every request that had one.
	bodies map[string]map[string]any

	snapshots []map[string]any
	// liveDocs is the _cat/indices answer.
	liveDocs map[string]int64
	// probeCount is what /probe-<idx>/_count returns.
	probeCount int64
	// failDeleteTemp makes the probe's cleanup DELETE fail.
	failDeleteTemp bool
	// failRestore makes the _restore call fail.
	failRestore bool
	// blockRestore, when non-nil, holds the restore until it is closed (used to
	// pin an operation in `running` for the 409 test).
	blockRestore chan struct{}
	// repoLocation is the repository path the registration reports.
	repoLocation string
	// nodesFS, when non-nil, serves GET /_nodes/stats/fs (total, available).
	nodesFS *[2]int64
	// failPolicyGET makes the SM policy read 500.
	failPolicyGET bool
	// policy is the mutable SM policy document.
	policy map[string]any
	// putURL / putBody record the last policy PUT.
	putURL     string
	putBody    []byte
	startCalls int
	stopCalls  int
	hits       int
}

func newOSStub() *osStub {
	return &osStub{
		bodies: map[string]map[string]any{},
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
		policy: map[string]any{
			"enabled":           true,
			"last_updated_time": float64(1786066432336),
			"creation": map[string]any{"schedule": map[string]any{
				"cron": map[string]any{"expression": "30 1 * * *", "timezone": "UTC"}}},
			"deletion":       map[string]any{"condition": map[string]any{"max_count": float64(14)}},
			"schema_version": float64(19),
		},
	}
}

func (st *osStub) record(r *http.Request, body []byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	st.hits++
	key := r.Method + " " + r.URL.Path
	if r.URL.RawQuery != "" {
		key += "?" + r.URL.RawQuery
	}
	st.requests = append(st.requests, key)
	if len(body) > 0 {
		var decoded map[string]any
		if json.Unmarshal(body, &decoded) == nil && len(decoded) > 0 {
			st.bodies[r.Method+" "+r.URL.Path] = decoded
		}
	}
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

func (st *osStub) body(key string) map[string]any {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.bodies[key]
}

func (st *osStub) hitCount() int {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.hits
}

func (st *osStub) lastPolicyPut() (string, []byte) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.putURL, st.putBody
}

func (st *osStub) startStop() (int, int) {
	st.mu.Lock()
	defer st.mu.Unlock()
	return st.startCalls, st.stopCalls
}

func (st *osStub) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		st.record(r, raw)
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
		// node filesystem stats (the repository-headroom fallback)
		case r.Method == http.MethodGet && p == "/_nodes/stats/fs":
			if st.nodesFS == nil {
				http.Error(w, `{"error":"no permissions for [cluster:monitor/nodes/stats]"}`, http.StatusForbidden)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"nodes": map[string]any{"n1": map[string]any{
				"fs": map[string]any{"total": map[string]any{
					"total_in_bytes": st.nodesFS[0], "available_in_bytes": st.nodesFS[1],
				}},
			}}})
		// per-snapshot status (sizes + the no-live-index fallback)
		case r.Method == http.MethodGet && strings.HasSuffix(p, "/_status"):
			_ = json.NewEncoder(w).Encode(map[string]any{"snapshots": []map[string]any{{
				"stats": map[string]any{"total": map[string]any{"size_in_bytes": 12345}},
				"indices": map[string]any{
					"netops-syslog-2026.09.02": map[string]any{
						"stats": map[string]any{"total": map[string]any{"size_in_bytes": 10}}},
					"netops-flows-2026.09.02": map[string]any{
						"stats": map[string]any{"total": map[string]any{"size_in_bytes": 999}}},
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
			if st.failRestore {
				http.Error(w, `{"error":"repository_missing_exception"}`, http.StatusInternalServerError)
				return
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
			if st.failDeleteTemp {
				http.Error(w, `{"error":"cleanup refused"}`, http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// create / delete a snapshot
		case r.Method == http.MethodPut && strings.HasPrefix(p, "/_snapshot/netops-fs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"snapshot": map[string]any{"state": "SUCCESS"}})
		case r.Method == http.MethodDelete && strings.HasPrefix(p, "/_snapshot/netops-fs/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// close / open (in_place)
		case r.Method == http.MethodPost && (strings.HasSuffix(p, "/_close") || strings.HasSuffix(p, "/_open")):
			_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
		// the #150 SM policy plumbing
		case strings.Contains(p, "/_sm/policies/netops-daily"):
			st.servePolicy(w, r, raw)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// servePolicy is the SM policy/explain/_start/_stop half of the double. It
// mirrors SM's real behaviour on the one point that matters: a PUT without the
// concurrency token is a 400 (the apply-ism.sh bug class).
func (st *osStub) servePolicy(w http.ResponseWriter, r *http.Request, raw []byte) {
	switch {
	case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/_explain"):
		_ = json.NewEncoder(w).Encode(map[string]any{
			"policies": []map[string]any{{
				"name": "netops-daily",
				"creation": map[string]any{
					"trigger": map[string]any{"time": 1786152600000},
					"latest_execution": map[string]any{
						"status":     "SUCCESS",
						"start_time": 1786066252803,
						"end_time":   1786066432336,
					},
				},
			}},
		})
	case r.Method == http.MethodGet:
		if st.failPolicyGET {
			http.Error(w, "boom", http.StatusInternalServerError)
			return
		}
		st.mu.Lock()
		policy := st.policy
		st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"_seq_no": 1573863, "_primary_term": 19, "sm_policy": policy,
		})
	case r.Method == http.MethodPut:
		st.mu.Lock()
		st.putURL, st.putBody = r.URL.RawQuery, raw
		st.mu.Unlock()
		if !strings.Contains(r.URL.RawQuery, "if_seq_no=") || !strings.Contains(r.URL.RawQuery, "if_primary_term=") {
			http.Error(w, "seq_no must be provided when updating", http.StatusBadRequest)
			return
		}
		var body map[string]any
		if json.Unmarshal(raw, &body) == nil {
			st.mu.Lock()
			// SM re-stamps last_updated_time on every accepted write; the
			// managed_by verdict is derived from it, so the double must do the
			// same or the test would be asserting against a shape the cluster
			// never produces.
			body["last_updated_time"] = float64(time.Now().UnixMilli())
			st.policy = body
			st.mu.Unlock()
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"_id": "netops-daily"})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_start"):
		st.mu.Lock()
		st.startCalls++
		st.policy["enabled"] = true
		st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/_stop"):
		st.mu.Lock()
		st.stopCalls++
		st.policy["enabled"] = false
		st.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{"acknowledged": true})
	default:
		http.NotFound(w, r)
	}
}

// ── the injected seams, in their test shapes ────────────────────────────────

// httpOS is the OpenSearch implementation the integrator ships, reproduced here
// so the interface itself is exercised over real HTTP: an explicit per-call
// timeout, and a non-2xx that comes back as a *StatusError carrying a BOUNDED
// slice of the body.
type httpOS struct{ base string }

func (h httpOS) Do(ctx context.Context, method, path string, body []byte, out any, timeout time.Duration) error {
	var rd io.Reader = strings.NewReader("")
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base+path, rd)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		snippet, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		msg := "opensearch " + resp.Status + " on " + path
		if t := strings.TrimSpace(string(snippet)); t != "" {
			msg += ": " + t
		}
		return &StatusError{Status: resp.StatusCode, StatusText: resp.Status, Msg: msg}
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// recordingAudit captures every audited outcome so a test can assert that BOTH
// the refusals and the acceptances were recorded.
type recordingAudit struct {
	mu     sync.Mutex
	events []AuditRecord
}

func (a *recordingAudit) Record(_ *http.Request, ev AuditRecord) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, ev)
}

func (a *recordingAudit) all() []AuditRecord {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]AuditRecord, len(a.events))
	copy(out, a.events)
	return out
}

// stubDeviceConfigs reports the config-backup module's facts. off=true is the
// shipped default in these tests, matching a build with the flag unset.
type stubDeviceConfigs struct {
	facts DeviceConfigFacts
	on    bool
}

func (d stubDeviceConfigs) Facts() (DeviceConfigFacts, bool) { return d.facts, d.on }

func testWriteJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// ── the harness ─────────────────────────────────────────────────────────────

type harness struct {
	svc   *Service
	stub  *osStub
	audit *recordingAudit
	cfg   *FileConfigStore
	dir   string
	srv   *httptest.Server
}

// newHarness stands the module up against the stub, with writable paths for the
// intent store, the operation ring and the probe-verdict file.
func newHarness(t *testing.T, stub *osStub, mutate ...func(*Deps)) *harness {
	t.Helper()
	os := stub.server(t)
	dir := t.TempDir()
	cfg, err := NewFileConfigStore(dir + "/system_backup.json")
	if err != nil {
		t.Fatalf("config store: %v", err)
	}
	audit := &recordingAudit{}
	deps := Deps{
		Search:                 httpOS{base: os.URL},
		Audit:                  audit,
		Authz:                  func(http.ResponseWriter, *http.Request) (Principal, bool) { return Principal{Subject: "admin"}, true },
		Config:                 cfg,
		WriteJSON:              testWriteJSON,
		DeviceConfigs:          stubDeviceConfigs{},
		OpsFile:                dir + "/snapshot_operations.json",
		VerifyFile:             dir + "/snapshot_verify.json",
		BackupReportPath:       dir + "/backup-report.json",
		RestoreDrillReportPath: dir + "/restore-drill.report.json",
		BackupDrillReportPath:  dir + "/backup-drill.report.json",
		ProbeEnabled:           true,
	}
	for _, m := range mutate {
		m(&deps)
	}
	h := &harness{svc: New(deps), stub: stub, audit: audit, cfg: cfg, dir: dir}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/system/backup", h.svc.HandleConfig)
	mux.HandleFunc("/api/system/backup/snapshots", h.svc.HandlePolicy)
	mux.HandleFunc("/api/system/backup/coverage", h.svc.HandleCoverage)
	mux.HandleFunc("/api/system/backup/snapshots/", h.svc.HandleSnapshotOps)
	mux.HandleFunc("/api/system/backup/operations", h.svc.HandleOperations)
	mux.HandleFunc("/api/system/backup/operations/", h.svc.HandleOperationByID)
	h.srv = httptest.NewServer(mux)
	t.Cleanup(h.srv.Close)
	return h
}

// do issues one request against the module's own routes.
func (h *harness) do(t *testing.T, method, path string, body any) (int, []byte) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("marshal body: %v", err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, h.srv.URL+path, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, out
}

func (h *harness) operationFrom(t *testing.T, b []byte) Operation {
	t.Helper()
	var wrap struct {
		Operation Operation `json:"operation"`
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
func (h *harness) waitForOperation(t *testing.T, id string) Operation {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		st, b := h.do(t, "GET", "/api/system/backup/operations/"+id, nil)
		if st != 200 {
			t.Fatalf("poll %s: %d %s", id, st, b)
		}
		var op Operation
		if err := json.Unmarshal(b, &op); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if op.State != OpStateRunning {
			return op
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("operation %s never finished", id)
	return Operation{}
}
