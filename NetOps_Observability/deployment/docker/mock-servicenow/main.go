// Command mock-servicenow is a tiny, stdlib-only stand-in for the ServiceNow
// Table API (incident table ONLY) used to exercise Correlix's RCA auto-ticketing
// create leg (#78) end-to-end on the live stack WITHOUT a real ServiceNow
// instance. It is a TEST FIXTURE — never a production dependency:
//
//   - It is off by default (compose profile "mock-snow"); the stack never starts
//     it unless explicitly asked.
//   - It implements only the four endpoints the Correlix adapter
//     (src/backend/ticketing_servicenow.go) actually calls:
//       GET   /api/now/table/incident?sysparm_query=correlation_id=<id>  (lookup)
//       GET   /api/now/table/incident?sysparm_limit=1&sysparm_fields=sys_id (health)
//       POST  /api/now/table/incident                                    (create)
//       PATCH /api/now/table/incident/{sys_id}                           (update/note/resolve)
//     plus a non-ServiceNow GET /inspect (watch what landed) and GET /healthz.
//   - Storage is in-memory; restarting it clears all incidents.
//
// Faithful behaviours that matter for the worker's correctness:
//   - HTTP Basic (or Bearer) auth — wrong creds → 401, so the adapter's
//     no-secret-leak path is exercised against a real network peer.
//   - ServiceNow's native correlation_id is the dedupe anchor: a create echoes it
//     back and lookup finds it, so the worker never double-creates.
//   - A chaos knob (MOCK_SNOW_FAIL_NEXT / POST /_control/fail) returns 5xx for the
//     next N create/patch calls so the worker's retry+backoff path can be watched
//     live.
//
// Zero deps, builds offline (CLAUDE.md §6 stdlib-only).
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// store is the in-memory incident table. sys_id -> fields, plus a
// correlation_id -> sys_id index for ServiceNow's native dedupe lookup.
type store struct {
	mu        sync.Mutex
	incidents map[string]map[string]any
	byCorr    map[string]string
	order     []string // sys_id insertion order, for a stable /inspect view
	seq       int
	failNext  int32 // return 5xx for the next N create/patch calls (chaos knob)
}

func newStore() *store {
	return &store{incidents: map[string]map[string]any{}, byCorr: map[string]string{}}
}

type config struct {
	addr     string
	user     string
	password string
	token    string // optional Bearer; when set, Bearer auth is also accepted
}

func loadConfig() config {
	return config{
		addr:     envOr("MOCK_SNOW_ADDR", ":8090"),
		user:     envOr("MOCK_SNOW_USER", "correlix"),
		password: envOr("MOCK_SNOW_PASSWORD", "correlix-mock-secret"),
		token:    os.Getenv("MOCK_SNOW_TOKEN"),
	}
}

func main() {
	cfg := loadConfig()
	st := newStore()
	if n, err := strconv.Atoi(os.Getenv("MOCK_SNOW_FAIL_NEXT")); err == nil && n > 0 {
		st.failNext = int32(n)
	}

	mux := http.NewServeMux()
	// Liveness — unauthenticated, for the compose healthcheck.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"status": "ok", "service": "mock-servicenow"})
	})
	// Human/JSON view of everything created — NOT a ServiceNow endpoint. Lets you
	// watch a Correlix-filed incident land in real time. Auth-guarded like the rest.
	mux.HandleFunc("/inspect", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(cfg, r) {
			unauthorized(w)
			return
		}
		writeJSON(w, 200, st.snapshot())
	})
	// Chaos control: make the next N create/patch calls fail with 503 so the
	// worker's retry/backoff/dead-letter path can be exercised live.
	mux.HandleFunc("/_control/fail", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(cfg, r) {
			unauthorized(w)
			return
		}
		n, _ := strconv.Atoi(r.URL.Query().Get("n"))
		if n < 0 {
			n = 0
		}
		atomic.StoreInt32(&st.failNext, int32(n))
		writeJSON(w, 200, map[string]any{"fail_next": n})
	})
	mux.HandleFunc("/api/now/table/incident", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(cfg, r) {
			unauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			st.handleQuery(w, r)
		case http.MethodPost:
			st.handleCreate(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})
	// GET/PATCH /api/now/table/incident/{sys_id} — read one incident (inbound state
	// sync) or update it (also used to SIMULATE a human moving the ticket through
	// ServiceNow states during validation).
	mux.HandleFunc("/api/now/table/incident/", func(w http.ResponseWriter, r *http.Request) {
		if !authOK(cfg, r) {
			unauthorized(w)
			return
		}
		switch r.Method {
		case http.MethodGet:
			st.handleGetOne(w, r)
		case http.MethodPatch, http.MethodPut:
			st.handlePatch(w, r)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	srv := &http.Server{
		Addr:              cfg.addr,
		Handler:           logging(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
	}
	log.Printf("mock-servicenow listening on %s (user=%q, bearer=%v) — incident Table API stub", cfg.addr, cfg.user, cfg.token != "")
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("mock-servicenow: %v", err)
	}
}

// ── handlers ─────────────────────────────────────────────────────────────────

func (st *store) handleQuery(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("sysparm_query")
	st.mu.Lock()
	defer st.mu.Unlock()
	var res []map[string]any
	if corr, ok := strings.CutPrefix(q, "correlation_id="); ok {
		if sysID, found := st.byCorr[corr]; found {
			inc := st.incidents[sysID]
			res = append(res, map[string]any{"number": inc["number"], "sys_id": sysID})
		}
	}
	// Health-check (no correlation filter): echo the most recent few so an empty
	// table still proves auth+reachability without leaking a large body.
	if q == "" {
		limit := atoiOr(r.URL.Query().Get("sysparm_limit"), 1)
		for i := len(st.order) - 1; i >= 0 && len(res) < limit; i-- {
			sysID := st.order[i]
			res = append(res, map[string]any{"sys_id": sysID, "number": st.incidents[sysID]["number"]})
		}
	}
	writeJSON(w, 200, map[string]any{"result": res})
}

func (st *store) handleCreate(w http.ResponseWriter, r *http.Request) {
	if st.takeFailure() {
		writeJSON(w, http.StatusServiceUnavailable, snowError("simulated upstream failure (chaos knob)"))
		return
	}
	body := readBody(r)
	st.mu.Lock()
	defer st.mu.Unlock()
	st.seq++
	sysID := fmt.Sprintf("sys%07d", st.seq)
	number := fmt.Sprintf("INC%07d", st.seq)
	body["sys_id"] = sysID
	body["number"] = number
	body["sys_created_on"] = nowStamp()
	st.incidents[sysID] = body
	st.order = append(st.order, sysID)
	if corr, _ := body["correlation_id"].(string); corr != "" {
		st.byCorr[corr] = sysID
	}
	log.Printf("CREATE %s (%s) correlation_id=%v verdict=%v short_description=%q",
		number, sysID, body["correlation_id"], body["u_correlix_verdict"], body["short_description"])
	writeJSON(w, http.StatusCreated, map[string]any{"result": map[string]any{"number": number, "sys_id": sysID}})
}

// handleGetOne serves GET /api/now/table/incident/{sys_id} — the single record the
// inbound state sync reads back. Honors sysparm_fields by returning the whole
// record (a faithful-enough subset for the stub); 404 for an unknown sys_id.
func (st *store) handleGetOne(w http.ResponseWriter, r *http.Request) {
	sysID := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
	st.mu.Lock()
	inc, ok := st.incidents[sysID]
	st.mu.Unlock()
	if !ok {
		writeJSON(w, http.StatusNotFound, snowError("no record for "+sysID))
		return
	}
	writeJSON(w, 200, map[string]any{"result": inc})
}

func (st *store) handlePatch(w http.ResponseWriter, r *http.Request) {
	if st.takeFailure() {
		writeJSON(w, http.StatusServiceUnavailable, snowError("simulated upstream failure (chaos knob)"))
		return
	}
	sysID := strings.TrimPrefix(r.URL.Path, "/api/now/table/incident/")
	patch := readBody(r)
	st.mu.Lock()
	defer st.mu.Unlock()
	inc, ok := st.incidents[sysID]
	if !ok {
		writeJSON(w, http.StatusNotFound, snowError("no record for "+sysID))
		return
	}
	for k, v := range patch {
		inc[k] = v
	}
	// A real ServiceNow stamps these when the state transition happens in the UI;
	// mirror that so a bare `{"state":"6"}` PATCH still yields honest lifecycle
	// timestamps — but never overwrite a caller-supplied value.
	if state := atoiOr(asString(inc["state"]), 0); state > 0 {
		for field, minState := range map[string]int{"work_start": 2, "resolved_at": 6, "closed_at": 7} {
			if state >= minState && asString(inc[field]) == "" {
				inc[field] = nowStamp()
			}
		}
	}
	inc["sys_updated_on"] = nowStamp()
	st.incidents[sysID] = inc
	log.Printf("PATCH  %v (%s) state=%v work_notes=%q", inc["number"], sysID, inc["state"], asString(patch["work_notes"]))
	writeJSON(w, 200, map[string]any{"result": inc})
}

// snapshot returns all incidents in insertion order for /inspect.
func (st *store) snapshot() map[string]any {
	st.mu.Lock()
	defer st.mu.Unlock()
	out := make([]map[string]any, 0, len(st.order))
	for _, sysID := range st.order {
		out = append(out, st.incidents[sysID])
	}
	return map[string]any{"count": len(out), "incidents": out, "fail_next": atomic.LoadInt32(&st.failNext)}
}

// takeFailure consumes one chaos credit; true means "fail this call".
func (st *store) takeFailure() bool {
	for {
		n := atomic.LoadInt32(&st.failNext)
		if n <= 0 {
			return false
		}
		if atomic.CompareAndSwapInt32(&st.failNext, n, n-1) {
			return true
		}
	}
}

// ── auth ─────────────────────────────────────────────────────────────────────

func authOK(cfg config, r *http.Request) bool {
	if cfg.token != "" {
		if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
			return strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")) == cfg.token
		}
	}
	u, p, ok := r.BasicAuth()
	return ok && u == cfg.user && p == cfg.password
}

func unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Basic realm="mock-servicenow"`)
	writeJSON(w, http.StatusUnauthorized, snowError("user not authenticated"))
}

// ── helpers ──────────────────────────────────────────────────────────────────

func snowError(msg string) map[string]any {
	return map[string]any{"error": map[string]any{"message": msg, "detail": ""}, "status": "failure"}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(r *http.Request) map[string]any {
	defer r.Body.Close()
	m := map[string]any{}
	// Bound the body — ServiceNow incident payloads are small.
	_ = json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20)).Decode(&m)
	return m
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
	})
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(strings.TrimSpace(s)); err == nil {
		return n
	}
	return def
}

func asString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}

func nowStamp() string { return time.Now().UTC().Format("2006-01-02 15:04:05") }
