// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// http_test.go — the isolation and honesty tests for the HTTP surface.
//
// THE ISOLATION HARNESS. `fakeOS` is index-aware: it holds documents keyed by
// the index they live in and returns ONLY the ones whose index matches the
// pattern the handler actually asked for. So "acme must not see globex's lines"
// is proven the way it is enforced in production — by the index pattern — and
// not by a stub that hands back whatever it was seeded with. Every request path
// and body is recorded, so the tenant clause is asserted on the WIRE.
//
// The route-level RBAC wiring (requirePlatformAdmin / requirePerm /
// principalTenant) lives in package backend and is exercised by its own
// cross-org suite; here the gate is the injected seam, so what is proven is
// that each handler asks for the RIGHT gate and refuses when the gate refuses.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"netops/backend/internal/oslog"
)

// ---- fakes -------------------------------------------------------------------

type osDoc struct {
	index string
	src   map[string]any
}

type fakeOS struct {
	mu      sync.Mutex
	paths   []string
	bodies  []map[string]any
	docs    []osDoc
	stamped map[string]int64 // index → count of stamped docs
	version string
	fail    error
	notFnd  bool
}

func (f *fakeOS) matches(pattern, index string) bool {
	for _, p := range strings.Split(pattern, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if star := strings.IndexByte(p, '*'); star >= 0 {
			if strings.HasPrefix(index, p[:star]) {
				return true
			}
			continue
		}
		if p == index {
			return true
		}
	}
	return false
}

func (f *fakeOS) search(method, path string, body any) (*http.Response, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, f.fail
	}
	f.paths = append(f.paths, path)
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var b map[string]any
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, err
	}
	f.bodies = append(f.bodies, b)
	if f.notFnd {
		return jsonResp(http.StatusNotFound, `{"error":"index_not_found_exception"}`), nil
	}

	pattern := strings.TrimPrefix(path, "/")
	pattern = pattern[:strings.Index(pattern, "/_search")]

	size := int(b["size"].(float64))
	if size == 0 {
		if _, isProbe := b["aggs"]; isProbe {
			var n int64
			for idx, c := range f.stamped {
				if f.matches(pattern, idx) {
					n += c
				}
			}
			buckets := "[]"
			if n > 0 && f.version != "" {
				buckets = fmt.Sprintf(`[{"key":%q,"doc_count":%d}]`, f.version, n)
			}
			return jsonResp(http.StatusOK, fmt.Sprintf(
				`{"hits":{"total":{"value":%d}},"aggregations":{"versions":{"buckets":%s}}}`, n, buckets)), nil
		}
		var n int64
		for idx, c := range f.stamped {
			if f.matches(pattern, idx) {
				n += c
			}
		}
		for _, d := range f.docs {
			if f.matches(pattern, d.index) {
				n++
			}
		}
		return jsonResp(http.StatusOK, fmt.Sprintf(`{"hits":{"total":{"value":%d}}}`, n)), nil
	}

	// scan page
	after := -1
	if sa, ok := b["search_after"].([]any); ok && len(sa) > 0 {
		after = int(sa[0].(float64))
	}
	hits := make([]map[string]any, 0, size)
	for i, d := range f.docs {
		if i <= after || !f.matches(pattern, d.index) {
			continue
		}
		hits = append(hits, map[string]any{"_source": d.src, "sort": []any{i}})
		if len(hits) == size {
			break
		}
	}
	out, err := json.Marshal(map[string]any{"hits": map[string]any{
		"total": map[string]any{"value": len(hits)}, "hits": hits}})
	if err != nil {
		return nil, err
	}
	return jsonResp(http.StatusOK, string(out)), nil
}

func jsonResp(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
}

// harness wires an API over fakes and records what each handler wrote.
type harness struct {
	api      *API
	os       *fakeOS
	metrics  *Metrics
	audits   []map[string]any
	gate     Gate // the gate the last Authz call asked for
	deny     map[Gate]int
	replicas map[string]string // url → body
	now      time.Time
}

func newHarness(t *testing.T, p Principal) *harness {
	t.Helper()
	h := &harness{
		os:       &fakeOS{stamped: map[string]int64{}},
		metrics:  NewMetrics(),
		deny:     map[Gate]int{},
		replicas: map[string]string{},
		now:      time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC),
	}
	h.api = New(Deps{
		Authz: func(w http.ResponseWriter, r *http.Request, g Gate) (Principal, bool) {
			h.gate = g
			if status, denied := h.deny[g]; denied {
				w.WriteHeader(status)
				return Principal{}, false
			}
			return p, true
		},
		Search: h.os.search,
		Fetch: func(ctx context.Context, url string) ([]byte, error) {
			body, ok := h.replicas[url]
			if !ok {
				return nil, fmt.Errorf("no such replica endpoint %q", url)
			}
			return []byte(body), nil
		},
		Replicas: func(ctx context.Context) []string {
			seen := map[string]bool{}
			out := []string{}
			for u := range h.replicas {
				base := strings.TrimSuffix(strings.TrimSuffix(u, "/healthz"), "/metrics")
				if !seen[base] {
					seen[base] = true
					out = append(out, base)
				}
			}
			// deterministic order
			for i := 0; i < len(out); i++ {
				for j := i + 1; j < len(out); j++ {
					if out[j] < out[i] {
						out[i], out[j] = out[j], out[i]
					}
				}
			}
			return out
		},
		Metrics: h.metrics,
		Audit: func(r *http.Request, tenant, action string, detail map[string]any) {
			d := map[string]any{"tenant": tenant, "action": action}
			for k, v := range detail {
				d[k] = v
			}
			h.audits = append(h.audits, d)
		},
		WriteJSON: func(w http.ResponseWriter, status int, body any) {
			raw, err := json.Marshal(body)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(raw) // test sink: a short write has nothing to recover
		},
		WriteError: func(w http.ResponseWriter, status int, err error) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":` + strconv.Quote(err.Error()) + `}`))
		},
		Now:      func() time.Time { return h.now },
		MaxLines: 500,
	})
	return h
}

func acme() Principal {
	return Principal{Tenant: "acme", Subject: "op@acme", DeviceKeys: []string{"rtr-1"}, DeviceAddrs: []string{"10.0.0.1"}}
}

func platform() Principal {
	return Principal{Tenant: "", Cross: true, Subject: "owner"}
}

func syslogDoc(host, app, mnemonic, msg, sev, ts string) map[string]any {
	return map[string]any{
		"timestamp": ts, "message": msg, "appname": app, "event_type": mnemonic,
		"hostname": host, "severity": sev,
	}
}

func (h *harness) seedStamped(index string, n int64, version string) {
	h.os.stamped[index] = n
	h.os.version = version
}

func (h *harness) seedDoc(index string, src map[string]any) {
	h.os.docs = append(h.os.docs, osDoc{index: index, src: src})
}

func (h *harness) get(t *testing.T, target string) (*httptest.ResponseRecorder, Page) {
	t.Helper()
	w := httptest.NewRecorder()
	h.api.HandleUnrecognized(w, httptest.NewRequest(http.MethodGet, target, nil))
	var page Page
	if w.Code == http.StatusOK {
		if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
			t.Fatalf("decode page: %v (%s)", err, w.Body.String())
		}
	}
	return w, page
}

// ---- isolation ---------------------------------------------------------------

// TestUnrecognizedNamesOnlyTheCallersIndices is the primary isolation
// assertion: the pattern on the WIRE is exactly oslog.TenantIndexPattern's, so
// another tenant's index is never named and its documents are unreachable at
// the storage layer.
func TestUnrecognizedNamesOnlyTheCallersIndices(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 100, "0538afc1b47c")
	h.seedDoc("netops-syslog-acme-2026.09.01",
		syslogDoc("rtr-1", "%LINK-3-UPDOWN", "updown", "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down", "error", "2026-09-01T00:00:00Z"))

	w, page := h.get(t, "/api/telemetry/unrecognized?days=7&limit=50")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(page.Items) != 1 {
		t.Fatalf("expected 1 shape, got %d (%s)", len(page.Items), page.Note)
	}

	want := oslog.TenantIndexPattern("syslog", "acme", false)
	if want != "netops-syslog-acme-*,netops-syslog-untagged-*" {
		t.Fatalf("oslog contract changed under this test: %q", want)
	}
	if len(h.os.paths) == 0 {
		t.Fatal("no OpenSearch request was issued")
	}
	for _, p := range h.os.paths {
		if !strings.HasPrefix(p, "/"+want+"/_search") {
			t.Fatalf("query addressed %q, want the caller's pattern %q", p, want)
		}
		if strings.Contains(p, "globex") {
			t.Fatalf("another tenant's index appeared in the path: %q", p)
		}
	}
	// And the per-doc clause is on every body, byte-identical to
	// oslog.TenantFilter's output.
	wantClause := mustMarshal(t, oslog.TenantFilter("acme", false, []string{"rtr-1"}, []string{"10.0.0.1"}))
	for i, b := range h.os.bodies {
		filters := queryFilters(t, b)
		var found bool
		for _, f := range filters {
			if mustMarshal(t, f) == wantClause {
				found = true
			}
		}
		if !found {
			t.Fatalf("body %d carries no oslog.TenantFilter clause:\n%s\nwant: %s", i, mustMarshal(t, b), wantClause)
		}
	}
}

// TestUnrecognizedReturnsNothingFromAnotherTenant proves the storage-layer
// consequence: globex's documents exist in the fake cluster and never reach an
// acme caller, because acme's pattern does not name globex's index.
func TestUnrecognizedReturnsNothingFromAnotherTenant(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 10, "0538afc1b47c")
	h.seedStamped("netops-syslog-globex-2026.09.01", 10, "0538afc1b47c")
	h.seedDoc("netops-syslog-globex-2026.09.01",
		syslogDoc("gx-rtr-9", "%SECRET-3-LEAK", "leak", "%SECRET-3-LEAK: globex only", "error", "2026-09-01T00:00:00Z"))

	w, page := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(page.Items) != 0 {
		t.Fatalf("acme received %d shape(s) mined from globex's index: %+v", len(page.Items), page.Items)
	}
	if !strings.Contains(page.Note, "No unrecognized") {
		t.Fatalf("an empty result must say why: %q", page.Note)
	}
	body, _ := json.Marshal(page)
	if strings.Contains(string(body), "globex") || strings.Contains(string(body), "gx-rtr-9") {
		t.Fatalf("another tenant's data leaked into the response: %s", body)
	}
}

// TestUnrecognizedPlatformOwnerReadsEveryTenant is the other half of the rule:
// the cross-tenant principal gets the unrestricted pattern and NO per-doc
// clause (oslog.TenantFilter returns nil for cross).
func TestUnrecognizedPlatformOwnerReadsEveryTenant(t *testing.T) {
	h := newHarness(t, platform())
	h.seedStamped("netops-syslog-acme-2026.09.01", 10, "0538afc1b47c")
	h.seedDoc("netops-syslog-globex-2026.09.01",
		syslogDoc("gx-1", "%X-3-Y", "y", "%X-3-Y: something odd here", "error", "2026-09-01T00:00:00Z"))

	w, page := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if len(page.Items) != 1 {
		t.Fatalf("platform owner mined %d shapes, want 1 (%s)", len(page.Items), page.Note)
	}
	for _, p := range h.os.paths {
		if !strings.HasPrefix(p, "/netops-syslog-*/_search") {
			t.Fatalf("platform pattern = %q, want /netops-syslog-*/_search…", p)
		}
	}
	for _, b := range h.os.bodies {
		if strings.Contains(mustMarshal(t, b), `"tenant_id"`) {
			t.Fatalf("the cross-tenant caller's query carries a tenant clause: %s", mustMarshal(t, b))
		}
	}
}

func TestUnrecognizedGateIsInfrastructureRead(t *testing.T) {
	h := newHarness(t, acme())
	h.deny[GateRead] = http.StatusForbidden
	w, _ := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	if h.gate != GateRead {
		t.Fatalf("handler asked for gate %v, want GateRead", h.gate)
	}
	if len(h.os.paths) != 0 {
		t.Fatal("a refused caller still reached OpenSearch")
	}
}

// TestParserStatsIsPlatformAdminOnly: a tenant admin holds full
// administration:admin, so a scope-blind gate here would be a privilege leak
// (§3a rule 3). The 403 is a legitimate ANSWER the UI renders as a card.
func TestParserStatsIsPlatformAdminOnly(t *testing.T) {
	h := newHarness(t, Principal{Tenant: "acme", Subject: "admin@acme"})
	h.deny[GateStats] = http.StatusForbidden
	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status %d, want 403", w.Code)
	}
	if h.gate != GateStats {
		t.Fatalf("handler asked for gate %v, want GateStats", h.gate)
	}
	if len(h.replicas) != 0 {
		t.Fatal("replicas were configured for a test that must not scrape")
	}
}

// ---- parser stats ------------------------------------------------------------

func TestParserStatsSumsAcrossReplicas(t *testing.T) {
	h := newHarness(t, platform())
	health := func(used int64, rate float64, passed int64) string {
		return fmt.Sprintf(`{"ingest":{"syslog_prefilter_passed":%d,"syslog_prefilter_rejected":2},
		 "parser":{"parser_rev":"2026.09.02-a6","rules_hash":"9f3c1b7ad2e5",
		 "rule_hits":{"syslog.link.updown":10},"shadow_hits":{"syslog.ospf.candidate":3},
		 "generic_fallbacks":{"syslog":4,"trap":1},
		 "semantic_promotion_rate":%v,"promotion_window":10000,"promotion_window_used":%d}}`, passed, rate, used)
	}
	h.replicas["https://c1:8443/healthz"] = health(8000, 0.9, 100)
	h.replicas["https://c1:8443/metrics"] = ""
	h.replicas["https://c2:8443/healthz"] = health(2000, 0.5, 50)
	h.replicas["https://c2:8443/metrics"] = ""

	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var st Stats
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.Prefilter != (Prefilter{Passed: 150, Rejected: 4}) {
		t.Fatalf("prefilter = %+v (must sum both replicas)", st.Prefilter)
	}
	if st.WindowLines != 10000 {
		t.Fatalf("window_lines = %d, want 10000", st.WindowLines)
	}
	if st.PromotionRate == nil || *st.PromotionRate != (0.9*8000+0.5*2000)/10000 {
		t.Fatalf("promotion rate = %v, want the weighted mean", st.PromotionRate)
	}
	if len(st.Rules) != 2 {
		t.Fatalf("rules = %+v", st.Rules)
	}
	for _, r := range st.Rules {
		if r.RuleID == "syslog.link.updown" && r.Hits != 20 {
			t.Fatalf("summed hits = %d, want 20", r.Hits)
		}
		if r.RuleID == "syslog.ospf.candidate" && (!r.Shadow || r.Hits != 6) {
			t.Fatalf("shadow rule folded as %+v", r)
		}
		if r.Lane != "" || r.Kind != "" || r.Fidelity != "" {
			t.Fatalf("rule %q carries metadata the engine never published: %+v", r.RuleID, r)
		}
	}
	if st.GeneratedAt != "2026-09-02T10:00:00Z" {
		t.Fatalf("generated_at = %q", st.GeneratedAt)
	}
}

// TestParserStatsRefusesRatherThanReportZeros: every replica silent is an
// outage, and zeros would read as "the parser classified nothing".
func TestParserStatsRefusesWhenNoReplicaAnswers(t *testing.T) {
	h := newHarness(t, platform())
	h.api.d.Replicas = func(context.Context) []string { return []string{"https://dead:8443"} }
	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502", w.Code)
	}
}

func TestParserStatsRefusesWhenNoReplicaIsConfigured(t *testing.T) {
	h := newHarness(t, platform())
	w := httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodGet, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
}

// ---- the honest refusals -----------------------------------------------------

// TestUnrecognizedRefusesWithoutTheAdmissionStamp is the anti-fabrication test:
// with documents in the window but no engine verdict on any of them, the route
// must 503 rather than report the entire firehose as unrecognized.
func TestUnrecognizedRefusesWithoutTheAdmissionStamp(t *testing.T) {
	h := newHarness(t, acme())
	h.seedDoc("netops-syslog-acme-2026.09.01",
		syslogDoc("rtr-1", "%LINK-3-UPDOWN", "updown", "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down", "error", "2026-09-01T00:00:00Z"))
	w, _ := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503; body %s", w.Code, w.Body.String())
	}
	for _, want := range []string{admissionField, "gen-syslog-admission.py", "will not guess"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Errorf("the 503 does not explain itself (%q missing): %s", want, w.Body.String())
		}
	}
	runs, _ := h.metrics.Snapshot()
	if runs[OutcomeUnavailable] != 1 {
		t.Fatalf("outcome counters = %v, want one %q", runs, OutcomeUnavailable)
	}
}

// TestUnrecognizedTrapLaneIsRefused: no trap-side screen exists, so there is no
// set of "traps the engine would not admit" to mine.
func TestUnrecognizedTrapLaneIsRefused(t *testing.T) {
	h := newHarness(t, acme())
	w, _ := h.get(t, "/api/telemetry/unrecognized?lane=trap")
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", w.Code)
	}
	if !strings.Contains(w.Body.String(), "trap lane publishes no ingest admission stamp") {
		t.Fatalf("unhelpful 503: %s", w.Body.String())
	}
	if len(h.os.paths) != 0 {
		t.Fatal("the trap refusal still queried OpenSearch")
	}
}

func TestUnrecognizedEmptyWindowSaysSo(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 42, "0538afc1b47c")
	_, page := h.get(t, "/api/telemetry/unrecognized")
	if len(page.Items) != 0 || page.Total != 0 {
		t.Fatalf("expected an empty page, got %+v", page)
	}
	if !strings.Contains(page.Note, "No unrecognized syslog lines in the last 7 day(s)") {
		t.Fatalf("note = %q", page.Note)
	}
	if !strings.Contains(page.Note, "0538afc1b47c") {
		t.Fatalf("the note must name the corpus that judged the window: %q", page.Note)
	}
	runs, _ := h.metrics.Snapshot()
	if runs[OutcomeEmpty] != 1 {
		t.Fatalf("outcome counters = %v", runs)
	}
}

func TestUnrecognizedReportsItsOwnTruncation(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 1, "0538afc1b47c")
	for i := 0; i < 600; i++ { // MaxLines is 500 in the harness
		h.seedDoc("netops-syslog-acme-2026.09.01", syslogDoc(
			fmt.Sprintf("rtr-%d", i), "%LINK-3-UPDOWN", "updown",
			fmt.Sprintf("%%LINK-3-UPDOWN: Interface Gi0/%d, changed state to down", i),
			"error", "2026-09-01T00:00:00Z"))
	}
	_, page := h.get(t, "/api/telemetry/unrecognized")
	if !strings.Contains(page.Note, "PARTIAL") || !strings.Contains(page.Note, "PARSERCOV_MAX_LINES") {
		t.Fatalf("a truncated scan must say so: %q", page.Note)
	}
	runs, lines := h.metrics.Snapshot()
	if runs[OutcomePartial] != 1 {
		t.Fatalf("outcome counters = %v, want one %q", runs, OutcomePartial)
	}
	if lines != 500 {
		t.Fatalf("netops_parsercov_lines_scanned_total = %d, want the 500-line cap", lines)
	}
}

func TestUnrecognizedLimitTrimsButTotalIsHonest(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 1, "0538afc1b47c")
	for i := 0; i < 5; i++ {
		h.seedDoc("netops-syslog-acme-2026.09.01", syslogDoc(
			"rtr-1", fmt.Sprintf("APP%d", i), "", fmt.Sprintf("shape%d alpha bravo charlie", i),
			"error", "2026-09-01T00:00:00Z"))
	}
	_, page := h.get(t, "/api/telemetry/unrecognized?limit=2")
	if len(page.Items) != 2 {
		t.Fatalf("items = %d, want the requested 2", len(page.Items))
	}
	if page.Total != 5 {
		t.Fatalf("total = %d, want the honest 5", page.Total)
	}
	if !strings.Contains(page.Note, "showing the 2 largest") {
		t.Fatalf("note = %q", page.Note)
	}
}

// ---- caching -----------------------------------------------------------------

func TestUnrecognizedServesTheSecondCallFromCache(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 5, "0538afc1b47c")
	h.seedDoc("netops-syslog-acme-2026.09.01",
		syslogDoc("rtr-1", "%LINK-3-UPDOWN", "updown", "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down", "error", "2026-09-01T00:00:00Z"))

	_, first := h.get(t, "/api/telemetry/unrecognized")
	n := len(h.os.paths)
	_, second := h.get(t, "/api/telemetry/unrecognized")
	if len(h.os.paths) != n {
		t.Fatalf("the second call issued %d more OpenSearch queries", len(h.os.paths)-n)
	}
	if first.Items[0].TemplateID != second.Items[0].TemplateID {
		t.Fatal("the cached run returned a different template id")
	}
	runs, _ := h.metrics.Snapshot()
	if runs[OutcomeCached] != 1 {
		t.Fatalf("outcome counters = %v, want one %q", runs, OutcomeCached)
	}
	// Past the TTL, it re-mines.
	h.now = h.now.Add(cacheTTL + time.Minute)
	_, _ = h.get(t, "/api/telemetry/unrecognized")
	if len(h.os.paths) == n {
		t.Fatal("an expired cache entry was still served")
	}
}

// ---- propose -----------------------------------------------------------------

func TestProposeDraftsAndAppliesNothing(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 5, "0538afc1b47c")
	h.seedDoc("netops-syslog-acme-2026.09.01",
		syslogDoc("rtr-1", "%LINK-3-UPDOWN", "updown", "%LINK-3-UPDOWN: Interface Gi0/3, changed state to down", "error", "2026-09-01T00:00:00Z"))
	_, page := h.get(t, "/api/telemetry/unrecognized")
	id := page.Items[0].TemplateID

	w := httptest.NewRecorder()
	h.api.HandlePropose(w, httptest.NewRequest(http.MethodPost, "/api/telemetry/unrecognized/"+id+"/propose", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if h.gate != GateWrite {
		t.Fatalf("propose asked for gate %v, want GateWrite", h.gate)
	}
	var prop Proposal
	if err := json.Unmarshal(w.Body.Bytes(), &prop); err != nil {
		t.Fatal(err)
	}
	if prop.Status != "drafted" || prop.ProposalID != ProposalID(id) {
		t.Fatalf("proposal = %+v", prop)
	}
	if !strings.Contains(prop.CatalogRow, "shadow: true") {
		t.Fatal("the drafted row is not a shadow rule")
	}
	// NOTHING is applied: the only upstream calls this route ever makes are
	// _search reads.
	for _, p := range h.os.paths {
		if !strings.Contains(p, "/_search") {
			t.Fatalf("propose issued a non-search request: %q", p)
		}
	}
	// ...and it is audited, without the device line in the record.
	if len(h.audits) != 1 {
		t.Fatalf("audits = %v", h.audits)
	}
	a := h.audits[0]
	if a["action"] != "parser.catalog_row_drafted" || a["applied"] != false || a["tenant"] != "acme" {
		t.Fatalf("audit record = %v", a)
	}
	raw := mustMarshal(t, a)
	if strings.Contains(raw, "GigabitEthernet") || strings.Contains(raw, "Interface Gi0/3") {
		t.Fatalf("the audit record embeds the device log line: %s", raw)
	}
}

// TestProposeIsNotAnExistenceOracle: an id that does not resolve in THIS
// caller's scope answers 404 — the same answer another tenant's id gets.
func TestProposeIsNotAnExistenceOracle(t *testing.T) {
	h := newHarness(t, acme())
	h.seedStamped("netops-syslog-acme-2026.09.01", 5, "0538afc1b47c")
	h.seedStamped("netops-syslog-globex-2026.09.01", 5, "0538afc1b47c")
	h.seedDoc("netops-syslog-globex-2026.09.01",
		syslogDoc("gx-1", "%SECRET-3-LEAK", "leak", "%SECRET-3-LEAK: globex only shape", "error", "2026-09-01T00:00:00Z"))

	// Mine as the platform owner to learn globex's real template id...
	po := newHarness(t, platform())
	po.os = h.os
	po.api.d.Search = h.os.search
	_, all := po.get(t, "/api/telemetry/unrecognized")
	if len(all.Items) != 1 {
		t.Fatalf("setup: platform owner mined %d shapes", len(all.Items))
	}
	foreign := all.Items[0].TemplateID

	// ...then ask for it as acme.
	w := httptest.NewRecorder()
	h.api.HandlePropose(w, httptest.NewRequest(http.MethodPost, "/api/telemetry/unrecognized/"+foreign+"/propose", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status %d, want 404 for another tenant's template id; body %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "globex") {
		t.Fatalf("the 404 leaked the other tenant: %s", w.Body.String())
	}
}

func TestProposeValidatesTheTemplateIDShape(t *testing.T) {
	h := newHarness(t, acme())
	for _, bad := range []string{"nope", "t-XYZ", "t-0123456789abc", "..%2f..%2fetc"} {
		w := httptest.NewRecorder()
		h.api.HandlePropose(w, httptest.NewRequest(http.MethodPost, "/api/telemetry/unrecognized/"+bad+"/propose", nil))
		if w.Code != http.StatusBadRequest && w.Code != http.StatusNotFound {
			t.Errorf("template_id %q answered %d, want 400/404", bad, w.Code)
		}
		if len(h.os.paths) != 0 {
			t.Fatalf("a malformed template_id %q still reached OpenSearch", bad)
		}
	}
}

func TestProposePathMatching(t *testing.T) {
	cases := map[string]string{
		"/api/telemetry/unrecognized/t-0123456789/propose": "t-0123456789",
		"/api/telemetry/unrecognized/x/propose":            "x",
	}
	for path, want := range cases {
		got, ok := proposePath(path)
		if !ok || got != want {
			t.Errorf("proposePath(%q) = (%q,%v)", path, got, ok)
		}
	}
	for _, path := range []string{
		"/api/telemetry/unrecognized", "/api/telemetry/unrecognized/",
		"/api/telemetry/unrecognized/a/b/propose", "/api/telemetry/unrecognized//propose",
		"/api/telemetry/unrecognized/t-0123456789", "/elsewhere/t-1/propose",
	} {
		if _, ok := proposePath(path); ok {
			t.Errorf("proposePath(%q) matched, want no match", path)
		}
	}
}

// ---- parameters and methods --------------------------------------------------

func TestBoundedQueryParamsFailClosed(t *testing.T) {
	h := newHarness(t, acme())
	for _, q := range []string{
		"?days=0", "?days=31", "?days=abc", "?limit=0", "?limit=201",
		"?lane=applogs", "?page_size=10",
	} {
		w, _ := h.get(t, "/api/telemetry/unrecognized"+q)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%q answered %d, want 400 — a silently ignored parameter is the F-61 failure", q, w.Code)
		}
	}
	if len(h.os.paths) != 0 {
		t.Fatal("a rejected request still reached OpenSearch")
	}
}

func TestMethodsAreConstrained(t *testing.T) {
	h := newHarness(t, acme())
	w := httptest.NewRecorder()
	h.api.HandleUnrecognized(w, httptest.NewRequest(http.MethodPost, "/api/telemetry/unrecognized", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET" {
		t.Fatalf("unrecognized POST → %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
	w = httptest.NewRecorder()
	h.api.HandleStats(w, httptest.NewRequest(http.MethodDelete, "/api/admin/parser/stats", nil))
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("stats DELETE → %d", w.Code)
	}
	w = httptest.NewRecorder()
	h.api.HandlePropose(w, httptest.NewRequest(http.MethodGet, "/api/telemetry/unrecognized/t-0123456789/propose", nil))
	if w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "POST" {
		t.Fatalf("propose GET → %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
}

// TestMissingIndexIsAnEmptyWindowNotAnOutage: a tenant that has never received
// a syslog line has no index family, and a 404 from OpenSearch must render as
// an empty, explained window.
func TestMissingIndexIsAnEmptyWindowNotAnOutage(t *testing.T) {
	h := newHarness(t, acme())
	h.os.notFnd = true
	w, page := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if page.Note == "" {
		t.Fatal("an empty page must carry a reason")
	}
}

func TestUpstreamFailureIsABadGatewayNotAnEmptyList(t *testing.T) {
	h := newHarness(t, acme())
	h.os.fail = fmt.Errorf("connection refused")
	w, _ := h.get(t, "/api/telemetry/unrecognized")
	if w.Code != http.StatusBadGateway {
		t.Fatalf("status %d, want 502 — an outage must never render as 'you have no unrecognized lines'", w.Code)
	}
	runs, _ := h.metrics.Snapshot()
	if runs[OutcomeError] != 1 {
		t.Fatalf("outcome counters = %v", runs)
	}
}

// ---- metrics ------------------------------------------------------------------

func TestMetricsExposeEverySeriesIncludingZeros(t *testing.T) {
	m := NewMetrics()
	m.IncRun(OutcomeOK)
	m.AddLines(7)
	m.IncRun("not-a-real-outcome") // dropped, never mislabelled
	var buf bytes.Buffer
	m.Write(&buf)
	out := buf.String()
	for _, o := range Outcomes {
		if !strings.Contains(out, fmt.Sprintf("netops_parsercov_mining_runs_total{outcome=%q}", o)) {
			t.Errorf("series for outcome %q is absent — a zero series and a missing series mean different things", o)
		}
	}
	if !strings.Contains(out, "netops_parsercov_lines_scanned_total 7") {
		t.Fatalf("lines counter: %s", out)
	}
	if strings.Contains(out, "not-a-real-outcome") {
		t.Fatal("an unknown outcome widened the label set")
	}
	runs, lines := m.Snapshot()
	if runs[OutcomeOK] != 1 || lines != 7 {
		t.Fatalf("snapshot = %v / %d", runs, lines)
	}
	// A nil Metrics is inert, not a panic (the field is optional in Deps).
	var nilM *Metrics
	nilM.IncRun(OutcomeOK)
	nilM.AddLines(1)
	nilM.Write(&buf)
}

// ---- helpers ------------------------------------------------------------------

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func queryFilters(t *testing.T, body map[string]any) []any {
	t.Helper()
	q, ok := body["query"].(map[string]any)
	if !ok {
		t.Fatalf("body has no query: %v", body)
	}
	b, ok := q["bool"].(map[string]any)
	if !ok {
		t.Fatalf("query has no bool: %v", q)
	}
	f, _ := b["filter"].([]any)
	return f
}
