// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

// stubUIHost is a UIQueryHost that answers from memory, so the dispatch and the
// bounded-capture behaviour can be tested without a live store.
type stubUIHost struct {
	scopeIndex   string
	scopeFilters []any
	scopeMustNot []any
	denyAll      bool
	forbidden    bool
	synthetic    map[string]any
	flowBody     string
	flowStatus   int
	metricBody   string
	metricStatus int
}

func (h *stubUIHost) LogsScope(*http.Request, string) (string, []any, []any, bool, bool) {
	return h.scopeIndex, h.scopeFilters, h.scopeMustNot, h.denyAll, h.forbidden
}
func (h *stubUIHost) SyntheticExclusion() map[string]any { return h.synthetic }
func (h *stubUIHost) SearchOpenSearch(string, string, any) (*http.Response, error) {
	return nil, errors.New("no OpenSearch in this test")
}
func (h *stubUIHost) IndexPatternFor(signal, _ string, _ bool) string { return signal + "-*" }
func (h *stubUIHost) ServeFlowsTopTalkers(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(h.flowStatus)
	_, _ = w.Write([]byte(h.flowBody))
}
func (h *stubUIHost) ServeMetricsQueryRange(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(h.metricStatus)
	_, _ = w.Write([]byte(h.metricBody))
}

// THE CLAUSE THIS TEST GUARDS is the only thing standing between an injected
// probe and an operator's log search. `withoutSyntheticExclusion` lifts it for
// the UI-query stage, and it reports whether it actually found it — if LogsScope
// ever stopped adding it, the lift would silently do nothing and ui.log would
// claim a check it did not perform.
func TestWithoutSyntheticExclusionDropsExactlyTheSyntheticClause(t *testing.T) {
	want := map[string]any{"match_phrase": map[string]any{"message": SyntheticTag}}
	tenantClause := map[string]any{"terms": map[string]any{"tenant_id": []string{"t_other"}}}
	mustNot := []any{tenantClause, map[string]any{"match_phrase": map[string]any{"message": SyntheticTag}}}

	kept, dropped := withoutSyntheticExclusion(mustNot, want)
	if !dropped {
		t.Fatal("the synthetic clause was not found — the lift would be a silent no-op")
	}
	if len(kept) != 1 || !reflect.DeepEqual(kept[0], tenantClause) {
		t.Fatalf("the compliance clause was not preserved: %v", kept)
	}

	// A scope with no synthetic clause must report dropped=false rather than
	// pretending it lifted one.
	kept, dropped = withoutSyntheticExclusion([]any{tenantClause}, want)
	if dropped {
		t.Fatal("dropped=true for a list that never carried the clause")
	}
	if len(kept) != 1 {
		t.Fatalf("kept %d clauses, want 1", len(kept))
	}
}

// captureWriter runs a REAL handler for its result. It must be bounded: a
// handler streaming megabytes must not be able to grow this buffer without
// limit, and a truncated body must SAY it was truncated rather than decode to
// "no rows" — which would read as a missing record.
func TestCaptureWriterIsBoundedAndReportsTruncation(t *testing.T) {
	cw := newCaptureWriter()
	if cw.status != http.StatusOK {
		t.Fatalf("default status %d, want 200 (a handler that writes a body without WriteHeader implies 200)", cw.status)
	}
	n, err := cw.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("Write: %d, %v", n, err)
	}
	if cw.overflow {
		t.Fatal("a small write reported overflow")
	}
	big := make([]byte, maxUIProbeBody+1024)
	if _, err := cw.Write(big); err != nil {
		t.Fatalf("a large write errored instead of truncating: %v", err)
	}
	if !cw.overflow {
		t.Fatal("an oversized body was truncated SILENTLY — a short body that decodes to zero rows reads as a missing record")
	}
	if cw.buf.Len() > maxUIProbeBody {
		t.Fatalf("the buffer grew to %d, past the %d cap", cw.buf.Len(), maxUIProbeBody)
	}
	// Further writes must stay capped, not append.
	before := cw.buf.Len()
	if _, err := cw.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if cw.buf.Len() != before {
		t.Fatalf("the buffer grew past the cap on a later write: %d -> %d", before, cw.buf.Len())
	}
}

// The probe runs the SPA's real handler, so it must carry the caller's
// authenticated CONTEXT — that is what keeps the tenant scoping production-real
// rather than a re-implementation that could drift open.
func TestCloneWithQueryKeepsTheCallersContextAndRetargetsTheRequest(t *testing.T) {
	orig := httptest.NewRequest(http.MethodPost, "/api/debug/stage/ui?marker=x", strings.NewReader(`{"a":1}`))
	type ctxKey struct{}
	orig = orig.WithContext(context.WithValue(orig.Context(), ctxKey{}, "claims"))

	q := url.Values{}
	q.Set("since", "1800s")
	q.Set("src", "192.0.2.7")
	out := cloneWithQuery(orig, "/api/flows/top", q)

	if out.Method != http.MethodGet {
		t.Errorf("method %s, want GET", out.Method)
	}
	if out.URL.Path != "/api/flows/top" {
		t.Errorf("path %s", out.URL.Path)
	}
	if got := out.URL.Query().Get("src"); got != "192.0.2.7" {
		t.Errorf("src %q", got)
	}
	if out.Context().Value(ctxKey{}) != "claims" {
		t.Fatal("the caller's context was dropped — the probe would run unscoped, which is a cross-tenant read")
	}
	if out.ContentLength != 0 || out.Body != http.NoBody {
		t.Error("the original POST body was carried onto a GET")
	}
	if orig.URL.Path != "/api/debug/stage/ui" {
		t.Error("the original request was mutated")
	}
}

func TestClickHouseRowCountReadsBothShapes(t *testing.T) {
	n, err := clickHouseRowCount([]byte(`{"data":[{"src":"192.0.2.1"}],"rows":1}`))
	if err != nil || n != 1 {
		t.Fatalf("rows form: %d, %v", n, err)
	}
	n, err = clickHouseRowCount([]byte(`{"data":[{"a":1},{"b":2}]}`))
	if err != nil || n != 2 {
		t.Fatalf("data form: %d, %v", n, err)
	}
	if n, err = clickHouseRowCount(nil); err != nil || n != 0 {
		t.Fatalf("empty: %d, %v", n, err)
	}
	// An undecodable body is an ERROR, never zero rows: "the store answered
	// something we could not read" and "the record is not there" are different
	// findings, and the UI stage must not collapse them.
	if _, err = clickHouseRowCount([]byte("<html>502</html>")); err == nil {
		t.Fatal("an undecodable ClickHouse body was reported as zero rows")
	}
}

// Every kind must have a probe. A kind with a contract entry but no probe would
// report not_observable for a stage the api is perfectly able to answer.
//
// The dispatch is asserted, not executed for the log kinds: running those needs
// a live store, and a test that reached for one would be testing the lab.
func TestEveryKindHasAUIProbe(t *testing.T) {
	u := uiRunner{host: &stubUIHost{}}
	for _, kind := range Kinds {
		if _, ok := UIQueryFor(kind); !ok {
			t.Errorf("kind %s has no UI-query contract entry", kind)
		}
		if _, ok := u.probeFor(kind); !ok {
			t.Errorf("kind %s has a contract entry but no probe — its UI stage would report not_observable for a query the api can run", kind)
		}
	}
	if _, ok := u.probeFor(Kind("netconf")); ok {
		t.Error("an unknown kind resolved to a probe")
	}
	if _, err := u.run(httptest.NewRequest(http.MethodGet, "/", nil),
		Kind("netconf"), "01j9abcdefghjkmnpqrstvwxyz", PassiveSpec{}, ""); err == nil {
		t.Error("an unknown kind did not produce an error")
	}
}

// A nil host must yield a nil seam, so the UI stage reports "not wired" rather
// than panicking in the middle of a trace.
func TestNewUIQueryRunWithNoHostIsNil(t *testing.T) {
	if NewUIQueryRun(nil) != nil {
		t.Fatal("a nil host produced a live seam")
	}
	if NewUIQueryRun(&stubUIHost{}) == nil {
		t.Fatal("a real host produced no seam")
	}
}

// The flow and gNMI probes run the api's REAL handlers. These assert the
// runner reads their answers rather than inventing one, including that a
// non-2xx is an error and not "zero rows".
func TestFlowAndMetricProbesReadTheRealHandlersAnswer(t *testing.T) {
	host := &stubUIHost{
		flowStatus:   http.StatusOK,
		flowBody:     `{"data":[{"src":"192.0.2.1"}],"rows":1}`,
		metricStatus: http.StatusOK,
		metricBody:   `{"status":"success","data":{"result":[{"metric":{},"values":[[1,"2"],[3,"4"]]}]}}`,
	}
	u := uiRunner{host: host}
	r := httptest.NewRequest(http.MethodGet, "/", nil)

	probe, err := u.probeFlows(r, "01j9abcdefghjkmnpqrstvwxyz")
	if err != nil || !probe.Found || probe.Rows != 1 {
		t.Fatalf("flow probe: %+v, %v", probe, err)
	}
	probe, err = u.probeMetrics(r, PassiveSpec{Device: "r1", Path: "/interfaces"})
	if err != nil || !probe.Found || probe.Rows != 1 {
		t.Fatalf("metric probe: %+v, %v", probe, err)
	}
	if got := probe.Detail["points"]; got != 2 {
		t.Fatalf("points %v, want 2", got)
	}

	host.flowStatus = http.StatusBadGateway
	if _, err := u.probeFlows(r, "01j9abcdefghjkmnpqrstvwxyz"); err == nil {
		t.Fatal("a 502 from the real handler was reported as a successful probe")
	}
	host.metricStatus = http.StatusForbidden
	if _, err := u.probeMetrics(r, PassiveSpec{}); err == nil {
		t.Fatal("a 403 from the real handler was reported as a successful probe")
	}
}

// A policy denial of the whole log scope is a POLICY answer, not a pipeline
// one, and must not read as "the record is missing".
func TestLogProbeDistinguishesPolicyDenialFromAMissingRecord(t *testing.T) {
	u := uiRunner{host: &stubUIHost{denyAll: true}}
	probe, err := u.probeLogs(httptest.NewRequest(http.MethodGet, "/", nil), KindSyslog, "m")
	if err != nil {
		t.Fatalf("deny-all: %v", err)
	}
	if probe.Found || !strings.Contains(probe.Note, "policy answer") {
		t.Fatalf("a policy denial did not say so: %+v", probe)
	}

	u = uiRunner{host: &stubUIHost{forbidden: true}}
	if _, err := u.probeLogs(httptest.NewRequest(http.MethodGet, "/", nil), KindSyslog, "m"); err == nil {
		t.Fatal("a forbidden scope was reported as a clean probe")
	}
}
