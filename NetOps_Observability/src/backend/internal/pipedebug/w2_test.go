// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ── (b) flow ────────────────────────────────────────────────────────────────

// A flow trace injects a NetFlow v5 datagram into the STACK's own collector and
// never touches a device.
func TestFlowTraceInjectsANetFlowV5Packet(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"flow","device":"spine1"}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("flow trace -> %d: %s", w.Code, w.Body.String())
	}
	if len(f.snap().injectedFlow) != 1 {
		t.Fatalf("injected %d flow packets, want 1", len(f.snap().injectedFlow))
	}
	if len(f.snap().injectedSyslog) != 0 || len(f.snap().injectedTrap) != 0 {
		t.Fatal("a flow trace also injected on another lane")
	}
	var receipt traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	pkt := f.snap().injectedFlow[0]
	fp := NewFlowFingerprint(receipt.Marker)
	if len(pkt) != 72 || pkt[0] != 0 || pkt[1] != 5 {
		t.Fatalf("the injected packet is not a one-record NetFlow v5 export (%d bytes, version bytes %v)", len(pkt), pkt[:2])
	}
	if !strings.Contains(FlowMarkerCH(receipt.Marker), fp.SrcAddr) {
		t.Fatal("the ClickHouse predicate and the injected packet disagree about the fingerprint")
	}
}

// The flow stage evidence is ClickHouse, and the tenant scope is injected.
func TestFlowClickHouseStageIsScopedAndExact(t *testing.T) {
	f := newFakeBackend()
	f.principal = Principal{Subject: "op", Tenant: "t_own"}
	f.chRows = []map[string]any{{"ts": "2026-09-04 11:05:07.100", "src_addr": "192.0.2.9"}}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/clickhouse?marker="+testMarker+"&kind=flow")
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Reason)
	}
	if len(f.snap().chSeen) == 0 || !strings.HasPrefix(f.snap().chSeen[0], "t_own|") {
		t.Fatalf("the flow stage query was not run under the caller's tenant scope: %v", f.snap().chSeen)
	}
	if !strings.Contains(f.snap().chSeen[0], "netops.flows") {
		t.Fatalf("the flow stage did not query the canonical flow table: %s", f.snap().chSeen[0])
	}
	if e.FirstSeen.IsZero() {
		t.Error("the row's own ts was not carried, so the timeline cannot compute a latency")
	}
}

// OpenSearch holds a 1-in-50 SAMPLE of flows. A miss there is not evidence of
// loss and must never be rendered as not_seen.
func TestFlowOpenSearchMissIsNotObservableNotNotSeen(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker+"&kind=flow")
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("a sampled-lane miss was reported as %s — that reads as a loss", e.Verdict)
	}
	if !strings.Contains(e.Reason, "1-in-50") || !strings.Contains(e.Reason, "ClickHouse") {
		t.Errorf("the sampling caveat is not in the reason: %q", e.Reason)
	}
	// A syslog miss, by contrast, IS a real not_seen.
	e = stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("a syslog miss should stay not_seen, got %s", e.Verdict)
	}
}

// The bus needle for a flow is loose (one documentation address); the API is
// what makes the claim exact. A record that carries the needle but not the full
// fingerprint must NOT be filed as this trace's evidence.
func TestFlowKafkaStageVerifiesTheFullFingerprint(t *testing.T) {
	fp := NewFlowFingerprint(testMarker)
	f := newFakeBackend()
	f.peek = PeekResult{Scanned: 30, Records: []PeekRecord{{
		Topic: "netops.flows.raw", Partition: 0, Offset: 9,
		Excerpt: `{"src_addr":"` + fp.SrcAddr + `","dst_addr":"203.0.113.7","src_port":1}`,
	}}}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/kafka?marker="+testMarker+"&kind=flow")
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("a partial match was accepted as this trace's record: %s", e.Verdict)
	}
	if !strings.Contains(e.Reason, "full fingerprint") {
		t.Errorf("the reason does not explain the verification: %q", e.Reason)
	}

	f.peek.Records[0].Excerpt = `{"src_addr":"` + fp.SrcAddr + `","dst_addr":"` + fp.DstAddr +
		`","src_port":` + itoa(int(fp.SrcPort)) + `,"dst_port":` + itoa(int(fp.DstPort)) + `}`
	api = New(f.deps())
	e = stageOf(t, api, "/api/debug/stage/kafka?marker="+testMarker+"&kind=flow")
	if e.Verdict != VerdictSeen || e.EvidenceRef != "netops.flows.raw[0]@9" {
		t.Fatalf("a full match was not accepted: %s / %q", e.Verdict, e.EvidenceRef)
	}
}

// A flow record has no free-text field, so corr_evidence cannot cite the
// marker. Reporting not_seen would blame the engine for a query that could
// never have hit.
func TestFlowCorrelationStageIsHonestAboutHavingNoTextMarker(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/correlation?marker="+testMarker+"&kind=flow")
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("verdict %s, want not_observable", e.Verdict)
	}
	if len(f.snap().chSeen) != 0 {
		t.Fatal("a query was run that could never have matched")
	}
}

func itoa(n int) string { return strings.TrimSpace(strings.Trim(jsonNum(n), `"`)) }

func jsonNum(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}

// ── (b) passive gNMI ────────────────────────────────────────────────────────

// The rule: a passive request injects NOTHING, on any lane.
func TestPassiveTraceInjectsNothing(t *testing.T) {
	f := newFakeBackend()
	f.vmBody = []byte(`{"metric":{"__name__":"gnmi_interfaces_in_octets","source":"spine1"},"timestamps":[1757000000000],"values":[7]}`)
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace",
		`{"kind":"gnmi","device":"spine1","passive":true,"since_seconds":600}`)
	if w.Code != http.StatusAccepted {
		t.Fatalf("passive gnmi -> %d: %s", w.Code, w.Body.String())
	}
	if len(f.snap().injectedSyslog)+len(f.snap().injectedTrap)+len(f.snap().injectedFlow) != 0 {
		t.Fatal("a --passive request injected a record the operator declined")
	}
	var receipt traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if receipt.Injected || receipt.Synthetic || !receipt.Passive {
		t.Fatalf("the receipt misreports a passive follow: %+v", receipt)
	}
}

func TestPassiveVictoriaStageIsTheLoadBearingEvidence(t *testing.T) {
	f := newFakeBackend()
	f.vmBody = []byte(`{"metric":{"__name__":"gnmi_x","source":"spine1"},"timestamps":[1757000000000,1757000015000],"values":[1,2]}` + "\n")
	api := New(f.deps())
	e := api.PassiveVictoriaStage(t.Context(), PassiveSpec{Kind: KindGNMI, Device: "spine1", Since: 10 * time.Minute})
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Reason)
	}
	if !strings.Contains(f.snap().vmMatch, `source="spine1"`) || !strings.Contains(f.snap().vmMatch, "gnmi_") {
		t.Fatalf("the selector does not query the device's raw gNMI lane: %q", f.snap().vmMatch)
	}
	if e.Detail["samples"] != 2 {
		t.Errorf("samples = %v, want 2", e.Detail["samples"])
	}
	// The weaker claim a passive follow makes must be stated, not implied.
	if claim, _ := e.Detail["claim"].(string); !strings.Contains(claim, "SOME") {
		t.Errorf("the passive claim is not stated as weaker than a marked trace's: %q", claim)
	}

	// An empty export is a real not_seen — that IS the device's whole raw lane.
	f.vmBody = nil
	api = New(f.deps())
	e = api.PassiveVictoriaStage(t.Context(), PassiveSpec{Kind: KindGNMI, Device: "spine1", Since: time.Minute})
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("an empty export was reported as %s", e.Verdict)
	}

	// A store that could not be reached is not_observable, never not_seen.
	f.vmErr = os.ErrDeadlineExceeded
	api = New(f.deps())
	e = api.PassiveVictoriaStage(t.Context(), PassiveSpec{Kind: KindGNMI, Device: "spine1", Since: time.Minute})
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("an unreachable store was reported as %s", e.Verdict)
	}
}

// The path filter reaches a PromQL regex, so its grammar is a security
// boundary, not tidiness.
func TestNormalizePathFilterIsAClosedGrammar(t *testing.T) {
	ok := map[string]string{
		"":                            "",
		"/interfaces/interface/state": "interfaces_interface_state",
		"in-octets":                   "in_octets",
		"  /Interfaces/Counters/  ":   "interfaces_counters",
	}
	for in, want := range ok {
		got, err := NormalizePathFilter(in)
		if err != nil {
			t.Errorf("NormalizePathFilter(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("NormalizePathFilter(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{`.*"} or vector(1) or {x="`, "a|b", "a(b)", "a[b]", "a\\b", "a$", strings.Repeat("x", 129)} {
		if _, err := NormalizePathFilter(bad); err == nil {
			t.Errorf("NormalizePathFilter(%q) accepted a value that would reach a PromQL regex", bad)
		}
	}
	sel := PassiveSeriesSelector("spine1", "in_octets")
	if !strings.Contains(sel, `gnmi_.*in_octets.*`) || !strings.Contains(sel, `source="spine1"`) {
		t.Fatalf("selector: %s", sel)
	}
}

func TestClampSinceIsBounded(t *testing.T) {
	if got := ClampSince(0); got != 10*time.Minute {
		t.Errorf("ClampSince(0) = %s", got)
	}
	if got := ClampSince(72 * time.Hour); got != MaxPassiveSince {
		t.Errorf("ClampSince(72h) = %s, want the cap %s", got, MaxPassiveSince)
	}
}

// ── (c) the UI-query contract ───────────────────────────────────────────────

// THE LINK THE TYPE SYSTEM CANNOT BE: every route in the Go contract table must
// actually be in the SPA's client. A rename that misses one of them fails here
// rather than producing a UI stage that checks a route the UI abandoned.
func TestUIQueryContractMatchesTheFrontendClient(t *testing.T) {
	path := filepath.Join("..", "..", "..", "frontend", "src", "services", "api.ts")
	raw, err := os.ReadFile(path) // #nosec G304 -- a fixed relative path inside the repo
	if err != nil {
		t.Fatalf("the SPA client could not be read (%s): %v — this test is the only thing keeping the contract honest, so it must fail loudly rather than skip", path, err)
	}
	src := string(raw)
	for _, kind := range Kinds {
		q, ok := UIQueries[kind]
		if !ok {
			t.Errorf("kind %s has no UI-query contract entry", kind)
			continue
		}
		if !strings.Contains(src, q.Literal) {
			t.Errorf("kind %s: api.ts does not contain %q — the SPA no longer issues %s, so the UI stage is checking a route nobody calls",
				kind, q.Literal, q.Route)
		}
		if !strings.Contains(src, strings.TrimPrefix(q.APIFn, "api.")+":") {
			t.Errorf("kind %s: api.ts has no %s function", kind, q.APIFn)
		}
	}
}

func TestRenderUIQuerySubstitutesThisRecordsValues(t *testing.T) {
	now := time.Date(2026, 9, 4, 11, 5, 0, 0, time.UTC)
	_, syslogQ, _ := RenderUIQuery(KindSyslog, testMarker, PassiveSpec{}, 0, now)
	if !strings.Contains(syslogQ, MarkerTag(testMarker)) || !strings.Contains(syslogQ, "/api/logs/search") {
		t.Errorf("syslog: %s", syslogQ)
	}
	fp := NewFlowFingerprint(testMarker)
	_, flowQ, _ := RenderUIQuery(KindFlow, testMarker, PassiveSpec{}, 0, now)
	if !strings.Contains(flowQ, "src="+fp.SrcAddr) || !strings.Contains(flowQ, "dst="+fp.DstAddr) {
		t.Errorf("flow: %s", flowQ)
	}
	_, gnmiQ, _ := RenderUIQuery(KindGNMI, testMarker, PassiveSpec{Device: "spine1"}, time.Hour, now)
	if !strings.Contains(gnmiQ, `source="spine1"`) || !strings.Contains(gnmiQ, "/api/metrics/query_range") {
		t.Errorf("gnmi: %s", gnmiQ)
	}
}

func TestUIStageReportsTheAnswerInWords(t *testing.T) {
	f := newFakeBackend()
	f.uiProbe = UIProbe{Found: true, Rows: 1, Ref: "netops-syslog-t1#42", Note: "exclusion lifted"}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/ui?marker="+testMarker)
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Reason)
	}
	answer, _ := e.Detail["answer"].(string)
	if answer != "the api returned the record for the UI's own query: yes" {
		t.Errorf("the answer is not stated plainly: %q", answer)
	}
	if e.Detail["api_ts_function"] != "api.searchLogs" {
		t.Errorf("the contract's call site is not recorded: %v", e.Detail["api_ts_function"])
	}

	// Not found is not_seen (the query ran); a transport failure is
	// not_observable (the query did not).
	f.uiProbe = UIProbe{}
	api = New(f.deps())
	if e = stageOf(t, api, "/api/debug/stage/ui?marker="+testMarker); e.Verdict != VerdictNotSeen {
		t.Fatalf("a miss was reported as %s", e.Verdict)
	}
	f.uiErr = os.ErrPermission
	api = New(f.deps())
	if e = stageOf(t, api, "/api/debug/stage/ui?marker="+testMarker); e.Verdict != VerdictNotObservable {
		t.Fatalf("a failed query was reported as %s", e.Verdict)
	}

	// An unwired seam must say so rather than claim a check that never ran.
	d := f.deps()
	d.UIQueryRun = nil
	api = New(d)
	if e = stageOf(t, api, "/api/debug/stage/ui?marker="+testMarker); e.Verdict != VerdictNotObservable ||
		!strings.Contains(e.Reason, "not wired") {
		t.Fatalf("an unwired UI seam: %s / %q", e.Verdict, e.Reason)
	}
}

// ── (a) the parser stage and the parse-marker switch ────────────────────────

func TestParserStageServesGoCollectorDecisions(t *testing.T) {
	f := newFakeBackend()
	f.ring.Append(testMarker, RingLine{Component: "parse:snmptrap", Msg: "trap decoded",
		Fields: map[string]any{"matched_trap_name": "linkDown"}})
	f.ring.Append(testMarker, RingLine{Component: "trace", Msg: "synthetic record injected"})
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/parser?marker="+testMarker+"&kind=trap")
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s: %s", e.Verdict, e.Reason)
	}
	decisions, _ := e.Detail["decisions"].([]any)
	if len(decisions) != 1 {
		t.Fatalf("the api's own request lines leaked into the parser stage: %v", e.Detail["decisions"])
	}
}

// A kind that is not parsed in Go must get the third verdict, never a miss: an
// empty Go-side answer for a syslog probe says nothing about whether Vector
// parsed it, and rendering it as not_seen points at the wrong hop.
func TestParserStageDoesNotBlameVectorParsedKinds(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/parser?marker="+testMarker+"&kind=syslog")
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("a syslog probe's empty Go-parser answer was reported as %s", e.Verdict)
	}
	if !strings.Contains(e.Reason, "cx_parse_trace") {
		t.Errorf("the reason does not point at where the Vector-side decision path is: %q", e.Reason)
	}
	e = stageOf(t, api, "/api/debug/stage/parser?marker="+testMarker+"&kind=trap")
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("a trap probe with no decision line should be not_seen, got %s", e.Verdict)
	}
}

type fakeParseSwitch struct {
	needle string
	until  time.Time
	on     bool
	armed  []string
	err    error
}

func (f *fakeParseSwitch) Arm(n string, w time.Duration) (time.Time, error) {
	if f.err != nil {
		return time.Time{}, f.err
	}
	f.armed = append(f.armed, n)
	f.needle, f.on = n, true
	f.until = time.Date(2026, 9, 4, 11, 10, 0, 0, time.UTC)
	return f.until, nil
}
func (f *fakeParseSwitch) Disarm() { f.needle, f.on = "", false }
func (f *fakeParseSwitch) Active() (string, time.Time, bool) {
	return f.needle, f.until, f.on
}

func TestParseMarkerRouteArmsBoundedAndDisarms(t *testing.T) {
	sw := &fakeParseSwitch{}
	f := newFakeBackend()
	f.parseFilter = sw
	api := New(f.deps())

	w := call(t, api.HandleParseMarker, http.MethodPut, "/api/debug/parsemarker",
		`{"marker":"`+testMarker+`","for_seconds":99999}`)
	if w.Code != http.StatusOK {
		t.Fatalf("arm -> %d: %s", w.Code, w.Body.String())
	}
	var st ParseMarkerState
	if err := json.Unmarshal(w.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if !st.Armed || st.Marker != testMarker {
		t.Fatalf("state after arm: %+v", st)
	}
	if len(sw.armed) != 1 || sw.armed[0] != testMarker {
		t.Fatalf("arm passed %v", sw.armed)
	}

	// The needle must NOT be audited verbatim: an operator may trace by a
	// message fragment, and a customer's log text in the immutable trail is a
	// PII leak.
	last := f.snap().audits[len(f.snap().audits)-1]
	detail, _ := last["detail"].(map[string]any)
	for _, v := range detail {
		if s, ok := v.(string); ok && strings.Contains(s, testMarker) {
			t.Fatalf("the audit record carries the needle verbatim: %v", detail)
		}
	}

	w = call(t, api.HandleParseMarker, http.MethodPut, "/api/debug/parsemarker", `{"off":true}`)
	if w.Code != http.StatusOK || sw.on {
		t.Fatalf("disarm -> %d, on=%v", w.Code, sw.on)
	}

	// GET reports the state without changing it.
	w = call(t, api.HandleParseMarker, http.MethodGet, "/api/debug/parsemarker", "")
	if w.Code != http.StatusOK || strings.Contains(w.Body.String(), `"armed":true`) {
		t.Fatalf("get -> %d: %s", w.Code, w.Body.String())
	}
}

func TestParseMarkerRouteIsPlatformAdminOnlyAndBounded(t *testing.T) {
	f := newFakeBackend()
	f.parseFilter = &fakeParseSwitch{}
	f.authOK = false
	api := New(f.deps())
	if w := call(t, api.HandleParseMarker, http.MethodPut, "/api/debug/parsemarker", `{"marker":"x"}`); w.Code != http.StatusForbidden {
		t.Fatalf("an unauthorized caller got %d", w.Code)
	}

	f.authOK = true
	api = New(f.deps())
	if w := call(t, api.HandleParseMarker, http.MethodPost, "/api/debug/parsemarker", `{}`); w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST got %d, want 405", w.Code)
	}
	big := `{"marker":"` + strings.Repeat("x", maxDebugBody) + `"}`
	if w := call(t, api.HandleParseMarker, http.MethodPut, "/api/debug/parsemarker", big); w.Code != http.StatusBadRequest {
		t.Fatalf("an oversized body got %d, want 400", w.Code)
	}

	// An unwired filter answers 200 with the reason, not a 5xx: a capability
	// gap must not look like a broken endpoint.
	f.parseFilter = nil
	api = New(f.deps())
	w := call(t, api.HandleParseMarker, http.MethodGet, "/api/debug/parsemarker", "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "no parser decision-trace filter is wired") {
		t.Fatalf("unwired filter -> %d: %s", w.Code, w.Body.String())
	}
}

// ── (d) the /metrics gauges the watchdog reads ──────────────────────────────

type fakeLevel struct {
	level  Level
	revert time.Time
}

func (f fakeLevel) Current() Level      { return f.level }
func (f fakeLevel) RevertAt() time.Time { return f.revert }

// ABSENCE MUST NOT BE POSSIBLE TO CONFUSE WITH ZERO. The watchdog can see
// nothing but these gauges; if they were omitted while nothing was raised, "the
// check could not run" and "the check passed" would look identical to it.
func TestMetricsAreAlwaysExportedEvenAtZero(t *testing.T) {
	out := RenderMetrics(
		map[Module]LevelReader{ModuleAPI: fakeLevel{level: LevelInfo}}, nil)
	for _, want := range []string{
		MetricLevelActive + `{module="api"} 0`,
		MetricLevelRevertAt + `{module="api"} 0`,
		MetricParseActive + " 0",
		MetricParseRevertAt + " 0",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the export is missing %q:\n%s", want, out)
		}
	}
	for _, name := range []string{MetricLevelActive, MetricLevelRevertAt, MetricParseActive, MetricParseRevertAt} {
		if !strings.Contains(out, "# TYPE "+name+" gauge") {
			t.Errorf("%s has no TYPE line", name)
		}
	}
}

func TestMetricsReportARaisedLevelAndAnArmedFilter(t *testing.T) {
	revert := time.Date(2026, 9, 4, 11, 30, 0, 0, time.UTC)
	sw := &fakeParseSwitch{needle: "spine1", until: revert, on: true}
	out := RenderMetrics(
		map[Module]LevelReader{ModuleAPI: fakeLevel{level: LevelDebug, revert: revert}}, sw)
	if !strings.Contains(out, MetricLevelActive+`{module="api"} 1`) {
		t.Errorf("a raised level is not exported as 1:\n%s", out)
	}
	if !strings.Contains(out, MetricLevelRevertAt+`{module="api"} 1757000`) &&
		!strings.Contains(out, MetricLevelRevertAt+`{module="api"} `+itoa(int(revert.Unix()))) {
		t.Errorf("the revert time is not exported:\n%s", out)
	}
	if !strings.Contains(out, MetricParseActive+" 1") {
		t.Errorf("an armed parse filter is not exported as 1:\n%s", out)
	}
	// The needle is a substring of a customer's telemetry. It must never be a
	// metric label.
	if strings.Contains(out, "spine1") {
		t.Fatalf("the armed needle leaked into /metrics:\n%s", out)
	}
}

// A level raised with NO auto-revert armed is the more serious condition, and
// the export must let the watchdog tell it apart from a normal window.
func TestMetricsDistinguishNoRevertArmedFromAFutureRevert(t *testing.T) {
	out := RenderMetrics(
		map[Module]LevelReader{ModuleAPI: fakeLevel{level: LevelDebug}}, nil)
	if !strings.Contains(out, MetricLevelActive+`{module="api"} 1`) ||
		!strings.Contains(out, MetricLevelRevertAt+`{module="api"} 0`) {
		t.Fatalf("a raise with no revert armed is not distinguishable:\n%s", out)
	}
}

// The real LevelSwitch must satisfy the reader the exporter needs.
func TestLevelSwitchIsAMetricsReader(t *testing.T) {
	var _ LevelReader = NewLevelSwitch(ModuleAPI, func(Level) error { return nil })
}
