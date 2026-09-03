package pipedebug

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testMarker = "01j9abcdefghjkmnpqrstvwxyz"

func stageOf(t *testing.T, api *API, path string) Entry {
	t.Helper()
	w := call(t, api.HandleStage, http.MethodGet, path, "")
	if w.Code != http.StatusOK {
		t.Fatalf("%s -> %d: %s", path, w.Code, w.Body.String())
	}
	var e Entry
	if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
		t.Fatal(err)
	}
	return e
}

// ── OpenSearch ──────────────────────────────────────────────────────────────

func TestOpenSearchStageSeenCarriesTheDocumentAddressAndTheQuery(t *testing.T) {
	f := newFakeBackend()
	f.osBody = `{"hits":{"total":{"value":1},"hits":[{"_index":"netops-syslog-t1-2026.09.04","_id":"cxk:netops.syslog:2:41","_source":{"timestamp":"2026-09-04T11:05:07Z","message":"cx_synthetic=true cx_debug=` + testMarker + `","topic":"netops.syslog"}}]}}`
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker+"&tenant=t1")
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s, want seen: %s", e.Verdict, e.Reason)
	}
	if e.EvidenceRef != "netops-syslog-t1-2026.09.04#cxk:netops.syslog:2:41" {
		t.Errorf("evidence ref does not address the document: %q", e.EvidenceRef)
	}
	if e.FirstSeen.IsZero() {
		t.Error("the store's own timestamp was not carried — the timeline cannot compute a latency without it")
	}
	// The exact query is returned verbatim so an operator can re-run it.
	if !strings.Contains(e.Query, "match_phrase") || !strings.Contains(e.Query, MarkerTag(testMarker)) {
		t.Errorf("the query is not reproducible from the answer: %q", e.Query)
	}
}

func TestOpenSearchStageNotSeenIsDistinctFromNotObservable(t *testing.T) {
	f := newFakeBackend() // 200 with zero hits
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("an empty result must be not_seen, got %s", e.Verdict)
	}

	// A store that REFUSED the query is not_observable — reporting it as
	// not_seen would blame the pipeline for a query failure.
	f.osStatus = 503
	api = New(f.deps())
	e = stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if e.Verdict != VerdictNotObservable || !strings.Contains(e.Reason, "503") {
		t.Fatalf("a refusing store was reported as %s (%q)", e.Verdict, e.Reason)
	}

	// Undecodable JSON is likewise not_observable, never an empty result.
	f.osStatus, f.osBody = 200, "<html>gateway error</html>"
	api = New(f.deps())
	e = stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("an undecodable body was reported as %s", e.Verdict)
	}
}

func TestOpenSearchStageQueriesTheTenantScopedIndex(t *testing.T) {
	f := newFakeBackend()
	f.principal = Principal{Subject: "owner", Tenant: "t_own", Cross: false}
	api := New(f.deps())
	stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if !strings.Contains(f.osIndex, "netops-syslog-t_own-*") {
		t.Errorf("a scoped principal's stage query did not name its own tenant index: %q", f.osIndex)
	}
	if strings.Contains(f.osIndex, "netops-syslog-*") {
		t.Error("a scoped principal's stage query named the cross-tenant pattern")
	}
}

func TestOpenSearchStageUsesTheTrapIndexForTheTrapKind(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker+"&kind=trap")
	if !strings.Contains(f.osIndex, "snmptrap") {
		t.Errorf("trap kind queried %q", f.osIndex)
	}
}

func TestOpenSearchResponseIsSizeBounded(t *testing.T) {
	f := newFakeBackend()
	f.osBody = strings.Repeat("x", maxStoreResponse+16)
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/opensearch?marker="+testMarker)
	if e.Verdict != VerdictNotObservable || !strings.Contains(e.Reason, "cap") {
		t.Errorf("an oversized store response was not refused: %s / %s", e.Verdict, e.Reason)
	}
}

// ── Kafka peek ──────────────────────────────────────────────────────────────

func TestKafkaStageSeenCarriesTopicPartitionOffset(t *testing.T) {
	f := newFakeBackend()
	f.peek = PeekResult{Records: []PeekRecord{{
		Topic: "netops.syslog", Partition: 2, Offset: 41,
		Timestamp: time.Date(2026, 9, 4, 11, 5, 7, 0, time.UTC).UnixMilli(),
		Excerpt:   "cx_debug=" + testMarker,
	}}, Scanned: 12, ElapsedS: 0.4}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/kafka?marker="+testMarker)
	if e.Verdict != VerdictSeen || e.EvidenceRef != "netops.syslog[2]@41" {
		t.Fatalf("kafka stage: %s / %q", e.Verdict, e.EvidenceRef)
	}
	if e.FirstSeen.IsZero() {
		t.Error("the bus timestamp was not carried")
	}
}

// THE inversion this whole feature exists to prevent: an unavailable peek must
// NEVER read as "the marker was not on the bus".
func TestKafkaPeekFailureIsNotObservableNotNotSeen(t *testing.T) {
	f := newFakeBackend()
	f.peekErr = errors.New("the correlation debug sidecar is not configured")
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/kafka?marker="+testMarker)
	if e.Verdict != VerdictNotObservable {
		t.Fatalf("an unavailable peek was reported as %s", e.Verdict)
	}
	if !strings.Contains(e.Reason, "not configured") {
		t.Errorf("the reason does not name the cause: %q", e.Reason)
	}
}

func TestKafkaStageNotSeenReportsWhatWasScanned(t *testing.T) {
	f := newFakeBackend()
	f.peek = PeekResult{Scanned: 250, ElapsedS: 9.8}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/kafka?marker="+testMarker)
	if e.Verdict != VerdictNotSeen || !strings.Contains(e.Reason, "250") {
		t.Errorf("a genuine miss does not say how hard it looked: %s / %q", e.Verdict, e.Reason)
	}
}

func TestKafkaStageIsNotObservableWithNoPeekSeam(t *testing.T) {
	f := newFakeBackend()
	d := f.deps()
	d.KafkaPeek = nil
	e := New(d).KafkaStage(context.Background(), KindSyslog, testMarker)
	if e.Verdict != VerdictNotObservable {
		t.Errorf("a missing seam was reported as %s", e.Verdict)
	}
}

// ── VictoriaMetrics and ClickHouse: honest not-observable ───────────────────

func TestVictoriaAndClickHouseAreHonestlyNotObservableForLogKinds(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	for _, kind := range []string{"syslog", "trap"} {
		vm := stageOf(t, api, "/api/debug/stage/victoria?marker="+testMarker+"&kind="+kind)
		if vm.Verdict != VerdictNotObservable {
			t.Errorf("victoria/%s = %s; a log record mints no per-record series, so not_seen would imply one was expected", kind, vm.Verdict)
		}
		if !strings.Contains(vm.Reason, "no per-record metric series") {
			t.Errorf("victoria/%s reason does not explain itself: %q", kind, vm.Reason)
		}
		ch := stageOf(t, api, "/api/debug/stage/clickhouse?marker="+testMarker+"&kind="+kind)
		if ch.Verdict != VerdictNotObservable || !strings.Contains(ch.Reason, "no ClickHouse raw row") {
			t.Errorf("clickhouse/%s = %s (%q)", kind, ch.Verdict, ch.Reason)
		}
	}
	if len(f.chSeen) != 0 {
		t.Error("the ClickHouse stage ran a query for a kind that has no raw table")
	}
}

// ── correlation ─────────────────────────────────────────────────────────────

func TestCorrelationStageQueriesCorrEvidenceUnderTheCallersScopeAndChecksTheDLQ(t *testing.T) {
	f := newFakeBackend()
	f.principal = Principal{Subject: "a", Tenant: "t_own", Cross: false}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/correlation?marker="+testMarker)
	if e.Verdict != VerdictNotSeen {
		t.Fatalf("verdict %s", e.Verdict)
	}
	if len(f.chSeen) != 1 || !strings.HasPrefix(f.chSeen[0], "t_own|") {
		t.Fatalf("the query did not carry the caller's ClickHouse scope: %v", f.chSeen)
	}
	if !strings.Contains(f.chSeen[0], "netops.corr_evidence") || !strings.Contains(f.chSeen[0], MarkerTag(testMarker)) {
		t.Errorf("the correlation query is wrong: %s", f.chSeen[0])
	}
	// The DLQ check distinguishes "the engine dropped it" from "the engine
	// could not persist it".
	if e.Detail["dead_letter_check"] == nil {
		t.Error("no dead-letter check was reported")
	}
	if !strings.Contains(e.Reason, "pre-filter") {
		t.Errorf("the miss is not explained: %q", e.Reason)
	}
}

func TestCorrelationStageFailureIsNotObservable(t *testing.T) {
	f := newFakeBackend()
	f.chErr = errors.New("clickhouse refused the connection")
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/correlation?marker="+testMarker)
	if e.Verdict != VerdictNotObservable || !strings.Contains(e.Reason, "refused") {
		t.Errorf("a failed query was reported as %s (%q)", e.Verdict, e.Reason)
	}
}

func TestCorrelationStageSeenRedactsTheRowsItReturns(t *testing.T) {
	f := newFakeBackend()
	f.chRows = []map[string]any{{
		"note":       "cx_debug=" + testMarker + " snmp-server community corrLeak RO",
		"created_at": "2026-09-04 11:05:09.000",
	}}
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/correlation?marker="+testMarker)
	if e.Verdict != VerdictSeen || e.FirstSeen.IsZero() {
		t.Fatalf("verdict %s firstSeen %v", e.Verdict, e.FirstSeen)
	}
	buf, err := json.Marshal(e.Detail)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(buf), "corrLeak") {
		t.Error("a community string travelled out of the correlation stage unredacted")
	}
}

// ── the API's own stage ─────────────────────────────────────────────────────

func TestAPIStageServesTheInProcessRingNotTheApplogsIndex(t *testing.T) {
	f := newFakeBackend()
	f.ring.Append(testMarker, RingLine{Level: "debug", Component: "trace", Msg: "injected"})
	api := New(f.deps())
	e := stageOf(t, api, "/api/debug/stage/api?marker="+testMarker)
	if e.Verdict != VerdictSeen {
		t.Fatalf("verdict %s (%q)", e.Verdict, e.Reason)
	}
	if !strings.Contains(e.Query, "in-process debug ring") {
		t.Errorf("the api stage claims a source it does not use: %q", e.Query)
	}
	if f.osIndex != "" {
		t.Error("the api stage read OpenSearch — it must not depend on the pipeline under test")
	}
}

func TestAPIStageIsNotSeenForAnUnknownMarker(t *testing.T) {
	api := New(newFakeBackend().deps())
	e := stageOf(t, api, "/api/debug/stage/api?marker="+NewMarker(time.Now()))
	if e.Verdict != VerdictNotSeen {
		t.Errorf("verdict %s", e.Verdict)
	}
}

// ── the trace's own api-stage evidence ──────────────────────────────────────

func TestTraceWritesItsOwnMarkerLineIntoTheRing(t *testing.T) {
	f := newFakeBackend()
	api := New(f.deps())
	w := post(t, api.HandleTrace, "/api/debug/trace", `{"kind":"syslog","device":"spine1"}`)
	var got traceReceipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(f.ring.Lines(got.Marker)) == 0 {
		t.Error("the trace left no api-stage evidence in the ring")
	}
}

func TestValidTopicIsAClosedGrammar(t *testing.T) {
	for _, ok := range []string{"netops.syslog", "netops-snmptrap_1"} {
		if !ValidTopic(ok) {
			t.Errorf("ValidTopic(%q) rejected a legal topic", ok)
		}
	}
	for _, bad := range []string{"", "netops.syslog;drop", "../x", strings.Repeat("a", 300), "a b"} {
		if ValidTopic(bad) {
			t.Errorf("ValidTopic(%q) accepted an illegal topic", bad)
		}
	}
}
