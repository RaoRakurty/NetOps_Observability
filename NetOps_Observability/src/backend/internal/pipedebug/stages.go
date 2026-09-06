// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// stages.go — the per-stage evidence queries the API serves (design §2).
//
// ONE RULE GOVERNS EVERY FUNCTION HERE: a stage returns `seen`, `not_seen` or
// `not_observable`, and the third always carries the reason. There is no path
// that turns "the store refused the query", "the peek is not configured" or
// "this kind produces no series" into an empty result set that a reader would
// read as "the record was lost here". That inversion is the exact defect the
// 2026-09-02 outage post-mortem is about, at a smaller scale.
//
// Every query is also RETURNED verbatim in the Entry, so an operator can re-run
// it by hand and does not have to trust this code's summary of it.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// maxStoreResponse bounds one store answer. Response size is chosen by the
// peer, so an unbounded read here is an OOM in the API process (audit F-27).
const maxStoreResponse = 8 << 20

// stageWindow is how far back a stage query looks for the marker. A trace is
// minutes old at most; a wider window only adds cost and false neighbours.
const stageWindow = 30 * time.Minute

// SignalFor maps a trace kind onto the log signal its record is stored under,
// or "" when the kind has no OpenSearch signal at all.
func SignalFor(k Kind) string {
	switch k {
	case KindTrap:
		return "snmptrap"
	case KindFlow:
		return "flows"
	case KindGNMI:
		// gNMI is metrics. It never reaches the search tier, and naming a
		// signal it does not have would send the OpenSearch stage looking in an
		// index that cannot contain the record — an "absence" that means
		// nothing but reads like a loss.
		return ""
	default:
		return "syslog"
	}
}

// TopicFor maps a trace kind onto the Kafka topic its record crosses first, or
// "" when the kind does not cross the bus at all in this deployment.
func TopicFor(k Kind) string {
	switch k {
	case KindTrap:
		return "netops.snmptrap"
	case KindFlow:
		// goflow2 produces the RAW topic; vector-router re-keys each record by
		// tenant onto netops.flows (compose: `-transport.kafka.topic
		// netops.flows.raw`). The raw topic is the FIRST bus hop, so it is the
		// one that answers "did the collector put it on the bus".
		return "netops.flows.raw"
	case KindGNMI:
		// gnmic writes straight to VictoriaMetrics over prometheus_write on the
		// default config; only the opt-in correlation lane
		// (GNMIC_CONFIG_FILE=gnmic-correlation.yaml) adds a bus output. The
		// GNMIKafkaTopic helper below answers that honestly per deployment.
		return ""
	default:
		return "netops.syslog"
	}
}

// ValidTopic is the closed grammar for a topic name reaching the peek proxy.
// The value is sent to another service and used to address a Kafka topic, so it
// is checked here rather than trusted from anywhere.
func ValidTopic(t string) bool {
	if t == "" || len(t) > 200 {
		return false
	}
	for _, r := range t {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

// markerQuery is the OpenSearch clause that finds the marker. match_phrase on
// the analysed `message` field: the standard analyser splits `cx_debug=<ulid>`
// into two adjacent tokens, so the phrase form matches exactly that pair and
// nothing else — a term query on an analysed field would never match at all.
func markerQuery(marker string) map[string]any {
	return map[string]any{"match_phrase": map[string]any{"message": MarkerTag(marker)}}
}

// markerQueryFor picks the clause for a kind. A flow document has no message
// field to carry the marker, so it is matched on the fingerprint tuple instead
// (flow.go). `match` rather than `term` on every field: the flows mapping is
// dynamic, and a `term` against a field that happened to be mapped as `text`
// silently matches nothing — a zero-hit answer that is a MAPPING fault dressed
// up as a missing record, which is the exact inversion this package refuses.
func markerQueryFor(kind Kind, marker string) map[string]any {
	if kind != KindFlow {
		return markerQuery(marker)
	}
	f := NewFlowFingerprint(marker)
	return map[string]any{"bool": map[string]any{"filter": []any{
		map[string]any{"match": map[string]any{"src_addr": f.SrcAddr}},
		map[string]any{"match": map[string]any{"dst_addr": f.DstAddr}},
		map[string]any{"match": map[string]any{"src_port": f.SrcPort}},
		map[string]any{"match": map[string]any{"dst_port": f.DstPort}},
	}}}
}

// OSSampledKinds names the kinds whose OpenSearch lane is a SAMPLE, not the
// stream. A miss on a sampled lane is not evidence of loss and must never be
// rendered as `not_seen`.
func osSampleReason(kind Kind) string {
	if kind != KindFlow {
		return ""
	}
	return "OpenSearch receives a 1-in-50 SAMPLE of the flow lane (vector-router `flows_os_sample`), so ~98% of healthy flow records are legitimately absent here. ClickHouse is the canonical flow store and the clickhouse stage below is the authoritative one for this kind"
}

// OpenSearchStage looks for the marker in the tenant's log index.
func (a *API) OpenSearchStage(ctx context.Context, p Principal, kind Kind, marker string, tenant string) Entry {
	e := Entry{Stage: StageOpenSearch, Module: string(StageOpenSearch)}
	signal := SignalFor(kind)
	if signal == "" {
		e.Query = "(none)"
		return notObservable(e, fmt.Sprintf(
			"a %s record never reaches the search tier — it is metric telemetry, and the victoria stage is where it is looked for", kind))
	}
	if a.deps.Search == nil || a.deps.OSIndexPattern == nil {
		return notObservable(e, "no OpenSearch client is wired into this API build")
	}
	index := a.deps.OSIndexPattern(signal, tenant, p.Cross && tenant == "")
	now := a.deps.now()
	body := map[string]any{
		"size":             5,
		"track_total_hits": true,
		"sort":             []any{map[string]any{"timestamp": map[string]string{"order": "asc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				markerQueryFor(kind, marker),
				map[string]any{"range": map[string]any{"timestamp": map[string]string{
					"gte": now.Add(-stageWindow).Format(time.RFC3339),
					"lte": now.Add(time.Minute).Format(time.RFC3339),
				}}},
			},
		}},
	}
	e.Query = fmt.Sprintf("POST /%s/_search %s", index, compact(body))

	resp, err := a.deps.Search(http.MethodPost, "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		return notObservable(e, "OpenSearch query failed: "+err.Error())
	}
	defer func() { _ = resp.Body.Close() }() // response drained below; a close error tells us nothing actionable
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxStoreResponse))
	if err != nil {
		return notObservable(e, "reading the OpenSearch response failed: "+err.Error())
	}
	if int64(len(raw)) >= maxStoreResponse {
		return notObservable(e, "OpenSearch response exceeded the read cap — refusing a truncated body")
	}
	if resp.StatusCode/100 != 2 {
		return notObservable(e, fmt.Sprintf("OpenSearch answered %d", resp.StatusCode))
	}
	var parsed struct {
		Hits struct {
			Total struct {
				Value int `json:"value"`
			} `json:"total"`
			Hits []struct {
				Index  string         `json:"_index"`
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return notObservable(e, "OpenSearch response was not decodable JSON: "+err.Error())
	}
	if len(parsed.Hits.Hits) == 0 {
		if why := osSampleReason(kind); why != "" {
			// A SAMPLED lane cannot answer "was this record here" at all. The
			// third verdict exists for precisely this: reporting a 98%-expected
			// absence as `not_seen` would send an operator hunting a hop that
			// never lost anything.
			return notObservable(e, why)
		}
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf("no document carrying the marker in %s over the last %s", index, stageWindow)
		return e
	}
	hit := parsed.Hits.Hits[0]
	e.Verdict = VerdictSeen
	e.FirstSeen = timeField(hit.Source, "timestamp")
	e.EvidenceRef = fmt.Sprintf("%s#%s", hit.Index, hit.ID)
	e.Detail = RedactFields(hit.Source)
	e.Detail["_index"] = hit.Index
	e.Detail["_id"] = hit.ID
	e.Detail["_total"] = parsed.Hits.Total.Value
	return e
}

// KafkaStage peeks the kind's topic for the marker through the correlation
// container's debug sidecar (Go has no Kafka client by design, §6).
func (a *API) KafkaStage(ctx context.Context, kind Kind, marker string) Entry {
	e := Entry{Stage: StageKafka, Module: string(StageKafka)}
	topic := TopicFor(kind)
	if topic == "" {
		e.Query = "(none)"
		return notObservable(e, fmt.Sprintf(
			"a %s update does not cross the bus in this deployment: gnmic writes straight to VictoriaMetrics over prometheus_write, and only the opt-in correlation lane (GNMIC_CONFIG_FILE=gnmic-correlation.yaml) adds a Kafka output", kind))
	}
	// A flow record carries no text marker, so the bus needle is the probe's
	// RFC 5737 source address — a closed, 256-value grammar the sidecar
	// validates independently. It is a LOOSE needle by design; every record it
	// returns is then verified against the full fingerprint here, so a loose
	// bus scan can never promote another probe's record into this trace.
	req := PeekRequest{Topic: topic, Marker: marker, MaxSeconds: 10, MaxRecords: 5, LookbackSeconds: 900}
	if kind == KindFlow {
		req.ProbeSrc = NewFlowFingerprint(marker).SrcAddr
		e.Query = fmt.Sprintf("correlation sidecar POST /debug/kafka-peek {topic=%s, marker=%s, probe_src=%s} (records then verified against %s)",
			topic, marker, req.ProbeSrc, NewFlowFingerprint(marker))
	} else {
		e.Query = fmt.Sprintf("correlation sidecar POST /debug/kafka-peek {topic=%s, marker=%s}", topic, marker)
	}
	if a.deps.KafkaPeek == nil {
		return notObservable(e, "the Kafka peek is not wired into this API build")
	}
	res, err := a.deps.KafkaPeek(ctx, req)
	if err != nil {
		return notObservable(e, "Kafka peek unavailable: "+err.Error())
	}
	matched := res.Records
	if kind == KindFlow {
		matched = verifyFlowRecords(marker, res.Records)
	}
	if len(matched) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf("scanned %d records on %s in %.1fs without the marker", res.Scanned, topic, res.ElapsedS)
		if kind == KindFlow && len(res.Records) > 0 {
			e.Reason = fmt.Sprintf("scanned %d records on %s in %.1fs; %d carried the probe's source address but none matched the full fingerprint %s",
				res.Scanned, topic, res.ElapsedS, len(res.Records), NewFlowFingerprint(marker))
		}
		return e
	}
	rec := matched[0]
	e.Verdict = VerdictSeen
	e.FirstSeen = time.UnixMilli(rec.Timestamp).UTC()
	e.EvidenceRef = fmt.Sprintf("%s[%d]@%d", rec.Topic, rec.Partition, rec.Offset)
	e.Detail = map[string]any{
		"topic": rec.Topic, "partition": rec.Partition, "offset": rec.Offset,
		"scanned": res.Scanned, "elapsed_s": res.ElapsedS, "truncated": res.Truncated,
		"excerpt": RedactString(rec.Excerpt),
	}
	if kind == KindFlow {
		e.Detail["fingerprint"] = NewFlowFingerprint(marker).Fields()
	}
	return e
}

// verifyFlowRecords keeps only the peeked records whose payload carries EVERY
// field of the marker's fingerprint. The bus needle is deliberately loose (one
// documentation-prefix address); this is where the claim is made exact.
func verifyFlowRecords(marker string, recs []PeekRecord) []PeekRecord {
	f := NewFlowFingerprint(marker)
	want := []string{
		f.SrcAddr, f.DstAddr,
		strconv.Itoa(int(f.SrcPort)), strconv.Itoa(int(f.DstPort)),
	}
	out := make([]PeekRecord, 0, len(recs))
	for _, rec := range recs {
		ok := true
		for _, w := range want {
			if !strings.Contains(rec.Excerpt, w) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, rec)
		}
	}
	return out
}

// VictoriaStage answers the metric store's half of stage 5.
//
// For syslog and trap the honest answer is NOT-OBSERVABLE, and saying so is the
// whole point: those records produce no per-record time series, so there is no
// selector that could find one. VictoriaMetrics carries pipeline COUNTERS,
// which move for every record and can never be attributed to one marker —
// reporting a counter delta as "the marker was seen" would be a fabrication.
// Kinds that DO mint a series (flow, gNMI — W2) run the export below.
func (a *API) VictoriaStage(ctx context.Context, kind Kind, marker string) Entry {
	e := Entry{Stage: StageVictoria, Module: string(StageVictoria)}
	sel := MarkerSeriesSelector(kind, marker)
	if sel == "" {
		e.Query = "(none)"
		return notObservable(e, victoriaReason(kind))
	}
	now := a.deps.now()
	e.Query = fmt.Sprintf("GET /api/v1/export?match[]=%s&start=%d&end=%d", sel, now.Add(-stageWindow).Unix(), now.Unix())
	if a.deps.VictoriaExport == nil {
		return notObservable(e, "no VictoriaMetrics client is wired into this API build")
	}
	raw, err := a.deps.VictoriaExport(ctx, sel, now.Add(-stageWindow), now)
	if err != nil {
		return notObservable(e, "VictoriaMetrics export failed: "+err.Error())
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = "the export returned no series for the marker selector"
		return e
	}
	e.Verdict = VerdictSeen
	e.EvidenceRef = "victoria.log"
	e.Detail = map[string]any{"export_bytes": len(raw)}
	return e
}

// MarkerSeriesSelector returns the VictoriaMetrics selector that would carry
// the marker for a kind, or "" when the kind mints no per-record series.
//
// EVERY KIND RETURNS "" TODAY, and that is a finding rather than a stub. None
// of syslog, trap or flow mints a per-record time series: VictoriaMetrics holds
// pipeline COUNTERS, which move for every record and cannot be attributed to
// one marker. gNMI is the one kind that IS metric telemetry — and it is
// passive-only, so it is followed by device+path over a window
// (PassiveSeriesSelector), never by a marker that no device would ever emit.
func MarkerSeriesSelector(kind Kind, marker string) string {
	_ = marker
	switch kind {
	case KindSyslog, KindTrap, KindFlow, KindGNMI:
		return ""
	default:
		return ""
	}
}

// victoriaReason explains, per kind, why there is no marker series to export.
func victoriaReason(kind Kind) string {
	switch kind {
	case KindGNMI:
		return "a gNMI trace is PASSIVE (no record is ever written to a device), so it is followed by device and path over a window rather than by a marker — run `correlix-debug trace --kind gnmi --passive --device <id> --since <window>`"
	case KindFlow:
		return "a flow record produces no per-record metric series; VictoriaMetrics holds pipeline counters, which move for every record and cannot be attributed to one probe. ClickHouse is this kind's authoritative store"
	default:
		return fmt.Sprintf("a %s record produces no per-record metric series; VictoriaMetrics holds pipeline counters, which move for every record and cannot be attributed to one marker", kind)
	}
}

// ClickHouseStage answers the analytics store's half of stage 5.
//
// syslog and trap have no ClickHouse RAW table — flows do (netops.flows), and
// correlation OUTPUT does (netops.corr_* / netops.findings, which is the
// correlation stage's job, not this one). Reporting "not seen" here would
// imply a row was expected; the honest verdict is not-observable with the
// reason.
func (a *API) ClickHouseStage(ctx context.Context, p Principal, kind Kind, marker string) Entry {
	e := Entry{Stage: StageClickHouse, Module: string(StageClickHouse)}
	table := RawCHTable(kind)
	if table == "" {
		e.Query = "(none)"
		return notObservable(e, fmt.Sprintf(
			"a %s record has no ClickHouse raw row (ClickHouse holds flows and correlation output; the correlation stage covers the latter)", kind))
	}
	if a.deps.CHSelect == nil || a.deps.CHScopeFor == nil {
		return notObservable(e, "no ClickHouse client is wired into this API build")
	}
	// The predicate is built from the marker's derived fingerprint (flow.go):
	// one address string from a fixed RFC 5737 prefix and five integers, none
	// of which is caller text. The marker itself passed ValidMarker before it
	// reached here, which is what makes the interpolation safe (§3).
	sql := fmt.Sprintf(
		"SELECT ts, src_addr, dst_addr, src_port, dst_port, proto, bytes, packets, sampler_address, flow_type, tenant_id "+
			"FROM %s WHERE %s AND ts >= now() - INTERVAL 30 MINUTE ORDER BY ts ASC LIMIT 5 FORMAT JSON",
		table, FlowMarkerCH(marker))
	e.Query = sql
	rows, err := a.deps.CHSelect(ctx, a.deps.CHScopeFor(p), sql, "api:/api/debug/stage/clickhouse")
	if err != nil {
		return notObservable(e, "ClickHouse query failed: "+err.Error())
	}
	if len(rows) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf("no row matching %s in %s over the last 30 minutes", NewFlowFingerprint(marker), table)
		return e
	}
	e.Verdict = VerdictSeen
	e.FirstSeen = timeField(rows[0], "ts")
	e.EvidenceRef = table
	e.Detail = map[string]any{
		"rows": len(rows), "table": table,
		"fingerprint": NewFlowFingerprint(marker).Fields(),
		"row":         RedactFields(rows[0]),
	}
	return e
}

// RawCHTable names the ClickHouse raw table a kind lands in, or "" when it has
// none.
func RawCHTable(kind Kind) string {
	switch kind {
	case KindFlow:
		// The CANONICAL flow store (deployment/docker/clickhouse/init.sql).
		// OpenSearch gets a 1-in-50 sample of the same lane, which is why the
		// OpenSearch stage below refuses to read a flow miss as a loss.
		return "netops.flows"
	default:
		return ""
	}
}

// CorrelationStage reports what the engine did with the record: the evidence
// row it grounded (netops.corr_evidence.note carries the marker when the record
// was admitted), plus the DEAD-LETTER check, so "the engine dropped it" and
// "the engine failed to persist it" are distinguishable.
func (a *API) CorrelationStage(ctx context.Context, p Principal, kind Kind, marker string) Entry {
	e := Entry{Stage: StageCorrelation, Module: string(StageCorrelation)}
	// corr_evidence.note is TEXT, and the marker only reaches it when the
	// record carried the marker as text. A flow probe never can (flow.go), so
	// claiming "not seen" here would assert that the engine dropped something
	// this query could never have found in the first place.
	if kind == KindFlow || kind == KindGNMI {
		e.Query = "(none)"
		return notObservable(e, fmt.Sprintf(
			"a %s record carries no free-text field, so no corr_evidence note can cite the marker. The %s lane reaches correlation as derived SIGNALS, not as a per-record citation — grounding for this kind is proved by the signal counters in the engine's health snapshot, not by a marker lookup", kind, kind))
	}
	if a.deps.CHSelect == nil || a.deps.CHScopeFor == nil {
		return notObservable(e, "no ClickHouse client is wired into this API build")
	}
	sql := fmt.Sprintf(
		"SELECT tenant_id, toString(correlation_id) AS correlation_id, subject_kind, subject_id, role, note, created_at "+
			"FROM netops.corr_evidence WHERE position(note, '%s') > 0 "+
			"AND created_at >= now() - INTERVAL 30 MINUTE LIMIT 5 FORMAT JSON",
		MarkerTag(marker))
	e.Query = sql
	rows, err := a.deps.CHSelect(ctx, a.deps.CHScopeFor(p), sql, "api:/api/debug/stage/correlation")
	if err != nil {
		return notObservable(e, "corr_evidence query failed: "+err.Error())
	}
	detail := map[string]any{"evidence_rows": len(rows)}
	if dlq, derr := a.dlqSnapshot(ctx); derr != nil {
		detail["dead_letter_check"] = "unavailable: " + derr.Error()
	} else {
		detail["dead_letter_check"] = dlq
	}
	if len(rows) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = "no corr_evidence row cites the marker — the engine's ingest pre-filter admits only records its parser corpus recognises, so an unparsed probe is expected to stop here"
		e.Detail = detail
		return e
	}
	e.Verdict = VerdictSeen
	if len(rows) > 0 {
		e.FirstSeen = timeField(rows[0], "created_at")
	}
	e.Detail = detail
	e.Detail["rows"] = RedactSlice(rows)
	return e
}

// dlqSnapshot pulls the correlation engine's dead-letter / quarantine counters.
func (a *API) dlqSnapshot(ctx context.Context) (map[string]any, error) {
	if a.deps.CorrHealth == nil {
		return nil, errors.New("no correlation health seam wired")
	}
	h, err := a.deps.CorrHealth(ctx)
	if err != nil {
		return nil, err
	}
	dur, _ := h["durability"].(map[string]any)
	if dur == nil {
		return nil, errors.New("health snapshot carried no durability block")
	}
	return map[string]any{
		"ch_rows_dlq_spooled":       dur["ch_rows_dlq_spooled"],
		"quarantined_events":        dur["quarantined_events"],
		"quarantine_write_failures": dur["quarantine_write_failures"],
	}, nil
}

// APIStage serves stage 7 from this process's own bounded debug ring — never
// from the applogs index, so the API's stage does not depend on the pipeline
// under test.
func (a *API) APIStage(marker string) Entry {
	e := Entry{Stage: StageAPI, Module: string(StageAPI)}
	e.Query = fmt.Sprintf("in-process debug ring, marker=%s (capacity %d lines)", marker, RingCapacity)
	if a.deps.Ring == nil {
		return notObservable(e, "the API debug ring is not wired into this build")
	}
	lines := a.deps.Ring.Lines(marker)
	if len(lines) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = "no API log line carries this marker"
		return e
	}
	e.Verdict = VerdictSeen
	e.FirstSeen = lines[0].TS
	e.Detail = map[string]any{"lines": lines}
	return e
}

// notObservable stamps the honest third verdict.
func notObservable(e Entry, reason string) Entry {
	e.Verdict = VerdictNotObservable
	e.Reason = reason
	return e
}

// timeField pulls a timestamp out of a decoded store row, tolerating the three
// shapes the stores use (RFC3339, ClickHouse "2006-01-02 15:04:05.000", epoch
// milliseconds). An unparseable value yields the zero time, which BuildTimeline
// renders as "no latency" rather than a fabricated one.
func timeField(row map[string]any, key string) time.Time {
	v, ok := row[key]
	if !ok {
		return time.Time{}
	}
	switch t := v.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05"} {
			if parsed, err := time.Parse(layout, t); err == nil {
				return parsed.UTC()
			}
		}
	case float64:
		if t > 1e12 {
			return time.UnixMilli(int64(t)).UTC()
		}
		return time.Unix(int64(t), 0).UTC()
	}
	return time.Time{}
}

// RedactSlice runs the redaction pass over a slice of decoded rows.
func RedactSlice(rows []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(rows))
	for _, r := range rows {
		out = append(out, RedactFields(r))
	}
	return out
}

func compact(v any) string {
	buf, err := json.Marshal(v)
	if err != nil {
		return "(unencodable query)"
	}
	return string(buf)
}
