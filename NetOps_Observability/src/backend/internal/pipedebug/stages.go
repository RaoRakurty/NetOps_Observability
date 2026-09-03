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
	"strings"
	"time"
)

// maxStoreResponse bounds one store answer. Response size is chosen by the
// peer, so an unbounded read here is an OOM in the API process (audit F-27).
const maxStoreResponse = 8 << 20

// stageWindow is how far back a stage query looks for the marker. A trace is
// minutes old at most; a wider window only adds cost and false neighbours.
const stageWindow = 30 * time.Minute

// SignalFor maps a trace kind onto the log signal its record is stored under.
func SignalFor(k Kind) string {
	switch k {
	case KindTrap:
		return "snmptrap"
	default:
		return "syslog"
	}
}

// TopicFor maps a trace kind onto the Kafka topic its record crosses.
func TopicFor(k Kind) string {
	switch k {
	case KindTrap:
		return "netops.snmptrap"
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

// OpenSearchStage looks for the marker in the tenant's log index.
func (a *API) OpenSearchStage(ctx context.Context, p Principal, kind Kind, marker string, tenant string) Entry {
	e := Entry{Stage: StageOpenSearch, Module: string(StageOpenSearch)}
	if a.deps.Search == nil || a.deps.OSIndexPattern == nil {
		return notObservable(e, "no OpenSearch client is wired into this API build")
	}
	signal := SignalFor(kind)
	index := a.deps.OSIndexPattern(signal, tenant, p.Cross && tenant == "")
	now := a.deps.now()
	body := map[string]any{
		"size":             5,
		"track_total_hits": true,
		"sort":             []any{map[string]any{"timestamp": map[string]string{"order": "asc", "unmapped_type": "date"}}},
		"query": map[string]any{"bool": map[string]any{
			"filter": []any{
				markerQuery(marker),
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
	e.Query = fmt.Sprintf("correlation sidecar POST /debug/kafka-peek {topic=%s, marker=%s}", topic, marker)
	if a.deps.KafkaPeek == nil {
		return notObservable(e, "the Kafka peek is not wired into this API build")
	}
	res, err := a.deps.KafkaPeek(ctx, PeekRequest{
		Topic: topic, Marker: marker,
		MaxSeconds: 10, MaxRecords: 5, LookbackSeconds: 900,
	})
	if err != nil {
		return notObservable(e, "Kafka peek unavailable: "+err.Error())
	}
	if len(res.Records) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf("scanned %d records on %s in %.1fs without the marker", res.Scanned, topic, res.ElapsedS)
		return e
	}
	rec := res.Records[0]
	e.Verdict = VerdictSeen
	e.FirstSeen = time.UnixMilli(rec.Timestamp).UTC()
	e.EvidenceRef = fmt.Sprintf("%s[%d]@%d", rec.Topic, rec.Partition, rec.Offset)
	e.Detail = map[string]any{
		"topic": rec.Topic, "partition": rec.Partition, "offset": rec.Offset,
		"scanned": res.Scanned, "elapsed_s": res.ElapsedS, "truncated": res.Truncated,
		"excerpt": RedactString(rec.Excerpt),
	}
	return e
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
		return notObservable(e, fmt.Sprintf(
			"a %s record produces no per-record metric series; VictoriaMetrics holds pipeline counters, which move for every record and cannot be attributed to one marker", kind))
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
func MarkerSeriesSelector(kind Kind, marker string) string {
	_ = marker
	switch kind {
	case KindSyslog, KindTrap:
		return ""
	default:
		return ""
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
	sql := fmt.Sprintf(
		"SELECT * FROM %s WHERE positionCaseInsensitive(toString(raw), '%s') > 0 AND ts >= now() - INTERVAL 30 MINUTE LIMIT 5 FORMAT JSON",
		table, MarkerTag(marker))
	e.Query = sql
	rows, err := a.deps.CHSelect(ctx, a.deps.CHScopeFor(p), sql, "api:/api/debug/stage/clickhouse")
	if err != nil {
		return notObservable(e, "ClickHouse query failed: "+err.Error())
	}
	if len(rows) == 0 {
		e.Verdict = VerdictNotSeen
		e.Reason = "no row carrying the marker in " + table
		return e
	}
	e.Verdict = VerdictSeen
	e.Detail = map[string]any{"rows": len(rows), "table": table}
	return e
}

// RawCHTable names the ClickHouse raw table a kind lands in, or "" when it has
// none.
func RawCHTable(kind Kind) string {
	switch kind {
	case KindSyslog, KindTrap:
		return ""
	default:
		return ""
	}
}

// CorrelationStage reports what the engine did with the record: the evidence
// row it grounded (netops.corr_evidence.note carries the marker when the record
// was admitted), plus the DEAD-LETTER check, so "the engine dropped it" and
// "the engine failed to persist it" are distinguishable.
func (a *API) CorrelationStage(ctx context.Context, p Principal, marker string) Entry {
	e := Entry{Stage: StageCorrelation, Module: string(StageCorrelation)}
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
