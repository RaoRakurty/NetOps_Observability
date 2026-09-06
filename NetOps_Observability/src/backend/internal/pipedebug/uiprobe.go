// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// uiprobe.go — the RUNNER behind stage 10: it actually issues the query the SPA
// itself issues and reports what came back. `uiquery.go` next door holds the
// contract (which route, which api.ts function, which store); this file holds
// the execution.
//
// THE STRONGEST FORM OF THIS CHECK IS TO CALL THE REAL HANDLER, and for two of
// the three stores that is exactly what happens: the flow and gNMI probes are
// answered by the api's own top-talkers and query_range handlers, invoked
// in-process with the SPA's own query string on a clone of the caller's
// request, so the tenant scoping, the row policies and the response shape are
// the production ones rather than a re-implementation that could drift. Those
// handlers live in package backend, so they arrive here through the
// UIQueryHost seam — this package holds no ambient authority (deps.go).
//
// THE LOG KINDS ARE THE ONE EXCEPTION, and the reason is a feature, not a
// shortcut. `logsScope` EXCLUDES `cx_synthetic=true` from every customer-facing
// log query, so a debug probe must NOT come back from /api/logs/search — that
// exclusion is the only thing standing between an injected record and an
// operator's log search. Calling the real handler would therefore return
// nothing for every healthy trace, and reporting that as "the UI cannot see it"
// would be a false alarm about a working control. So the log probe re-runs the
// scope with the synthetic clause LIFTED, and the answer says so in ui.log.
// What is proved: everything the UI's query depends on — index resolution,
// tenant filter, visibility restriction, the store itself — returns this
// record. What is deliberately NOT proved: that a synthetic probe is visible in
// the UI, because by design it must not be.
//
// Removal rule: drop the `UIQueryRun` line in package backend's debugDeps and
// the UI stage reports not-observable with its reason. Nothing else changes.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"time"
)

// maxUIProbeBody bounds what a captured handler response may return into this
// process. The body is chosen by a store, so an unbounded read here is an OOM
// in the api (the audit F-27 class).
const maxUIProbeBody = 4 << 20

// UIQueryHost is the seam onto the api's own query surfaces.
//
// It is deliberately narrow and behavioural: this package must run THE
// HANDLERS, not a copy of them, because a re-implementation of the tenant
// clause is exactly the drift that would let this stage pass while the real
// UI query returned another tenant's rows — or nothing at all.
type UIQueryHost interface {
	// LogsScope is the api's own log chokepoint: it resolves the readable index
	// and the filter/must_not clauses for this caller and signal, and reports
	// whether the caller may read the scope at all (forbidden) or is policy-
	// denied every row of it (denyAll).
	LogsScope(r *http.Request, signal string) (index string, filters, mustNot []any, denyAll, forbidden bool)
	// SyntheticExclusion returns the exact must_not clause LogsScope adds to
	// hide `cx_synthetic=true` records from customer-facing searches. It is
	// fetched rather than reconstructed so the lift cannot drift away from the
	// clause it is meant to lift.
	SyntheticExclusion() map[string]any
	// SearchOpenSearch issues one OpenSearch request with the api's configured,
	// credentialed client. The response body is this package's to close.
	SearchOpenSearch(method, path string, body any) (*http.Response, error)
	// IndexPatternFor resolves the readable index pattern for a signal, for the
	// evidence detail only.
	IndexPatternFor(signal, tenant string, cross bool) string
	// ServeFlowsTopTalkers and ServeMetricsQueryRange are the SPA's real
	// handlers, invoked in-process.
	ServeFlowsTopTalkers(w http.ResponseWriter, r *http.Request)
	ServeMetricsQueryRange(w http.ResponseWriter, r *http.Request)
}

// captureWriter is an http.ResponseWriter that buffers a handler's answer
// instead of sending it, so a real handler can be run for its RESULT.
//
// It is bounded on write: a handler that streamed megabytes would otherwise
// grow this buffer without limit, and the debugger must never be the thing that
// takes the api down during an incident (§9).
type captureWriter struct {
	hdr      http.Header
	status   int
	buf      bytes.Buffer
	overflow bool
}

func newCaptureWriter() *captureWriter {
	return &captureWriter{hdr: http.Header{}, status: http.StatusOK}
}

func (c *captureWriter) Header() http.Header { return c.hdr }

func (c *captureWriter) WriteHeader(status int) { c.status = status }

func (c *captureWriter) Write(b []byte) (int, error) {
	if c.buf.Len() >= maxUIProbeBody {
		// Report the truncation rather than silently keeping a prefix: a
		// truncated body that decoded to "no rows" would read as a missing
		// record.
		c.overflow = true
		return len(b), nil
	}
	room := maxUIProbeBody - c.buf.Len()
	if len(b) > room {
		c.overflow = true
		c.buf.Write(b[:room])
		return len(b), nil
	}
	return c.buf.Write(b)
}

// uiProbeFn runs the SPA's own query for one kind.
type uiProbeFn func(r *http.Request, marker string, spec PassiveSpec) (UIProbe, error)

// uiRunner binds the host to the probe dispatch.
type uiRunner struct{ host UIQueryHost }

// NewUIQueryRun builds the Deps.UIQueryRun seam over a host. A nil host yields
// a nil seam, which the UI stage reports honestly as "not wired" rather than
// panicking mid-trace.
func NewUIQueryRun(host UIQueryHost) func(r *http.Request, kind Kind, marker string, spec PassiveSpec, tenant string) (UIProbe, error) {
	if host == nil {
		return nil
	}
	return uiRunner{host: host}.run
}

// probeFor resolves the probe for a kind. The dispatch is a separate,
// side-effect-free lookup so a test can assert that EVERY kind in the closed
// set has one — a kind with a contract entry but no probe would report
// not_observable for a stage the api is perfectly able to answer, and finding
// that out by running a store query is not a test, it is an outage.
func (u uiRunner) probeFor(kind Kind) (uiProbeFn, bool) {
	switch kind {
	case KindSyslog, KindTrap:
		return func(r *http.Request, marker string, _ PassiveSpec) (UIProbe, error) {
			return u.probeLogs(r, kind, marker)
		}, true
	case KindFlow:
		return func(r *http.Request, marker string, _ PassiveSpec) (UIProbe, error) {
			return u.probeFlows(r, marker)
		}, true
	case KindGNMI:
		return func(r *http.Request, _ string, spec PassiveSpec) (UIProbe, error) {
			return u.probeMetrics(r, spec)
		}, true
	default:
		return nil, false
	}
}

// run is the Deps.UIQueryRun seam.
func (u uiRunner) run(r *http.Request, kind Kind, marker string, spec PassiveSpec, tenant string) (UIProbe, error) {
	_ = tenant // the scope comes from the request's own claims, never from a parameter (§3a rule 2)
	probe, ok := u.probeFor(kind)
	if !ok {
		return UIProbe{}, fmt.Errorf("no UI-query probe exists for kind %q", kind)
	}
	return probe(r, marker, spec)
}

// probeLogs re-runs the SPA's log query with the synthetic exclusion lifted.
func (u uiRunner) probeLogs(r *http.Request, kind Kind, marker string) (UIProbe, error) {
	signal := SignalFor(kind)
	index, filters, mustNot, denyAll, forbidden := u.host.LogsScope(r, signal)
	if forbidden {
		return UIProbe{}, fmt.Errorf("the caller may not read the %s log scope at all", signal)
	}
	if denyAll {
		return UIProbe{
			Note: "this tenant's operator-visibility policy denies the whole log scope, so the SPA's query returns nothing for ANY record — that is a policy answer, not a pipeline one",
		}, nil
	}
	lifted, dropped := withoutSyntheticExclusion(mustNot, u.host.SyntheticExclusion())

	end := time.Now().UTC()
	start := end.Add(-30 * time.Minute)
	query := append([]any{}, filters...)
	query = append(query,
		map[string]any{"match_phrase": map[string]any{"message": MarkerTag(marker)}},
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339), "lte": end.Add(time.Minute).Format(time.RFC3339),
		}}})
	body := map[string]any{
		"size":             5,
		"track_total_hits": true,
		"sort":             []any{map[string]any{"timestamp": map[string]string{"order": "asc", "unmapped_type": "date"}}},
		"query":            map[string]any{"bool": map[string]any{"filter": query, "must_not": lifted}},
	}

	resp, err := u.host.SearchOpenSearch(http.MethodPost, "/"+index+"/_search?ignore_unavailable=true", body)
	if err != nil {
		return UIProbe{}, fmt.Errorf("the UI's log query failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }() // drained below; a close error carries nothing actionable
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxUIProbeBody))
	if err != nil {
		return UIProbe{}, fmt.Errorf("reading the UI log query response failed: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		return UIProbe{}, fmt.Errorf("the UI's log query answered HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Hits struct {
			Hits []struct {
				Index  string         `json:"_index"`
				ID     string         `json:"_id"`
				Source map[string]any `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return UIProbe{}, fmt.Errorf("the UI log query response was not decodable JSON: %w", err)
	}
	probe := UIProbe{
		Rows: len(parsed.Hits.Hits),
		Note: "the SPA's own scope was used (index pattern, tenant filter, visibility restriction) with ONE clause lifted: the cx_synthetic=true exclusion, which by design hides debug probes from the customer-facing log search. A real device record needs no lift",
		Detail: map[string]any{
			"index":                      index,
			"synthetic_exclusion_lifted": dropped,
			"resolved_index_pattern":     u.host.IndexPatternFor(signal, "", true),
		},
	}
	if len(parsed.Hits.Hits) > 0 {
		hit := parsed.Hits.Hits[0]
		probe.Found = true
		probe.Ref = hit.Index + "#" + hit.ID
		if ts, ok := hit.Source["timestamp"].(string); ok {
			if t, perr := time.Parse(time.RFC3339, ts); perr == nil {
				probe.TS = t.UTC()
			}
		}
	}
	return probe, nil
}

// withoutSyntheticExclusion removes the `want` clause from a must_not list and
// reports whether it was actually there.
//
// The `dropped` return is not decoration: if LogsScope ever stopped adding the
// clause, this function would silently do nothing and ui.log would claim a lift
// that never happened. Reporting false is how that becomes visible, and
// uiprobe_test.go asserts it is true today.
func withoutSyntheticExclusion(mustNot []any, want map[string]any) (kept []any, dropped bool) {
	kept = make([]any, 0, len(mustNot))
	for _, clause := range mustNot {
		if m, ok := clause.(map[string]any); ok && reflect.DeepEqual(m, want) {
			dropped = true
			continue
		}
		kept = append(kept, clause)
	}
	return kept, dropped
}

// probeFlows runs the REAL top-talkers handler with the SPA's own filters.
func (u uiRunner) probeFlows(r *http.Request, marker string) (UIProbe, error) {
	f := NewFlowFingerprint(marker)
	q := url.Values{}
	q.Set("since", "1800s")
	q.Set("limit", "20")
	q.Set("src", f.SrcAddr)
	q.Set("dst", f.DstAddr)

	cw := newCaptureWriter()
	u.host.ServeFlowsTopTalkers(cw, cloneWithQuery(r, "/api/flows/top", q))
	if cw.status/100 != 2 {
		return UIProbe{}, fmt.Errorf("the UI's flow query answered HTTP %d", cw.status)
	}
	rows, err := clickHouseRowCount(cw.buf.Bytes())
	if err != nil {
		return UIProbe{}, err
	}
	return UIProbe{
		Found: rows > 0, Rows: rows, Ref: "netops.flows",
		Note: "this is the SPA's handler itself (handleFlowsTopTalkers), invoked in-process with the dashboard's own src/dst filter — the tenant clause and the ClickHouse row policy are the production ones",
		Detail: map[string]any{
			"filters":            map[string]any{"src": f.SrcAddr, "dst": f.DstAddr, "since": "1800s"},
			"truncated_response": cw.overflow,
		},
	}, nil
}

// probeMetrics runs the REAL query_range handler for a passive gNMI follow.
func (u uiRunner) probeMetrics(r *http.Request, spec PassiveSpec) (UIProbe, error) {
	end := time.Now().UTC()
	since := ClampSince(spec.Since)
	start := end.Add(-since)
	sel := PassiveSeriesSelector(spec.Device, spec.Path)

	q := url.Values{}
	q.Set("query", sel)
	q.Set("start", fmt.Sprint(start.Unix()))
	q.Set("end", fmt.Sprint(end.Unix()))
	q.Set("step", "60")

	cw := newCaptureWriter()
	u.host.ServeMetricsQueryRange(cw, cloneWithQuery(r, "/api/metrics/query_range", q))
	if cw.status/100 != 2 {
		return UIProbe{}, fmt.Errorf("the UI's metrics query answered HTTP %d", cw.status)
	}
	var parsed struct {
		Status string `json:"status"`
		Data   struct {
			Result []struct {
				Metric map[string]string `json:"metric"`
				Values [][]any           `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.Unmarshal(cw.buf.Bytes(), &parsed); err != nil {
		return UIProbe{}, fmt.Errorf("the UI metrics response was not decodable JSON: %w", err)
	}
	points := 0
	for _, res := range parsed.Data.Result {
		points += len(res.Values)
	}
	return UIProbe{
		Found: len(parsed.Data.Result) > 0, Rows: len(parsed.Data.Result),
		Ref: "victoriametrics:" + sel, TS: end,
		Note: "this is the SPA's handler itself (handleMetricsQueryRange), invoked in-process with the chart's own selector and window — the per-tenant device label filter is the production one",
		Detail: map[string]any{
			"selector": sel, "series": len(parsed.Data.Result), "points": points,
			"window": since.String(), "truncated_response": cw.overflow,
		},
	}, nil
}

// cloneWithQuery returns a GET copy of r aimed at path with query q. The
// CONTEXT is carried over, which is what keeps the caller's authenticated
// claims — and therefore the tenant scoping — attached to the probe.
func cloneWithQuery(r *http.Request, path string, q url.Values) *http.Request {
	out := r.Clone(r.Context())
	out.Method = http.MethodGet
	out.Body = http.NoBody
	out.ContentLength = 0
	out.URL = &url.URL{Path: path, RawQuery: q.Encode()}
	out.RequestURI = ""
	return out
}

// clickHouseRowCount counts the rows in a ClickHouse `FORMAT JSON` body.
func clickHouseRowCount(raw []byte) (int, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return 0, nil
	}
	var parsed struct {
		Data []map[string]any `json:"data"`
		Rows *int             `json:"rows"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return 0, fmt.Errorf("the UI flow response was not decodable JSON: %w (body starts %q)",
			err, strings.TrimSpace(string(raw[:min(len(raw), 120)])))
	}
	if parsed.Rows != nil {
		return *parsed.Rows, nil
	}
	return len(parsed.Data), nil
}
