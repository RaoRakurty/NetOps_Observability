// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pipedebug

// uiquery.go — stage 10: the UI-query contract (design §2, stage 8).
//
// WHAT THIS STAGE CLAIMS, EXACTLY. Not "the record is on a screen" — no
// headless browser runs, and one that did would be testing React, not the
// pipeline. The claim is narrower and checkable: **the api returns this record
// for the very query the SPA issues to display records of this kind.** If the
// api answers that query with the record, everything between the store and the
// browser is a rendering concern; if it does not, the operator has the route
// and the exact query in hand and can re-run it themselves.
//
// WHY THE CONTRACT IS A TABLE IN GO. The route the SPA calls lives in
// TypeScript (src/frontend/src/services/api.ts) and this stage lives in Go. A
// hand-copied path drifts the first time someone renames a route, and a
// debugger whose "UI check" silently calls a route the UI abandoned is worse
// than no check at all. So the table below is the single source, and
// w2_test.go READS api.ts and fails the build if any Literal here is not
// actually in the SPA's client. The test is the link the type system cannot be.
//
// THE SYNTHETIC-EXCLUSION CAVEAT, stated in the answer rather than buried here.
// A trace's record is tagged `cx_synthetic=true`, and logsScope EXCLUDES that
// tag from every customer-facing log query (logs.go) so a probe can never
// appear as device traffic. So the SPA's log query, run verbatim, must NOT
// return a probe — and reporting that as "the UI cannot see it" would be a
// false alarm about a working exclusion. The stage therefore runs the SPA's
// query with the synthetic clause LIFTED, and says so in the reason and in
// ui.log. What is proved is "everything the UI's query depends on returns this
// record"; what is deliberately not proved is that a synthetic probe is
// visible, because by design it must not be.

import (
	"fmt"
	"net/http"
	"time"
)

// UIQuery is one kind's UI-facing contract.
type UIQuery struct {
	// Kind is the record class.
	Kind Kind
	// Method and Route are what the SPA calls.
	Method string
	Route  string
	// Literal is the exact substring that MUST appear in
	// src/frontend/src/services/api.ts. It is the route as the SPA writes it,
	// including the first query separator, so a rename cannot pass by leaving a
	// same-prefixed path behind.
	Literal string
	// APIFn names the api.ts function, so a reader can find the call site.
	APIFn string
	// Store names which store actually answers, so a `not_seen` at this stage
	// points somewhere.
	Store string
	// Shape describes, in words, the query the SPA sends.
	Shape string
}

// UIQueries is the CLOSED contract table, one entry per kind.
//
// gNMI shares no entry with the log kinds on purpose: it is metric telemetry,
// the SPA charts it through the Prometheus-compatible proxy, and pretending it
// is reachable through the log search would send this stage looking in a store
// that cannot hold it.
var UIQueries = map[Kind]UIQuery{
	KindSyslog: {
		Kind: KindSyslog, Method: "POST", Route: "/api/logs/search",
		Literal: `"/api/logs/search"`, APIFn: "api.searchLogs",
		Store: "OpenSearch (tenant log index)",
		Shape: `{"query":"cx_debug=<marker>","signal":"syslog","from":"<start>","to":"<end>","size":50}`,
	},
	KindTrap: {
		Kind: KindTrap, Method: "POST", Route: "/api/logs/search",
		Literal: `"/api/logs/search"`, APIFn: "api.searchLogs",
		Store: "OpenSearch (tenant log index)",
		Shape: `{"query":"cx_debug=<marker>","signal":"snmptrap","from":"<start>","to":"<end>","size":50}`,
	},
	KindFlow: {
		Kind: KindFlow, Method: "GET", Route: "/api/flows/top",
		Literal: "/api/flows/top?since=", APIFn: "api.topTalkers",
		Store: "ClickHouse (netops.flows)",
		Shape: "/api/flows/top?since=<n>s&limit=20&src=<probe src>&dst=<probe dst>",
	},
	KindGNMI: {
		Kind: KindGNMI, Method: "GET", Route: "/api/metrics/query_range",
		Literal: "/api/metrics/query_range?", APIFn: "api.metricsQueryRange",
		Store: "VictoriaMetrics (Prometheus-compatible proxy)",
		Shape: "/api/metrics/query_range?query=<selector>&start=<unix>&end=<unix>&step=<n>",
	},
}

// UIQueryFor returns a kind's contract entry.
func UIQueryFor(kind Kind) (UIQuery, bool) {
	q, ok := UIQueries[kind]
	return q, ok
}

// RenderUIQuery renders the contract for ONE record, so the operator sees the
// query with this trace's values already substituted and can paste it.
func RenderUIQuery(kind Kind, marker string, spec PassiveSpec, since time.Duration, now time.Time) (UIQuery, string, bool) {
	q, ok := UIQueries[kind]
	if !ok {
		return UIQuery{}, "", false
	}
	if since <= 0 {
		since = stageWindow
	}
	start := now.Add(-since)
	switch kind {
	case KindSyslog, KindTrap:
		return q, fmt.Sprintf(`POST /api/logs/search {"query":%q,"signal":%q,"from":%q,"to":%q,"size":50}`,
			MarkerTag(marker), SignalFor(kind), start.Format(time.RFC3339), now.Format(time.RFC3339)), true
	case KindFlow:
		f := NewFlowFingerprint(marker)
		return q, fmt.Sprintf("GET /api/flows/top?since=%ds&limit=20&src=%s&dst=%s",
			int(since.Seconds()), f.SrcAddr, f.DstAddr), true
	case KindGNMI:
		return q, fmt.Sprintf("GET /api/metrics/query_range?query=%s&start=%d&end=%d&step=60",
			PassiveSeriesSelector(spec.Device, spec.Path), start.Unix(), now.Unix()), true
	default:
		return q, "", true
	}
}

// UIProbe is what running the SPA's own query returned.
type UIProbe struct {
	// Found is the whole answer to stage 10.
	Found bool `json:"found"`
	// Rows is how many records came back.
	Rows int `json:"rows"`
	// Ref addresses the returned record (index#id, table, series count).
	Ref string `json:"ref,omitempty"`
	// TS is the record's own timestamp, when the answer carries one.
	TS time.Time `json:"ts,omitempty"`
	// Note carries anything the caller must know to read the result honestly —
	// above all, that the synthetic exclusion was lifted.
	Note string `json:"note,omitempty"`
	// Detail is the redacted evidence written into ui.log.
	Detail map[string]any `json:"detail,omitempty"`
}

// UIStage answers stage 10 over the injected UIQueryRun seam.
func (a *API) UIStage(r *http.Request, kind Kind, marker string, spec PassiveSpec, tenant string) Entry {
	e := Entry{Stage: StageUI, Module: string(StageUI)}
	contract, rendered, ok := RenderUIQuery(kind, marker, spec, 0, a.deps.now())
	if !ok {
		return notObservable(e, fmt.Sprintf("no UI-query contract is defined for kind %q", kind))
	}
	e.Query = rendered
	if a.deps.UIQueryRun == nil {
		return notObservable(e, "the UI-query seam is not wired into this API build — the contract above is what the SPA issues ("+contract.APIFn+"), but nothing ran it")
	}
	probe, err := a.deps.UIQueryRun(r, kind, marker, spec, tenant)
	if err != nil {
		return notObservable(e, "running the SPA's own query failed: "+err.Error())
	}
	detail := map[string]any{
		"route": contract.Route, "method": contract.Method,
		"api_ts_function": contract.APIFn, "store": contract.Store,
		"contract_shape": contract.Shape, "rendered_query": rendered,
		"rows": probe.Rows,
		"answer": fmt.Sprintf("the api returned the record for the UI's own query: %s",
			yesNo(probe.Found)),
	}
	for k, v := range probe.Detail {
		detail[k] = v
	}
	if probe.Note != "" {
		detail["note"] = probe.Note
	}
	e.Detail = detail
	if !probe.Found {
		e.Verdict = VerdictNotSeen
		e.Reason = fmt.Sprintf("the api did NOT return this record for %s, the query %s issues — the store above holds it or does not, and this is the query to re-run by hand",
			contract.Route, contract.APIFn)
		return e
	}
	e.Verdict = VerdictSeen
	e.FirstSeen = probe.TS
	e.EvidenceRef = probe.Ref
	if e.EvidenceRef == "" {
		e.EvidenceRef = StageUI.LogFile()
	}
	return e
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
