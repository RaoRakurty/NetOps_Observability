// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package parsercov

// query.go — the OpenSearch query builders and the document projection.
//
// PURE. Every function here is a value → value transform, so the wire bodies
// are BYTE-PINNABLE in a test (the secapi/query_test.go precedent): a change
// that only MOVES the tenant clause still shows up as a diff, which is the
// point — an isolation clause that quietly becomes a `should` is a leak that a
// "contains tenant_id" assertion would not catch.
//
// Isolation is not optional here and is not a parameter a caller may forget:
// scopeOf builds BOTH the index pattern and the per-doc clause, and every body
// below takes the clause it produced.

import (
	"encoding/json"
	"strings"
	"time"

	"netops/backend/internal/oslog"
)

// scanFields is the projection each scanned document returns. Naming the
// fields keeps the response small (§9: bounded IO) and makes the read surface
// explicit — nothing else about a device's log line ever reaches this process.
var scanFields = []string{
	"timestamp", "message", "appname", "facility", "event_type",
	"hostname", "host", "severity",
}

// scopeOf resolves the caller's index pattern and per-doc tenant clause. It is
// the ONE place both are derived (§3a rule 4), so no handler can hand-roll a
// pattern. `cross` (the platform owner) gets the unrestricted pattern and a nil
// clause; a scoped tenant gets its own tagged indices plus the shared untagged
// ones, narrowed further by the device matcher.
func scopeOf(p Principal, lane Lane) (index string, tenantClause map[string]any) {
	signal := "syslog"
	if lane == LaneTrap {
		signal = "snmptrap"
	}
	return oslog.TenantIndexPattern(signal, p.Tenant, p.Cross),
		oslog.TenantFilter(p.Tenant, p.Cross, p.DeviceKeys, p.DeviceAddrs)
}

// timeRange is the window clause. `format` is pinned so a locale-shifted index
// mapping cannot reinterpret the bounds.
func timeRange(start, end time.Time) map[string]any {
	return map[string]any{"range": map[string]any{"timestamp": map[string]any{
		"gte":    start.UTC().Format(time.RFC3339),
		"lte":    end.UTC().Format(time.RFC3339),
		"format": "strict_date_optional_time",
	}}}
}

// baseFilters is the window plus the isolation clause, in that fixed order.
func baseFilters(tenantClause map[string]any, start, end time.Time) []any {
	filters := []any{timeRange(start, end)}
	if tenantClause != nil {
		filters = append(filters, tenantClause)
	}
	return filters
}

// BuildStampProbeBody counts, within the caller's scope and window, how many
// documents CARRY the engine's admission stamp, and which corpus versions
// stamped them. `size: 0` — this is an accounting query, not a read.
//
// It is what stands between an honest answer and a guess (see admission.go):
// zero stamped documents means the lane is not publishing its verdict, and the
// caller answers 503 rather than reporting every unstamped line as
// "unrecognized".
func BuildStampProbeBody(tenantClause map[string]any, start, end time.Time) map[string]any {
	filters := append(baseFilters(tenantClause, start, end),
		map[string]any{"exists": map[string]any{"field": admissionField}})
	return map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query":            map[string]any{"bool": map[string]any{"filter": filters}},
		"aggs": map[string]any{
			"versions": map[string]any{"terms": map[string]any{
				"field": admissionVersionField, "size": 5,
			}},
		},
	}
}

// BuildWindowTotalBody counts every document in the caller's scope and window,
// stamped or not. Together with the probe it yields the stamp COVERAGE the note
// reports.
func BuildWindowTotalBody(tenantClause map[string]any, start, end time.Time) map[string]any {
	return map[string]any{
		"size":             0,
		"track_total_hits": true,
		"query": map[string]any{"bool": map[string]any{
			"filter": baseFilters(tenantClause, start, end),
		}},
	}
}

// BuildScanBody pages the UNRECOGNIZED subset: in the caller's scope and
// window, documents with no admission stamp.
//
// Sorted ascending on `timestamp` with an `_id` tiebreaker so `search_after`
// pages deterministically and no document is skipped or repeated across pages
// — the same pager shape internal/logexport uses, and the reason the mining is
// reproducible run to run.
func BuildScanBody(tenantClause map[string]any, start, end time.Time, size int, searchAfter []any) map[string]any {
	body := map[string]any{
		"size":    size,
		"_source": scanFields,
		"sort": []any{
			map[string]any{"timestamp": map[string]any{"order": "asc", "unmapped_type": "date"}},
			map[string]any{"_id": "asc"},
		},
		"query": map[string]any{"bool": map[string]any{
			"filter":   baseFilters(tenantClause, start, end),
			"must_not": []any{map[string]any{"exists": map[string]any{"field": admissionField}}},
		}},
	}
	if len(searchAfter) > 0 {
		body["search_after"] = searchAfter
	}
	return body
}

// ---- response shapes --------------------------------------------------------

type osTotal struct {
	Value int64 `json:"value"`
}

type osCountResponse struct {
	Hits struct {
		Total osTotal `json:"total"`
	} `json:"hits"`
	Aggregations struct {
		Versions struct {
			Buckets []struct {
				Key string `json:"key"`
			} `json:"buckets"`
		} `json:"versions"`
	} `json:"aggregations"`
}

type osScanHit struct {
	Source json.RawMessage `json:"_source"`
	Sort   []any           `json:"sort"`
}

type osScanResponse struct {
	Hits struct {
		Total osTotal     `json:"total"`
		Hits  []osScanHit `json:"hits"`
	} `json:"hits"`
}

// scanDoc is the decoded projection of one log document. Every field is
// optional on the wire — a device-supplied document is untrusted input (§3), so
// nothing here may assume a shape.
type scanDoc struct {
	Timestamp string `json:"timestamp"`
	Message   string `json:"message"`
	AppName   string `json:"appname"`
	Facility  string `json:"facility"`
	EventType string `json:"event_type"`
	Hostname  string `json:"hostname"`
	Host      string `json:"host"`
	Severity  string `json:"severity"`
}

// toLine projects one document onto the miner's input.
//
// The three derivations, and why:
//
//   - appname: the document's `appname`, falling back to `facility`. The
//     aggregator defaults a missing app name to the literal "unknown"
//     (vector.yaml's syslog lane), which is a placeholder, not an identity, so
//     it is treated as absent.
//   - mnemonic: `event_type`, upper-cased. The aggregator sets it from the
//     %FAC-N-MNEMONIC parse and stores it down-cased; the catalog and the UI
//     both speak the mnemonic in upper case.
//   - severity: the engine's own resolution (keyword vs the tag digit, most
//     severe wins) — see admission.go.
func (d scanDoc) toLine() Line {
	app := strings.TrimSpace(d.AppName)
	if app == "" || strings.EqualFold(app, "unknown") {
		app = strings.TrimSpace(d.Facility)
	}
	host := strings.TrimSpace(d.Hostname)
	if host == "" || strings.EqualFold(host, "unknown") {
		host = strings.TrimSpace(d.Host)
	}
	ts, err := oslog.ParseTimeFlexible(strings.TrimSpace(d.Timestamp))
	if err != nil {
		ts = time.Time{} // no usable timestamp: excluded from first/last seen
	}
	return Line{
		Message:  d.Message,
		AppName:  app,
		Mnemonic: strings.ToUpper(strings.TrimSpace(d.EventType)),
		Host:     host,
		Severity: mostSevere(d.Severity, d.AppName),
		Time:     ts.UTC(),
	}
}
