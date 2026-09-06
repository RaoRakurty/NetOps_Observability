// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package logexport is the Explore→Logs export core (Phase-2 W3.11, extracted
// from package main's logs_export.go): the export spec, the bounded
// search_after pager (row + byte caps with the honest ErrTooLarge), the
// OpenSearch query body over the oslog tenant projections, source flattening
// and the csv/json/ndjson/xlsx encoders producing a reports.Artifact. The
// handlers, audit, signed links, rate limiting and the async pipeline hooks
// stay in main; the transport is the injected SearchFn.
package logexport

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"netops/backend/internal/oslog"
	"netops/backend/reports"
)

const ()

// ErrTooLarge is a deterministic (non-retryable) failure: the matched set
// exceeds the configured caps. The caller surfaces an actionable message.
var ErrTooLarge = errors.New("export exceeds configured size limit")

// Spec is the frozen, self-contained parameter set for one export — the
// job payload for Mode B and the request shape for Mode A's query path.
type Spec struct {
	Query  string `json:"query"`
	From   string `json:"from"` // RFC3339 / unix
	To     string `json:"to"`
	Signal string `json:"signal"`
	Format string `json:"format"` // csv | json | ndjson | xlsx

	// Frozen tenant-visibility snapshot: the async worker reproduces exactly what
	// the requester could see at request time (the device set may change later).
	Tenant      string   `json:"tenant,omitempty"` // #20 Phase 3: caller's tenant for index routing + tenant_id filter
	Cross       bool     `json:"cross"`
	DeviceKeys  []string `json:"device_keys,omitempty"`
	DeviceAddrs []string `json:"device_addrs,omitempty"`

	// Compliance: operator-visibility restriction, frozen at request time so the
	// async worker reproduces it. ExcludeTenants are tenant ids whose telemetry is
	// filtered out of an operator's Global export; DenyAll empties the result when
	// the operator scoped into a restricted tenant. See operatorTelemetryRestriction.
	ExcludeTenants []string `json:"exclude_tenants,omitempty"`
	DenyAll        bool     `json:"deny_all,omitempty"`
}

// Columns is the canonical tabular projection used for csv/xlsx (and for
// json/ndjson when no raw document is available, i.e. Mode A selected rows).
var Columns = []string{"time", "source", "level", "message"}

func NormalizeFormat(f string) string {
	f = strings.ToLower(strings.TrimSpace(f))
	switch f {
	case "csv", "json", "ndjson", "xlsx":
		return f
	case "", "excel", "xls":
		if f == "excel" || f == "xls" {
			return "xlsx"
		}
		return "csv"
	default:
		return ""
	}
}

func ContentType(format string) (contentType, ext string) {
	switch format {
	case "csv":
		return "text/csv; charset=utf-8", "csv"
	case "json":
		return "application/json", "json"
	case "ndjson":
		return "application/x-ndjson", "ndjson"
	case "xlsx":
		return "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "xlsx"
	default:
		return "application/octet-stream", "bin"
	}
}

// ---- query construction + paging -------------------------------------------

// BuildSearchBody mirrors handleLogsSearch's tenant scoping but sorts
// ascending with an _id tiebreaker so search_after pages deterministically.
func BuildSearchBody(spec Spec, start, end time.Time, size int, searchAfter []any) map[string]any {
	filters := []any{
		map[string]any{"range": map[string]any{"timestamp": map[string]string{
			"gte": start.Format(time.RFC3339),
			"lte": end.Format(time.RFC3339),
		}}},
	}
	// Tenant isolation (#20 Phase 3) — same index-pattern + tenant_id/device clause
	// as handleLogsSearch, frozen onto the spec. The platform owner (Cross) is
	// unrestricted; the read index pattern (tenantIndexPattern) already excludes
	// other tenants' indices at the storage layer.
	if f := oslog.TenantFilter(spec.Tenant, spec.Cross, spec.DeviceKeys, spec.DeviceAddrs); f != nil {
		filters = append(filters, f)
	}
	// Compliance: operator-visibility restriction frozen onto the spec (mirrors
	// handleLogsSearch). DenyAll → empty result; ExcludeTenants → drop their docs.
	boolQuery := map[string]any{
		"must": []any{map[string]any{"query_string": map[string]any{
			"query":            oslog.QueryOrAll(spec.Query),
			"analyze_wildcard": true,
		}}},
		"filter": filters,
	}
	if spec.DenyAll {
		boolQuery["filter"] = append(filters, map[string]any{"match_none": map[string]any{}})
	} else if len(spec.ExcludeTenants) > 0 {
		boolQuery["must_not"] = []any{map[string]any{"terms": map[string]any{"tenant_id": spec.ExcludeTenants}}}
	}
	body := map[string]any{
		"size": size,
		"sort": []any{
			map[string]any{"timestamp": map[string]string{"order": "asc", "unmapped_type": "date"}},
			map[string]any{"_id": "asc"}, // unique tiebreaker for search_after
		},
		"query": map[string]any{"bool": boolQuery},
	}
	if len(searchAfter) > 0 {
		body["search_after"] = searchAfter
	}
	return body
}

// osHit is the slice of a _search response we consume.
type osSearchResp struct {
	Hits struct {
		Hits []struct {
			Index  string          `json:"_index"`
			ID     string          `json:"_id"`
			Source json.RawMessage `json:"_source"`
			Sort   []any           `json:"sort"`
		} `json:"hits"`
	} `json:"hits"`
}

// Data is the accumulated, bounded result of an export query. raw carries
// the verbatim _source per row (lossless json/ndjson); rows carries the canonical
// tabular projection (csv/xlsx). Both are bounded by the caps.
type Data struct {
	Rows  [][]string
	Raw   []json.RawMessage
	bytes int
}

// FetchBounded pages the tenant-scoped query with search_after, accumulating
// rows under maxRows/maxBytes. Exceeding either cap is a deterministic failure
// (ErrTooLarge) rather than a silent truncation. Memory is bounded by the
// caps (the honest Phase-1 contract; a streaming sink is a later substrate add).
// SearchFn is the OpenSearch transport seam (main's env-configured client).
type SearchFn func(method, path string, body any) (*http.Response, error)

func FetchBounded(ctx context.Context, search SearchFn, spec Spec, start, end time.Time, maxRows, maxBytes int) (Data, error) {
	const batch = 1000
	index := oslog.TenantIndexPattern(spec.Signal, spec.Tenant, spec.Cross)
	var data Data
	var after []any
	for {
		select {
		case <-ctx.Done():
			return data, ctx.Err()
		default:
		}
		body := BuildSearchBody(spec, start, end, batch, after)
		resp, err := search("POST", "/"+index+"/_search", body)
		if err != nil {
			return data, err
		}
		var parsed osSearchResp
		decErr := json.NewDecoder(resp.Body).Decode(&parsed)
		_ = resp.Body.Close() // best-effort: nothing actionable on close failure
		if resp.StatusCode/100 != 2 {
			return data, fmt.Errorf("opensearch search status %d", resp.StatusCode)
		}
		if decErr != nil {
			return data, decErr
		}
		hits := parsed.Hits.Hits
		if len(hits) == 0 {
			break
		}
		for i := range hits {
			h := hits[i]
			data.bytes += len(h.Source)
			data.Rows = append(data.Rows, FlattenSource(h.Source, h.Index))
			data.Raw = append(data.Raw, h.Source)
			if len(data.Rows) > maxRows {
				return data, fmt.Errorf("%w: more than %d rows match — narrow the query or time range", ErrTooLarge, maxRows)
			}
			if data.bytes > maxBytes {
				return data, fmt.Errorf("%w: result exceeds %d bytes — narrow the query or time range", ErrTooLarge, maxBytes)
			}
		}
		after = hits[len(hits)-1].Sort
		if len(hits) < batch || len(after) == 0 {
			break
		}
	}
	return data, nil
}

// FlattenSource projects one log document to the canonical [time, source,
// level, message] row, matching the Logs UI's resolution (flow rows show the
// real source host, not the collector container).
func FlattenSource(raw json.RawMessage, index string) []string {
	var s map[string]any
	if err := json.Unmarshal(raw, &s); err != nil {
		return []string{"", "", "", string(raw)}
	}
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := s[k]; ok && v != nil {
				if vs := fmt.Sprintf("%v", v); vs != "" {
					return vs
				}
			}
		}
		return ""
	}
	ts := str("@timestamp", "timestamp", "ts", "time", "time_received_ns")
	level := str("level", "severity")
	source := str("src_addr") // flow source host wins over the collector container
	if source == "" {
		source = str("compose_service", "container_name", "hostname", "appname")
	}
	if source == "" {
		source = index
	}
	message := str("message", "msg")
	if message == "" {
		message = string(raw)
	}
	return []string{ts, source, level, message}
}

// ---- encoders --------------------------------------------------------------

// Encode renders accumulated data to the requested format. json/ndjson use
// the verbatim documents when present (lossless), else the tabular projection.
func Encode(ctx context.Context, format string, cols []string, data Data) (reports.Artifact, error) {
	contentType, _ := ContentType(format)
	switch format {
	case "csv":
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		_ = w.Write(cols) // csv.Writer latches the first error; the row writes below check it
		for _, r := range data.Rows {
			if err := w.Write(r); err != nil {
				return reports.Artifact{}, err
			}
		}
		w.Flush()
		if err := w.Error(); err != nil {
			return reports.Artifact{}, err
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: buf.Bytes(), Summary: Summary(len(data.Rows))}, nil

	case "ndjson":
		var buf bytes.Buffer
		if len(data.Raw) > 0 {
			for _, raw := range data.Raw {
				buf.Write(raw)
				buf.WriteByte('\n')
			}
		} else {
			enc := json.NewEncoder(&buf)
			for _, r := range data.Rows {
				if err := enc.Encode(RowObject(cols, r)); err != nil {
					return reports.Artifact{}, err
				}
			}
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: buf.Bytes(), Summary: Summary(len(data.Rows))}, nil

	case "json":
		var out []byte
		var err error
		if len(data.Raw) > 0 {
			var buf bytes.Buffer
			buf.WriteByte('[')
			for i, raw := range data.Raw {
				if i > 0 {
					buf.WriteByte(',')
				}
				buf.Write(raw)
			}
			buf.WriteByte(']')
			out = buf.Bytes()
		} else {
			objs := make([]map[string]string, 0, len(data.Rows))
			for _, r := range data.Rows {
				objs = append(objs, RowObject(cols, r))
			}
			out, err = json.Marshal(objs)
			if err != nil {
				return reports.Artifact{}, err
			}
		}
		return reports.Artifact{Format: format, ContentType: contentType, Bytes: out, Summary: Summary(len(data.Rows))}, nil

	case "xlsx":
		vm := reports.ViewModel{
			ReportName:  "Log export",
			Kind:        "logs",
			GeneratedAt: time.Now().UTC(),
			Sections:    []reports.Section{{Title: "Logs", Header: cols, Rows: data.Rows}},
		}
		return reports.NewXLSXRenderer().Render(ctx, vm)

	default:
		return reports.Artifact{}, fmt.Errorf("unsupported export format %q", format)
	}
}

func RowObject(cols, row []string) map[string]string {
	m := make(map[string]string, len(cols))
	for i, c := range cols {
		if i < len(row) {
			m[c] = row[i]
		}
	}
	return m
}

func Summary(n int) string { return fmt.Sprintf("%d log rows", n) }

// ---- Mode B: GET /api/logs/export (entire result set) ----------------------
