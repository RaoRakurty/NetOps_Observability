// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"netops/backend/internal/logexport"
)

func TestNormalizeExportFormat(t *testing.T) {
	cases := map[string]string{
		"csv": "csv", "CSV": "csv", "json": "json", "ndjson": "ndjson",
		"xlsx": "xlsx", "excel": "xlsx", "xls": "xlsx",
		"": "csv", "  json ": "json",
		"pdf": "", "parquet": "",
	}
	for in, want := range cases {
		if got := logexport.NormalizeFormat(in); got != want {
			t.Errorf("logexport.NormalizeFormat(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlattenLogSource(t *testing.T) {
	// Flow record: the real source host (src_addr) must win over the collector
	// container that emitted it.
	flow := `{"container_name":"netops-goflow2-1","src_addr":"10.10.10.100","dst_addr":"172.16.100.20","timestamp":"2026-06-03T02:48:00Z","message":"flow"}`
	row := logexport.FlattenSource(json.RawMessage(flow), "netops-flows-2026.06.03")
	if row[1] != "10.10.10.100" {
		t.Errorf("flow source = %q, want src_addr 10.10.10.100", row[1])
	}

	// App log: falls back to compose_service/container_name, not src_addr.
	app := `{"container_name":"netops-api-1","compose_service":"api","level":"info","timestamp":"2026-06-03T02:52:30Z","message":"notify email: no recipients"}`
	row = logexport.FlattenSource(json.RawMessage(app), "netops-applogs-2026.06.03")
	if row[1] != "api" {
		t.Errorf("applog source = %q, want compose_service 'api'", row[1])
	}
	if row[2] != "info" || !strings.Contains(row[3], "notify email") {
		t.Errorf("applog level/message wrong: %+v", row)
	}

	// Syslog: hostname when no src_addr/service.
	sys := `{"hostname":"router-01","severity":"err","timestamp":"2026-06-03T02:00:00Z","message":"link down"}`
	row = logexport.FlattenSource(json.RawMessage(sys), "netops-syslog-2026.06.03")
	if row[1] != "router-01" || row[2] != "err" {
		t.Errorf("syslog row wrong: %+v", row)
	}

	// No message field → falls back to the raw document.
	raw := `{"hostname":"x","timestamp":"t"}`
	row = logexport.FlattenSource(json.RawMessage(raw), "i")
	if !strings.Contains(row[3], "hostname") {
		t.Errorf("message fallback should carry raw doc, got %q", row[3])
	}
}

func TestBuildExportSearchBody_TenantScoping(t *testing.T) {
	t0, t1 := exportTimeRange("", "")

	// Cross-tenant platform owner: no device restriction.
	cross := logexport.Spec{Cross: true}
	js := mustJSON(t, logexport.BuildSearchBody(cross, t0, t1, 1000, nil))
	if strings.Contains(js, "match_none") || strings.Contains(js, "minimum_should_match") {
		t.Errorf("cross-tenant export must not be device-filtered: %s", js)
	}
	if !strings.Contains(js, `"_id"`) {
		t.Errorf("search_after tiebreaker _id missing from sort: %s", js)
	}

	// Scoped tenant with visible devices: bool/should over host/hostname/source_ip.
	scoped := logexport.Spec{DeviceKeys: []string{"router-01"}, DeviceAddrs: []string{"10.0.0.1"}}
	js = mustJSON(t, logexport.BuildSearchBody(scoped, t0, t1, 1000, nil))
	for _, frag := range []string{"minimum_should_match", "host", "hostname", "source_ip", "router-01", "10.0.0.1"} {
		if !strings.Contains(js, frag) {
			t.Errorf("scoped export missing %q: %s", frag, js)
		}
	}

	// Scoped tenant with NO visible devices: match_none (empty namespace).
	empty := logexport.Spec{Cross: false}
	js = mustJSON(t, logexport.BuildSearchBody(empty, t0, t1, 1000, nil))
	if !strings.Contains(js, "match_none") {
		t.Errorf("empty visible set must produce match_none: %s", js)
	}

	// search_after is included only when provided.
	js = mustJSON(t, logexport.BuildSearchBody(cross, t0, t1, 1000, []any{12345, "abc"}))
	if !strings.Contains(js, "search_after") {
		t.Errorf("search_after must be present when a cursor is given: %s", js)
	}
}

func TestEncodeExport(t *testing.T) {
	ctx := context.Background()
	cols := logexport.Columns
	data := logexport.Data{
		Rows: [][]string{
			{"2026-06-03T02:00:00Z", "router-01", "err", "link down"},
			{"2026-06-03T02:01:00Z", "10.10.10.100", "info", "flow, with comma"},
		},
		Raw: []json.RawMessage{
			json.RawMessage(`{"a":1}`),
			json.RawMessage(`{"b":2}`),
		},
	}

	// CSV: header + escaped rows.
	art, err := logexport.Encode(ctx, "csv", cols, data)
	if err != nil || art.Format != "csv" {
		t.Fatalf("csv encode: %v", err)
	}
	csv := string(art.Bytes)
	if !strings.Contains(csv, "time,source,level,message") || !strings.Contains(csv, `"flow, with comma"`) {
		t.Errorf("csv content wrong:\n%s", csv)
	}

	// NDJSON: one raw doc per line (lossless).
	art, _ = logexport.Encode(ctx, "ndjson", cols, data)
	lines := strings.Split(strings.TrimSpace(string(art.Bytes)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], `"a":1`) {
		t.Errorf("ndjson should be 2 raw lines, got: %q", art.Bytes)
	}

	// JSON: array of raw docs.
	art, _ = logexport.Encode(ctx, "json", cols, data)
	var arr []map[string]int
	if err := json.Unmarshal(art.Bytes, &arr); err != nil || len(arr) != 2 {
		t.Errorf("json should be array of 2 docs: %v / %s", err, art.Bytes)
	}

	// XLSX: a real OOXML (zip) container.
	art, err = logexport.Encode(ctx, "xlsx", cols, data)
	if err != nil || art.Format != "xlsx" {
		t.Fatalf("xlsx encode: %v", err)
	}
	if len(art.Bytes) < 4 || string(art.Bytes[:2]) != "PK" {
		t.Errorf("xlsx must be a zip (PK magic), got %d bytes", len(art.Bytes))
	}

	// NDJSON without raw docs falls back to the tabular projection.
	art, _ = logexport.Encode(ctx, "ndjson", cols, logexport.Data{Rows: data.Rows})
	if !strings.Contains(string(art.Bytes), `"source":"router-01"`) {
		t.Errorf("ndjson tabular fallback wrong: %s", art.Bytes)
	}
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}
