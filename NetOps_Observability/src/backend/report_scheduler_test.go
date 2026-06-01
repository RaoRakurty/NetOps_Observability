package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// atoiSafe parses a leading run of digits and stops at the first non-digit,
// returning whatever it accumulated (never errors).
func TestAtoiSafe(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{"", 0},
		{"0", 0},
		{"42", 42},
		{"  17  ", 17},     // surrounding space trimmed before parsing
		{"123abc", 123},    // stops at first non-digit
		{"abc", 0},         // no leading digits
		{"-5", 0},          // '-' is not a digit, stops immediately
		{"9 8", 9},         // embedded space stops parsing
		{"007", 7},         // leading zeros fine
		{"1000000", 1000000},
	}
	for _, c := range cases {
		if got := atoiSafe(c.in); got != c.want {
			t.Errorf("atoiSafe(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

// parseReportSpec decodes the slice of a report body the scheduler cares about
// and ignores unknown keys the frontend carries.
func TestParseReportSpec(t *testing.T) {
	body := json.RawMessage(`{
		"kind": "wan_utilization",
		"interval_minutes": 15,
		"severity": "warning",
		"enabled": true,
		"description": "weekly WAN rollup",
		"channels": ["slack", "email"],
		"frontend_only_field": {"foo": "bar"}
	}`)
	spec, err := parseReportSpec(body)
	if err != nil {
		t.Fatalf("parseReportSpec: %v", err)
	}
	if spec.Kind != "wan_utilization" {
		t.Errorf("Kind = %q", spec.Kind)
	}
	if spec.IntervalMinutes != 15 {
		t.Errorf("IntervalMinutes = %d", spec.IntervalMinutes)
	}
	if spec.Severity != "warning" {
		t.Errorf("Severity = %q", spec.Severity)
	}
	if !spec.Enabled {
		t.Errorf("Enabled = false, want true")
	}
	if spec.Description != "weekly WAN rollup" {
		t.Errorf("Description = %q", spec.Description)
	}
	if len(spec.Channels) != 2 || spec.Channels[0] != "slack" || spec.Channels[1] != "email" {
		t.Errorf("Channels = %v", spec.Channels)
	}
}

func TestParseReportSpecEmptyBody(t *testing.T) {
	if _, err := parseReportSpec(nil); err == nil {
		t.Fatalf("parseReportSpec(nil) = nil error, want error")
	}
	if _, err := parseReportSpec(json.RawMessage(``)); err == nil {
		t.Fatalf("parseReportSpec(empty) = nil error, want error")
	}
}

func TestParseReportSpecInvalidJSON(t *testing.T) {
	if _, err := parseReportSpec(json.RawMessage(`{not json`)); err == nil {
		t.Fatalf("parseReportSpec(bad json) = nil error, want error")
	}
}

// chQuery POSTs SQL to ClickHouse and returns the non-empty result lines.
// Stub the HTTP endpoint via CLICKHOUSE_URL so no live ClickHouse is needed.
func TestChQueryParsesLines(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("chQuery method = %s, want POST", r.Method)
		}
		// Trailing/blank lines must be stripped from the result.
		_, _ = w.Write([]byte("line-one\nline-two\n\n   \nline-three\n"))
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	t.Setenv("CLICKHOUSE_PASSWORD", "")

	got := chQuery("SELECT 1")
	want := []string{"line-one", "line-two", "line-three"}
	if len(got) != len(want) {
		t.Fatalf("chQuery returned %d lines (%v), want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

// A non-200 response (or unreachable backend) yields nil, so callers degrade to
// a clean "no data" report rather than failing.
func TestChQueryNonOKReturnsNil(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	if got := chQuery("SELECT 1"); got != nil {
		t.Fatalf("chQuery on 500 = %v, want nil", got)
	}
}

// vmTopk runs an instant PromQL query and formats each series as
// "<device> <value><unit>", preferring device > instance > host for the label.
func TestVMTopkParsesAndFormats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("query"); got != "topk(2, x)" {
			t.Errorf("vmTopk query = %q, want topk(2, x)", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"data": {"result": [
				{"metric": {"device": "core1"}, "value": [1700000000, "93.5"]},
				{"metric": {"instance": "10.0.0.2"}, "value": [1700000000, "80"]},
				{"metric": {"host": "edge9", "device": "edge9-dev"}, "value": [1700000000, "12"]},
				{"metric": {}, "value": [1700000000, "1"]}
			]}
		}`))
	}))
	defer srv.Close()
	t.Setenv("VICTORIA_URL", srv.URL)

	got := vmTopk("topk(2, x)", "%")
	want := []string{
		"core1 93.5%",
		"10.0.0.2 80%",  // falls back to instance
		"edge9-dev 12%", // device wins over host
		"device 1%",     // no labels -> literal "device"
	}
	if len(got) != len(want) {
		t.Fatalf("vmTopk returned %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestVMTopkUnreachableReturnsNil(t *testing.T) {
	// Point at a closed port so the GET fails fast -> nil.
	t.Setenv("VICTORIA_URL", "http://127.0.0.1:1")
	t.Setenv("METRICS_URL", "http://127.0.0.1:1")
	if got := vmTopk("topk(1, x)", "%"); got != nil {
		t.Fatalf("vmTopk unreachable = %v, want nil", got)
	}
}
