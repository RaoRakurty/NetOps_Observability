package main

import (
	"net/http/httptest"
	"net/url"
	"testing"
)

// TestFlowTypeClause pins the injection-safe whitelist: only netflow/ipfix/sflow
// (case-insensitive) yield a clause; everything else (incl. SQL-ish input) is
// dropped to no-clause = all sources.
func TestFlowTypeClause(t *testing.T) {
	cases := map[string]string{
		"netflow":            " AND flow_type = 'netflow'",
		"ipfix":              " AND flow_type = 'ipfix'",
		"sflow":              " AND flow_type = 'sflow'",
		"SFLOW":              " AND flow_type = 'sflow'",
		"  netflow  ":        " AND flow_type = 'netflow'",
		"":                   "",
		"bogus":              "",
		"sflow'; DROP TABLE": "",
	}
	for in, want := range cases {
		r := httptest.NewRequest("GET", "/api/flows/top?type="+url.QueryEscape(in), nil)
		if got := flowTypeClause(r); got != want {
			t.Errorf("type=%q: got %q want %q", in, got, want)
		}
	}
}
