// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"encoding/csv"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"netops/backend/cloud"
)

func TestClampExportLimit(t *testing.T) {
	cases := map[string]int{
		"":       cloudExportMaxRows,
		"junk":   cloudExportMaxRows,
		"0":      cloudExportMaxRows,
		"-5":     cloudExportMaxRows,
		"100":    100,
		"5000":   5000,
		"999999": cloudExportMaxRows,
	}
	for raw, want := range cases {
		if got := clampExportLimit(raw); got != want {
			t.Errorf("clampExportLimit(%q) = %d, want %d", raw, got, want)
		}
	}
}

func TestExportFormat(t *testing.T) {
	for raw, want := range map[string]string{"": "", "csv": "csv", "json": "json", "CSV": "csv", "%20json%20": "json"} {
		r := httptest.NewRequest("GET", "/api/cloud/health?format="+raw, nil)
		got, err := exportFormat(r)
		if err != nil || got != want {
			t.Errorf("exportFormat(%q) = (%q, %v), want (%q, nil)", raw, got, err, want)
		}
	}
	r := httptest.NewRequest("GET", "/api/cloud/health?format=xlsx", nil)
	if _, err := exportFormat(r); err == nil {
		t.Fatal("exportFormat must reject unknown formats, not silently fall back")
	}
}

func TestExportFilename(t *testing.T) {
	now := time.Date(2026, 7, 17, 12, 34, 56, 0, time.UTC)
	if got := exportFilename("health", "csv", now); got != "cloud-health-20260717-123456.csv" {
		t.Fatalf("exportFilename = %q", got)
	}
}

// CSV export must survive hostile field content — commas, quotes, newlines —
// via RFC 4180 quoting, and round-trip through a standard CSV reader.
func TestWriteSignalExportCSVEscaping(t *testing.T) {
	sigs := []cloudHealthSignal{{
		Time: "2026-07-17T01:02:03Z", App: `evil,"app"`, Resource: "vm-1\nline2",
		Signal: "cloud_health", State: "degraded", Metric: "cpu, percent",
		Current: "91", Baseline: "12", Severity: "critical", Source: "aws",
		Reason: `said "unhealthy", twice`,
	}}
	rec := httptest.NewRecorder()
	writeSignalExport(rec, "health", "csv", healthExportHeader, healthExportRows(sigs), nil)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/csv") {
		t.Fatalf("Content-Type = %q, want text/csv", ct)
	}
	cd := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="cloud-health-`) || !strings.HasSuffix(cd, `.csv"`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	rows, err := csv.NewReader(strings.NewReader(rec.Body.String())).ReadAll()
	if err != nil {
		t.Fatalf("exported CSV does not re-parse: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want header + 1", len(rows))
	}
	if len(rows[0]) != len(healthExportHeader) || len(rows[1]) != len(healthExportHeader) {
		t.Fatalf("column drift: header %d, row %d, spec %d", len(rows[0]), len(rows[1]), len(healthExportHeader))
	}
	if rows[1][1] != `evil,"app"` || rows[1][2] != "vm-1\nline2" || rows[1][10] != `said "unhealthy", twice` {
		t.Fatalf("hostile fields did not round-trip: %#v", rows[1])
	}
}

func TestWriteSignalExportJSONDisposition(t *testing.T) {
	rec := httptest.NewRecorder()
	writeSignalExport(rec, "changes", "json", changeExportHeader, nil, map[string]any{"changes": []string{}})
	cd := rec.Header().Get("Content-Disposition")
	if !strings.HasPrefix(cd, `attachment; filename="cloud-changes-`) || !strings.HasSuffix(cd, `.json"`) {
		t.Fatalf("Content-Disposition = %q", cd)
	}
	if !strings.Contains(rec.Body.String(), `"changes"`) {
		t.Fatalf("JSON export body must be the table body, got %q", rec.Body.String())
	}
}

// Every serializer row must match its header width — a drifted column would
// silently shift every subsequent field in the spreadsheet.
func TestExportSerializerWidths(t *testing.T) {
	h := healthExportRows([]cloudHealthSignal{{}})
	c := changeExportRows([]cloudChangeEvent{{RelatedSymptoms: []string{"a", "b"}}})
	e := evidenceExportRows([]cloudEvidenceRow{{Grounded: true}})
	if len(h[0]) != len(healthExportHeader) {
		t.Errorf("health row width %d != header %d", len(h[0]), len(healthExportHeader))
	}
	if len(c[0]) != len(changeExportHeader) {
		t.Errorf("changes row width %d != header %d", len(c[0]), len(changeExportHeader))
	}
	if len(e[0]) != len(evidenceExportHeader) {
		t.Errorf("evidence row width %d != header %d", len(e[0]), len(evidenceExportHeader))
	}
	if c[0][7] != "a; b" {
		t.Errorf("related_symptoms join = %q", c[0][7])
	}
	if e[0][8] != "true" {
		t.Errorf("grounded bool render = %q", e[0][8])
	}
}

// The export path reuses the exact same SQL builders as the table read — this
// test locks the tenancy property at the only place export differs: the limit.
// (Scope injection itself is covered by TestCloudSignalQueriesAreTenantScoped.)
func TestExportUsesScopedBuilders(t *testing.T) {
	q := cloud.HealthSQL(24, "", clampExportLimit(""), "acme")
	if !strings.Contains(q, "SETTINGS tenant_scope = 'acme'") {
		t.Fatalf("export-sized health query lost tenant scope:\n%s", q)
	}
	if !strings.Contains(q, "LIMIT 5000") {
		t.Fatalf("export-sized health query lost its row cap:\n%s", q)
	}
}
