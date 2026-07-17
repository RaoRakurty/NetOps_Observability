package main

// ── #10 scale-out: CSV/JSON export for the cloud signal surfaces ─────────────
//
// Export is the SAME read as the table it exports: the handler builds its rows
// through the identical SQL builders (tenant scope, ?q= search, ?window_hours=,
// app filter) and only the serialization differs. There is deliberately no
// separate export query — a second path would be a place for tenancy to drift.
// The only export-specific knob is the row cap: tables default to a small page,
// an export reads up to cloudExportMaxRows in one bounded request.

import (
	"encoding/csv"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// cloudExportMaxRows bounds a single export read. It exists so an export can
// never become an unbounded scan: the LIMIT is stamped into the SQL exactly
// like the table reads' limit.
const cloudExportMaxRows = 5000

var errBadExportFormat = errors.New("format must be csv or json")

// exportFormat reads ?format= — "" (not an export), "csv" or "json". Anything
// else fails the request; a typo must not silently return the JSON table body
// the caller would mistake for an export honoring their intent.
func exportFormat(r *http.Request) (string, error) {
	f := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	switch f {
	case "", "csv", "json":
		return f, nil
	}
	return "", errBadExportFormat
}

// clampExportLimit bounds the export row count: absent/junk → the full export
// cap (an export means "give me everything in the filter", not one page);
// an explicit smaller ?limit= is honored.
func clampExportLimit(raw string) int {
	n, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || n <= 0 || n > cloudExportMaxRows {
		return cloudExportMaxRows
	}
	return n
}

// exportFilename names the download: surface + UTC stamp, so two exports never
// collide in a Downloads dir and the name states when the snapshot was taken.
func exportFilename(surface, format string, now time.Time) string {
	return fmt.Sprintf("cloud-%s-%s.%s", surface, now.UTC().Format("20060102-150405"), format)
}

// writeSignalExport serializes an export response. CSV goes through
// encoding/csv (RFC 4180 quoting — commas/quotes/newlines in values survive);
// JSON reuses the exact table body so the two formats can never disagree.
func writeSignalExport(w http.ResponseWriter, surface, format string, header []string, rows [][]string, jsonBody any) {
	filename := exportFilename(surface, format, time.Now())
	w.Header().Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	if format == "json" {
		writeJSON(w, http.StatusOK, jsonBody)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	cw := csv.NewWriter(w)
	// Errors on a streaming HTTP body cannot be reported as a status (headers
	// are gone); csv.Writer accumulates them and Flush surfaces the first one.
	_ = cw.Write(header)
	for _, row := range rows {
		_ = cw.Write(row)
	}
	cw.Flush()
	if err := cw.Error(); err != nil {
		log.Printf("cloud export: csv write failed surface=%s: %v", surface, err)
	}
}

// Per-surface serializers: pure, one row per table row, columns mirror what
// the operator sees in the UI table (plus the raw identifiers a spreadsheet
// pivot needs). Header and row builders live next to each other so a drifted
// column count is caught by the tests below, not by a mis-aligned CSV.

var healthExportHeader = []string{
	"time", "app", "resource", "signal", "state", "metric",
	"current", "baseline", "severity", "source", "reason",
}

func healthExportRows(sigs []cloudHealthSignal) [][]string {
	rows := make([][]string, 0, len(sigs))
	for _, s := range sigs {
		rows = append(rows, []string{
			s.Time, s.App, s.Resource, s.Signal, s.State, s.Metric,
			s.Current, s.Baseline, s.Severity, s.Source, s.Reason,
		})
	}
	return rows
}

var changeExportHeader = []string{
	"time", "app", "resource", "change_type", "actor", "source",
	"confidence", "related_symptoms", "provider", "account", "region",
}

func changeExportRows(evs []cloudChangeEvent) [][]string {
	rows := make([][]string, 0, len(evs))
	for _, c := range evs {
		rows = append(rows, []string{
			c.Time, c.App, c.Resource, c.ChangeType, c.Actor, c.Source,
			c.Confidence, strings.Join(c.RelatedSymptoms, "; "),
			c.CloudRef.Provider, c.CloudRef.Account, c.CloudRef.Region,
		})
	}
	return rows
}

var evidenceExportHeader = []string{
	"time", "category", "signal_type", "app", "resource", "source",
	"confidence", "reason", "grounded", "rca_group", "evidence_ref",
}

func evidenceExportRows(rows []cloudEvidenceRow) [][]string {
	out := make([][]string, 0, len(rows))
	for _, e := range rows {
		out = append(out, []string{
			e.Time, e.Category, e.SignalType, e.App, e.Resource, e.Source,
			e.Confidence, e.Reason, strconv.FormatBool(e.Grounded),
			e.RcaGroup, e.EvidenceRef,
		})
	}
	return out
}
