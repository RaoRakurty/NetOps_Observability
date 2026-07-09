package main

// bounded_io_test.go — #100 incident guardrails (2026-07-09 ClickHouse
// bounded-IO incident, docs/incidents/correlix-clickhouse-bounded-io.md).
//
// The incident class: a hot read path whose cost is unbounded in table size —
// SELECT * (or a wide blob column) carried through a full-table sort/fold, or
// a whole-table GROUP BY to decorate a LIMIT'd page. Harmless at small row
// counts, a 2.6 GiB/query memory bomb at storm size (~236k version rows), and
// ClickHouse's OvercommitTracker turns ONE bad query shape into platform-wide
// 502s. These tests make the banned shapes fail CI, not production.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// corrHotTables are the correlation tables a HOT (user-facing, polled) path may
// touch only in bounded form. corr_current is the sanctioned hot projection.
var corrWideColumns = []string{"hypotheses", "layer_coverage", "app_impact"}

// backendSQLSources returns the package .go sources (non-test) as name→content.
func backendSQLSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		out[name] = string(b)
	}
	return out
}

// Rule 1 (permanent): no SELECT * against any correlation table anywhere in the
// backend. Column pruning through views/CTEs is an optimizer behavior, not a
// contract — one added outer column reference silently re-widens the scan.
func TestNoSelectStarOnCorrTables(t *testing.T) {
	// Matches SELECT * ... FROM netops.corr_<anything> within one SQL literal,
	// tolerating newlines between the star and the FROM.
	re := regexp.MustCompile(`(?is)SELECT\s+\*\s+FROM\s+netops\.corr_`)
	for name, src := range backendSQLSources(t) {
		if name == "corr_schema.go" {
			// The corr_objects_latest VIEW definition legitimately uses SELECT *
			// (CREATE OR REPLACE keeps its columns in lockstep with the table).
			// Consumers of the view are still covered by the other rules.
			continue
		}
		if re.MatchString(src) {
			t.Errorf("%s: SELECT * against a netops.corr_* table — hot corr reads must name narrow columns (#100)", name)
		}
	}
}

// Rule 2 (permanent): wide blob columns must never cross a latest-version fold
// (ORDER BY ... LIMIT 1 BY) — that is the exact 2.6 GiB shape. A query string
// that contains both a fold and a wide column is banned regardless of file.
// corr_objects_latest counts as a fold: the view body IS a LIMIT 1 BY, and an
// outer wide-column reference re-widens it (optimizer pruning is not a
// contract — this exact shape memory-killed the reliability endpoints).
func TestNoWideColumnsThroughFolds(t *testing.T) {
	strLit := regexp.MustCompile("(?s)`[^`]*`")
	for name, src := range backendSQLSources(t) {
		if name == "corr_schema.go" {
			continue // DDL: the backfill INSERT folds narrow columns only (checked below)
		}
		for _, lit := range strLit.FindAllString(src, -1) {
			folds := strings.Contains(lit, "LIMIT 1 BY") || strings.Contains(lit, "corr_objects_latest")
			if !strings.Contains(lit, "netops.corr_") || !folds {
				continue
			}
			for _, wide := range corrWideColumns {
				if strings.Contains(lit, wide) {
					t.Errorf("%s: SQL folds (LIMIT 1 BY) while touching wide column %q — fetch it keyed by the picked (id, version) pairs instead (#100)", name, wide)
				}
			}
		}
	}
}

// Rule 2b: the corr_current backfill keeps the sanctioned #100 split — its
// latest-version FOLD picks narrow keys only; the wide hypotheses badge
// extracts run ONLY in the outer read, keyed by the folded (id, version) set,
// so no blob ever crosses the sort.
func TestCorrCurrentBackfillStaysNarrow(t *testing.T) {
	for _, s := range corrSchemaDDL() {
		if !strings.Contains(s, "INSERT INTO netops.corr_current") {
			continue
		}
		foldAt := strings.LastIndex(s, "SELECT tenant_id, correlation_id, version")
		if foldAt == -1 || !strings.Contains(s[foldAt:], "LIMIT 1 BY") {
			t.Fatalf("corr_current backfill lost its narrow-keys fold:\n%s", s)
		}
		for _, wide := range corrWideColumns {
			if strings.Contains(s[foldAt:], wide) {
				t.Errorf("corr_current backfill folds wide column %q — the fold must pick narrow keys only (#100)", wide)
			}
		}
		// The wide badge extracts must be keyed by the folded set, and layer
		// blobs must never be projected at all.
		if !strings.Contains(s, "IN (") {
			t.Error("corr_current backfill wide read is not keyed by the folded (tenant, id, version) set")
		}
		for _, banned := range []string{"layer_coverage", "app_impact"} {
			if strings.Contains(s, banned) {
				t.Errorf("corr_current backfill touches %q — only hypotheses badge extracts are sanctioned", banned)
			}
		}
		return
	}
	t.Fatal("corr_current backfill statement not found in corrSchemaDDL")
}

// Rule 3 (permanent): the Command Center list query keeps its bounded shape —
// page and badges served from the corr_current projection (the hypotheses blob
// is NEVER read: even keyed, its JSONExtracts dragged ~1.3 GiB of blob granules
// per page at storm size), edges and app_impact fetched ONLY keyed by the
// picked set, bounded LIMIT, time-bounded history touch.
func TestCorrelationsListSQLShape(t *testing.T) {
	sinceCond := "created_at >= now() - INTERVAL 86400 SECOND"
	sql := correlationsListSQL(sinceCond, []string{"1", "state = 'open'"}, 100)

	for _, must := range []string{
		"FROM netops.corr_current FINAL",                  // hot pick + serve source
		"LIMIT 100",                                       // bounded rows
		"IN (SELECT correlation_id, version FROM picked)", // keyed decorate
		"ANY LEFT JOIN",                                   // duplicate-history guard on the keyed fetch
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("correlations list SQL lost its bounded shape: missing %q\n%s", must, sql)
		}
	}
	// The blob column must not appear AT ALL — badges come from the projection.
	if strings.Contains(sql, "hypotheses") {
		t.Errorf("correlations list SQL reads the hypotheses blob — badges must come from corr_current's narrow columns (#100)\n%s", sql)
	}
	// The only history (corr_objects) touch is the keyed, time-bounded
	// app_impact fetch.
	if objsAt := strings.Index(sql, "netops.corr_objects"); objsAt != -1 {
		objs := sql[objsAt:]
		if !strings.Contains(objs, sinceCond) || !strings.Contains(objs, "FROM picked") {
			t.Errorf("corr_objects touch is not keyed+time-bounded:\n%s", objs)
		}
	}
	// The picked CTE itself must not reference any wide column.
	picked := sql[:strings.Index(sql, ")")]
	for _, wide := range corrWideColumns {
		if strings.Contains(picked, wide) {
			t.Errorf("picked CTE references wide column %q — the page pick must stay narrow", wide)
		}
	}
	// The edges aggregation must be scoped to picked, never the whole table:
	// "FROM netops.corr_edges" must be followed by a WHERE ... picked before its
	// GROUP BY (the pre-incident shape aggregated all 771k rows per poll).
	edges := sql[strings.Index(sql, "netops.corr_edges"):]
	groupAt := strings.Index(edges, "GROUP BY")
	scopeAt := strings.Index(edges, "FROM picked")
	if groupAt == -1 || scopeAt == -1 || scopeAt > groupAt {
		t.Error("corr_edges aggregation is not scoped to the picked set before GROUP BY (#100)")
	}
	// No SELECT * anywhere in the hot query.
	if regexp.MustCompile(`(?i)SELECT\s+\*`).MatchString(sql) {
		t.Error("correlations list SQL contains SELECT *")
	}
}

// Rule 4 (permanent): whole-table GROUP BY over corr_edges to decorate a page
// is banned everywhere — an edges aggregation must carry a picked/IN scope.
func TestNoWholeTableEdgesAggregation(t *testing.T) {
	strLit := regexp.MustCompile("(?s)`[^`]*`")
	for name, src := range backendSQLSources(t) {
		for _, lit := range strLit.FindAllString(src, -1) {
			if !strings.Contains(lit, "netops.corr_edges") || !strings.Contains(lit, "GROUP BY") {
				continue
			}
			seg := lit[strings.Index(lit, "netops.corr_edges"):]
			groupAt := strings.Index(seg, "GROUP BY")
			whereAt := strings.Index(seg, "WHERE")
			if whereAt == -1 || whereAt > groupAt {
				t.Errorf("%s: corr_edges GROUP BY without a preceding WHERE scope — decorating a page must not aggregate the whole table (#100)", name)
			}
		}
	}
}
