// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"netops/backend/internal/chschema"
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
	for _, s := range chschema.CorrSchemaDDL() {
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
	t.Fatal("corr_current backfill statement not found in chschema.CorrSchemaDDL")
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
		"FROM netops.corr_current FINAL", // hot pick + serve source
		"LIMIT 100",                      // bounded rows
		"IN (SELECT correlation_id, version FROM picked)", // keyed decorate
		"ANY LEFT JOIN", // duplicate-history guard on the keyed fetch
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

// corrWideDisplayColumns are the columns no latest-version FOLD over the
// history table may carry: the #100 blobs, plus the two display strings that
// are wide in practice (a hypothesis signature and the affected-entity JSON
// array) — those two are what made the 30 d time-range read 732 MiB.
var corrWideDisplayColumns = append([]string{"top_hypothesis", "affected", "evidence_missing", "attribution"}, corrWideColumns...)

// corrFoldExemptionMarker lets a genuinely bounded fold opt out of Rule 5 in
// writing. It must appear IN the SQL literal (a `--` comment ClickHouse
// ignores) and say why, e.g.
//
//	-- bounded-io: exempt — single correlation_id, at most one page of versions
//
// A reviewer then sees the claim next to the query it excuses. There is no
// silent exemption.
const corrFoldExemptionMarker = "bounded-io: exempt"

// Rule 5 (permanent, 2026-09-19 + 2026-09-20 Iris regressions): a
// LATEST-VERSION FOLD over netops.corr_objects must (a) carry a created_at
// bound AND (b) keep the #100 split — the fold picks NARROW keys, the wide
// columns are fetched keyed by that ≤limit set.
//
// corr_objects is the full version history, partitioned by
// (tenant_id, toYYYYMMDD(created_at)). A fold with no created_at predicate
// prunes NOTHING: every partition is read and every matching history row is
// materialised and sorted before `LIMIT 1 BY` folds it away. That is how
// aiDataSource.ListActiveProblems — Iris's "what is going on right now" — died
// with MEMORY_LIMIT_EXCEEDED on a one-month appliance (measured: 2 660 822
// rows / 773.95 MiB read, 1011.30 MiB peak, to return 25 rows), surfacing to
// the operator as a 502 from the assistant.
//
// Half (a) alone was NOT enough, which is why half (b) exists. Its sibling
// aiDataSource.ListProblemsInWindow — "what happened last night", `/history`,
// and every "in the last N days" question — carried a created_at bound and
// passed this rule as originally written, and still died the same death one
// day later: the bound prunes partitions, it does not stop the sort from
// dragging top_hypothesis and affected through every version row in the
// window. MEASURED at a 30 d lookback (the clampLookback maximum) with
// tenant_scope='__all__': 2 444 427 rows / 737.24 MiB read / 1023.34 MiB peak
// → Code 241, against 2 686 812 rows / 95.42 MiB / 92.02 MiB for the split
// shape. So the bound is necessary and the split is what makes it sufficient.
//
// The fix for a new fold is one of: the sanctioned hot projection
// (netops.corr_current, for a "right now" question), the narrow-pick +
// keyed-wide-fetch split (aiProblemsInWindowSQL, for a history question), or a
// written corrFoldExemptionMarker saying why this one is bounded anyway.
func TestNoUnboundedCorrObjectsFold(t *testing.T) {
	strLit := regexp.MustCompile("(?s)`[^`]*`")
	for name, src := range backendSQLSources(t) {
		for _, lit := range strLit.FindAllString(src, -1) {
			if !strings.Contains(lit, "netops.corr_objects") || !strings.Contains(lit, "LIMIT 1 BY") {
				continue
			}
			if strings.Contains(lit, corrFoldExemptionMarker) {
				continue // opted out in writing, next to the query
			}
			if !strings.Contains(lit, "created_at >=") {
				t.Errorf("%s: latest-version fold over netops.corr_objects with no created_at bound — "+
					"nothing prunes, so the whole history is sorted to return one page (#100):\n%s", name, lit)
			}
			// (b) the FIRST fold is the pick, and a pick carries narrow keys
			// only — everything before it is the picking SELECT and its WHERE.
			pick := lit[:strings.Index(lit, "LIMIT 1 BY")]
			for _, wide := range corrWideDisplayColumns {
				if strings.Contains(pick, wide) {
					t.Errorf("%s: latest-version fold over netops.corr_objects drags wide column %q through its sort — "+
						"pick (correlation_id, version) narrow first and fetch the wide columns keyed by that set (#100):\n%s",
						name, wide, lit)
				}
			}
			// …and the wide read that follows must be keyed by the picked set.
			if !strings.Contains(lit, ") IN (SELECT") {
				t.Errorf("%s: fold over netops.corr_objects has no keyed wide fetch — the columns the answer needs "+
					"must be read `WHERE (…) IN (SELECT … FROM <pick>)`, never carried through the fold (#100):\n%s", name, lit)
			}
		}
	}
}

// Rule 5b: Iris's active-problems read keeps the shape that fixed it — the hot
// projection, a narrow pick, the wide columns fetched keyed by that pick, and
// the liveness bound whenever the orphan sweep is on.
func TestAIActiveProblemsSQLShape(t *testing.T) {
	sql := aiActiveProblemsSQL(25, corrOrphanOpenCloseHoursDefault)
	for _, must := range []string{
		"FROM netops.corr_current FINAL",                  // hot projection, folded before state is tested
		"created_at >= now() - INTERVAL 24 HOUR",          // liveness horizon == the orphan sweep's
		"LIMIT 1 BY correlation_id",                       // belt-and-braces fold
		"IN (SELECT correlation_id, version FROM picked)", // wide columns fetched keyed
		"LIMIT 25", // bounded rows
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("active-problems SQL lost its bounded shape: missing %q\n%s", must, sql)
		}
	}
	if strings.Contains(sql, "netops.corr_objects") {
		t.Errorf("active-problems SQL is back on the history table — that is the 502:\n%s", sql)
	}
	// The pick must stay narrow: no wide column may cross its sort.
	picked := sql[strings.Index(sql, "WITH picked"):strings.Index(sql, "\n)")]
	for _, wide := range append([]string{"top_hypothesis", "affected"}, corrWideColumns...) {
		if strings.Contains(picked, wide) {
			t.Errorf("active-problems pick references %q — the fold must pick narrow keys only (#100)\n%s", wide, picked)
		}
	}
	// Sweep disabled (0 = open rows may legitimately be arbitrarily old): no
	// bound at all, never a zero-hour bound that would answer "nothing".
	if off := aiActiveProblemsSQL(25, 0); strings.Contains(off, "created_at >= now()") {
		t.Errorf("orphan sweep disabled must drop the liveness bound, not narrow to now():\n%s", off)
	}
}

// Rule 5c: Iris's time-range read ("what happened last night", /history) keeps
// the shape that fixed its 30 d MEMORY_LIMIT_EXCEEDED — a narrow page pick, an
// exact latest-version resolve, the wide columns fetched keyed by that set,
// and a partition-pruning created_at bound on every history touch.
func TestAIProblemsInWindowSQLShape(t *testing.T) {
	const since = 30 * 24 * 3600
	sql := aiProblemsInWindowSQL(since, aiWindowProblemsLimit)

	for _, must := range []string{
		"WITH page AS", // stage 1: the narrow page pick
		"window_start >= now() - INTERVAL 2592000 SECOND", // the caller's window
		"created_at >= now() - INTERVAL 2678400 SECOND",   // + partition-pruning slack
		"max(version) AS version",                         // stage 2: exact latest version
		"(o.tenant_id, o.correlation_id, o.version) IN (SELECT tenant_id, correlation_id, version FROM picked)", // stage 3, keyed on the table's ORDER BY prefix
		"LIMIT 1 BY o.correlation_id", // belt-and-braces fold
		"LIMIT 1000",                  // bounded rows
	} {
		if !strings.Contains(sql, must) {
			t.Errorf("time-range SQL lost its bounded shape: missing %q\n%s", must, sql)
		}
	}
	// Every history touch must prune partitions: one created_at bound per
	// `FROM netops.corr_objects` (three stages, three bounds).
	bounds, touches := strings.Count(sql, "created_at >= now()"), strings.Count(sql, "FROM netops.corr_objects")
	if bounds != touches {
		t.Errorf("time-range SQL touches netops.corr_objects %d times but carries %d created_at bounds — "+
			"an unbounded touch reads every partition (#100)\n%s", touches, bounds, sql)
	}
	// The page pick must stay narrow: no wide column may cross its sort.
	page := sql[strings.Index(sql, "WITH page AS"):strings.Index(sql, "), picked AS")]
	for _, wide := range corrWideDisplayColumns {
		if strings.Contains(page, wide) {
			t.Errorf("time-range page pick references %q — the fold must pick narrow keys only (#100)\n%s", wide, page)
		}
	}
	// The latest-version resolve is deliberately NOT window-bounded (a later
	// version may have slid its window_start out of the window) but it must
	// stay keyed to the page, never scan the window again.
	picked := sql[strings.Index(sql, "), picked AS"):strings.Index(sql, "\nSELECT toString(")]
	if !strings.Contains(picked, "(tenant_id, correlation_id) IN (SELECT tenant_id, correlation_id FROM page)") {
		t.Errorf("latest-version resolve is not keyed to the picked page:\n%s", picked)
	}
	if regexp.MustCompile(`(?i)SELECT\s+\*`).MatchString(sql) {
		t.Error("time-range SQL contains SELECT *")
	}
}
