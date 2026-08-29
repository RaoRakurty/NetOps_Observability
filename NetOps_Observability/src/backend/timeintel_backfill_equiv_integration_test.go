//go:build integration

package backend

// timeintel_backfill_equiv_integration_test.go — the 2026-08-29 storm-incident
// equivalence proof, against a REAL ClickHouse.
//
// The hermetic tests in timeintel_backfill_test.go pin the SHAPE of the repaired
// read (bounded pick, prunable created_at bound, tenant-led key tuple) and the
// GUARDS that go over the wire. Neither can prove the thing that actually
// matters about a rewritten query: that it returns the same rows. Only a server
// can answer that, so this file asks one.
//
// Run it against a throwaway server (never the live stack — it creates and drops
// a scratch database):
//
//	docker run -d --rm --name chdrill \
//	  -e CLICKHOUSE_USER=drill -e CLICKHOUSE_PASSWORD=drillpw \
//	  -p 18123:8123 --tmpfs /var/lib/clickhouse:rw,size=512m \
//	  -v "$PWD/deployment/docker/clickhouse/custom-settings.xml":/etc/clickhouse-server/config.d/custom-settings.xml:ro \
//	  clickhouse/clickhouse-server:24.8-alpine
//	CH_TEST_URL=http://localhost:18123 CLICKHOUSE_USER=drill CLICKHOUSE_PASSWORD=drillpw \
//	  go test -tags=integration -run TimeIntelBackfill ./
//
// The custom-settings mount is REQUIRED: every read this package makes carries
// the `tenant_scope` custom setting, and a stock server rejects it (UNKNOWN_SETTING).
//
// The same fixture was verified read-only against the live storm table on
// 2026-08-29 using inline `values(...)` CTEs: 3 rows from each shape, symmetric
// difference 0.

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// timeIntelBackfillSQLOld is the shape that failed every pass during the storm,
// kept HERE (not in production code) purely as the equivalence oracle.
const timeIntelBackfillSQLOld = `
WITH picked AS (
     SELECT correlation_id, version, window_start FROM (
          SELECT tenant_id, correlation_id, version, window_start
            FROM netops.corr_objects
           ORDER BY tenant_id, correlation_id, version DESC
           LIMIT 1 BY tenant_id, correlation_id
     )
      WHERE window_start >= now() - INTERVAL 3600 SECOND
      ORDER BY window_start ASC
      LIMIT 20000
)
SELECT toString(o.tenant_id)      AS tenant_id,
       toString(o.correlation_id) AS correlation_id,
       o.top_hypothesis           AS top_hypothesis,
       o.state                    AS state,
       JSONExtractString(o.hypotheses,'ranking','hypotheses',1,'verdict','owner') AS owner,
       JSONExtractString(o.hypotheses,'grounding_context','seams',1,'seam_type')  AS seam_type
  FROM netops.corr_objects AS o
 WHERE (o.correlation_id, o.version) IN (SELECT correlation_id, version FROM picked)
 ORDER BY o.window_start ASC
 FORMAT JSON`

// corrFixtureDDL mirrors the production corr_objects / corr_current definitions
// closely enough for the query shapes under test (keys, engines, the wide blob).
var corrFixtureDDL = []string{
	`CREATE DATABASE IF NOT EXISTS netops`,
	`DROP TABLE IF EXISTS netops.corr_objects`,
	`DROP TABLE IF EXISTS netops.corr_current`,
	`CREATE TABLE netops.corr_objects (
	    tenant_id LowCardinality(String) DEFAULT '',
	    correlation_id UUID, version UInt32,
	    state Enum8('open'=1,'closed'=2,'merged'=3),
	    window_start DateTime64(3), window_end DateTime64(3),
	    top_hypothesis String, top_confidence Float32,
	    verdict_tier Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
	    hypotheses String CODEC(ZSTD(3)),
	    evidence_missing String DEFAULT '[]', affected String DEFAULT '[]',
	    signal_count UInt32, node_count UInt16,
	    created_at DateTime64(3) DEFAULT now64(3))
	  ENGINE = MergeTree PARTITION BY (tenant_id, toYYYYMMDD(created_at))
	  ORDER BY (tenant_id, correlation_id, version)`,
	`CREATE TABLE netops.corr_current (
	    tenant_id LowCardinality(String) DEFAULT '',
	    correlation_id UUID, version UInt32,
	    state Enum8('open'=1,'closed'=2,'merged'=3),
	    window_start DateTime64(3), window_end DateTime64(3),
	    top_hypothesis String, top_confidence Float32,
	    verdict_tier Enum8('undetermined'=0,'suspected'=1,'confirmed'=2),
	    evidence_missing String DEFAULT '[]', affected String DEFAULT '[]',
	    signal_count UInt32, node_count UInt16,
	    created_at DateTime64(3) DEFAULT now64(3))
	  ENGINE = ReplacingMergeTree(created_at)
	  PARTITION BY tenant_id ORDER BY (tenant_id, correlation_id)`,
}

// The fixture, per the incident's own edge cases:
//
//	a (t1) — three versions, in window: the fold must pick v3, not v1.
//	b (t1) — two versions, window_start OUTSIDE the lookback: excluded by both.
//	c (t2) — one version, in window: a second tenant must not be lost.
//	e (t1) — window_start 30 min AHEAD of created_at (device clock skew): the
//	         new created_at bound must NOT drop it, which is the whole reason
//	         for corrPartitionSkewSlackSeconds.
const (
	idA = "11111111-1111-4111-8111-111111111111"
	idB = "22222222-2222-4222-8222-222222222222"
	idC = "33333333-3333-4333-8333-333333333333"
	idE = "55555555-5555-4555-8555-555555555555"
)

func hyp(owner, seam string) string {
	return `{"ranking":{"hypotheses":[{"verdict":{"owner":"` + owner + `"}}]},` +
		`"grounding_context":{"seams":[{"seam_type":"` + seam + `"}]}}`
}

func corrFixtureRows() string {
	row := func(tenant, id string, ver int, wsOff, caOff, hypJSON, top string) string {
		return `('` + tenant + `','` + id + `',` + intToString(ver) + `,'open',` +
			`now64(3) ` + wsOff + `, now64(3), '` + top + `', 0.9, 'confirmed', '` +
			strings.ReplaceAll(hypJSON, "'", "\\'") + `','[]','[]',1,1, now64(3) ` + caOff + `)`
	}
	return `INSERT INTO netops.corr_objects
	  (tenant_id, correlation_id, version, state, window_start, window_end,
	   top_hypothesis, top_confidence, verdict_tier, hypotheses,
	   evidence_missing, affected, signal_count, node_count, created_at) VALUES ` +
		strings.Join([]string{
			row("t1", idA, 1, "- INTERVAL 1800 SECOND", "- INTERVAL 1790 SECOND", hyp("isp", "DIA"), "h-a1"),
			row("t1", idA, 2, "- INTERVAL 1800 SECOND", "- INTERVAL 1700 SECOND", hyp("isp", "DIA"), "h-a2"),
			row("t1", idA, 3, "- INTERVAL 1800 SECOND", "- INTERVAL 1600 SECOND", hyp("lan", "LAN"), "h-a3"),
			row("t1", idB, 1, "- INTERVAL 7200 SECOND", "- INTERVAL 7190 SECOND", hyp("isp", "DIA"), "h-b1"),
			row("t1", idB, 2, "- INTERVAL 7200 SECOND", "- INTERVAL 7100 SECOND", hyp("isp", "DIA"), "h-b2"),
			row("t2", idC, 1, "- INTERVAL 900 SECOND", "- INTERVAL 890 SECOND", hyp("cloud", "CLOUD"), "h-c1"),
			row("t1", idE, 1, "+ INTERVAL 1800 SECOND", "- INTERVAL 60 SECOND", hyp("wan", "WAN"), "h-e1"),
		}, ",")
}

// corrCurrentSeed projects the latest version of each object, exactly as the
// engine's dual-write and corr_current_reconcile.go do.
const corrCurrentSeed = `INSERT INTO netops.corr_current
  (tenant_id, correlation_id, version, state, window_start, window_end,
   top_hypothesis, top_confidence, verdict_tier, evidence_missing, affected,
   signal_count, node_count, created_at)
SELECT tenant_id, correlation_id, version, state, window_start, window_end,
       top_hypothesis, top_confidence, verdict_tier, evidence_missing, affected,
       signal_count, node_count, created_at
  FROM (SELECT * FROM netops.corr_objects
         ORDER BY tenant_id, correlation_id, version DESC
         LIMIT 1 BY tenant_id, correlation_id)`

func requireCHTestURL(t *testing.T) {
	t.Helper()
	base := os.Getenv("CH_TEST_URL")
	if base == "" {
		t.Skip("CH_TEST_URL not set — see the header of this file for the docker line")
	}
	t.Setenv("CLICKHOUSE_URL", base)
}

// TestTimeIntelBackfillNewSQLMatchesOldOnFixture is the regression: the repaired
// query must return the SAME rows as the shape it replaces.
func TestTimeIntelBackfillNewSQLMatchesOldOnFixture(t *testing.T) {
	requireCHTestURL(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// SHIP-SAFETY: this test DROPs netops.corr_objects. Refuse to run against a
	// server that already holds correlation history — a mistyped CH_TEST_URL
	// must cost a failed test, never a production table.
	if rows, err := chWorkerQuery(ctx, `SELECT count() AS n FROM system.tables
	  WHERE database='netops' AND name='corr_objects' FORMAT JSON`); err == nil &&
		len(rows) == 1 && asFloat(rows[0]["n"]) > 0 {
		n, qerr := chWorkerQuery(ctx, `SELECT count() AS n FROM netops.corr_objects FORMAT JSON`)
		if qerr != nil || len(n) != 1 || asFloat(n[0]["n"]) > 0 {
			t.Fatalf("CH_TEST_URL points at a server with a populated netops.corr_objects — refusing to drop it (rows=%v err=%v)", n, qerr)
		}
	}

	for _, stmt := range corrFixtureDDL {
		if err := chWorkerExec(ctx, stmt); err != nil {
			t.Fatalf("fixture DDL %.60s…: %v", stmt, err)
		}
	}
	if err := chWorkerExec(ctx, corrFixtureRows()); err != nil {
		t.Fatalf("fixture insert: %v", err)
	}
	if err := chWorkerExec(ctx, corrCurrentSeed); err != nil {
		t.Fatalf("corr_current seed: %v", err)
	}

	// The comparison projects only the columns both shapes share, so a
	// difference is a difference in the ROWS PICKED, not in formatting.
	narrow := func(rows []map[string]any) map[string]string {
		out := map[string]string{}
		for _, r := range rows {
			out[asString(r["correlation_id"])] = strings.Join([]string{
				asString(r["tenant_id"]), asString(r["top_hypothesis"]),
				asString(r["owner"]), asString(r["seam_type"]), asString(r["state"]),
			}, "|")
		}
		return out
	}

	oldRows, err := chWorkerQuery(ctx, timeIntelBackfillSQLOld)
	if err != nil {
		t.Fatalf("old SQL: %v", err)
	}
	newRows, err := chWorkerQueryTuned(ctx, chWorkerRead{
		SQL: timeIntelBackfillSQL(3600, timeIntelBackfillCap),
		Tag: timeIntelBackfillTag, Budget: timeIntelBackfillBudget,
		MaxBytes: timeIntelBackfillMaxResponseBytes,
	})
	if err != nil {
		t.Fatalf("new SQL: %v", err)
	}

	got, want := narrow(newRows), narrow(oldRows)
	if len(want) != 3 {
		t.Fatalf("fixture oracle picked %d objects, want 3 (a, c, e) — the fixture drifted: %v", len(want), want)
	}
	for id, w := range want {
		if g, ok := got[id]; !ok {
			t.Errorf("new SQL dropped correlation %s (%s)", id, w)
		} else if g != w {
			t.Errorf("correlation %s: new SQL returned %q, old returned %q", id, g, w)
		}
	}
	for id := range got {
		if _, ok := want[id]; !ok {
			t.Errorf("new SQL invented correlation %s", id)
		}
	}
	// The clock-skewed object is the one the created_at bound could plausibly
	// have eaten; name it so a regression there is unmistakable.
	if _, ok := got[idE]; !ok {
		t.Error("the skew fixture (window_start ahead of created_at) was dropped — corrPartitionSkewSlackSeconds is no longer non-narrowing")
	}
	if _, ok := got[idB]; ok {
		t.Error("an object outside the lookback was returned — the window bound is not being applied")
	}
}
