package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"netops/backend/timeintel"
)

func TestHandleReliabilityTimeMetricsGet(t *testing.T) {
	m := timeintel.NewMemMetricsStore()
	_ = m.Upsert(context.Background(), incidentTimeMetricRow{
		TenantID: "acme", CorrelationID: "c1", CalcVersion: "ti-1",
		OccurredAt: time.Now().UTC(), SeamType: "DIA", OwnerDomain: "isp",
	})
	s := &server{incidentTimeMetrics: m}

	// GET with no permission gate available in this lightweight server: requirePerm
	// will reject (no auth) → we assert it does NOT 200 without auth, proving the
	// read is gated (full positive-path auth is covered by the route-isolation
	// ledger + the store isolation test above).
	r := httptest.NewRequest(http.MethodGet, "/api/reliability/time-metrics", nil)
	w := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w, r)
	if w.Code == http.StatusOK {
		t.Fatalf("unauthenticated GET must be gated, got 200")
	}

	// An unknown method is rejected.
	r2 := httptest.NewRequest(http.MethodDelete, "/api/reliability/time-metrics", nil)
	w2 := httptest.NewRecorder()
	s.handleReliabilityTimeMetrics(w2, r2)
	if w2.Code != http.StatusMethodNotAllowed {
		t.Fatalf("DELETE want 405, got %d", w2.Code)
	}
}

// ── 2026-08-29 storm incident regression ─────────────────────────────────────
//
// The backfill's ClickHouse read folded the ENTIRE corr_objects history on every
// 15-minute tick (ORDER BY tenant_id, correlation_id, version DESC + LIMIT 1 BY,
// with the lookback applied outside the fold) and then read the wide hypotheses
// column keyed off the primary-key prefix. At 2 M history rows that is ~4 M rows
// / 45 GiB and a 1.8 GiB peak — over ClickHouse's 2 GiB per-query cap — so every
// pass died with MEMORY_LIMIT_EXCEEDED or TIMEOUT_EXCEEDED and incident_time_metrics
// stopped being written for the whole storm.
//
// These tests pin the three properties that keep it from coming back: the shape
// (bounded + prunable), the guards (stated per query, not inherited), and the
// failure mode (loud, never a silent empty pass).

// TestTimeIntelBackfillSQLIsBoundedAndPrunable asserts the read shape.
func TestTimeIntelBackfillSQLIsBoundedAndPrunable(t *testing.T) {
	sql := timeIntelBackfillSQL(3600, 20000)

	// 1. No full-history latest-version fold. `LIMIT 1 BY` over corr_objects is
	//    the exact banned shape (#100 rule 2, bounded_io_test.go).
	if strings.Contains(sql, "LIMIT 1 BY") {
		t.Errorf("backfill SQL folds corr_objects history again (LIMIT 1 BY):\n%s", sql)
	}
	// 2. The latest version comes from the corr_current hot projection.
	if !strings.Contains(sql, "FROM netops.corr_current FINAL") {
		t.Errorf("backfill SQL must pick the latest version from corr_current:\n%s", sql)
	}
	// 3. The history (wide) read carries the partition-prunable created_at bound,
	//    widened by exactly the documented clock-skew slack — non-narrowing.
	wantBound := "o.created_at >= now() - INTERVAL " + intToString(3600+corrPartitionSkewSlackSeconds) + " SECOND"
	if !strings.Contains(sql, wantBound) {
		t.Errorf("backfill SQL lost its prunable created_at bound (want %q):\n%s", wantBound, sql)
	}
	// 4. The window bound is on the pick, not applied after an unbounded fold.
	if !strings.Contains(sql, "WHERE window_start >= now() - INTERVAL 3600 SECOND") {
		t.Errorf("backfill SQL must bound the PICK by window_start:\n%s", sql)
	}
	// 5. The keyed history lookup leads with tenant_id so the corr_objects
	//    primary key prefix (tenant_id, correlation_id, version) is usable.
	if !strings.Contains(sql, "(o.tenant_id, o.correlation_id, o.version) IN (") {
		t.Errorf("backfill SQL key tuple must lead with tenant_id:\n%s", sql)
	}
	// 6. Still capped.
	if !strings.Contains(sql, "LIMIT 20000") {
		t.Errorf("backfill SQL lost its row cap:\n%s", sql)
	}
	// 7. No outer ORDER BY over the wide read: sorting the result set holds
	//    hypotheses blocks alive across the whole scan (971 MiB measured, over
	//    the 1 GiB ceiling) and buys nothing — the loop upserts by key.
	if outer := sql[strings.Index(sql, "FROM netops.corr_objects AS o"):]; strings.Contains(outer, "ORDER BY") {
		t.Errorf("the wide history read must not sort its result set:\n%s", outer)
	}
	// 8. The wide blob is touched ONLY in the keyed outer read — never inside
	//    the pick, which must stay narrow.
	pick := sql[strings.Index(sql, "WITH picked AS"):strings.Index(sql, "SELECT toString(o.tenant_id)")]
	for _, wide := range []string{"hypotheses", "layer_coverage", "app_impact"} {
		if strings.Contains(pick, wide) {
			t.Errorf("the pick touches wide column %q — it must fold narrow keys only (#100):\n%s", wide, pick)
		}
	}
}

// capturingCH records the request URL of every ClickHouse call and answers with
// the supplied rows, so a test can assert what settings actually went over the
// wire (a guard that is only in a comment is not a guard).
func capturingCH(t *testing.T, data []map[string]any) *[]url.Values {
	t.Helper()
	seen := &[]url.Values{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = append(*seen, r.URL.Query())
		_ = json.NewEncoder(w).Encode(map[string]any{"data": data})
	}))
	t.Cleanup(srv.Close)
	t.Setenv("CLICKHOUSE_URL", srv.URL)
	return seen
}

// TestTimeIntelBackfillSendsExplicitReadGuards proves the containment settings
// reach ClickHouse. Before the fix the pass inherited the 2 GiB default cap and
// the generic 20 s worker budget, and was attributed to `worker:cross-tenant`
// (shared with the appid fusion store) — so it could neither be bounded nor
// found in system.query_log.
func TestTimeIntelBackfillSendsExplicitReadGuards(t *testing.T) {
	seen := capturingCH(t, nil)
	s := &server{incidentTimeMetrics: timeintel.NewMemMetricsStore()}
	if _, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour); err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if len(*seen) != 1 {
		t.Fatalf("want exactly one ClickHouse call, got %d", len(*seen))
	}
	q := (*seen)[0]
	for k, want := range map[string]string{
		"tenant_scope":       "__all__",
		"log_comment":        timeIntelBackfillTag,
		"max_memory_usage":   strconv.Itoa(chWorkerReadMemoryBytes),
		"max_execution_time": strconv.Itoa(int(timeIntelBackfillBudget / time.Second)),
		"max_block_size":     intToString(timeIntelBackfillBlockRows),
		"max_threads":        intToString(timeIntelBackfillThreads),
	} {
		if got := q.Get(k); got != want {
			t.Errorf("%s = %q, want %q (the guard must be stated per query, not inherited)", k, got, want)
		}
	}
	// The ceiling has to leave room for the rest of the platform: two worker
	// lanes plus the 1 GiB hot-UI lane must fit inside the 4 GiB server budget.
	if 2*chWorkerReadMemoryBytes+(1<<30) > 4<<30 {
		t.Errorf("worker memory ceiling %d leaves no room for the hot UI lane under the 4 GiB server cap", chWorkerReadMemoryBytes)
	}
	// The response bound must fit a FULL cap-sized page (measured ~900 B/row on
	// the storm table), or the first successful pass fails on truncation.
	if timeIntelBackfillMaxResponseBytes < int64(timeIntelBackfillCap)*900 {
		t.Errorf("response bound %d cannot hold %d rows at the measured ~900 B/row",
			timeIntelBackfillMaxResponseBytes, timeIntelBackfillCap)
	}
	// And the transport must outlive the server-side budget it carries, or the
	// classified ClickHouse error can never reach the caller.
	if timeIntelBackfillPassTimeout <= timeIntelBackfillBudget {
		t.Errorf("pass timeout %s must exceed the read budget %s", timeIntelBackfillPassTimeout, timeIntelBackfillBudget)
	}
}

// TestTimeIntelBackfillFailedReadIsLoud: a refused read must surface as an error
// with zero rows written, never as a successful pass over an empty result. This
// is the difference between "the storm had no incidents" and "we wrote nothing
// for six hours".
func TestTimeIntelBackfillFailedReadIsLoud(t *testing.T) {
	failingCH(t)
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	n, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour)
	if err == nil {
		t.Fatal("a refused ClickHouse read must return an error, not a clean empty pass")
	}
	if n != 0 {
		t.Errorf("written = %d on a failed read, want 0", n)
	}
	rows, lerr := m.List(context.Background(), "", true, 10)
	if lerr != nil {
		t.Fatalf("store list: %v", lerr)
	}
	if len(rows) != 0 {
		t.Errorf("a failed pass wrote %d snapshots", len(rows))
	}
}

// TestTimeIntelBackfillWritesSnapshotsPerTenant is the positive control for the
// two tests above: the same plumbing, answering normally, still stamps each
// snapshot under the corr object's OWN tenant (CLAUDE.md §3a).
func TestTimeIntelBackfillWritesSnapshotsPerTenant(t *testing.T) {
	capturingCH(t, []map[string]any{
		{
			"tenant_id": "acme", "correlation_id": "c-1",
			"window_start": "2026-08-29T10:00:00Z", "created_at": "2026-08-29T10:01:00Z",
			"verdict_tier": "confirmed", "top_confidence": 0.9,
			"top_hypothesis": "link_down", "evidence_missing": "[]",
			"affected": "{}", "state": "open", "owner": "isp", "seam_type": "DIA",
		},
		{
			"tenant_id": "globex", "correlation_id": "c-2",
			"window_start": "2026-08-29T10:05:00Z", "created_at": "2026-08-29T10:06:00Z",
			"verdict_tier": "suspected", "top_confidence": 0.4,
			"top_hypothesis": "cpu_hog", "evidence_missing": "[]",
			"affected": "{}", "state": "closed", "owner": "customer", "seam_type": "LAN",
		},
	})
	m := timeintel.NewMemMetricsStore()
	s := &server{incidentTimeMetrics: m}
	n, err := s.backfillIncidentTimeMetrics(context.Background(), time.Hour)
	if err != nil {
		t.Fatalf("backfill: %v", err)
	}
	if n != 2 {
		t.Fatalf("written = %d, want 2", n)
	}
	own, err := m.List(context.Background(), "acme", false, 10)
	if err != nil {
		t.Fatalf("store list: %v", err)
	}
	if len(own) != 1 || own[0].TenantID != "acme" || own[0].SeamType != "DIA" {
		t.Fatalf("acme must see exactly its own snapshot, got %+v", own)
	}
}
