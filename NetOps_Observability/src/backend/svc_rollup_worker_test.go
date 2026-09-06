// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// svc_rollup_worker_test.go — unit + isolation tests for the #69 P2 rollup
// worker (CLAUDE.md §3a.5: REQUIRED with the feature). The worker's IO is
// injectable, so these drive real ticks against fakes and assert the §3a
// invariant directly on the SQL: a rollup statement never mixes tenants —
// its scope, its stamped tenant_id and its scan bounds all belong to ONE
// tenant.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"netops/backend/internal/servicecat"
)

func rollupSets() []svcSelectorSet {
	return []svcSelectorSet{
		{TenantID: "acme", ServiceID: "11111111-1111-4111-8111-111111111111", Version: 3,
			Spec: map[string]any{"ports": []any{float64(443)}}},
		{TenantID: "globex", ServiceID: "22222222-2222-4222-8222-222222222222", Version: 1,
			Spec: map[string]any{"dst_prefixes": []any{"10.2.0.0/16"}}},
	}
}

type execCall struct{ scope, body string }

// testRollupWorker builds a worker over fakes. checkpoints maps tenant →
// last-live-minute unix (nil = no checkpoint rows).
func testRollupWorker(now time.Time, checkpoints map[string]int64, execErr map[string]error) (*svcRollupWorker, *[]execCall) {
	var calls []execCall
	w := &svcRollupWorker{
		listSets: func(context.Context, int) ([]svcSelectorSet, error) { return rollupSets(), nil },
		query: func(_ context.Context, scope, sql string) ([]map[string]any, error) {
			if scope != "__all__" {
				return nil, errors.New("checkpoint read must run at __all__, got " + scope)
			}
			var rows []map[string]any
			for t, m := range checkpoints {
				rows = append(rows, map[string]any{"tenant_id": t, "m": float64(m)})
			}
			return rows, nil
		},
		exec: func(_ context.Context, scope, body string) error {
			calls = append(calls, execCall{scope, body})
			if execErr != nil {
				return execErr[scope]
			}
			return nil
		},
		addrClause: func(tenant string) (string, bool) {
			switch tenant {
			case "acme":
				return " AND (src_addr IN ('10.1.0.1') OR dst_addr IN ('10.1.0.1'))", false
			case "globex":
				return " AND (src_addr IN ('10.2.0.1') OR dst_addr IN ('10.2.0.1'))", false
			default:
				return "", true // no visible devices
			}
		},
		now: func() time.Time { return now },
	}
	return w, &calls
}

// §3a.5 isolation: one statement per tenant, run at THAT tenant's scope,
// stamping THAT tenant only, scan bounded to THAT tenant's rows + devices.
func TestSvcRollupTickNeverMixesTenants(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 30, 30, 0, time.UTC)
	w, calls := testRollupWorker(now, nil, nil)
	ran, err := w.tick(context.Background())
	if err != nil {
		t.Fatalf("tick: %v", err)
	}
	if ran != 2 || len(*calls) != 2 {
		t.Fatalf("want one statement per tenant (2), got ran=%d calls=%d", ran, len(*calls))
	}
	for _, c := range *calls {
		other, otherAddr := "globex", "10.2.0.1"
		if c.scope == "globex" {
			other, otherAddr = "acme", "10.1.0.1"
		}
		if !strings.Contains(c.body, "'"+c.scope+"' AS tenant_id") {
			t.Errorf("scope %s: statement does not stamp its own tenant:\n%s", c.scope, c.body)
		}
		if !strings.Contains(c.body, "tenant_id = '"+c.scope+"'") {
			t.Errorf("scope %s: scan not bounded to the tenant's tagged rows:\n%s", c.scope, c.body)
		}
		if strings.Contains(c.body, other) || strings.Contains(c.body, otherAddr) {
			t.Errorf("TENANT LEAK: scope %s statement mentions %s/%s:\n%s", c.scope, other, otherAddr, c.body)
		}
		if !strings.Contains(c.body, "rolled_by") || !strings.Contains(c.body, "'live'") {
			t.Errorf("scope %s: live roller must stamp rolled_by='live':\n%s", c.scope, c.body)
		}
	}
}

// Idempotency guard: a tenant whose checkpoint equals the last closed minute is
// skipped entirely (SummingMergeTree would double-count a re-insert), and a
// stale checkpoint resumes exactly one minute after it.
func TestSvcRollupCheckpointGuard(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 30, 30, 0, time.UTC)
	lastClosed := time.Date(2026, 7, 20, 12, 29, 0, 0, time.UTC)
	cp := map[string]int64{
		"acme":   lastClosed.Unix(),                       // fully rolled → must skip
		"globex": lastClosed.Add(-3 * time.Minute).Unix(), // 3 minutes behind
	}
	w, calls := testRollupWorker(now, cp, nil)
	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	if len(*calls) != 1 {
		t.Fatalf("acme is up to date and must be skipped; got %d statements", len(*calls))
	}
	c := (*calls)[0]
	if c.scope != "globex" {
		t.Fatalf("expected only globex to roll, got scope %s", c.scope)
	}
	from := lastClosed.Add(-2 * time.Minute) // checkpoint+1m
	if !strings.Contains(c.body, "toDateTime("+intToString(int(from.Unix()))+")") {
		t.Errorf("globex window must resume at checkpoint+1m (%s):\n%s", from, c.body)
	}
	// upper bound is lastClosed inclusive → ts < lastClosed+1m
	if !strings.Contains(c.body, "toDateTime("+intToString(int(lastClosed.Add(time.Minute).Unix()))+")") {
		t.Errorf("globex window must end at the last closed minute:\n%s", c.body)
	}
}

// Cold start is bounded: no checkpoint → only the capped trailing window, never
// an unbounded catch-up scan.
func TestSvcRollupColdStartBounded(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 30, 30, 0, time.UTC)
	w, calls := testRollupWorker(now, nil, nil)
	if _, err := w.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
	lastClosed := time.Date(2026, 7, 20, 12, 29, 0, 0, time.UTC)
	from := lastClosed.Add(-time.Duration(svcRollupMaxMinutesPerTick-1) * time.Minute)
	for _, c := range *calls {
		if !strings.Contains(c.body, "toDateTime("+intToString(int(from.Unix()))+")") {
			t.Errorf("cold start must begin at lastClosed-%dm:\n%s", svcRollupMaxMinutesPerTick-1, c.body)
		}
	}
}

// A tenant with no visible devices attributes ONLY its tagged rows: the
// untagged-share clause must be absent (default-closed).
func TestSvcRollupInsertSQLNoDevicesDefaultClosed(t *testing.T) {
	from := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sql, n := servicecat.RollupInsertSQL("nodev", rollupSets()[:1], from, from.Add(4*time.Minute), "", "live")
	if n != 1 {
		t.Fatalf("want 1 select, got %d", n)
	}
	if strings.Contains(sql, "tenant_id = ''") {
		t.Errorf("no-device tenant must not read untagged rows:\n%s", sql)
	}
	if !strings.Contains(sql, "tenant_id = 'nodev'") {
		t.Errorf("scan must be bounded to the tenant's tagged rows:\n%s", sql)
	}
}

// A selector with no usable predicate yields no statement — the service stays
// honestly unattributed instead of matching everything.
func TestSvcRollupInsertSQLSkipsUnusableSelector(t *testing.T) {
	from := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sets := []svcSelectorSet{
		{TenantID: "acme", ServiceID: "11111111-1111-4111-8111-111111111111", Version: 1, Spec: map[string]any{}},
		{TenantID: "acme", ServiceID: "not-a-uuid", Version: 1, Spec: map[string]any{"ports": []any{float64(53)}}},
	}
	if sql, n := servicecat.RollupInsertSQL("acme", sets, from, from, "", "live"); n != 0 || sql != "" {
		t.Fatalf("unusable selectors must produce no statement, got n=%d sql=%q", n, sql)
	}
}

// Selector predicates are stamped with the version that attributed them, and
// the protocols predicate uses the real flows column (`proto`).
func TestSvcRollupInsertSQLStampsVersionAndProto(t *testing.T) {
	from := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	sets := []svcSelectorSet{{TenantID: "acme", ServiceID: "11111111-1111-4111-8111-111111111111", Version: 7,
		Spec: map[string]any{"protocols": []any{float64(17)}}}}
	sql, n := servicecat.RollupInsertSQL("acme", sets, from, from, "", "backfill")
	if n != 1 {
		t.Fatalf("want 1 select, got %d", n)
	}
	if !strings.Contains(sql, "toUInt32(7) AS selector_version") {
		t.Errorf("selector_version not stamped:\n%s", sql)
	}
	if !strings.Contains(sql, "proto IN (17)") || strings.Contains(sql, "protocol IN") {
		t.Errorf("protocols predicate must target the `proto` column:\n%s", sql)
	}
	if !strings.Contains(sql, "'backfill' AS rolled_by") {
		t.Errorf("rolled_by not stamped:\n%s", sql)
	}
}

// A failing tenant is retried (checkpoint untouched), doesn't block others, and
// the tick reports the error so the loop backs off with jitter.
func TestSvcRollupTickErrorIsolatesAndBacksOff(t *testing.T) {
	now := time.Date(2026, 7, 20, 12, 30, 30, 0, time.UTC)
	w, calls := testRollupWorker(now, nil, map[string]error{"acme": errors.New("boom")})
	ran, err := w.tick(context.Background())
	if err == nil {
		t.Fatal("tick must surface the tenant failure")
	}
	if ran != 1 || len(*calls) != 2 {
		t.Fatalf("the healthy tenant must still run: ran=%d calls=%d", ran, len(*calls))
	}
	w.backoffAfterFailure(time.Minute)
	if !w.nextTry.After(now) {
		t.Error("backoff must schedule the next attempt in the future")
	}
	w.failures = 20 // overflow guard: shift must clamp, not wrap negative
	w.backoffAfterFailure(time.Minute)
	if w.nextTry.After(now.Add(svcRollupMaxBackoff + svcRollupMaxBackoff/2)) {
		t.Errorf("backoff exceeded its cap: %v", w.nextTry.Sub(now))
	}
}
