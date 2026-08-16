package backend

import (
	"context"
	"errors"
	"fmt"
	"netops/backend/internal/platformdb"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/reports"
)

// TestPgJobQueue exercises the Postgres job queue end to end: enqueue idempotency,
// concurrent SKIP-LOCKED claiming (no double-claim), lease expiry re-claim (crash
// recovery), lease renewal (the double-delivery guard), backoff + dead-letter, and
// the report_jobs RLS policy. Gated on DATABASE_URL_TEST (a superuser that
// provisions a non-superuser app role so RLS actually enforces).
func TestPgJobQueue(t *testing.T) {
	adminDSN := os.Getenv("DATABASE_URL_TEST")
	if adminDSN == "" {
		t.Skip("set DATABASE_URL_TEST to run the Postgres job-queue test")
	}
	ctx := context.Background()
	ps, err := platformdb.NewPGStore(ctx, provisionAppRole(ctx, t, adminDSN))
	if err != nil {
		t.Fatalf("newPgStore: %v", err)
	}
	defer ps.DB().Close()
	q := reports.NewPGJobQueue(ps.DB(), 3)
	now := time.Now().UTC()
	fire := func(i int) time.Time { return time.Date(2026, 6, 1, 0, i, 0, 0, time.UTC) }
	mk := func(id, sched, tenant string, f time.Time) reports.Job {
		return reports.Job{ID: id, TenantID: tenant, ScheduleID: sched, ExecutionID: "x-" + id, FireTime: f}
	}

	// ---- idempotency on (schedule_id, fire_time) ----
	if _, created, err := q.Enqueue(ctx, mk("j1", "sched-a", "acme", fire(0)), now); err != nil || !created {
		t.Fatalf("first enqueue: created=%v err=%v", created, err)
	}
	if _, created, err := q.Enqueue(ctx, mk("j1-dup", "sched-a", "acme", fire(0)), now); err != nil || created {
		t.Fatalf("duplicate enqueue must be a no-op: created=%v err=%v", created, err)
	}
	if p, err := q.Pending(ctx); err != nil || p != 1 {
		t.Fatalf("pending after dedup = %d err=%v, want 1", p, err)
	}

	// ---- claim + complete ----
	got, err := q.Claim(ctx, "w1", 10, 30*time.Second)
	if err != nil || len(got) != 1 || got[0].ID != "j1" {
		t.Fatalf("claim = %v err=%v, want [j1]", got, err)
	}
	if got[0].Attempts != 1 {
		t.Fatalf("claimed attempts = %d, want 1", got[0].Attempts)
	}
	if got[0].LockedBy != "w1" {
		t.Fatalf("claimed LockedBy = %q, want w1 (M11: workers present it on Complete/Fail)", got[0].LockedBy)
	}
	if err := q.Complete(ctx, "j1", "w1"); err != nil {
		t.Fatalf("complete: %v", err)
	}
	if p, _ := q.Pending(ctx); p != 0 {
		t.Fatalf("pending after complete = %d, want 0 (done excluded)", p)
	}

	// ---- concurrent claim: every job claimed exactly once ----
	const n = 24
	for i := 0; i < n; i++ {
		if _, _, err := q.Enqueue(ctx, mk(fmt.Sprintf("c%d", i), fmt.Sprintf("s%d", i), "acme", fire(i+1)), now); err != nil {
			t.Fatalf("enqueue c%d: %v", i, err)
		}
	}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for k := 0; k < 6; k++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for {
				js, err := q.Claim(ctx, fmt.Sprintf("w%d", worker), 3, 30*time.Second)
				if err != nil || len(js) == 0 {
					return
				}
				mu.Lock()
				for _, j := range js {
					seen[j.ID]++
				}
				mu.Unlock()
			}
		}(k)
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("concurrent claim covered %d jobs, want %d", len(seen), n)
	}
	for id, c := range seen {
		if c != 1 {
			t.Errorf("job %s claimed %d times (double-claim)", id, c)
		}
	}

	// ---- lease expiry → re-claim (crash recovery) ----
	if _, _, err := q.Enqueue(ctx, mk("lease1", "sl", "acme", fire(100)), now); err != nil {
		t.Fatalf("enqueue lease1: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, time.Millisecond); len(js) != 1 {
		t.Fatalf("claim lease1 = %v, want 1", js)
	}
	time.Sleep(40 * time.Millisecond) // let the 1ms lease lapse
	js2, _ := q.Claim(ctx, "w2", 10, 30*time.Second)
	if len(js2) != 1 || js2[0].ID != "lease1" {
		t.Fatalf("expired lease should be re-claimable, got %v", js2)
	}
	if js2[0].Attempts != 2 {
		t.Fatalf("re-claim attempts = %d, want 2", js2[0].Attempts)
	}
	// M11 lease guard: the crashed worker (w1) can no longer finalize the job
	// w2 re-claimed; only the current lease holder can.
	if err := q.Complete(ctx, "lease1", "w1"); !errors.Is(err, reports.ErrLeaseLost) {
		t.Fatalf("complete by evicted worker = %v, want reports.ErrLeaseLost", err)
	}
	if err := q.Complete(ctx, "lease1", "w2"); err != nil {
		t.Fatalf("complete by current holder: %v", err)
	}

	// ---- lease renewal keeps a long job out of other workers' reach ----
	if _, _, err := q.Enqueue(ctx, mk("ren1", "sr", "acme", fire(101)), now); err != nil {
		t.Fatalf("enqueue ren1: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, time.Millisecond); len(js) != 1 {
		t.Fatalf("claim ren1 failed")
	}
	if err := q.RenewLease(ctx, "ren1", "w1", 60*time.Second); err != nil {
		t.Fatalf("renew lease: %v", err)
	}
	time.Sleep(40 * time.Millisecond) // original 1ms lease would have lapsed
	if js, _ := q.Claim(ctx, "w2", 10, 30*time.Second); len(js) != 0 {
		t.Fatalf("renewed lease must NOT be re-claimable, got %v", js)
	}
	if err := q.RenewLease(ctx, "ren1", "w-other", 60*time.Second); !errors.Is(err, reports.ErrLeaseLost) {
		t.Fatalf("renew by wrong worker = %v, want reports.ErrLeaseLost", err)
	}
	_ = q.Complete(ctx, "ren1", "w1")

	// ---- backoff + dead-letter ----
	if _, _, err := q.Enqueue(ctx, mk("f1", "sf", "acme", fire(102)), now); err != nil {
		t.Fatalf("enqueue f1: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, 30*time.Second); len(js) != 1 {
		t.Fatalf("claim f1 failed")
	}
	if err := q.Fail(ctx, "f1", "w1", 1, "boom", time.Now().Add(time.Hour), false); err != nil {
		t.Fatalf("fail-retry: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, 30*time.Second); len(js) != 0 {
		t.Fatalf("backoff (future run_after) should hide f1, got %v", js)
	}
	// Dead-letter happens from a RUNNING job (Fail is lease-guarded, M11): a
	// second job walks the claim→fail(dead) path.
	if _, _, err := q.Enqueue(ctx, mk("f2", "sf2", "acme", fire(103)), now); err != nil {
		t.Fatalf("enqueue f2: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, 30*time.Second); len(js) != 1 || js[0].ID != "f2" {
		t.Fatalf("claim f2 failed")
	}
	if err := q.Fail(ctx, "f2", "w1", 3, "boom again", time.Now().UTC(), true); err != nil {
		t.Fatalf("dead-letter: %v", err)
	}
	if js, _ := q.Claim(ctx, "w1", 10, 30*time.Second); len(js) != 0 {
		t.Fatalf("dead-lettered job must never be claimable, got %v", js)
	}

	// ---- RLS policy on report_jobs: a tenant-scoped read sees only its rows ----
	if _, _, err := q.Enqueue(ctx, mk("rls-globex", "sg", "globex", fire(200)), now); err != nil {
		t.Fatalf("enqueue globex: %v", err)
	}
	var acmeRows []string
	if err := ps.DB().WithTenant(ctx, "acme", false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id, tenant_id FROM report_jobs`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, tenant string
			if err := rows.Scan(&id, &tenant); err != nil {
				return err
			}
			if tenant != "acme" {
				t.Errorf("JOB LEAK: acme scope saw tenant %q (job %s)", tenant, id)
			}
			acmeRows = append(acmeRows, id)
		}
		return rows.Err()
	}); err != nil {
		t.Fatalf("scoped read: %v", err)
	}
	for _, id := range acmeRows {
		if id == "rls-globex" {
			t.Fatalf("JOB LEAK: acme scope claimed to see globex's job")
		}
	}
}
