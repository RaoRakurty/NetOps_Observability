// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// ledger_filters_test.go — N-D1: every filter of the change-ledger query is
// applied by the STORE, before the row limit, identically on both backends.
//
// The Postgres side runs against pg_changes_test.go's fakeChangeDB, which learns
// which column each placeholder is compared with by READING the SQL — so a
// filter the statement never binds is a filter it never applies. The real
// database run of the same statement is pg_change_ledger_test.go in package
// backend (DATABASE_URL_TEST, the pgintegration leg).

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// recordingDB records the scope a statement ran under and every Exec issued in
// it. It answers nothing else: pgx.Tx is embedded as a nil interface, so any
// other call panics loudly instead of pretending.
type recordingDB struct {
	tenant string
	cross  bool
	stmts  []string
	args   [][]any
}

func (r *recordingDB) WithTenant(_ context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	r.tenant, r.cross = tenant, cross
	return fn(recordingTx{db: r})
}

type recordingTx struct {
	pgx.Tx
	db *recordingDB
}

func (tx recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	tx.db.stmts = append(tx.db.stmts, sql)
	tx.db.args = append(tx.db.args, args)
	return pgconn.NewCommandTag("OK 1"), nil
}

// ledgerCorpus is one tenant's ledger in which every N-D1 filter has a row that
// matches it and rows that do not, and the rows a filter wants are the OLDEST —
// so a filter applied after the limit, rather than in the query, loses them.
func ledgerCorpus() []ChangeEvent {
	mk := func(n int, mut func(*ChangeEvent)) ChangeEvent {
		c := ChangeEvent{
			TenantID: "acme", ID: fmt.Sprintf("chg-%032d", n), Type: ChangeConfig,
			Object: fmt.Sprintf("dev-%d", n), ObjectKind: "device",
			Summary: fmt.Sprintf("change %d", n), App: "checkout", Site: "dc1", Seam: "DIA",
			Actor: "noise-bot", ActorType: ChangeActorAutomation, SourceSystem: SourceSystemLedger,
			Provenance: prov(SourceConfigDrift, -time.Duration(n)*time.Minute),
		}
		if mut != nil {
			mut(&c)
		}
		return c
	}
	out := []ChangeEvent{}
	for i := 1; i <= 6; i++ { // the six newest rows are noise
		out = append(out, mk(i, nil))
	}
	return append(out,
		mk(7, func(c *ChangeEvent) {
			c.Actor, c.ActorID, c.ActorDisplay, c.ActorType = "jsmith", "u_7", "John Smith", ChangeActorUser
		}),
		mk(8, func(c *ChangeEvent) { c.Object, c.ObjectKind = "edge-9", "cloud_resource" }),
		mk(9, func(c *ChangeEvent) { c.SourceSystem = SourceSystemConfigCapture; c.Site, c.App = "dfw", "billing" }),
		mk(10, func(c *ChangeEvent) { c.Seam = "SDWAN"; c.Type = ChangeNetwork }),
		// A pre-N-D1 row: none of the new fields set, so the store's defaults
		// (source ledger, actor id = actor, type unknown) are what filters see.
		mk(11, func(c *ChangeEvent) {
			c.Actor, c.ActorType, c.SourceSystem, c.ActorID = "legacy-op", "", "", ""
		}),
	)
}

func changeIDNums(list []ChangeEvent) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, strings.TrimLeft(strings.TrimPrefix(c.ID, "chg-"), "0"))
	}
	return out
}

func TestBothBackendsApplyEveryLedgerFilterBeforeTheLimit(t *testing.T) {
	ctx := context.Background()
	corpus := ledgerCorpus()
	file := newTestFileStore("")
	for _, c := range corpus {
		if _, err := file.RecordChange(ctx, c); err != nil {
			t.Fatalf("seed %s: %v", c.ID, err)
		}
	}
	pg := NewPGStore(&fakeChangeDB{table: corpus})
	window := testNow.Add(-time.Hour)

	for _, tc := range []struct {
		name string
		q    ChangeQuery
		want []string
	}{
		{"actor by source identity", ChangeQuery{Actors: []string{"jsmith"}, Limit: 2}, []string{"7"}},
		{"actor by canonical id", ChangeQuery{Actors: []string{"u_7"}, Limit: 2}, []string{"7"}},
		{"actor by display name, any case", ChangeQuery{Actors: []string{"john SMITH"}, Limit: 2}, []string{"7"}},
		{"a legacy row's actor id defaults to its source actor", ChangeQuery{Actors: []string{"legacy-op"}, Limit: 2}, []string{"11"}},
		{"object", ChangeQuery{Objects: []string{"edge-9"}, Limit: 2}, []string{"8"}},
		{"object kind", ChangeQuery{ObjectKinds: []string{"cloud_resource"}, Limit: 2}, []string{"8"}},
		{"source system, any case", ChangeQuery{Sources: []string{"CONFIG_CAPTURE"}, Limit: 2}, []string{"9"}},
		{"a legacy row reads as the ledger source", ChangeQuery{Sources: []string{"ledger"}, Actors: []string{"legacy-op"}, Limit: 2}, []string{"11"}},
		{"any of several sites", ChangeQuery{Sites: []string{"dfw", "nowhere"}, Limit: 2}, []string{"9"}},
		{"any of several apps", ChangeQuery{Apps: []string{"billing"}, Limit: 2}, []string{"9"}},
		{"seam", ChangeQuery{Seams: []string{"SDWAN"}, Limit: 2}, []string{"10"}},
		{"until is inclusive and bounds the newest end", ChangeQuery{Since: window, Until: testNow.Add(-10 * time.Minute), Limit: 3}, []string{"10", "11"}},
		{"excluded ids are never returned", ChangeQuery{ExcludeIDs: []string{fmt.Sprintf("chg-%032d", 1), fmt.Sprintf("chg-%032d", 2)}, Limit: 2}, []string{"3", "4"}},
		{"filters combine with AND", ChangeQuery{Sites: []string{"dfw"}, Sources: []string{"ledger"}, Limit: 5}, []string{}},
		{"selected ids, any of", ChangeQuery{IDs: []string{fmt.Sprintf("chg-%032d", 3), fmt.Sprintf("chg-%032d", 8), "chg-none"}, Limit: 5}, []string{"3", "8"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fileGot, err := file.ListChanges(ctx, "acme", tc.q)
			if err != nil {
				t.Fatalf("file backend: %v", err)
			}
			pgGot, err := pg.ListChanges(ctx, "acme", tc.q)
			if err != nil {
				t.Fatalf("pg backend: %v", err)
			}
			if got := changeIDNums(fileGot); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("file backend answered %v, want %v", got, tc.want)
			}
			if got := changeIDNums(pgGot); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("pg backend answered %v, want %v — the filter did not reach the statement", got, tc.want)
			}
			// COUNT runs the SAME predicate with the limit dropped.
			q := tc.q
			q.Limit = 0
			fileN, ferr := file.CountChanges(ctx, "acme", q)
			pgN, perr := pg.CountChanges(ctx, "acme", q)
			if ferr != nil || perr != nil {
				t.Fatalf("count: file %v, pg %v", ferr, perr)
			}
			if fileN != pgN || fileN < len(tc.want) {
				t.Errorf("counts disagree: file %d, pg %d (the list returned %d)", fileN, pgN, len(tc.want))
			}
		})
	}
}

// A pre-N-D1 row read back from Postgres carries the defaults the migration
// backfilled into its columns, so the JSON a caller sees agrees with what the
// filters matched on.
func TestALegacyRowReadsBackWithTheBackfilledDefaults(t *testing.T) {
	legacy := ledgerCorpus()[10]
	got, err := NewPGStore(&fakeChangeDB{table: []ChangeEvent{legacy}}).ListChanges(context.Background(), "acme", ChangeQuery{})
	if err != nil || len(got) != 1 {
		t.Fatalf("list: %v %+v", err, got)
	}
	if got[0].SourceSystem != SourceSystemLedger || got[0].ActorID != "legacy-op" || got[0].ActorType != ChangeActorUnknown {
		t.Fatalf("legacy row read back as source=%q actor_id=%q actor_type=%q", got[0].SourceSystem, got[0].ActorID, got[0].ActorType)
	}
}

// A list that is too long is REFUSED by both backends, never clipped: clipping
// an exclusion list would return rows the caller excluded.
func TestAnOverlongLedgerFilterIsRefusedNotClipped(t *testing.T) {
	ctx := context.Background()
	long := make([]string, MaxChangeFilterValues+1)
	for i := range long {
		long[i] = fmt.Sprintf("chg-%032d", i)
	}
	q := ChangeQuery{ExcludeIDs: long}
	for name, st := range map[string]Store{
		"file": newTestFileStore(""),
		"pg":   NewPGStore(&fakeChangeDB{table: ledgerCorpus()}),
	} {
		if _, err := st.ListChanges(ctx, "acme", q); err == nil {
			t.Errorf("%s: an over-long exclusion list was accepted", name)
		}
		if _, err := st.CountChanges(ctx, "acme", q); err == nil {
			t.Errorf("%s: an over-long exclusion list was counted", name)
		}
	}
}

// Every N-D1 column is bound in the statement, and List and Count share it.
func TestEveryLedgerFilterIsInTheStatement(t *testing.T) {
	fake := &fakeChangeDB{table: ledgerCorpus()}
	pg := NewPGStore(fake)
	if _, err := pg.ListChanges(context.Background(), "acme", ChangeQuery{Limit: 1}); err != nil {
		t.Fatal(err)
	}
	listSQL := fake.sql
	if _, err := pg.CountChanges(context.Background(), "acme", ChangeQuery{}); err != nil {
		t.Fatal(err)
	}
	for _, col := range []string{"event_at <=", "lower(actor)", "lower(actor_id)", "lower(actor_display)",
		"object =", "object_kind", "source_system", "change_id", "data->>'seam'"} {
		if !strings.Contains(listSQL, col) {
			t.Errorf("the list statement does not bound %q:\n%s", col, listSQL)
		}
	}
	if !strings.Contains(listSQL, pgChangeWhere) || !strings.Contains(fake.sql, pgChangeWhere) {
		t.Error("ListChanges and CountChanges no longer share pgChangeWhere — a count could answer a different question from its list")
	}
}

// ── retention ───────────────────────────────────────────────────────────────

// A change already outside retention is refused on both backends — never stored
// and then silently deleted by the next write.
func TestAChangeOlderThanRetentionIsRefused(t *testing.T) {
	old := ledgerCorpus()[0]
	old.EventAt, old.ObservedAt = testNow.Add(-ChangeRetention-time.Hour), testNow
	pg := NewPGStore(&fakeChangeDB{})
	pg.now = func() time.Time { return testNow }
	for name, st := range map[string]Store{"file": newTestFileStore(""), "pg": pg} {
		if _, err := st.RecordChange(context.Background(), old); err == nil || !strings.Contains(err.Error(), "longer ago") {
			t.Errorf("%s: a change past retention was accepted (err %v)", name, err)
		}
	}
}

// Retention is PER TENANT: pruning one tenant's expired rows never touches
// another tenant's rows, expired or not, and it is bounded by max.
func TestPruneChangesIsTenantScopedAndBounded(t *testing.T) {
	ctx := context.Background()
	clock := testNow
	s := NewFileStoreWithClock("", func() time.Time { return clock })
	for _, tenant := range []string{"acme", "globex"} {
		for i := 1; i <= 3; i++ {
			c := ledgerCorpus()[i]
			c.TenantID = tenant
			c.EventAt, c.ObservedAt = testNow.Add(-time.Duration(i)*24*time.Hour), testNow
			if _, err := s.RecordChange(ctx, c); err != nil {
				t.Fatalf("seed %s: %v", tenant, err)
			}
		}
	}
	// Everything older than 36h: two rows per tenant. Ask for at most one.
	cutoff := testNow.Add(-36 * time.Hour)
	n, err := s.PruneChanges(ctx, "acme", cutoff, 1)
	if err != nil || n != 1 {
		t.Fatalf("bounded prune removed %d (err %v), want 1", n, err)
	}
	if n, err = s.PruneChanges(ctx, "acme", cutoff, 10); err != nil || n != 1 {
		t.Fatalf("second prune removed %d (err %v), want the one remaining expired row", n, err)
	}
	acme, _ := s.ListChanges(ctx, "acme", ChangeQuery{})
	globex, _ := s.ListChanges(ctx, "globex", ChangeQuery{})
	if len(acme) != 1 || len(globex) != 3 {
		t.Fatalf("after pruning acme: acme %d rows (want 1), globex %d rows (want 3, untouched)", len(acme), len(globex))
	}
	if _, err := s.PruneChanges(ctx, "*", cutoff, 10); err == nil {
		t.Fatal("a wildcard tenant was allowed to prune")
	}

	// The clock moving past retention ages rows out on the next write, and only
	// in the tenant being written.
	clock = testNow.Add(ChangeRetention)
	fresh := ledgerCorpus()[5]
	fresh.TenantID, fresh.EventAt, fresh.ObservedAt = "acme", clock, clock
	if _, err := s.RecordChange(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	acme, _ = s.ListChanges(ctx, "acme", ChangeQuery{})
	globex, _ = s.ListChanges(ctx, "globex", ChangeQuery{})
	if len(acme) != 1 || acme[0].ID != fresh.ID {
		t.Fatalf("acme's expired row survived its own write: %v", changeIDNums(acme))
	}
	if len(globex) != 3 {
		t.Fatalf("a write in acme aged out globex's rows: globex now has %d", len(globex))
	}
}

// The Postgres prune is issued inside the WRITING tenant's WithTenant, bounded,
// and as part of RecordChange — so it can only reach that tenant's rows (RLS)
// and a write can never become an unbounded delete.
func TestPGRecordChangePrunesInsideTheWritersTenantScope(t *testing.T) {
	rec := &recordingDB{}
	pg := NewPGStore(rec)
	pg.now = func() time.Time { return testNow }
	c := ledgerCorpus()[0]
	if _, err := pg.RecordChange(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if rec.tenant != "acme" || rec.cross {
		t.Fatalf("the write ran under tenant %q cross=%v", rec.tenant, rec.cross)
	}
	if len(rec.stmts) != 2 || !strings.HasPrefix(strings.TrimSpace(rec.stmts[0]), "INSERT") ||
		!strings.Contains(rec.stmts[1], "DELETE FROM dem_change_events") || !strings.Contains(rec.stmts[1], "LIMIT $2") {
		t.Fatalf("RecordChange issued %q", rec.stmts)
	}
	if got := rec.args[1]; got[0] != testNow.Add(-ChangeRetention) || got[1] != changePruneBatch {
		t.Fatalf("prune bound (%v, %v), want (%v, %d)", got[0], got[1], testNow.Add(-ChangeRetention), changePruneBatch)
	}
	// Every typed column the migration added is written.
	for _, col := range []string{"source_system", "actor_type", "actor_id", "actor_display", "ticket_ref", "automation", "detected_at", "object_kind"} {
		if !strings.Contains(rec.stmts[0], col) {
			t.Errorf("the insert does not write %s", col)
		}
	}
	if n := strings.Count(pgInsertChange, "$"); n != len(pgInsertChangeArgs(c, nil)) {
		t.Errorf("the insert has %d placeholders but binds %d values", n, len(pgInsertChangeArgs(c, nil)))
	}
}
