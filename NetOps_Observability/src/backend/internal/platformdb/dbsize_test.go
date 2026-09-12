// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// dbsize_test.go — the breakdown failure must be SAYABLE.
//
// DatabaseSize used to answer a failed per-relation query with (total, nil, nil):
// storagemeter then published `measured: true` beside an empty itemisation,
// which reads to an operator as "this database holds nothing" when the truth is
// "we could not look". §10 forbids exactly that.

// ── the smallest querier that can fail on demand ─────────────────────────────

type fakeRow struct {
	val int64
	err error
}

func (r fakeRow) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("fakeRow: want exactly one destination")
	}
	p, ok := dest[0].(*int64)
	if !ok {
		return errors.New("fakeRow: destination is not *int64")
	}
	*p = r.val
	return nil
}

// fakeRows replays a fixed set of (name, bytes) pairs, optionally failing on a
// chosen row or at the end of the set.
type fakeRows struct {
	names   []string
	bytes   []int64
	i       int
	scanErr error // returned on the LAST row's Scan
	endErr  error // returned by Err() once the set is exhausted
	closed  bool
}

func (r *fakeRows) Close()                                       { r.closed = true }
func (r *fakeRows) Err() error                                   { return r.endErr }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, errors.New("not used") }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

func (r *fakeRows) Next() bool {
	if r.i >= len(r.names) {
		return false
	}
	r.i++
	return true
}

func (r *fakeRows) Scan(dest ...any) error {
	if r.scanErr != nil && r.i == len(r.names) {
		return r.scanErr
	}
	if len(dest) != 2 {
		return errors.New("fakeRows: want two destinations")
	}
	name, ok1 := dest[0].(*string)
	b, ok2 := dest[1].(*int64)
	if !ok1 || !ok2 {
		return errors.New("fakeRows: destination types")
	}
	*name = r.names[r.i-1]
	*b = r.bytes[r.i-1]
	return nil
}

type fakeQuerier struct {
	total    int64
	totalErr error
	rows     *fakeRows
	queryErr error
}

func (q *fakeQuerier) QueryRow(context.Context, string, ...any) pgx.Row {
	return fakeRow{val: q.total, err: q.totalErr}
}

func (q *fakeQuerier) Query(context.Context, string, ...any) (pgx.Rows, error) {
	if q.queryErr != nil {
		return nil, q.queryErr
	}
	return q.rows, nil
}

// ── the contract ─────────────────────────────────────────────────────────────

// TestDatabaseSizeBreakdownFailureIsNeverSilent is the regression: a failed
// breakdown query must be reported, and the total — which WAS measured — must
// come back with it so the caller can still say how big the database is.
func TestDatabaseSizeBreakdownFailureIsNeverSilent(t *testing.T) {
	boom := errors.New("pg: relation catalogue unavailable")

	t.Run("the breakdown query fails", func(t *testing.T) {
		q := &fakeQuerier{total: 7_340_032, queryErr: boom}
		total, rels, err := databaseSize(context.Background(), q)
		if err == nil {
			t.Fatal("a failed breakdown returned nil: storagemeter would publish `measured: true` with an empty itemisation, which reads as a database holding nothing")
		}
		if !errors.Is(err, ErrBreakdownUnavailable) {
			t.Fatalf("err = %v, want it to match ErrBreakdownUnavailable so the caller can tell it from a total it never got", err)
		}
		if !errors.Is(err, boom) {
			t.Fatalf("err = %v, must wrap the cause so the reason is in the log", err)
		}
		if total != 7_340_032 {
			t.Fatalf("total = %d, want the measurement that DID succeed to survive", total)
		}
		if len(rels) != 0 {
			t.Fatalf("no breakdown was read, so none may be handed back: %+v", rels)
		}
	})

	t.Run("a row scan fails part-way", func(t *testing.T) {
		q := &fakeQuerier{
			total: 1024,
			rows: &fakeRows{
				names:   []string{"public.devices", "public.audit"},
				bytes:   []int64{900, 124},
				scanErr: boom,
			},
		}
		total, rels, err := databaseSize(context.Background(), q)
		if !errors.Is(err, ErrBreakdownUnavailable) {
			t.Fatalf("err = %v, want ErrBreakdownUnavailable", err)
		}
		if total != 1024 {
			t.Fatalf("total = %d, want 1024", total)
		}
		if len(rels) != 0 {
			t.Fatalf("a PARTIAL itemisation must not be handed back as if it were whole: %+v", rels)
		}
	})

	t.Run("rows.Err fails after the set", func(t *testing.T) {
		q := &fakeQuerier{
			total: 2048,
			rows:  &fakeRows{names: []string{"public.devices"}, bytes: []int64{2000}, endErr: boom},
		}
		total, rels, err := databaseSize(context.Background(), q)
		if !errors.Is(err, ErrBreakdownUnavailable) {
			t.Fatalf("err = %v, want ErrBreakdownUnavailable", err)
		}
		if total != 2048 || len(rels) != 0 {
			t.Fatalf("total = %d, rels = %+v", total, rels)
		}
	})

	t.Run("the total itself fails", func(t *testing.T) {
		q := &fakeQuerier{totalErr: boom}
		total, rels, err := databaseSize(context.Background(), q)
		if err == nil || errors.Is(err, ErrBreakdownUnavailable) {
			t.Fatalf("err = %v: nothing was measured, so this is NOT the breakdown-only sentinel", err)
		}
		if total != 0 || rels != nil {
			t.Fatalf("nothing measured: total = %d, rels = %+v", total, rels)
		}
	})

	t.Run("both succeed", func(t *testing.T) {
		q := &fakeQuerier{
			total: 3000,
			rows:  &fakeRows{names: []string{"public.devices", "public.audit"}, bytes: []int64{2000, 900}},
		}
		total, rels, err := databaseSize(context.Background(), q)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if total != 3000 || len(rels) != 2 || rels[0].Name != "public.devices" || rels[0].Bytes != 2000 {
			t.Fatalf("total = %d, rels = %+v", total, rels)
		}
		if !q.rows.closed {
			t.Fatal("rows must be closed")
		}
	})
}

// TestDatabaseSizeNoPool keeps the file-backend refusal distinguishable from a
// measurement failure — the two render differently and always must.
func TestDatabaseSizeNoPool(t *testing.T) {
	var db *DB
	total, rels, err := db.DatabaseSize(context.Background())
	if !errors.Is(err, ErrNoPool) {
		t.Fatalf("err = %v, want ErrNoPool", err)
	}
	if errors.Is(err, ErrBreakdownUnavailable) {
		t.Fatal("no pool is not a breakdown problem")
	}
	if total != 0 || rels != nil {
		t.Fatalf("total = %d, rels = %+v", total, rels)
	}
}
