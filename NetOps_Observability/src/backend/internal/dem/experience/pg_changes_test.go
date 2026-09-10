// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// pg_changes_test.go — the two backends must bound the SAME set.
//
// ListChanges answers an operator's question during an incident: "what changed
// in this window, of this kind, for this app or site". The file backend applies
// the whole predicate and then takes the caller's limit. The Postgres backend
// pushed only the time bound into SQL and applied the rest in Go AFTER the row
// limit, so a filtered query on a busy tenant could answer "nothing changed"
// while the deploy that caused the incident sat one page down.
//
// No database is needed and none is skipped for. PGStore takes its relational
// seam as an injected interface, so the statement it issues can be driven
// against a stand-in that applies EXACTLY the predicates the statement binds —
// which is the property under test. A predicate the query never binds is a
// predicate the database never applies.

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── the stand-in relational seam ────────────────────────────────────────────

// fakeChangeDB holds one tenant's dem_change_events table and answers the
// statement ListChanges issues. It reads the BOUND ARGUMENTS by type — the time
// bound (time.Time), the change-type list ([]string), the app and site strings
// in that order, and the row limit (int) — and applies them the way PostgreSQL
// would. Arguments the statement does not bind are not applied.
type fakeChangeDB struct {
	table []ChangeEvent
	sql   string
	args  []any
}

func (f *fakeChangeDB) WithTenant(_ context.Context, _ string, _ bool, fn func(pgx.Tx) error) error {
	return fn(&fakeTx{db: f})
}

func (f *fakeChangeDB) query(sql string, args []any) []ChangeEvent {
	f.sql, f.args = sql, args

	var since time.Time
	var types []string
	var strs []string
	limit := len(f.table)
	for _, a := range args {
		switch v := a.(type) {
		case time.Time:
			since = v
		case []string:
			types = v
		case string:
			strs = append(strs, v)
		case int:
			limit = v
		case int32:
			limit = int(v)
		}
	}
	app, site := "", ""
	if len(strs) > 0 {
		app = strs[0]
	}
	if len(strs) > 1 {
		site = strs[1]
	}

	typeSet := map[string]bool{}
	for _, t := range types {
		typeSet[t] = true
	}
	out := []ChangeEvent{}
	for _, c := range f.table {
		if c.EventAt.Before(since) {
			continue
		}
		if len(typeSet) > 0 && !typeSet[c.Type] {
			continue
		}
		if app != "" && c.App != app {
			continue
		}
		if site != "" && c.Site != site {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].EventAt.After(out[j].EventAt) })
	if limit >= 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

type fakeTx struct{ db *fakeChangeDB }

func (tx *fakeTx) Query(_ context.Context, sql string, args ...any) (pgx.Rows, error) {
	rows := tx.db.query(sql, args)
	encoded := make([][]byte, 0, len(rows))
	for _, c := range rows {
		b, err := json.Marshal(c)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, b)
	}
	return &fakeRows{data: encoded, at: -1}, nil
}

// Everything below exists only to satisfy pgx.Tx. ListChanges calls Query and
// nothing else, so any other call is a test bug and says so loudly.
func (tx *fakeTx) Begin(context.Context) (pgx.Tx, error) { panic("unused") }
func (tx *fakeTx) Commit(context.Context) error          { panic("unused") }
func (tx *fakeTx) Rollback(context.Context) error        { panic("unused") }
func (tx *fakeTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	panic("unused")
}
func (tx *fakeTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { panic("unused") }
func (tx *fakeTx) LargeObjects() pgx.LargeObjects                         { panic("unused") }
func (tx *fakeTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	panic("unused")
}
func (tx *fakeTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("unused")
}
func (tx *fakeTx) QueryRow(context.Context, string, ...any) pgx.Row { panic("unused") }
func (tx *fakeTx) Conn() *pgx.Conn                                  { return nil }

type fakeRows struct {
	data [][]byte
	at   int
}

func (r *fakeRows) Next() bool {
	r.at++
	return r.at < len(r.data)
}

func (r *fakeRows) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("fake rows: the statement selects exactly one column")
	}
	p, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("fake rows: the selected column is scanned as []byte")
	}
	*p = r.data[r.at]
	return nil
}

func (r *fakeRows) Close()                                       {}
func (r *fakeRows) Err() error                                   { return nil }
func (r *fakeRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fakeRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fakeRows) Values() ([]any, error)                       { return nil, errors.New("unused") }
func (r *fakeRows) RawValues() [][]byte                          { return nil }
func (r *fakeRows) Conn() *pgx.Conn                              { return nil }

// ── the corpus ──────────────────────────────────────────────────────────────

// busyTenantChanges is a window in which the noise is newer than the answer:
// three config changes, and behind them the deploy the operator is looking for.
// Any limit of three or less pushes the deploy off an unfiltered read.
func busyTenantChanges() []ChangeEvent {
	mk := func(id, kind, app, site string, offset time.Duration) ChangeEvent {
		c := ChangeEvent{
			TenantID: "acme", ID: "chg-" + id, Type: kind, Object: "sw-" + id,
			Summary: kind + " on sw-" + id, App: app, Site: site,
			Provenance: prov(SourceConfigDrift, offset),
		}
		return c
	}
	return []ChangeEvent{
		mk("00000000000000000000000000000001", ChangeConfig, "checkout", "dc1", -1*time.Minute),
		mk("00000000000000000000000000000002", ChangeConfig, "checkout", "dc1", -2*time.Minute),
		mk("00000000000000000000000000000003", ChangeConfig, "checkout", "dc1", -3*time.Minute),
		mk("00000000000000000000000000000004", ChangeApplicationDeploy, "checkout", "dc1", -4*time.Minute),
	}
}

func ids(list []ChangeEvent) []string {
	out := make([]string, 0, len(list))
	for _, c := range list {
		out = append(out, c.ID)
	}
	return out
}

// A filtered query must find the change it matches even when that change sits
// beyond the limit of the UNFILTERED set, and both backends must say the same.
func TestBothBackendsBoundTheSameFilteredChangeSet(t *testing.T) {
	ctx := context.Background()
	corpus := busyTenantChanges()

	file := NewFileStore("")
	for _, c := range corpus {
		if _, err := file.RecordChange(ctx, c); err != nil {
			t.Fatalf("seed %s: %v", c.ID, err)
		}
	}
	fake := &fakeChangeDB{table: corpus}
	pg := NewPGStore(fake)

	for _, tc := range []struct {
		name string
		q    ChangeQuery
		want []string
	}{
		{
			name: "the deploy is four rows down and the caller asked for three",
			q:    ChangeQuery{Types: []string{ChangeApplicationDeploy}, Limit: 3},
			want: []string{"chg-00000000000000000000000000000004"},
		},
		{
			name: "an app that matches nothing answers nothing, not the newest three",
			q:    ChangeQuery{App: "billing", Limit: 3},
			want: []string{},
		},
		{
			name: "a site that matches nothing answers nothing",
			q:    ChangeQuery{Site: "dc9", Limit: 3},
			want: []string{},
		},
		{
			name: "no filter still answers the newest rows, newest first",
			q:    ChangeQuery{Limit: 2},
			want: []string{"chg-00000000000000000000000000000001", "chg-00000000000000000000000000000002"},
		},
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
			if !reflect.DeepEqual(ids(fileGot), tc.want) {
				t.Errorf("file backend answered %v, want %v", ids(fileGot), tc.want)
			}
			if !reflect.DeepEqual(ids(pgGot), tc.want) {
				t.Errorf("pg backend answered %v, want %v — the filter did not reach the database, so the row limit was spent on rows the caller did not ask for", ids(pgGot), tc.want)
			}
		})
	}
}

// The predicates must be IN the statement. Applying them in Go afterwards
// answers a different question from the one the caller asked, however the rows
// happen to fall today.
func TestChangeFiltersArePushedIntoTheStatement(t *testing.T) {
	fake := &fakeChangeDB{table: busyTenantChanges()}
	if _, err := NewPGStore(fake).ListChanges(context.Background(), "acme",
		ChangeQuery{Types: []string{ChangeApplicationDeploy}, App: "checkout", Site: "dc1", Limit: 3}); err != nil {
		t.Fatalf("list: %v", err)
	}
	for _, col := range []string{"event_at", "change_type", "app", "site"} {
		if !strings.Contains(fake.sql, col) {
			t.Errorf("the change query does not bound %s in SQL:\n%s", col, fake.sql)
		}
	}
}
