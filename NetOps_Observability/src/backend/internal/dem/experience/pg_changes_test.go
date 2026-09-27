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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── the stand-in relational seam ────────────────────────────────────────────

// fakeChangeDB holds one tenant's dem_change_events table and answers the
// statements ListChanges and CountChanges issue. It does NOT know the argument
// layout: it READS THE SQL to learn which column each placeholder is compared
// with (`event_at >= $n`, `event_at <= $n`, `<column> = ANY($n)`,
// `NOT (change_id = ANY($n))`, `LIMIT $n`) and applies exactly those
// comparisons to the bound values, the way PostgreSQL would. A filter the
// statement never binds is therefore a filter this database never applies —
// which is the property under test — and a placeholder bound to the wrong
// column fails the parity tests instead of passing by coincidence.
type fakeChangeDB struct {
	table []ChangeEvent
	sql   string
	args  []any
}

func (f *fakeChangeDB) WithTenant(_ context.Context, _ string, _ bool, fn func(pgx.Tx) error) error {
	return fn(&fakeTx{db: f})
}

var (
	fakeAnyRe   = regexp.MustCompile(`(NOT \()?(change_type|app|site|COALESCE\(data->>'seam', ''\)|lower\(actor\)|lower\(actor_id\)|lower\(actor_display\)|object|object_kind|source_system|change_id) = ANY\(\$(\d+)`)
	fakeSinceRe = regexp.MustCompile(`event_at >= \$(\d+)`)
	fakeUntilRe = regexp.MustCompile(`event_at <= \$(\d+)`)
	fakeLimitRe = regexp.MustCompile(`LIMIT \$(\d+)`)
)

// fakeColumn reads the row value a SQL column expression names.
func fakeColumn(c ChangeEvent, expr string) string {
	switch expr {
	case "change_type":
		return c.Type
	case "app":
		return c.App
	case "site":
		return c.Site
	case "COALESCE(data->>'seam', '')":
		return c.Seam
	case "lower(actor)":
		return strings.ToLower(c.Actor)
	case "lower(actor_id)":
		return strings.ToLower(c.ActorID)
	case "lower(actor_display)":
		return strings.ToLower(c.ActorDisplay)
	case "object":
		return c.Object
	case "object_kind":
		return c.ObjectKind
	case "source_system":
		return c.SourceSystem
	case "change_id":
		return c.ID
	}
	panic("fake: unmapped column " + expr)
}

func argAt(args []any, pos string) any {
	i, err := strconv.Atoi(pos)
	if err != nil || i < 1 || i > len(args) {
		panic("fake: placeholder $" + pos + " has no bound argument")
	}
	return args[i-1]
}

func (f *fakeChangeDB) query(sql string, args []any) []ChangeEvent {
	f.sql, f.args = sql, args

	var since, until time.Time
	if m := fakeSinceRe.FindStringSubmatch(sql); m != nil {
		since = argAt(args, m[1]).(time.Time)
	}
	if m := fakeUntilRe.FindStringSubmatch(sql); m != nil {
		if v, ok := argAt(args, m[1]).(time.Time); ok {
			until = v
		}
	}
	limit := -1
	if m := fakeLimitRe.FindStringSubmatch(sql); m != nil {
		limit = argAt(args, m[1]).(int)
	}
	// placeholder → the column expressions compared with it, ORed together.
	type anyFilter struct {
		cols    []string
		negated bool
	}
	filters := map[string]*anyFilter{}
	order := []string{}
	for _, m := range fakeAnyRe.FindAllStringSubmatch(sql, -1) {
		af, ok := filters[m[3]]
		if !ok {
			af = &anyFilter{}
			filters[m[3]] = af
			order = append(order, m[3])
		}
		af.cols = append(af.cols, m[2])
		af.negated = af.negated || m[1] != ""
	}

	out := []ChangeEvent{}
	for _, c := range f.table {
		c.applyDefaults()
		if c.EventAt.Before(since) || (!until.IsZero() && c.EventAt.After(until)) {
			continue
		}
		keep := true
		for _, pos := range order {
			vals, _ := argAt(args, pos).([]string)
			if len(vals) == 0 {
				continue // cardinality 0: "no such filter"
			}
			hit := false
			for _, col := range filters[pos].cols {
				for _, v := range vals {
					if fakeColumn(c, col) == v {
						hit = true
					}
				}
			}
			if hit == filters[pos].negated {
				keep = false
				break
			}
		}
		if keep {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].EventAt.Equal(out[j].EventAt) {
			return out[i].EventAt.After(out[j].EventAt)
		}
		return out[i].ID < out[j].ID
	})
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

// QueryRow answers CountChanges' `SELECT count(*)` over the same fake predicate.
func (tx *fakeTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	if !strings.Contains(sql, "count(*)") {
		panic("fake: only the count statement is answered by QueryRow")
	}
	return fakeCountRow{n: len(tx.db.query(sql, args))}
}
func (tx *fakeTx) Conn() *pgx.Conn { return nil }

type fakeCountRow struct{ n int }

func (r fakeCountRow) Scan(dest ...any) error {
	p, ok := dest[0].(*int)
	if len(dest) != 1 || !ok {
		return errors.New("fake count row: scanned into one *int")
	}
	*p = r.n
	return nil
}

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

	file := newTestFileStore("")
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
