// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// pg_isolation_test.go — the §3a rule-5 isolation test for the POSTGRES
// catalogue (review finding 3.2-16), and the serialisation proof for its
// per-tenant cap (3.2-15).
//
// Why this file has to exist: PGStore is the DEFAULT backend on a fresh install
// (tracker 245) and the rule-5 cross-org test in the root package builds
// NewFileStore, so the backend that actually ships had no isolation test at all.
// Its scoped statements deliberately carry no `WHERE tenant_id = …` — that is
// RLS's job — which is correct, and precisely why it needs a guard: an edit that
// widened a statement, or a WithTenant call that lost its scope, would leave no
// visible mark anywhere in this package.
//
// No database is needed and none is skipped for. PGStore takes its relational
// seam as an injected interface, so the statements it issues are driven against
// a stand-in that behaves the way the tenant_iso FORCE-RLS policy does: every
// read and write sees ONLY the rows of the tenant WithTenant was scoped to. A
// statement that reaches another tenant's row therefore fails here exactly as it
// would fail in the database.

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// ── the RLS-shaped stand-in ─────────────────────────────────────────────────

type rlsRow struct {
	tenant string
	id     string
	data   []byte
}

type rlsDB struct {
	rows []rlsRow
	// locks records every advisory lock taken, in order, so the cap's
	// serialisation can be asserted (3.2-15).
	locks []int32
	// crossSeen records any WithTenant call that asked for cross-tenant scope.
	crossSeen bool
}

func (d *rlsDB) WithTenant(_ context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	if cross {
		d.crossSeen = true
	}
	return fn(&rlsTx{db: d, tenant: tenant, cross: cross})
}

// visible is the policy: a scoped transaction sees its own tenant's rows only.
func (d *rlsDB) visible(tenant string, cross bool) []rlsRow {
	out := make([]rlsRow, 0, len(d.rows))
	for _, r := range d.rows {
		if cross || r.tenant == tenant {
			out = append(out, r)
		}
	}
	return out
}

type rlsTx struct {
	db     *rlsDB
	tenant string
	cross  bool
}

func argString(args []any, i int) string {
	if i >= len(args) {
		return ""
	}
	s, _ := args[i].(string)
	return s
}

func (tx *rlsTx) Query(_ context.Context, sql string, _ ...any) (pgx.Rows, error) {
	if !strings.Contains(sql, "SELECT data FROM dem_targets") {
		return nil, errors.New("rls: unexpected query: " + sql)
	}
	rows := tx.db.visible(tx.tenant, tx.cross)
	encoded := make([][]byte, 0, len(rows))
	for _, r := range rows {
		encoded = append(encoded, r.data)
	}
	return &rlsRows{data: encoded, at: -1}, nil
}

func (tx *rlsTx) QueryRow(_ context.Context, sql string, args ...any) pgx.Row {
	switch {
	case strings.Contains(sql, "count(*)"):
		return &rlsRow1{count: len(tx.db.visible(tx.tenant, tx.cross))}
	case strings.Contains(sql, "SELECT data FROM dem_targets WHERE target_id="):
		id := argString(args, 0)
		for _, r := range tx.db.visible(tx.tenant, tx.cross) {
			if r.id == id {
				return &rlsRow1{data: r.data}
			}
		}
		return &rlsRow1{err: pgx.ErrNoRows}
	}
	return &rlsRow1{err: errors.New("rls: unexpected query row: " + sql)}
}

func (tx *rlsTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	switch {
	case strings.Contains(sql, "pg_advisory_xact_lock"):
		key, _ := args[1].(int32)
		tx.db.locks = append(tx.db.locks, key)
		return pgconn.NewCommandTag("SELECT 1"), nil
	case strings.HasPrefix(strings.TrimSpace(sql), "INSERT INTO dem_targets"):
		// The OWNER is whatever the statement binds; the stand-in records it so
		// a write stamped from anything but the scoped tenant is visible.
		tenant := argString(args, 0)
		id := argString(args, 1)
		data, _ := args[7].([]byte)
		tx.db.rows = append(tx.db.rows, rlsRow{tenant: tenant, id: id, data: data})
		return pgconn.NewCommandTag("INSERT 0 1"), nil
	case strings.HasPrefix(strings.TrimSpace(sql), "UPDATE dem_targets"):
		id := argString(args, 0)
		data, _ := args[5].([]byte)
		for i := range tx.db.rows {
			if tx.db.rows[i].id != id {
				continue
			}
			if !tx.cross && tx.db.rows[i].tenant != tx.tenant {
				continue // the policy hides it: the UPDATE matches nothing
			}
			tx.db.rows[i].data = data
			return pgconn.NewCommandTag("UPDATE 1"), nil
		}
		return pgconn.NewCommandTag("UPDATE 0"), nil
	case strings.HasPrefix(strings.TrimSpace(sql), "DELETE FROM dem_targets"):
		id := argString(args, 0)
		for i := range tx.db.rows {
			if tx.db.rows[i].id != id {
				continue
			}
			if !tx.cross && tx.db.rows[i].tenant != tx.tenant {
				continue
			}
			tx.db.rows = append(tx.db.rows[:i], tx.db.rows[i+1:]...)
			return pgconn.NewCommandTag("DELETE 1"), nil
		}
		return pgconn.NewCommandTag("DELETE 0"), nil
	}
	return pgconn.CommandTag{}, errors.New("rls: unexpected exec: " + sql)
}

func (tx *rlsTx) Begin(context.Context) (pgx.Tx, error) { panic("unused") }
func (tx *rlsTx) Commit(context.Context) error          { panic("unused") }
func (tx *rlsTx) Rollback(context.Context) error        { panic("unused") }
func (tx *rlsTx) CopyFrom(context.Context, pgx.Identifier, []string, pgx.CopyFromSource) (int64, error) {
	panic("unused")
}
func (tx *rlsTx) SendBatch(context.Context, *pgx.Batch) pgx.BatchResults { panic("unused") }
func (tx *rlsTx) LargeObjects() pgx.LargeObjects                         { panic("unused") }
func (tx *rlsTx) Prepare(context.Context, string, string) (*pgconn.StatementDescription, error) {
	panic("unused")
}
func (tx *rlsTx) Conn() *pgx.Conn { return nil }

type rlsRow1 struct {
	data  []byte
	count int
	err   error
}

func (r *rlsRow1) Scan(dest ...any) error {
	if r.err != nil {
		return r.err
	}
	if len(dest) != 1 {
		return errors.New("rls: one column")
	}
	switch p := dest[0].(type) {
	case *[]byte:
		*p = r.data
		return nil
	case *int:
		*p = r.count
		return nil
	}
	return errors.New("rls: unexpected scan target")
}

type rlsRows struct {
	data [][]byte
	at   int
}

func (r *rlsRows) Next() bool { r.at++; return r.at < len(r.data) }
func (r *rlsRows) Scan(dest ...any) error {
	p, ok := dest[0].(*[]byte)
	if !ok {
		return errors.New("rls: the selected column is scanned as []byte")
	}
	*p = r.data[r.at]
	return nil
}
func (r *rlsRows) Close()                                       {}
func (r *rlsRows) Err() error                                   { return nil }
func (r *rlsRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *rlsRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *rlsRows) Values() ([]any, error)                       { return nil, errors.New("unused") }
func (r *rlsRows) RawValues() [][]byte                          { return nil }
func (r *rlsRows) Conn() *pgx.Conn                              { return nil }

// ── the isolation test ──────────────────────────────────────────────────────

func pgTarget(tenant, name string) Target {
	return Target{TenantID: tenant, Name: name, Kind: KindICMP, Host: "10.0.0.1", CreatedBy: "op@" + tenant}
}

// 3.2-16 — THE DEFAULT BACKEND IS SCOPED, DEFAULT-CLOSED, ON EVERY VERB.
func TestPGCatalogueIsolation(t *testing.T) {
	ctx := context.Background()
	db := &rlsDB{}
	s := NewPGStore(db)

	a, err := s.Create(ctx, pgTarget("org-a", "checkout-a"))
	if err != nil {
		t.Fatalf("create a: %v", err)
	}
	b, err := s.Create(ctx, pgTarget("org-b", "checkout-b"))
	if err != nil {
		t.Fatalf("create b: %v", err)
	}

	// 1. The owner is stamped from the caller's own scope, and the row lands
	//    under it.
	for _, row := range db.rows {
		if row.id == a.ID && row.tenant != "org-a" {
			t.Fatalf("target A was stored under %q", row.tenant)
		}
	}

	// 2. OWN-ONLY LIST.
	listA, err := s.List(ctx, "org-a")
	if err != nil {
		t.Fatalf("list a: %v", err)
	}
	if len(listA) != 1 || listA[0].ID != a.ID {
		t.Fatalf("org-a sees %d rows: %+v", len(listA), listA)
	}

	// 3. CROSS-TENANT GET / UPDATE / DELETE by id → ErrNotFound, and the
	//    victim's row survives.
	if _, gerr := s.Get(ctx, "org-a", b.ID); !errors.Is(gerr, ErrNotFound) {
		t.Fatalf("cross-tenant get = %v, want ErrNotFound", gerr)
	}
	paused := true
	if _, uerr := s.Update(ctx, "org-a", b.ID, Patch{Paused: &paused}); !errors.Is(uerr, ErrNotFound) {
		t.Fatalf("cross-tenant update = %v, want ErrNotFound", uerr)
	}
	if derr := s.Delete(ctx, "org-a", b.ID); !errors.Is(derr, ErrNotFound) {
		t.Fatalf("cross-tenant delete = %v, want ErrNotFound", derr)
	}
	victim, err := s.Get(ctx, "org-b", b.ID)
	if err != nil {
		t.Fatalf("the victim's row did not survive: %v", err)
	}
	if victim.Paused {
		t.Fatal("a cross-tenant update reached another tenant's row")
	}

	// 4. NO SCOPE, NO ROWS: a blank or wildcard tenant is default-closed on
	//    every verb rather than reading the platform.
	for _, scope := range []string{"", "*"} {
		if rows, lerr := s.List(ctx, scope); lerr != nil || len(rows) != 0 {
			t.Fatalf("list(%q) = %d rows, %v — want the default-closed answer", scope, len(rows), lerr)
		}
		if _, gerr := s.Get(ctx, scope, a.ID); !errors.Is(gerr, ErrNotFound) {
			t.Fatalf("get(%q) = %v, want ErrNotFound", scope, gerr)
		}
		if derr := s.Delete(ctx, scope, a.ID); !errors.Is(derr, ErrNotFound) {
			t.Fatalf("delete(%q) = %v, want ErrNotFound", scope, derr)
		}
	}

	// 5. Nothing on this path ever asks the seam for cross-tenant scope.
	if db.crossSeen {
		t.Fatal("a catalogue statement ran with cross-tenant scope")
	}
}

// 3.2-15 — THE PER-TENANT CAP IS TAKEN BEHIND A PER-TENANT LOCK.
//
// The cap was a bare `SELECT count(*)` inside the transaction. Being inside the
// transaction is not enough: at READ COMMITTED that count takes no lock and
// cannot see another transaction's uncommitted insert, so two concurrent
// creates could both see the last free slot and both take it — while the
// comment above them claimed the opposite. The lock is what the comment claims.
func TestPGCreateTakesThePerTenantCatalogueLock(t *testing.T) {
	ctx := context.Background()
	db := &rlsDB{}
	s := NewPGStore(db)

	if _, err := s.Create(ctx, pgTarget("org-a", "one")); err != nil {
		t.Fatalf("create: %v", err)
	}
	if len(db.locks) != 1 {
		t.Fatalf("the create took %d advisory locks — the cap is still a lock-free count, so two concurrent creates can both take the last slot", len(db.locks))
	}
	if db.locks[0] != tenantLockKey("org-a") {
		t.Fatalf("the lock key is not this tenant's: %d", db.locks[0])
	}
	// A DIFFERENT tenant takes a DIFFERENT key, so one tenant's creates cannot
	// serialise behind another's.
	if _, err := s.Create(ctx, pgTarget("org-b", "two")); err != nil {
		t.Fatalf("create b: %v", err)
	}
	if len(db.locks) != 2 || db.locks[1] == db.locks[0] {
		t.Fatalf("tenants share a catalogue lock key: %v", db.locks)
	}
}

// The stand-in must be driven by the statements, not by the test's beliefs: if
// Create ever stopped binding the tenant it was scoped to, this would catch it.
func TestPGCreateStampsTheScopedOwnerIntoTheRow(t *testing.T) {
	ctx := context.Background()
	db := &rlsDB{}
	s := NewPGStore(db)
	got, err := s.Create(ctx, pgTarget("org-a", "checkout"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	var stored Target
	if jerr := json.Unmarshal(db.rows[0].data, &stored); jerr != nil {
		t.Fatal(jerr)
	}
	if stored.TenantID != "org-a" || stored.ID != got.ID {
		t.Fatalf("stored row = %+v", stored)
	}
}
