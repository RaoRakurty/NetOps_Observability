package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// db.go — the relational app-state foundation (M0).
//
// app-state moves from blob-kv (one JSON row per store, RLS-incompatible) to
// normalized per-row tables with a tenant_id column and PostgreSQL Row-Level
// Security. This file owns the connection pool, an in-house forward-only
// migrator (so the only new dependency is the pgx driver — no migration tool),
// and withTenant(): every data access runs in a transaction that first binds the
// session's tenant via a GUC, so RLS does the filtering even if a query forgets
// a WHERE clause. The platform owner binds '*' to see all tenants.
//
// pgx is now an allowlisted dependency (CLAUDE.md §6) and is vendored, so the
// offline image build is unaffected. The relational path is used when
// STORE_BACKEND=postgres; file mode stays the dependency-light default for dev.

//go:embed migrations/*.sql
var migrationsFS embed.FS

type pgDB struct {
	pool *pgxpool.Pool
}

// newPgDB connects, verifies, and runs pending migrations. Fails fast (no silent
// fallback) so a misconfigured Postgres aborts startup.
//
// ⚠️ RLS REQUIREMENT: DATABASE_URL must authenticate as a NON-superuser role
// without BYPASSRLS. PostgreSQL superusers (and BYPASSRLS roles) ignore Row-Level
// Security entirely — even with FORCE ROW LEVEL SECURITY — so connecting as
// `postgres` silently disables tenant isolation. Provision a dedicated
// least-privilege role (e.g. CREATE ROLE netops_app LOGIN NOSUPERUSER) that owns
// the app-state tables; FORCE RLS keeps even the owner subject to policy.
func newPgDB(ctx context.Context, dsn string) (*pgDB, error) {
	if dsn == "" {
		return nil, errors.New("STORE_BACKEND=postgres requires DATABASE_URL")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse DATABASE_URL: %w", err)
	}
	cfg.MaxConns = 10
	cfg.MaxConnIdleTime = 5 * time.Minute

	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(pctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect postgres: %w", err)
	}
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	db := &pgDB{pool: pool}
	if err := db.assertRLSCapable(pctx); err != nil {
		pool.Close()
		return nil, err
	}
	if err := db.migrate(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}
	return db, nil
}

// assertRLSCapable fails closed if the connection's role would bypass Row-Level
// Security — a PostgreSQL superuser or a role with BYPASSRLS ignores RLS even
// under FORCE ROW LEVEL SECURITY, which would silently disable tenant isolation
// (a multi-tenant data breach with no error). Refusing to start turns that
// silent hole into an unmissable abort. A single-tenant operator who knowingly
// does not want isolation can override with STORE_PG_ALLOW_RLS_BYPASS=true,
// which downgrades the abort to a loud warning.
func (db *pgDB) assertRLSCapable(ctx context.Context) error {
	var role string
	var isSuper, bypassRLS bool
	if err := db.pool.QueryRow(ctx,
		`SELECT current_user,
		        current_setting('is_superuser')::bool,
		        COALESCE((SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user), false)`,
	).Scan(&role, &isSuper, &bypassRLS); err != nil {
		return fmt.Errorf("verify RLS capability: %w", err)
	}
	if !isSuper && !bypassRLS {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("STORE_PG_ALLOW_RLS_BYPASS")), "true") {
		logWarn("db", "DATABASE_URL role BYPASSES Row-Level Security — tenant isolation is DISABLED (STORE_PG_ALLOW_RLS_BYPASS=true)",
			map[string]any{"role": role, "superuser": isSuper, "bypassrls": bypassRLS})
		return nil
	}
	return fmt.Errorf("DATABASE_URL role %q bypasses Row-Level Security (superuser=%v, bypassrls=%v): "+
		"tenant isolation would be silently disabled. Use a non-superuser role without BYPASSRLS, "+
		"or set STORE_PG_ALLOW_RLS_BYPASS=true to override for a single-tenant deployment", role, isSuper, bypassRLS)
}

// migrate applies pending migrations/*.sql in lexical order, each in its own
// transaction, recording applied versions in schema_migrations (forward-only).
func (db *pgDB) migrate(ctx context.Context) error {
	if _, err := db.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
		version    TEXT PRIMARY KEY,
		applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`); err != nil {
		return err
	}
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return err
	}
	files := make([]string, 0, len(entries))
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".sql") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	for _, f := range files {
		var done bool
		if err := db.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, f).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return err
		}
		tx, err := db.pool.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("apply %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations(version) VALUES($1)`, f); err != nil {
			_ = tx.Rollback(ctx)
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		logInfo("db", "migration applied", map[string]any{"version": f})
	}
	return nil
}

// withTenant runs fn in a transaction whose RLS scope is bound to the principal:
// a scoped tenant sees only its rows; the platform owner ('*') sees all. The GUC
// is set via set_config (parameterized — no SQL string interpolation), so RLS
// enforces isolation even on a query that forgets `WHERE tenant_id = …`.
func (db *pgDB) withTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	scope := strings.ToLower(strings.TrimSpace(tenant))
	if cross {
		scope = "*"
	}
	tx, err := db.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// app.tenant_id is the per-request RLS session var read by every tenant_iso
	// policy (renamed from app.current_tenant in migration 0013). It carries the
	// canonical OPAQUE tenant id, or '*' for the platform-owner cross-tenant view.
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, scope); err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// close releases the pool.
func (db *pgDB) close() {
	if db != nil && db.pool != nil {
		db.pool.Close()
	}
}
