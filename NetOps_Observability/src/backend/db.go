package main

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
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

// boundedEnvInt reads an int from env, clamped to [min,max] and falling back to
// def when unset or unparseable. Fail-CLOSED to the default rather than to a
// value outside the safe range: pool sizing that silently accepts 0 or 100000
// is a worse outcome than ignoring a typo (F-71 discipline applied to config).
func boundedEnvInt(key string, def, min, max int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		logWarn("db", "ignoring out-of-range configuration value", map[string]any{
			"key": key, "value": raw, "min": min, "max": max, "using": def,
		})
		return def
	}
	return n
}

// setDefaultParam sets a libpq runtime parameter unless the operator already
// pinned it in DATABASE_URL — an explicit setting in the DSN always wins.
func setDefaultParam(rp map[string]string, key, val string) {
	if strings.TrimSpace(val) == "" {
		return
	}
	if _, ok := rp[key]; !ok {
		rp[key] = val
	}
}

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
	// ── F-60: pool sizing + server-side statement bounds ─────────────────────
	//
	// MaxConns was a hardcoded 10. Every data access opens an explicit
	// transaction to set the app.tenant_id GUC for RLS, so a connection is held
	// for the whole logical operation — ten concurrent requests saturate the
	// pool and the eleventh queues behind them. Tunable, with a floor so a typo
	// cannot configure the pool down to something that deadlocks.
	cfg.MaxConns = int32(boundedEnvInt("PG_MAX_CONNS", 25, 4, 200))
	cfg.MinConns = 2
	cfg.MaxConnIdleTime = 5 * time.Minute
	// A connection that has lived a long time has also accumulated a long-lived
	// server-side backend; recycling bounds that and lets a failover be picked up.
	cfg.MaxConnLifetime = durationOr("PG_MAX_CONN_LIFETIME", 30*time.Minute)

	// statement_timeout / lock_timeout / idle_in_transaction_session_timeout did
	// not appear ANYWHERE in the repo — not in Go, not in SQL. Without them a
	// runaway query keeps its backend and its LOCKS after the caller's context
	// has already expired and the caller has moved on: the Go side gives up, the
	// database does not, and the next request blocks on locks held by work
	// nobody is waiting for any more. Setting them as connection RuntimeParams
	// applies them to every statement on every pooled connection — one place,
	// no call site can forget.
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	rp := cfg.ConnConfig.RuntimeParams
	setDefaultParam(rp, "statement_timeout", envOr("PG_STATEMENT_TIMEOUT", "30s"))
	setDefaultParam(rp, "lock_timeout", envOr("PG_LOCK_TIMEOUT", "10s"))
	// A transaction left idle holds its snapshot and its locks; withTenant opens
	// one per request, so a wedged handler must not be able to park one forever.
	setDefaultParam(rp, "idle_in_transaction_session_timeout", envOr("PG_IDLE_TX_TIMEOUT", "60s"))

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

// migrationLockKey is the advisory-lock key guarding schema migration. Any
// constant works as long as it is stable and unique to this concern.
const migrationLockKey int64 = 0x4E45544F50534D47 // "NETOPSMG"

// migrationStatementTimeout is the per-statement budget DURING migration. The
// pool's 30s statement_timeout is right for request-path queries and wrong for
// a CREATE INDEX on a large table, so migrations raise it for their own
// transaction only (SET LOCAL — reverted on commit/rollback).
const migrationStatementTimeout = "15min"

// migrate applies pending migrations/*.sql in lexical order, each in its own
// transaction, recording applied versions in schema_migrations (forward-only).
//
// F-60: this had NO lock. Two replicas booting together (a rolling deploy, a
// scaled Compose service, a restart storm) both read schema_migrations, both
// saw the same file pending, and both applied it — one then crashed on the
// duplicate, and the loser's failure mode depended on what the migration did.
// A session-level advisory lock serialises them: the second replica WAITS,
// re-reads schema_migrations, and finds the work already done.
func (db *pgDB) migrate(ctx context.Context) error {
	// The lock must be held on ONE session for the whole migration, so take a
	// dedicated connection rather than using the pool (which would hand
	// different statements to different backends and silently drop the lock).
	conn, err := db.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire migration connection: %w", err)
	}
	defer conn.Release()

	lockStart := time.Now()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		// Release explicitly: the lock is session-scoped and the connection goes
		// back to the pool, so leaving it held would block every future boot.
		if _, err := conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock($1)`, migrationLockKey); err != nil {
			logError("db", "failed to release migration advisory lock — the next boot will block until this connection closes",
				map[string]any{"err": err.Error()})
		}
	}()
	if waited := time.Since(lockStart); waited > time.Second {
		logInfo("db", "waited for another replica's migration", map[string]any{"waited_ms": waited.Milliseconds()})
	}

	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
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
		if err := conn.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version=$1)`, f).Scan(&done); err != nil {
			return err
		}
		if done {
			continue
		}
		body, err := migrationsFS.ReadFile("migrations/" + f)
		if err != nil {
			return err
		}
		tx, err := conn.Begin(ctx)
		if err != nil {
			return err
		}
		// DDL on a populated table can exceed the request-path statement_timeout
		// (F-60); SET LOCAL raises it for this transaction only.
		if _, err := tx.Exec(ctx, `SET LOCAL statement_timeout = '`+migrationStatementTimeout+`'`); err != nil {
			_ = tx.Rollback(ctx)
			return fmt.Errorf("set migration statement_timeout: %w", err)
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
