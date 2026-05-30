package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"time"
)

// pgkv.go — Postgres backend for the identity/saved stores.
//
// It persists each store's JSON blob as a row in a single key/value table, so
// the file-backed stores move to Postgres with NO change to their logic or the
// HTTP API — only the backend swaps (STORE_BACKEND=postgres + DATABASE_URL).
//
// IMPORTANT — stdlib-only invariant: this file imports ONLY database/sql from
// the standard library, so the default build remains dependency-free (go.mod
// stays empty) per CLAUDE.md. A Postgres *driver* (github.com/lib/pq,
// jackc/pgx, …) is third-party and is intentionally NOT imported here. To
// actually run this backend an operator compiles the binary with a driver
// registered under DATABASE_DRIVER (default "postgres"), e.g. add a one-line
// file:
//
//	//go:build pg
//	package main
//	import _ "github.com/lib/pq"
//
// and build with `go build -tags pg` after `go get github.com/lib/pq`. That
// single, opt-in dependency is the ONLY place the dependency-free rule is
// relaxed, and only when the operator chooses Postgres. Without a registered
// driver, sql.Open fails and startup aborts with a clear message rather than
// silently falling back to files.
type pgKV struct {
	db    *sql.DB
	table string
}

func newPostgresKV(dsn string) (*pgKV, error) {
	if dsn == "" {
		return nil, errors.New("STORE_BACKEND=postgres requires DATABASE_URL")
	}
	driver := os.Getenv("DATABASE_DRIVER")
	if driver == "" {
		driver = "postgres"
	}
	db, err := sql.Open(driver, dsn)
	if err != nil {
		return nil, fmt.Errorf("open postgres (driver %q — is it compiled in? see pgkv.go): %w", driver, err)
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxIdleTime(5 * time.Minute)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping postgres (driver %q not registered? add a build-tagged driver import — see pgkv.go): %w", driver, err)
	}

	table := os.Getenv("DATABASE_KV_TABLE")
	if table == "" {
		table = "netops_kv"
	}
	kv := &pgKV{db: db, table: table}
	if err := kv.ensureSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	return kv, nil
}

func (p *pgKV) ensureSchema(ctx context.Context) error {
	// table is operator-controlled config (DATABASE_KV_TABLE), never user input.
	_, err := p.db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+p.table+` (
		key        TEXT PRIMARY KEY,
		data       BYTEA NOT NULL,
		updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
	)`)
	return err
}

func (p *pgKV) Load(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var data []byte
	err := p.db.QueryRowContext(ctx, `SELECT data FROM `+p.table+` WHERE key = $1`, key).Scan(&data)
	if errors.Is(err, sql.ErrNoRows) {
		// Mirror the file backend's "absent" signal so the store constructors'
		// errors.Is(err, os.ErrNotExist) checks treat an empty store identically.
		return nil, os.ErrNotExist
	}
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (p *pgKV) Save(key string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := p.db.ExecContext(ctx, `INSERT INTO `+p.table+` (key, data, updated_at)
		VALUES ($1, $2, now())
		ON CONFLICT (key) DO UPDATE SET data = EXCLUDED.data, updated_at = now()`, key, data)
	return err
}
