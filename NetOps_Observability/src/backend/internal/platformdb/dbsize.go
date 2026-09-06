// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package platformdb

import (
	"context"
	"errors"
	"time"
)

// dbsize.go — MEASURED on-disk size of the application database (tracker 204).
//
// It lives here because this package owns the pool, and the pool is private on
// purpose. The caller (internal/storagemeter) never sees pgx: it receives plain
// numbers and turns them into a reading whose `source` names the exact function
// below, so the claim "measured" is auditable without reading this file.
//
// Both queries are PostgreSQL's own accounting, not an estimate:
//   - pg_database_size() is the size of the database's directory tree;
//   - pg_total_relation_size() is a table PLUS its indexes and TOAST, which is
//     why the relations sum to (very nearly) the database total rather than to
//     a fraction of it.

// ErrNoPool is what a size read returns when there is no application database
// on this installation (STORE_BACKEND=file). A distinct, matchable error rather
// than a nil total, because "no database" and "a database of zero bytes" are
// different facts and the caller renders them differently.
var ErrNoPool = errors.New("no PostgreSQL pool: this installation does not use the Postgres app-state backend")

// RelationSize is one relation's total on-disk size, indexes and TOAST included.
type RelationSize struct {
	// Name is schema-qualified ("public.users").
	Name string
	// Bytes is pg_total_relation_size for that relation.
	Bytes int64
}

// dbSizeTimeout bounds the size read (§9: all IO has a timeout). Both queries
// read catalog metadata and are cheap, but "cheap" is not "bounded".
const dbSizeTimeout = 10 * time.Second

// maxSizedRelations bounds the breakdown. The total is always the whole
// database; only the itemisation is capped.
const maxSizedRelations = 200

// DatabaseSize reports the database's total on-disk bytes and the per-relation
// breakdown, largest first. A nil receiver returns (0, nil, ErrNoDB-shaped
// error) rather than panicking, so a caller on a file-backed installation gets
// a refusal it can turn into an honest "not measured" sentence.
func (d *DB) DatabaseSize(ctx context.Context) (int64, []RelationSize, error) {
	if d == nil || d.pool == nil {
		return 0, nil, ErrNoPool
	}
	ctx, cancel := context.WithTimeout(ctx, dbSizeTimeout)
	defer cancel()

	var total int64
	if err := d.pool.QueryRow(ctx,
		`SELECT pg_database_size(current_database())`).Scan(&total); err != nil {
		return 0, nil, err
	}

	rows, err := d.pool.Query(ctx, `
		SELECT n.nspname || '.' || c.relname AS name,
		       pg_total_relation_size(c.oid)  AS bytes
		  FROM pg_class c
		  JOIN pg_namespace n ON n.oid = c.relnamespace
		 WHERE c.relkind IN ('r', 'p', 'm')
		   AND n.nspname NOT IN ('pg_catalog', 'information_schema')
		   AND n.nspname NOT LIKE 'pg_toast%'
		 ORDER BY 2 DESC
		 LIMIT $1`, maxSizedRelations)
	if err != nil {
		// The total was measured; the breakdown was not. Returning the error
		// would throw away a real measurement, so the total stands alone.
		return total, nil, nil
	}
	defer rows.Close()
	out := make([]RelationSize, 0, 32)
	for rows.Next() {
		var r RelationSize
		if err := rows.Scan(&r.Name, &r.Bytes); err != nil {
			return total, out, err
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return total, out, err
	}
	return total, out, nil
}
