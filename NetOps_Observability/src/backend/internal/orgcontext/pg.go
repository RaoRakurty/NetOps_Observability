// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package orgcontext

// pg.go — the Postgres store over org_context_docs / org_context_versions
// (migration 0058). Every statement runs inside WithTenant(tenant, cross=false)
// under the FORCE-RLS tenant_iso policy; tenant_id is also filtered
// explicitly. A transition loads the document FOR UPDATE, runs Apply, and
// writes the difference — the database's CHECKs and trigger refuse anything
// Apply would not do (self-approval, rewriting a submitted text).

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct {
	db  DB
	now func() time.Time
}

// NewPGStore builds the Postgres store.
func NewPGStore(db DB) *PGStore {
	return &PGStore{db: db, now: func() time.Time { return time.Now().UTC() }}
}

const pgTimeout = 10 * time.Second

// List implements Store.
func (p *PGStore) List(ctx context.Context, tenant string) ([]Doc, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Doc
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = loadDocs(ctx, tx, tenant, "", false)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("orgcontext: list: %w", err)
	}
	return out, nil
}

// Get implements Store.
func (p *PGStore) Get(ctx context.Context, tenant, id string) (Doc, error) {
	if !ValidID(id) {
		return Doc{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Doc
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = loadDocs(ctx, tx, tenant, id, false)
		return err
	})
	if err != nil {
		return Doc{}, fmt.Errorf("orgcontext: get: %w", err)
	}
	if len(out) == 0 {
		return Doc{}, ErrNotFound
	}
	return out[0], nil
}

// Create implements Store. The per-tenant document count is checked under a
// transaction-scoped advisory lock on the tenant, so two concurrent creates
// cannot both pass the cap.
func (p *PGStore) Create(ctx context.Context, tenant, actor string, in NewDoc) (Doc, error) {
	if err := checkNew(tenant, actor, in); err != nil {
		return Doc{}, err
	}
	id, err := NewID()
	if err != nil {
		return Doc{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	now := p.now()
	d := Doc{ID: id, TenantID: tenant, Scope: in.Scope, Kind: in.Kind, Key: in.Key, CreatedBy: actor, CreatedAt: now, UpdatedAt: now,
		Versions: []Version{{Version: 1, Body: in.Body, BodySHA256: BodySHA256(in.Body), State: StateDraft, Author: actor, CreatedAt: now}}}
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('org_context:' || $1::text))`, tenant); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM org_context_docs WHERE tenant_id = $1::text`, tenant).Scan(&n); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if n >= MaxDocsPerTenant {
			return ErrFull
		}
		if _, err := tx.Exec(ctx, `INSERT INTO org_context_docs (tenant_id, id, scope, kind, key, created_by, created_at, updated_at)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`, tenant, id, in.Scope, string(in.Kind), in.Key, actor, now); err != nil {
			if uniqueViolation(err) {
				return ErrExists
			}
			return fmt.Errorf("insert doc: %w", err)
		}
		return insertVersion(ctx, tx, tenant, id, d.Versions[0])
	})
	if err != nil {
		return Doc{}, wrap("create", err)
	}
	return d, nil
}

// Do implements Store.
func (p *PGStore) Do(ctx context.Context, tenant, id string, op Op) (Doc, error) {
	if !ValidID(id) {
		return Doc{}, ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	if op.Now.IsZero() {
		op.Now = p.now()
	}
	var out Doc
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		docs, err := loadDocs(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if len(docs) == 0 {
			return ErrNotFound
		}
		before := docs[0]
		after, err := Apply(before, op)
		if err != nil {
			return err
		}
		if err := persist(ctx, tx, tenant, before, after); err != nil {
			return err
		}
		out = after
		return nil
	})
	if err != nil {
		return Doc{}, wrap(string(op.Kind), err)
	}
	return out, nil
}

// ActiveFacts implements Store.
func (p *PGStore) ActiveFacts(ctx context.Context, tenant string) ([]Fact, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Fact
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT d.id::text, v.version, d.scope, d.kind, d.key, v.body
		      FROM org_context_docs d JOIN org_context_versions v ON v.tenant_id = d.tenant_id AND v.doc_id = d.id
		     WHERE d.tenant_id = $1::text AND v.state = 'active'`, tenant)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var f Fact
			var kind string
			if err := rows.Scan(&f.DocID, &f.Version, &f.Scope, &kind, &f.Key, &f.Body); err != nil {
				return err
			}
			f.Kind = Kind(kind)
			out = append(out, f)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("orgcontext: active facts: %w", err)
	}
	SortFacts(out)
	return out, nil
}

// persist writes the difference Apply made: deleted, changed and new versions,
// then the document's updated_at (or the document itself when its last
// version was discarded).
func persist(ctx context.Context, tx pgx.Tx, tenant string, before, after Doc) error {
	old := map[int]Version{}
	for _, v := range before.Versions {
		old[v.Version] = v
	}
	seen := map[int]bool{}
	// Demotions first (active → superseded) so the one-active index never
	// sees two active versions mid-statement.
	ordered := make([]Version, 0, len(after.Versions))
	for _, v := range after.Versions {
		if v.State != StateActive {
			ordered = append(ordered, v)
		}
	}
	for _, v := range after.Versions {
		if v.State == StateActive {
			ordered = append(ordered, v)
		}
	}
	for _, v := range ordered {
		seen[v.Version] = true
		o, existed := old[v.Version]
		switch {
		case !existed:
			if err := insertVersion(ctx, tx, tenant, after.ID, v); err != nil {
				return err
			}
		case o.State != v.State || o.Body != v.Body || o.Reason != v.Reason || o.Approver != v.Approver ||
			o.ActivatedBy != v.ActivatedBy || o.DecidedBy != v.DecidedBy:
			if _, err := tx.Exec(ctx, `UPDATE org_context_versions
			       SET body = $4, body_sha256 = $5, state = $6, approver_sub = NULLIF($7, ''), activated_by = $8,
			           decided_by = $9, reason = $10, created_at = $11, decided_at = $12
			     WHERE tenant_id = $1::text AND doc_id = $2::uuid AND version = $3`,
				tenant, after.ID, v.Version, v.Body, v.BodySHA256, string(v.State), v.Approver, v.ActivatedBy,
				v.DecidedBy, v.Reason, v.CreatedAt, v.DecidedAt); err != nil {
				return fmt.Errorf("update version %d: %w", v.Version, err)
			}
		}
	}
	for n, v := range old {
		if !seen[n] {
			if _, err := tx.Exec(ctx, `DELETE FROM org_context_versions WHERE tenant_id = $1::text AND doc_id = $2::uuid AND version = $3`,
				tenant, after.ID, v.Version); err != nil {
				return fmt.Errorf("delete version %d: %w", v.Version, err)
			}
		}
	}
	if len(after.Versions) == 0 {
		_, err := tx.Exec(ctx, `DELETE FROM org_context_docs WHERE tenant_id = $1::text AND id = $2::uuid`, tenant, after.ID)
		if err != nil {
			return fmt.Errorf("delete doc: %w", err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE org_context_docs SET updated_at = $3 WHERE tenant_id = $1::text AND id = $2::uuid`,
		tenant, after.ID, after.UpdatedAt); err != nil {
		return fmt.Errorf("touch doc: %w", err)
	}
	return nil
}

func insertVersion(ctx context.Context, tx pgx.Tx, tenant, docID string, v Version) error {
	var restored *int
	if v.RestoredFrom > 0 {
		r := v.RestoredFrom
		restored = &r
	}
	_, err := tx.Exec(ctx, `INSERT INTO org_context_versions
	      (tenant_id, doc_id, version, body, body_sha256, state, author_sub, approver_sub, activated_by, decided_by,
	       restored_from, reason, created_at, decided_at)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, NULLIF($8, ''), $9, $10, $11, $12, $13, $14)`,
		tenant, docID, v.Version, v.Body, v.BodySHA256, string(v.State), v.Author, v.Approver, v.ActivatedBy, v.DecidedBy,
		restored, v.Reason, v.CreatedAt, v.DecidedAt)
	if err != nil {
		return fmt.Errorf("insert version %d: %w", v.Version, err)
	}
	return nil
}

// loadDocs reads one document (id != "") or all of the tenant's, with their
// versions; lock takes FOR UPDATE on the document row.
func loadDocs(ctx context.Context, tx pgx.Tx, tenant, id string, lock bool) ([]Doc, error) {
	q := `SELECT id::text, scope, kind, key, created_by, created_at, updated_at FROM org_context_docs WHERE tenant_id = $1::text`
	args := []any{tenant}
	if id != "" {
		q += ` AND id = $2::uuid`
		args = append(args, id)
	}
	q += ` ORDER BY created_at, id`
	if lock {
		q += ` FOR UPDATE`
	}
	rows, err := tx.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var docs []Doc
	idx := map[string]int{}
	for rows.Next() {
		var d Doc
		var kind string
		if err := rows.Scan(&d.ID, &d.Scope, &kind, &d.Key, &d.CreatedBy, &d.CreatedAt, &d.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		d.Kind, d.TenantID = Kind(kind), tenant
		idx[d.ID] = len(docs)
		docs = append(docs, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(docs) == 0 {
		return nil, nil
	}
	vq := `SELECT doc_id::text, version, body, body_sha256, state, author_sub, coalesce(approver_sub, ''), activated_by, decided_by,
	              coalesce(restored_from, 0), reason, created_at, decided_at
	         FROM org_context_versions WHERE tenant_id = $1::text`
	if id != "" {
		vq += ` AND doc_id = $2::uuid`
	}
	vq += ` ORDER BY doc_id, version`
	vrows, err := tx.Query(ctx, vq, args...)
	if err != nil {
		return nil, err
	}
	defer vrows.Close()
	for vrows.Next() {
		var docID, state string
		var v Version
		if err := vrows.Scan(&docID, &v.Version, &v.Body, &v.BodySHA256, &state, &v.Author, &v.Approver, &v.ActivatedBy,
			&v.DecidedBy, &v.RestoredFrom, &v.Reason, &v.CreatedAt, &v.DecidedAt); err != nil {
			return nil, err
		}
		v.State = State(state)
		if i, ok := idx[docID]; ok {
			docs[i].Versions = append(docs[i].Versions, v)
		}
	}
	return docs, vrows.Err()
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// wrap keeps the store's sentinel errors matchable and labels the rest. A
// unique violation on a transition is two concurrent approvals racing for the
// one active slot: the loser is told the state moved.
func wrap(what string, err error) error {
	for _, s := range []error{ErrNotFound, ErrInvalid, ErrExists, ErrFull, ErrWrongState, ErrSelfApproval, ErrNotAuthor, ErrStale} {
		if errors.Is(err, s) {
			return err
		}
	}
	if uniqueViolation(err) {
		return ErrWrongState
	}
	return fmt.Errorf("orgcontext: %s: %w", what, err)
}
