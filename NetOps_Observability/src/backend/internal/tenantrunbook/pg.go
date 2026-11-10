// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tenantrunbook

// pg.go — the Postgres store over tenant_runbooks / tenant_runbook_versions /
// tenant_runbook_links (migration 0066). Every statement runs inside
// WithTenant(tenant, cross=false) under the FORCE-RLS tenant_iso policy; tenant_id
// is also filtered explicitly. A transition prepares unlocked, then loads the
// runbook FOR UPDATE, decides, and writes the difference; the database's CHECKs and
// trigger refuse anything decide would not do.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"netops/backend/internal/orgcontext"
)

// DB is the injected relational seam.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// PGStore is the Postgres Store.
type PGStore struct {
	db  DB
	cfg Config
	now func() time.Time
}

// NewPGStore builds the Postgres store.
func NewPGStore(db DB, cfg Config) *PGStore {
	return &PGStore{db: db, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

const pgTimeout = 10 * time.Second

// List implements Store.
func (p *PGStore) List(ctx context.Context, tenant string) ([]Runbook, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Runbook
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = loadRunbooks(ctx, tx, tenant, "", false)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tenantrunbook: list: %w", err)
	}
	return out, nil
}

// Get implements Store.
func (p *PGStore) Get(ctx context.Context, tenant, id string) (Runbook, error) {
	if !ValidID(id) {
		return Runbook{}, orgcontext.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Runbook
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = loadRunbooks(ctx, tx, tenant, id, false)
		return err
	})
	if err != nil {
		return Runbook{}, fmt.Errorf("tenantrunbook: get: %w", err)
	}
	if len(out) == 0 {
		return Runbook{}, orgcontext.ErrNotFound
	}
	return out[0], nil
}

// Create implements Store. The per-tenant count is read under a transaction-scoped
// advisory lock on the tenant, so two concurrent creates cannot both pass the cap.
func (p *PGStore) Create(ctx context.Context, tenant, actor string, in NewRunbook) (out Runbook, err error) {
	defer func() { p.cfg.Metrics.op("create", err) }()
	body, when, err := p.cfg.checkNew(tenant, actor, in)
	if err != nil {
		return Runbook{}, err
	}
	id, err := orgcontext.NewID()
	if err != nil {
		return Runbook{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	now := p.now()
	r := newRunbook(tenant, actor, id, body, when, in, now)
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('tenant_runbook:' || $1::text))`, tenant); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tenant_runbooks WHERE tenant_id = $1::text`, tenant).Scan(&n); err != nil {
			return fmt.Errorf("count: %w", err)
		}
		if n >= MaxRunbooksPerTenant {
			return orgcontext.ErrFull
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_runbooks (tenant_id, id, name, kind, when_to_use_text, created_by, created_at, updated_at)
		    VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`, tenant, id, in.Name, string(in.Kind), when, actor, now); err != nil {
			if uniqueViolation(err) {
				return orgcontext.ErrExists
			}
			return fmt.Errorf("insert runbook: %w", err)
		}
		return insertVersion(ctx, tx, r, r.Versions[0])
	})
	if err != nil {
		return Runbook{}, wrap("create", err)
	}
	return r, nil
}

// Do implements Store.
func (p *PGStore) Do(ctx context.Context, tenant, id string, op orgcontext.Op) (out Runbook, err error) {
	defer func() { p.cfg.Metrics.op(string(op.Kind), err) }()
	if op.Now.IsZero() {
		op.Now = p.now()
	}
	before, err := p.Get(ctx, tenant, id)
	if err != nil {
		return Runbook{}, err
	}
	proved, err := p.cfg.prepare(ctx, before, op, func() ([]Runbook, error) { return p.List(ctx, tenant) })
	if err != nil {
		return Runbook{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := loadRunbooks(ctx, tx, tenant, id, true)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return orgcontext.ErrNotFound
		}
		cur := rows[0]
		after, err := p.cfg.decide(cur, op, proved)
		if err != nil {
			return err
		}
		if err := persist(ctx, tx, cur, after); err != nil {
			return err
		}
		out = after
		return nil
	})
	if err != nil {
		return Runbook{}, wrap(string(op.Kind), err)
	}
	return out, nil
}

// Check implements Store. It holds no lock and no transaction across the run.
func (p *PGStore) Check(ctx context.Context, tenant, id string) (HarnessResult, error) {
	r, err := p.Get(ctx, tenant, id)
	if err != nil {
		return HarnessResult{}, err
	}
	v, err := checkTarget(r)
	if err != nil {
		return HarnessResult{}, err
	}
	return p.cfg.prove(ctx, r, v, func() ([]Runbook, error) { return p.List(ctx, tenant) })
}

// Links implements Store.
func (p *PGStore) Links(ctx context.Context, tenant, id string) ([]Link, error) {
	if !ValidID(id) {
		return nil, orgcontext.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []Link
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if err := lockRunbook(ctx, tx, tenant, id, false); err != nil {
			return err
		}
		var err error
		out, err = loadLinks(ctx, tx, tenant, id)
		return err
	})
	if err != nil {
		return nil, wrap("links", err)
	}
	return out, nil
}

// PutLink implements Store. The count is read under the runbook's row lock.
func (p *PGStore) PutLink(ctx context.Context, tenant, id, actor string, t LinkType, key string) (out []Link, err error) {
	defer func() { p.cfg.Metrics.op("link", err) }()
	if !ValidID(id) {
		return nil, orgcontext.ErrNotFound
	}
	if err := checkLink(t, key); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	now := p.now()
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if err := lockRunbook(ctx, tx, tenant, id, true); err != nil {
			return err
		}
		cur, err := loadLinks(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		for _, l := range cur {
			if l.Type == t && l.Key == key {
				out = cur
				return nil
			}
		}
		if len(cur) >= MaxLinksPerRunbook {
			return orgcontext.ErrFull
		}
		if _, err := tx.Exec(ctx, `INSERT INTO tenant_runbook_links (tenant_id, runbook_id, link_type, link_key, created_by, created_at)
		    VALUES ($1, $2, $3, $4, $5, $6)`, tenant, id, string(t), key, actor, now); err != nil {
			return fmt.Errorf("insert link: %w", err)
		}
		out = append(cur, Link{Type: t, Key: key, CreatedBy: actor, CreatedAt: now})
		return nil
	})
	if err != nil {
		return nil, wrap("link", err)
	}
	return out, nil
}

// DeleteLink implements Store.
func (p *PGStore) DeleteLink(ctx context.Context, tenant, id string, t LinkType, key string) (out []Link, err error) {
	defer func() { p.cfg.Metrics.op("unlink", err) }()
	if !ValidID(id) {
		return nil, orgcontext.ErrNotFound
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	err = p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		if err := lockRunbook(ctx, tx, tenant, id, true); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `DELETE FROM tenant_runbook_links WHERE tenant_id = $1::text AND runbook_id = $2::uuid AND link_type = $3 AND link_key = $4`,
			tenant, id, string(t), key)
		if err != nil {
			return fmt.Errorf("delete link: %w", err)
		}
		if tag.RowsAffected() == 0 {
			return orgcontext.ErrNotFound
		}
		out, err = loadLinks(ctx, tx, tenant, id)
		return err
	})
	if err != nil {
		return nil, wrap("unlink", err)
	}
	return out, nil
}

// retrievalColumns and retrievalJoin select a RetrievalDoc; the LEFT JOIN finds the
// active version, of which the database guarantees at most one.
const (
	retrievalColumns = `r.id::text, r.name, r.when_to_use_text, r.created_at, v.version IS NOT NULL, v.decided_at`
	retrievalJoin    = ` LEFT JOIN tenant_runbook_versions v
	      ON v.tenant_id = r.tenant_id AND v.runbook_id = r.id AND v.state = 'active'`
)

// ListByLink implements Store.
func (p *PGStore) ListByLink(ctx context.Context, tenant string, t LinkType, key string) ([]RetrievalDoc, error) {
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []RetrievalDoc
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = queryRetrieval(ctx, tx, tenant, `SELECT `+retrievalColumns+`
		      FROM tenant_runbook_links l
		      JOIN tenant_runbooks r ON r.tenant_id = l.tenant_id AND r.id = l.runbook_id`+retrievalJoin+`
		     WHERE l.tenant_id = $1::text AND l.link_type = $2 AND l.link_key = $3
		     ORDER BY v.version IS NOT NULL DESC, r.updated_at DESC, r.id`, tenant, string(t), key)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tenantrunbook: list by link: %w", err)
	}
	return out, nil
}

// Search implements Store.
func (p *PGStore) Search(ctx context.Context, tenant, q string, limit int) ([]RetrievalDoc, error) {
	if len(searchWords(q)) == 0 {
		return []RetrievalDoc{}, nil
	}
	ctx, cancel := context.WithTimeout(ctx, pgTimeout)
	defer cancel()
	var out []RetrievalDoc
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		var err error
		out, err = queryRetrieval(ctx, tx, tenant, `SELECT `+retrievalColumns+`
		      FROM tenant_runbooks r`+retrievalJoin+`
		     CROSS JOIN plainto_tsquery('simple', $2) q
		     WHERE r.tenant_id = $1::text AND r.search @@ q
		     ORDER BY ts_rank(r.search, q) DESC, v.version IS NOT NULL DESC, r.updated_at DESC, r.id
		     LIMIT $3`, tenant, q, clampLimit(limit))
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("tenantrunbook: search: %w", err)
	}
	return out, nil
}

func queryRetrieval(ctx context.Context, tx pgx.Tx, tenant, sql string, args ...any) ([]RetrievalDoc, error) {
	rows, err := tx.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RetrievalDoc{}
	for rows.Next() {
		d := RetrievalDoc{Tenant: tenant, Type: retrievalType, Source: retrievalSource, Scope: orgcontext.ScopeTenant, Authority: AuthorityUnapproved}
		var active bool
		if err := rows.Scan(&d.ID, &d.Name, &d.Snippet, &d.CreatedAt, &active, &d.ApprovedAt); err != nil {
			return nil, err
		}
		if active {
			d.Authority = AuthorityApproved
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// lockRunbook proves the runbook is this tenant's; forUpdate also serialises writers.
func lockRunbook(ctx context.Context, tx pgx.Tx, tenant, id string, forUpdate bool) error {
	q := `SELECT 1 FROM tenant_runbooks WHERE tenant_id = $1::text AND id = $2::uuid`
	if forUpdate {
		q += ` FOR UPDATE`
	}
	var one int
	err := tx.QueryRow(ctx, q, tenant, id).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return orgcontext.ErrNotFound
	}
	return err
}

func loadLinks(ctx context.Context, tx pgx.Tx, tenant, id string) ([]Link, error) {
	rows, err := tx.Query(ctx, `SELECT link_type, link_key, created_by, created_at FROM tenant_runbook_links
	     WHERE tenant_id = $1::text AND runbook_id = $2::uuid ORDER BY link_type, link_key`, tenant, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Link{}
	for rows.Next() {
		var l Link
		var t string
		if err := rows.Scan(&t, &l.Key, &l.CreatedBy, &l.CreatedAt); err != nil {
			return nil, err
		}
		l.Type = LinkType(t)
		out = append(out, l)
	}
	return out, rows.Err()
}

// persist writes the difference decide made.
func persist(ctx context.Context, tx pgx.Tx, before, after Runbook) error {
	old := map[int]orgcontext.Version{}
	for _, v := range before.Versions {
		old[v.Version] = v
	}
	seen := map[int]bool{}
	// Demotions first (active → superseded) so the one-active index never sees two
	// active versions mid-statement.
	ordered := make([]orgcontext.Version, 0, len(after.Versions))
	for _, v := range after.Versions {
		if v.State != orgcontext.StateActive {
			ordered = append(ordered, v)
		}
	}
	for _, v := range after.Versions {
		if v.State == orgcontext.StateActive {
			ordered = append(ordered, v)
		}
	}
	for _, v := range ordered {
		seen[v.Version] = true
		o, existed := old[v.Version]
		switch {
		case !existed:
			if err := insertVersion(ctx, tx, after, v); err != nil {
				return err
			}
		case versionChanged(o, v) || before.Harness[v.Version] != after.Harness[v.Version]:
			if err := updateVersion(ctx, tx, after, v); err != nil {
				return err
			}
		}
	}
	for n := range old {
		if !seen[n] {
			if _, err := tx.Exec(ctx, `DELETE FROM tenant_runbook_versions WHERE tenant_id = $1::text AND runbook_id = $2::uuid AND version = $3`,
				after.TenantID, after.ID, n); err != nil {
				return fmt.Errorf("delete version %d: %w", n, err)
			}
		}
	}
	if len(after.Versions) == 0 {
		if _, err := tx.Exec(ctx, `DELETE FROM tenant_runbook_links WHERE tenant_id = $1::text AND runbook_id = $2::uuid`, after.TenantID, after.ID); err != nil {
			return fmt.Errorf("delete links: %w", err)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM tenant_runbooks WHERE tenant_id = $1::text AND id = $2::uuid`, after.TenantID, after.ID); err != nil {
			return fmt.Errorf("delete runbook: %w", err)
		}
		return nil
	}
	if _, err := tx.Exec(ctx, `UPDATE tenant_runbooks SET updated_at = $3, when_to_use_text = $4 WHERE tenant_id = $1::text AND id = $2::uuid`,
		after.TenantID, after.ID, after.UpdatedAt, after.WhenToUse); err != nil {
		return fmt.Errorf("touch runbook: %w", err)
	}
	return nil
}

func versionChanged(o, v orgcontext.Version) bool {
	return o.State != v.State || o.Body != v.Body || o.Reason != v.Reason || o.Approver != v.Approver ||
		o.ActivatedBy != v.ActivatedBy || o.DecidedBy != v.DecidedBy
}

func updateVersion(ctx context.Context, tx pgx.Tx, r Runbook, v orgcontext.Version) error {
	src, err := SplitBody(v.Body)
	if err != nil {
		return err
	}
	st := r.Harness[v.Version]
	if _, err := tx.Exec(ctx, `UPDATE tenant_runbook_versions
	       SET skill_md = $4, cases_yaml = $5, body_sha256 = $6, state = $7, approver_sub = NULLIF($8, ''), activated_by = $9,
	           decided_by = $10, reason = $11, created_at = $12, decided_at = $13,
	           harness_passed = $14, harness_fingerprint = $15, harness_at = $16
	     WHERE tenant_id = $1::text AND runbook_id = $2::uuid AND version = $3`,
		r.TenantID, r.ID, v.Version, src.SkillMD, src.CasesYAML, v.BodySHA256, string(v.State), v.Approver, v.ActivatedBy,
		v.DecidedBy, v.Reason, v.CreatedAt, v.DecidedAt, st.Passed, st.Fingerprint, st.At); err != nil {
		return fmt.Errorf("update version %d: %w", v.Version, err)
	}
	return nil
}

func insertVersion(ctx context.Context, tx pgx.Tx, r Runbook, v orgcontext.Version) error {
	src, err := SplitBody(v.Body)
	if err != nil {
		return err
	}
	var restored *int
	if v.RestoredFrom > 0 {
		n := v.RestoredFrom
		restored = &n
	}
	st := r.Harness[v.Version]
	if _, err := tx.Exec(ctx, `INSERT INTO tenant_runbook_versions
	      (tenant_id, runbook_id, version, skill_md, cases_yaml, body_sha256, state, author_sub, approver_sub, activated_by, decided_by,
	       restored_from, reason, harness_passed, harness_fingerprint, harness_at, created_at, decided_at)
	    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULLIF($9, ''), $10, $11, $12, $13, $14, $15, $16, $17, $18)`,
		r.TenantID, r.ID, v.Version, src.SkillMD, src.CasesYAML, v.BodySHA256, string(v.State), v.Author, v.Approver, v.ActivatedBy, v.DecidedBy,
		restored, v.Reason, st.Passed, st.Fingerprint, st.At, v.CreatedAt, v.DecidedAt); err != nil {
		return fmt.Errorf("insert version %d: %w", v.Version, err)
	}
	return nil
}

// loadRunbooks reads one runbook (id != "") or all of the tenant's, with their
// versions; lock takes FOR UPDATE on the runbook row.
func loadRunbooks(ctx context.Context, tx pgx.Tx, tenant, id string, lock bool) ([]Runbook, error) {
	q := `SELECT id::text, name, kind, when_to_use_text, created_by, created_at, updated_at FROM tenant_runbooks WHERE tenant_id = $1::text`
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
	var out []Runbook
	idx := map[string]int{}
	for rows.Next() {
		var r Runbook
		var kind string
		if err := rows.Scan(&r.ID, &r.Key, &kind, &r.WhenToUse, &r.CreatedBy, &r.CreatedAt, &r.UpdatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		r.RunbookKind, r.TenantID, r.Scope, r.Harness = Kind(kind), tenant, orgcontext.ScopeTenant, map[int]Stamp{}
		idx[r.ID] = len(out)
		out = append(out, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	vq := `SELECT runbook_id::text, version, skill_md, cases_yaml, body_sha256, state, author_sub, coalesce(approver_sub, ''), activated_by, decided_by,
	              coalesce(restored_from, 0), reason, harness_passed, harness_fingerprint, harness_at, created_at, decided_at
	         FROM tenant_runbook_versions WHERE tenant_id = $1::text`
	if id != "" {
		vq += ` AND runbook_id = $2::uuid`
	}
	vq += ` ORDER BY runbook_id, version`
	vrows, err := tx.Query(ctx, vq, args...)
	if err != nil {
		return nil, err
	}
	defer vrows.Close()
	for vrows.Next() {
		var rid, state string
		var src Source
		var v orgcontext.Version
		var st Stamp
		if err := vrows.Scan(&rid, &v.Version, &src.SkillMD, &src.CasesYAML, &v.BodySHA256, &state, &v.Author, &v.Approver, &v.ActivatedBy,
			&v.DecidedBy, &v.RestoredFrom, &v.Reason, &st.Passed, &st.Fingerprint, &st.At, &v.CreatedAt, &v.DecidedAt); err != nil {
			return nil, err
		}
		v.State = orgcontext.State(state)
		v.Body = src.SkillMD + bodySeparator + src.CasesYAML
		if i, ok := idx[rid]; ok {
			out[i].Versions = append(out[i].Versions, v)
			if st.Passed || st.Fingerprint != "" || st.At != nil {
				out[i].Harness[v.Version] = st
			}
		}
	}
	return out, vrows.Err()
}

func uniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

// wrap keeps the sentinel errors matchable and labels the rest. A unique violation
// on a transition is two concurrent approvals racing for the one active slot: the
// loser is told the state moved.
func wrap(what string, err error) error {
	for _, s := range []error{orgcontext.ErrNotFound, orgcontext.ErrInvalid, orgcontext.ErrExists, orgcontext.ErrFull,
		orgcontext.ErrWrongState, orgcontext.ErrSelfApproval, orgcontext.ErrNotAuthor, orgcontext.ErrStale, ErrHarnessStale} {
		if errors.Is(err, s) {
			return err
		}
	}
	if uniqueViolation(err) {
		return orgcontext.ErrWrongState
	}
	return fmt.Errorf("tenantrunbook: %s: %w", what, err)
}
