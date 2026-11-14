// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rcaresolution

// store.go — where resolutions live. Two backends behind one interface (the
// rcafeedback convention): FileStore for the non-Postgres build and tests,
// pgStore for Postgres (migration 0071, tenant_iso FORCE-RLS through the
// injected WithTenant seam).
//
// Isolation is enforced IN the store (CLAUDE.md §3a rule 4): every read is
// scoped by the caller's tenant — Postgres by the RLS policy and an explicit
// tenant filter, the file backend by a tenant-keyed map. Latest, the read the
// similar-incident recall uses, is never cross-tenant: recall only compares a
// case with its own tenant's past cases.

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// MaxLatestIDs bounds one Latest read (recall returns a handful of matches).
const MaxLatestIDs = 50

// Store is the resolution register. `cross` is the platform-owner flag from
// principalTenant(claims); a non-cross caller never observes another tenant's
// rows through any method here.
type Store interface {
	// List returns one case's resolutions, NEWEST FIRST.
	List(ctx context.Context, tenant string, cross bool, correlationID string) ([]Resolution, error)
	// Add appends one resolution. TenantID must already carry the
	// server-derived owner; id and CreatedAt are stamped here when empty.
	Add(ctx context.Context, tenant string, r Resolution) (Resolution, error)
	// Latest returns, for each of ids that has one, its newest resolution —
	// within exactly `tenant` (never cross-tenant).
	Latest(ctx context.Context, tenant string, ids []string) (map[string]Resolution, error)
}

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

func newestFirst(rows []Resolution) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		}
		return rows[i].ID < rows[j].ID
	})
}

func boundIDs(ids []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
		if len(out) == MaxLatestIDs {
			break
		}
	}
	return out
}

// ── file backend ────────────────────────────────────────────────────────────

// ErrStoreUnreadable refuses writes while the resolution file exists but could
// not be read at start-up: a flush would REPLACE the unread file, not update it.
var ErrStoreUnreadable = errors.New("rcaresolution: the resolution file could not be read at start-up, so writes are refused until it is repaired or removed")

// FileStore is the non-Postgres backend. Path "" keeps it in memory (tests).
type FileStore struct {
	mu      sync.RWMutex
	path    string
	rows    map[string]map[string][]Resolution // tenant → correlation id → rows
	loadErr error
}

// NewFileStore loads persisted resolutions. A missing file starts empty; a
// file that exists but cannot be read or parsed starts empty, is logged, and
// refuses every write.
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string][]Resolution{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s
	case err != nil:
		s.loadErr = fmt.Errorf("rcaresolution: the resolution file could not be read: %w", err)
		applog.Error("rcaresolution", "stored incident resolutions could not be read; writes are refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		return s
	}
	var list []storedRow
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = fmt.Errorf("rcaresolution: the resolution file could not be parsed: %w", uerr)
		applog.Error("rcaresolution", "stored incident resolutions could not be parsed; writes are refused until the file is repaired or removed",
			map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, r := range list {
		s.insertLocked(r.toResolution())
	}
	return s
}

// storedRow is the file form: the tenant is persisted (Resolution hides it
// from JSON responses).
type storedRow struct {
	Resolution
	Tenant string `json:"tenant_id"`
}

func (r storedRow) toResolution() Resolution {
	out := r.Resolution
	out.TenantID = r.Tenant
	return out
}

func (s *FileStore) insertLocked(r Resolution) {
	t := NormTenant(r.TenantID)
	if s.rows[t] == nil {
		s.rows[t] = map[string][]Resolution{}
	}
	s.rows[t][r.CorrelationID] = append(s.rows[t][r.CorrelationID], r)
}

func (s *FileStore) flushLocked() error {
	if s.loadErr != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	list := []storedRow{}
	for _, byCase := range s.rows {
		for _, rows := range byCase {
			for _, r := range rows {
				list = append(list, storedRow{Resolution: r, Tenant: r.TenantID})
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode incident resolutions: %w", err)
	}
	return platformdb.Save(s.path, b)
}

// List implements Store.
func (s *FileStore) List(_ context.Context, tenant string, cross bool, correlationID string) ([]Resolution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Resolution{}
	for owner, byCase := range s.rows {
		if !cross && owner != NormTenant(tenant) {
			continue
		}
		out = append(out, byCase[correlationID]...)
	}
	newestFirst(out)
	return out, nil
}

// Add implements Store.
func (s *FileStore) Add(_ context.Context, tenant string, r Resolution) (Resolution, error) {
	if NormTenant(r.TenantID) != NormTenant(tenant) {
		return Resolution{}, errors.New("rcaresolution: a resolution is written in its own tenant only")
	}
	if r.ID == "" {
		id, err := newUUIDv4()
		if err != nil {
			return Resolution{}, err
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.TenantID = NormTenant(r.TenantID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.rows[r.TenantID][r.CorrelationID]) >= MaxPerCase {
		return Resolution{}, ErrLimit
	}
	s.insertLocked(r)
	if err := s.flushLocked(); err != nil {
		rows := s.rows[r.TenantID][r.CorrelationID]
		s.rows[r.TenantID][r.CorrelationID] = rows[:len(rows)-1] // roll the append back: nothing was stored
		return Resolution{}, err
	}
	return r, nil
}

// Latest implements Store.
func (s *FileStore) Latest(_ context.Context, tenant string, ids []string) (map[string]Resolution, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := map[string]Resolution{}
	byCase := s.rows[NormTenant(tenant)]
	for _, id := range boundIDs(ids) {
		rows := append([]Resolution(nil), byCase[id]...)
		if len(rows) == 0 {
			continue
		}
		newestFirst(rows)
		out[id] = rows[0]
	}
	return out, nil
}

// ── Postgres backend ────────────────────────────────────────────────────────

// DB is the tenant-scoped transaction seam (platformdb).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed register.
func NewPGStore(db DB) Store { return &pgStore{db: db} }

const pgCols = `tenant_id, id, correlation_id, kind, note, change_id, created_by, created_at`

func scanRow(rows pgx.Rows) (Resolution, error) {
	var (
		r    Resolution
		kind string
	)
	if err := rows.Scan(&r.TenantID, &r.ID, &r.CorrelationID, &kind, &r.Note, &r.ChangeID, &r.CreatedBy, &r.CreatedAt); err != nil {
		return Resolution{}, err
	}
	r.Kind = Kind(kind)
	r.CreatedAt = r.CreatedAt.UTC()
	return r, nil
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool, correlationID string) ([]Resolution, error) {
	out := []Resolution{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		q := `SELECT ` + pgCols + ` FROM rca_resolutions WHERE correlation_id = $1`
		args := []any{correlationID}
		if !cross {
			q += ` AND tenant_id = $2`
			args = append(args, NormTenant(tenant))
		}
		rows, err := tx.Query(ctx, q+` ORDER BY created_at DESC, id ASC`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) Add(ctx context.Context, tenant string, r Resolution) (Resolution, error) {
	if NormTenant(r.TenantID) != NormTenant(tenant) {
		return Resolution{}, errors.New("rcaresolution: a resolution is written in its own tenant only")
	}
	if r.ID == "" {
		id, err := newUUIDv4()
		if err != nil {
			return Resolution{}, err
		}
		r.ID = id
	}
	if r.CreatedAt.IsZero() {
		r.CreatedAt = time.Now().UTC()
	}
	r.TenantID = NormTenant(r.TenantID)
	err := p.db.WithTenant(ctx, r.TenantID, false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM rca_resolutions
		    WHERE tenant_id = $1 AND correlation_id = $2`, r.TenantID, r.CorrelationID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPerCase {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO rca_resolutions (`+pgCols+`)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			r.TenantID, r.ID, r.CorrelationID, string(r.Kind), r.Note, r.ChangeID, r.CreatedBy, r.CreatedAt)
		return err
	})
	if err != nil {
		return Resolution{}, err
	}
	return r, nil
}

func (p *pgStore) Latest(ctx context.Context, tenant string, ids []string) (map[string]Resolution, error) {
	out := map[string]Resolution{}
	ids = boundIDs(ids)
	if len(ids) == 0 {
		return out, nil
	}
	t := NormTenant(tenant)
	err := p.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT ON (correlation_id) `+pgCols+`
		    FROM rca_resolutions
		    WHERE tenant_id = $1 AND correlation_id::text = ANY($2)
		    ORDER BY correlation_id, created_at DESC, id ASC`, t, ids)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			r, err := scanRow(rows)
			if err != nil {
				return err
			}
			out[r.CorrelationID] = r
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)
