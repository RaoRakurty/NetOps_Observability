// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package flowsampling keeps the sampling rate an operator DECLARES for a flow
// exporter that samples but reports no rate (tracker 401 (c)).
//
// The flow views multiply ONLY that exporter's records that carried no
// reported rate by the declared rate, per (tenant, exporter): a rate the
// exporter reports always wins, and two tenants behind one exporter address
// declare independently. Postgres (migration 0077, FORCE RLS) under the
// Postgres backend; a tenant-keyed file otherwise.
package flowsampling

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

const (
	// MinRate: 1 means "not sampling" — that is the default, not a declaration.
	MinRate = 2
	// MaxRate bounds a declaration (1 in a million).
	MaxRate = 1_000_000
	// MaxNote bounds the operator's note.
	MaxNote = 200
	// MaxPerTenant bounds one workspace's declarations.
	MaxPerTenant = 500
)

// ErrNotFound: no declaration for that exporter in the caller's workspace.
var ErrNotFound = errors.New("flowsampling: no declaration for that exporter")

// ErrTooMany: the workspace already holds MaxPerTenant declarations.
var ErrTooMany = errors.New("flowsampling: too many declarations for one workspace")

// Declaration is one exporter's declared rate in one workspace.
type Declaration struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	Exporter  string    `json:"exporter"`
	Rate      uint32    `json:"rate"`
	Note      string    `json:"note"`
	UpdatedBy string    `json:"updated_by"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store keeps declarations, scoped by tenant.
type Store interface {
	// List returns the tenant's declarations (every tenant's when cross).
	List(ctx context.Context, tenant string, cross bool) ([]Declaration, error)
	// Put creates or replaces the tenant's declaration for d.Exporter.
	Put(ctx context.Context, tenant string, d Declaration) (Declaration, error)
	// Delete removes it; ErrNotFound when the tenant has none for exporter.
	Delete(ctx context.Context, tenant, exporter string) error
}

// NormTenant is the stored form of a tenant id.
func NormTenant(t string) string { return strings.TrimSpace(t) }

// ParseExporter validates and normalises an exporter address.
func ParseExporter(v string) (string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil || a.Zone() != "" {
		return "", errors.New("exporter must be the device's IP address")
	}
	return a.Unmap().String(), nil
}

// Validate checks a declaration's operator-supplied fields.
func Validate(d Declaration) (Declaration, error) {
	exp, err := ParseExporter(d.Exporter)
	if err != nil {
		return Declaration{}, err
	}
	d.Exporter = exp
	if d.Rate < MinRate || d.Rate > MaxRate {
		return Declaration{}, fmt.Errorf("rate must be a whole number from %d to %d (\"1 in N\")", MinRate, MaxRate)
	}
	d.Note = strings.TrimSpace(d.Note)
	if len([]rune(d.Note)) > MaxNote {
		return Declaration{}, fmt.Errorf("note must be %d characters or fewer", MaxNote)
	}
	for _, r := range d.Note {
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return Declaration{}, errors.New("note must not contain control or invisible characters")
		}
	}
	return d, nil
}

func sortDecl(out []Declaration) {
	sort.Slice(out, func(i, j int) bool {
		if out[i].TenantID != out[j].TenantID {
			return out[i].TenantID < out[j].TenantID
		}
		return out[i].Exporter < out[j].Exporter
	})
}

// ── file backend ────────────────────────────────────────────────────────────

// ErrStoreUnreadable: the file could not be read at start-up; writes are
// refused so a corrupt file is never overwritten with a partial view.
var ErrStoreUnreadable = errors.New("flowsampling: the declarations file could not be read at start-up, so writes are refused until it is repaired or removed")

// FileStore keeps declarations in one file, keyed by tenant.
type FileStore struct {
	mu      sync.RWMutex
	path    string
	rows    map[string]map[string]Declaration // tenant → exporter → declaration
	loadErr error
}

// NewFileStore loads path ("" = memory only).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string]Declaration{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s
	case err != nil:
		s.loadErr = err
		applog.Error("flowsampling", "declared flow sampling could not be read; writes are refused until the file is repaired or removed", map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		return s
	}
	var list []Declaration
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = uerr
		applog.Error("flowsampling", "declared flow sampling could not be parsed; writes are refused until the file is repaired or removed", map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, d := range list {
		t := NormTenant(d.TenantID)
		if s.rows[t] == nil {
			s.rows[t] = map[string]Declaration{}
		}
		s.rows[t][d.Exporter] = d
	}
	return s
}

func (s *FileStore) flushLocked() error {
	if s.loadErr != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	list := []Declaration{}
	for _, byExp := range s.rows {
		for _, d := range byExp {
			list = append(list, d)
		}
	}
	sortDecl(list)
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode declared flow sampling: %w", err)
	}
	return platformdb.Save(s.path, b)
}

// List implements Store.
func (s *FileStore) List(_ context.Context, tenant string, cross bool) ([]Declaration, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Declaration{}
	for owner, byExp := range s.rows {
		if !cross && owner != NormTenant(tenant) {
			continue
		}
		for _, d := range byExp {
			out = append(out, d)
		}
	}
	sortDecl(out)
	return out, nil
}

// Put implements Store.
func (s *FileStore) Put(_ context.Context, tenant string, d Declaration) (Declaration, error) {
	d, err := Validate(d)
	if err != nil {
		return Declaration{}, err
	}
	t := NormTenant(tenant)
	d.TenantID = t
	if d.UpdatedAt.IsZero() {
		d.UpdatedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rows[t] == nil {
		s.rows[t] = map[string]Declaration{}
	}
	prev, had := s.rows[t][d.Exporter]
	if !had && len(s.rows[t]) >= MaxPerTenant {
		return Declaration{}, ErrTooMany
	}
	s.rows[t][d.Exporter] = d
	if err := s.flushLocked(); err != nil {
		if had {
			s.rows[t][d.Exporter] = prev
		} else {
			delete(s.rows[t], d.Exporter)
		}
		return Declaration{}, err
	}
	return d, nil
}

// Delete implements Store.
func (s *FileStore) Delete(_ context.Context, tenant, exporter string) error {
	exp, err := ParseExporter(exporter)
	if err != nil {
		return ErrNotFound
	}
	t := NormTenant(tenant)
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.rows[t][exp]
	if !ok {
		return ErrNotFound
	}
	delete(s.rows[t], exp)
	if err := s.flushLocked(); err != nil {
		s.rows[t][exp] = prev
		return err
	}
	return nil
}

// ── Postgres backend ────────────────────────────────────────────────────────

// DB is the tenant-scoped transaction seam (platformdb).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed store (migration 0077).
func NewPGStore(db DB) Store { return &pgStore{db: db} }

const pgCols = `tenant_id, exporter_addr, rate, note, updated_by, updated_at`

func (p *pgStore) List(ctx context.Context, tenant string, cross bool) ([]Declaration, error) {
	out := []Declaration{}
	err := p.db.WithTenant(ctx, NormTenant(tenant), cross, func(tx pgx.Tx) error {
		q, args := `SELECT `+pgCols+` FROM flow_declared_sampling`, []any{}
		if !cross {
			q += ` WHERE tenant_id = $1`
			args = append(args, NormTenant(tenant))
		}
		rows, err := tx.Query(ctx, q+` ORDER BY tenant_id, exporter_addr LIMIT 5000`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d Declaration
			var rate int64
			if err := rows.Scan(&d.TenantID, &d.Exporter, &rate, &d.Note, &d.UpdatedBy, &d.UpdatedAt); err != nil {
				return err
			}
			if rate < MinRate || rate > MaxRate {
				continue // the CHECK forbids it; never multiply by a value outside the range
			}
			d.Rate = uint32(rate)
			d.UpdatedAt = d.UpdatedAt.UTC()
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgStore) Put(ctx context.Context, tenant string, d Declaration) (Declaration, error) {
	d, err := Validate(d)
	if err != nil {
		return Declaration{}, err
	}
	d.TenantID = NormTenant(tenant)
	if d.UpdatedAt.IsZero() {
		d.UpdatedAt = time.Now().UTC()
	}
	err = p.db.WithTenant(ctx, d.TenantID, false, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM flow_declared_sampling WHERE tenant_id = $1 AND exporter_addr <> $2`, d.TenantID, d.Exporter).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPerTenant {
			return ErrTooMany
		}
		_, err := tx.Exec(ctx, `INSERT INTO flow_declared_sampling (`+pgCols+`) VALUES ($1, $2, $3, $4, $5, $6)
ON CONFLICT (tenant_id, exporter_addr) DO UPDATE SET rate = EXCLUDED.rate, note = EXCLUDED.note,
  updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			d.TenantID, d.Exporter, int64(d.Rate), d.Note, d.UpdatedBy, d.UpdatedAt)
		return err
	})
	if err != nil {
		return Declaration{}, err
	}
	return d, nil
}

func (p *pgStore) Delete(ctx context.Context, tenant, exporter string) error {
	exp, err := ParseExporter(exporter)
	if err != nil {
		return ErrNotFound
	}
	return p.db.WithTenant(ctx, NormTenant(tenant), false, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `DELETE FROM flow_declared_sampling WHERE tenant_id = $1 AND exporter_addr = $2`, NormTenant(tenant), exp)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}
