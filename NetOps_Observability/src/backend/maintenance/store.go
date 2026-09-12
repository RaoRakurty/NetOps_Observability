// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package maintenance

// store.go — persistence for maintenance windows. Two backends behind one
// interface (the wireless/nms convention): FileStore for the file/dev backend
// + tests, pgStore for production (migration 0031, tenant_iso FORCE-RLS via
// the injected WithTenant seam). Isolation is enforced IN the store (§3a):
// every read is scoped by the caller's tenant — PG via RLS, file via
// tenant-keyed maps. There is no unscoped "list all".

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// MaxPerTenant caps stored windows per tenant (bounded stores, §9).
const MaxPerTenant = 200

// ErrLimit is returned when a tenant hits the window cap (HTTP 400 upstream).
var ErrLimit = fmt.Errorf("a tenant is capped at %d maintenance windows", MaxPerTenant)

type Store interface {
	List(ctx context.Context, tenant string, cross bool) ([]Window, error)
	Get(ctx context.Context, tenant string, cross bool, id string) (Window, bool, error)
	// Create stamps id/created_at/updated_at; TenantID must already carry the
	// server-derived owner (never the request body).
	Create(ctx context.Context, tenant string, cross bool, w Window) (Window, error)
	// Update replaces the mutable fields; false = no visible row (cross-tenant
	// id → 404 upstream, existence never revealed).
	Update(ctx context.Context, tenant string, cross bool, id string, w Window) (Window, bool, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
	// Covering reports whether ANY enabled window of this tenant covers the
	// (device, site, rule) triple at instant `at`. Default-closed: only the
	// named tenant's windows are consulted (suppression + timeintel stamp).
	Covering(ctx context.Context, tenant, device, site, rule string, at time.Time) (Window, bool, error)
}

func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// newUUIDv4 mirrors the platform's RFC-4122 v4 minting (duplicated per the
// no-shared-utils rule).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// ── file backend (default; tenant-filtered IN the store) ─────────────────────

// ErrStoreUnreadable is returned by every write while the window file exists but
// could not be read or parsed at start-up. It is a REFUSAL, not a failure of the
// write itself: the file's real contents were never established, so a flush
// would not update it, it would REPLACE it with whatever this process happens to
// hold — which after such a load is nothing at all.
//
// Why REFUSE rather than let the operator overwrite: a maintenance window is an
// operator's declared intent, written once and relied on for weeks. Nothing
// rebuilds it, and losing a tenant's windows is silent — alerts simply stop
// being suppressed, or a change lands outside the window somebody agreed to. The
// repair is an operator act: fix the file's permissions, or remove it
// deliberately, and the api picks it up on the next start.
var ErrStoreUnreadable = errors.New("maintenance: the window file could not be read at start-up, so writes are refused until it is repaired or removed")

type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[string]map[string]Window // tenant → id → window
	// loadErr is set when the window file EXISTS but its contents could not be
	// established — an I/O or permission failure, or JSON we could not parse.
	// It is NOT set for an absent file, which is simply a store nobody has
	// written yet.
	loadErr error
}

// NewFileStore loads persisted windows. A MISSING file starts empty; a file that
// exists but could not be read or parsed starts empty, is LOGGED, and refuses
// every write from then on, so the file it could not read is never replaced by
// an empty one.
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string]Window{}}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: no window has been declared yet. That is the normal
		// first-boot state and an empty store is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folding the two together started the store
		// empty with nothing logged, and the first Create then renamed a temp
		// file over a file whose contents were never read.
		s.loadErr = fmt.Errorf("maintenance: the window file could not be read: %w", err)
		applog.Error("maintenance", "stored maintenance windows could not be read; the store starts EMPTY, nothing is suppressed, and every write is refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		// Present but empty: nothing stored yet, nothing broken.
		return s
	}
	var list []Window
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = fmt.Errorf("maintenance: the window file could not be parsed: %w", uerr)
		applog.Error("maintenance", "stored maintenance windows could not be parsed; the store starts EMPTY, nothing is suppressed, and every write is refused until the file is repaired or removed",
			map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, w := range list {
		t := normTenant(w.TenantID)
		if s.rows[t] == nil {
			s.rows[t] = map[string]Window{}
		}
		s.rows[t][w.ID] = w
	}
	return s
}

// LoadErr reports why the window file could not be read, or nil. A reader uses
// it to say "unknown" instead of reporting the empty store as a tenant that
// declared no maintenance.
func (s *FileStore) LoadErr() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// refuseIfUnreadable is the guard every mutating method opens with, BEFORE it
// touches s.rows: a refused write must change nothing at all, in memory or on
// disk. Call it with the write lock held.
func (s *FileStore) refuseIfUnreadable() error {
	if s.loadErr == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.loadErr)
}

// flushLocked persists the full set (call with mu held).
func (s *FileStore) flushLocked() error {
	// Repeated here because this is the choke point that protects the FILE: a
	// future write path that forgets the guard above still cannot overwrite a
	// file nobody read.
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	var list []Window
	for _, byID := range s.rows {
		for _, w := range byID {
			list = append(list, w)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) List(_ context.Context, tenant string, cross bool) ([]Window, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	out := []Window{}
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		for _, w := range byID {
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	return out, nil
}

func (s *FileStore) Get(_ context.Context, tenant string, cross bool, id string) (Window, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		if w, ok := byID[id]; ok {
			return w, true, nil
		}
	}
	return Window{}, false, nil
}

func (s *FileStore) Create(_ context.Context, _ string, _ bool, w Window) (Window, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Window{}, err
	}
	now := time.Now().UTC()
	w.ID, w.TenantID = id, normTenant(w.TenantID)
	w.CreatedAt, w.UpdatedAt = now, now
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return Window{}, err
	}
	if len(s.rows[w.TenantID]) >= MaxPerTenant {
		return Window{}, ErrLimit
	}
	if s.rows[w.TenantID] == nil {
		s.rows[w.TenantID] = map[string]Window{}
	}
	s.rows[w.TenantID][w.ID] = w
	return w, s.flushLocked()
}

func (s *FileStore) Update(_ context.Context, tenant string, cross bool, id string, in Window) (Window, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return Window{}, false, err
	}
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		cur, ok := byID[id]
		if !ok {
			continue
		}
		// Server-owned identity/stamps survive; mutable fields replace.
		in.ID, in.TenantID = cur.ID, cur.TenantID
		in.CreatedBy, in.CreatedAt = cur.CreatedBy, cur.CreatedAt
		in.UpdatedAt = time.Now().UTC()
		byID[id] = in
		return in, true, s.flushLocked()
	}
	return Window{}, false, nil
}

func (s *FileStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return false, err
	}
	t := normTenant(tenant)
	for tid, byID := range s.rows {
		if !cross && tid != t {
			continue
		}
		if _, ok := byID[id]; ok {
			delete(byID, id)
			return true, s.flushLocked()
		}
	}
	return false, nil
}

func (s *FileStore) Covering(_ context.Context, tenant, device, site, rule string, at time.Time) (Window, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, w := range s.rows[normTenant(tenant)] {
		if w.Covers(at, device, site, rule) {
			return w, true, nil
		}
	}
	return Window{}, false, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0031) ───

// DB is the injected relational seam (the wireless/portintel idiom): run fn
// inside a transaction whose row-level security is scoped to tenant.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

func NewPGStore(db DB) *pgStore { return &pgStore{db: db} }

// jsonBlob encodes the full window for the data column; an encode failure is
// an ERROR, never a silently-empty row (§10).
func jsonBlob(w Window) ([]byte, error) {
	b, err := json.Marshal(w)
	if err != nil {
		return nil, fmt.Errorf("encode maintenance window: %w", err)
	}
	return b, nil
}

const pgWindowCols = `tenant_id, window_id, name, enabled, data, created_by, created_at, updated_at`

func scanPGWindow(rows pgx.Rows) (Window, error) {
	var (
		w        Window
		tenantID string
		id       string
		name     string
		enabled  bool
		blob     []byte
		by       string
		created  time.Time
		updated  time.Time
	)
	if err := rows.Scan(&tenantID, &id, &name, &enabled, &blob, &by, &created, &updated); err != nil {
		return Window{}, err
	}
	if err := json.Unmarshal(blob, &w); err != nil {
		return Window{}, err
	}
	// Typed columns are the truth for identity/lifecycle; the blob for the rest.
	w.TenantID, w.ID, w.Name, w.Enabled = tenantID, id, name, enabled
	w.CreatedBy, w.CreatedAt, w.UpdatedAt = by, created, updated
	return w, nil
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool) ([]Window, error) {
	out := []Window{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgWindowCols+` FROM maintenance_windows ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, err := scanPGWindow(rows)
			if err != nil {
				return err
			}
			out = append(out, w)
		}
		return rows.Err()
	})
	return out, err
}

func (p *pgStore) Get(ctx context.Context, tenant string, cross bool, id string) (Window, bool, error) {
	var w Window
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgWindowCols+` FROM maintenance_windows WHERE window_id = $1`, id)
		if err != nil {
			return err
		}
		defer rows.Close()
		if rows.Next() {
			if w, err = scanPGWindow(rows); err != nil {
				return err
			}
			found = true
		}
		return rows.Err()
	})
	return w, found, err
}

func (p *pgStore) Create(ctx context.Context, tenant string, cross bool, w Window) (Window, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Window{}, err
	}
	now := time.Now().UTC()
	w.ID, w.TenantID = id, normTenant(w.TenantID)
	w.CreatedAt, w.UpdatedAt = now, now
	blob, err := jsonBlob(w)
	if err != nil {
		return Window{}, err
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM maintenance_windows WHERE tenant_id = $1`, w.TenantID).Scan(&n); err != nil {
			return err
		}
		if n >= MaxPerTenant {
			return ErrLimit
		}
		_, err := tx.Exec(ctx, `INSERT INTO maintenance_windows
		        (tenant_id, window_id, name, enabled, data, created_by, created_at, updated_at)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
			w.TenantID, w.ID, w.Name, w.Enabled, blob, w.CreatedBy, w.CreatedAt, w.UpdatedAt)
		return err
	})
	if err != nil {
		return Window{}, err
	}
	return w, nil
}

func (p *pgStore) Update(ctx context.Context, tenant string, cross bool, id string, in Window) (Window, bool, error) {
	var out Window
	found := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgWindowCols+` FROM maintenance_windows WHERE window_id = $1`, id)
		if err != nil {
			return err
		}
		cur, scanErr := func() (Window, error) {
			defer rows.Close()
			if !rows.Next() {
				return Window{}, rows.Err()
			}
			return scanPGWindow(rows)
		}()
		if scanErr != nil {
			return scanErr
		}
		if cur.ID == "" {
			return nil // not visible → found stays false
		}
		in.ID, in.TenantID = cur.ID, cur.TenantID
		in.CreatedBy, in.CreatedAt = cur.CreatedBy, cur.CreatedAt
		in.UpdatedAt = time.Now().UTC()
		blob, err := jsonBlob(in)
		if err != nil {
			return err
		}
		ct, err := tx.Exec(ctx, `UPDATE maintenance_windows
		    SET name = $2, enabled = $3, data = $4, updated_at = $5
		    WHERE window_id = $1`, id, in.Name, in.Enabled, blob, in.UpdatedAt)
		if err != nil {
			return err
		}
		if ct.RowsAffected() > 0 {
			out, found = in, true
		}
		return nil
	})
	return out, found, err
}

func (p *pgStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `DELETE FROM maintenance_windows WHERE window_id = $1`, id)
		if err != nil {
			return err
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

func (p *pgStore) Covering(ctx context.Context, tenant, device, site, rule string, at time.Time) (Window, bool, error) {
	var hit Window
	found := false
	err := p.db.WithTenant(ctx, tenant, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+pgWindowCols+` FROM maintenance_windows WHERE enabled`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			w, err := scanPGWindow(rows)
			if err != nil {
				return err
			}
			if !found && w.Covers(at, device, site, rule) {
				hit, found = w, true
			}
		}
		return rows.Err()
	})
	if err != nil {
		return Window{}, false, err
	}
	return hit, found, nil
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)

// ErrNotFound is the typed miss for callers that need an error (handlers map
// the bool to 404 instead; kept for parity with sibling stores).
var ErrNotFound = errors.New("maintenance window not found")
