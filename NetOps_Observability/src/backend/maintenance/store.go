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
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

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

type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[string]map[string]Window // tenant → id → window
}

// NewFileStore loads persisted windows; a missing/corrupt file starts empty
// (the episode-store convention — state files are rebuildable operator input).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string]Window{}}
	if b, err := platformdb.Load(path); err == nil {
		var list []Window
		if json.Unmarshal(b, &list) == nil {
			for _, w := range list {
				t := normTenant(w.TenantID)
				if s.rows[t] == nil {
					s.rows[t] = map[string]Window{}
				}
				s.rows[t][w.ID] = w
			}
		}
	}
	return s
}

// flushLocked persists the full set (call with mu held).
func (s *FileStore) flushLocked() error {
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
