// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package devbaseline

// store.go — where baselines live. Two backends behind one interface (the
// rcaresolution convention): FileStore for the non-Postgres build and tests,
// pgStore for Postgres (migration 0079, tenant_iso FORCE-RLS through the
// injected WithTenant seam).
//
// Isolation is enforced IN the store (CLAUDE.md §3a rule 4): every read and
// write takes the owning tenant, which the server derives from the device it
// resolved under the caller's scope — never from a request field. A baseline id
// from another tenant, or for another device, is ErrNotFound: the two are
// indistinguishable to the caller.

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

// MaxBodyBytes bounds one stored baseline's JSON body (a device with every
// list at its cap stays well under it; the database enforces the same bound).
const MaxBodyBytes = 256 << 10

var (
	// ErrNotFound covers a missing baseline, another tenant's, and one taken
	// on a different device.
	ErrNotFound = errors.New("devbaseline: no such baseline")
	// ErrTooLarge refuses a baseline whose body exceeds MaxBodyBytes.
	ErrTooLarge = errors.New("devbaseline: the baseline is too large to store")
	// ErrStoreUnreadable refuses writes while the baseline file exists but
	// could not be read at start-up: a flush would replace the unread file.
	ErrStoreUnreadable = errors.New("devbaseline: the baseline file could not be read at start-up, so writes are refused until it is repaired or removed")
)

// Store is the baseline register. Every method is confined to `tenant`.
type Store interface {
	// Put stores s (TenantID must equal tenant), stamping its id and time
	// when empty, and drops the device's oldest baselines past MaxPerDevice.
	Put(ctx context.Context, tenant string, s Snapshot) (Snapshot, error)
	// Get returns one baseline of one device.
	Get(ctx context.Context, tenant, deviceID, id string) (Snapshot, error)
	// Latest returns the device's newest baseline.
	Latest(ctx context.Context, tenant, deviceID string) (Snapshot, error)
	// List returns the device's baselines, newest first.
	List(ctx context.Context, tenant, deviceID string) ([]Summary, error)
}

// NormTenant is the stored form of a tenant id.
func NormTenant(t string) string { return strings.TrimSpace(t) }

func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// prepare validates and stamps a snapshot for storage.
func prepare(tenant string, s Snapshot) (Snapshot, []byte, error) {
	if NormTenant(s.TenantID) != NormTenant(tenant) {
		return Snapshot{}, nil, errors.New("devbaseline: a baseline is written in its own tenant only")
	}
	if strings.TrimSpace(s.DeviceID) == "" || len(s.DeviceID) > 128 {
		return Snapshot{}, nil, errors.New("devbaseline: a baseline needs its device id")
	}
	if s.ID == "" {
		id, err := newUUIDv4()
		if err != nil {
			return Snapshot{}, nil, err
		}
		s.ID = id
	}
	if s.TakenAt.IsZero() {
		s.TakenAt = time.Now().UTC()
	}
	s.TakenAt = s.TakenAt.UTC()
	s.TenantID = NormTenant(s.TenantID)
	s.Label = clamp(s.Label, MaxLabel)
	s.TakenBy = clamp(s.TakenBy, maxText)
	body, err := json.Marshal(s)
	if err != nil {
		return Snapshot{}, nil, fmt.Errorf("encode baseline: %w", err)
	}
	if len(body) > MaxBodyBytes {
		return Snapshot{}, nil, ErrTooLarge
	}
	return s, body, nil
}

func newestFirst(rows []Snapshot) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].TakenAt.Equal(rows[j].TakenAt) {
			return rows[i].TakenAt.After(rows[j].TakenAt)
		}
		return rows[i].ID > rows[j].ID
	})
}

// ── file backend ────────────────────────────────────────────────────────────

// FileStore is the non-Postgres backend. Path "" keeps it in memory (tests).
type FileStore struct {
	mu      sync.RWMutex
	path    string
	rows    map[string]map[string][]Snapshot // tenant → device → baselines (newest first)
	loadErr error
}

// storedRow is the file form: the tenant is persisted (Snapshot hides it from
// JSON responses).
type storedRow struct {
	Snapshot
	Tenant string `json:"tenant_id"`
}

// NewFileStore loads persisted baselines. A missing file starts empty; a file
// that exists but cannot be read or parsed starts empty, is logged, and refuses
// every write.
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[string]map[string][]Snapshot{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return s
	case err != nil:
		s.loadErr = fmt.Errorf("devbaseline: the baseline file could not be read: %w", err)
		applog.Error("devbaseline", "stored device baselines could not be read; writes are refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		return s
	}
	var list []storedRow
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = fmt.Errorf("devbaseline: the baseline file could not be parsed: %w", uerr)
		applog.Error("devbaseline", "stored device baselines could not be parsed; writes are refused until the file is repaired or removed",
			map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, r := range list {
		snap := r.Snapshot
		snap.TenantID = r.Tenant
		s.insertLocked(snap)
	}
	return s
}

func (s *FileStore) insertLocked(snap Snapshot) {
	t := NormTenant(snap.TenantID)
	if s.rows[t] == nil {
		s.rows[t] = map[string][]Snapshot{}
	}
	list := append(s.rows[t][snap.DeviceID], snap)
	newestFirst(list)
	if len(list) > MaxPerDevice {
		list = list[:MaxPerDevice]
	}
	s.rows[t][snap.DeviceID] = list
}

func (s *FileStore) flushLocked() error {
	if s.loadErr != nil {
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.loadErr)
	}
	if s.path == "" {
		return nil
	}
	list := []storedRow{}
	for tenant, byDev := range s.rows {
		for _, rows := range byDev {
			for _, r := range rows {
				list = append(list, storedRow{Snapshot: r, Tenant: tenant})
			}
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode device baselines: %w", err)
	}
	return platformdb.Save(s.path, b)
}

// Put implements Store.
func (s *FileStore) Put(_ context.Context, tenant string, snap Snapshot) (Snapshot, error) {
	snap, _, err := prepare(tenant, snap)
	if err != nil {
		return Snapshot{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.loadErr != nil {
		return Snapshot{}, fmt.Errorf("%w: %w", ErrStoreUnreadable, s.loadErr)
	}
	prev := append([]Snapshot(nil), s.rows[snap.TenantID][snap.DeviceID]...)
	s.insertLocked(snap)
	if err := s.flushLocked(); err != nil {
		s.rows[snap.TenantID][snap.DeviceID] = prev // keep memory and disk in step
		return Snapshot{}, err
	}
	return snap, nil
}

// Get implements Store.
func (s *FileStore) Get(_ context.Context, tenant, deviceID, id string) (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, r := range s.rows[NormTenant(tenant)][deviceID] {
		if r.ID == id {
			return r, nil
		}
	}
	return Snapshot{}, ErrNotFound
}

// Latest implements Store.
func (s *FileStore) Latest(_ context.Context, tenant, deviceID string) (Snapshot, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := s.rows[NormTenant(tenant)][deviceID]
	if len(rows) == 0 {
		return Snapshot{}, ErrNotFound
	}
	return rows[0], nil
}

// List implements Store.
func (s *FileStore) List(_ context.Context, tenant, deviceID string) ([]Summary, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := []Summary{}
	for _, r := range s.rows[NormTenant(tenant)][deviceID] {
		out = append(out, r.Summarize())
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

func (p *pgStore) Put(ctx context.Context, tenant string, snap Snapshot) (Snapshot, error) {
	snap, body, err := prepare(tenant, snap)
	if err != nil {
		return Snapshot{}, err
	}
	err = p.db.WithTenant(ctx, snap.TenantID, false, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO device_baselines (tenant_id, id, device_id, taken_at, taken_by, label, body)
		    VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			snap.TenantID, snap.ID, snap.DeviceID, snap.TakenAt, snap.TakenBy, snap.Label, body); err != nil {
			return err
		}
		// Retention: keep the device's newest MaxPerDevice baselines.
		_, err := tx.Exec(ctx, `DELETE FROM device_baselines
		    WHERE tenant_id = $1 AND device_id = $2 AND id NOT IN (
		        SELECT id FROM device_baselines WHERE tenant_id = $1 AND device_id = $2
		        ORDER BY taken_at DESC, id DESC LIMIT $3)`,
			snap.TenantID, snap.DeviceID, MaxPerDevice)
		return err
	})
	if err != nil {
		return Snapshot{}, err
	}
	return snap, nil
}

func scanSnapshot(tenant string, body []byte) (Snapshot, error) {
	var s Snapshot
	if err := json.Unmarshal(body, &s); err != nil {
		return Snapshot{}, fmt.Errorf("decode baseline: %w", err)
	}
	s.TenantID = tenant
	s.TakenAt = s.TakenAt.UTC()
	return s, nil
}

func (p *pgStore) one(ctx context.Context, tenant, q string, args ...any) (Snapshot, error) {
	t := NormTenant(tenant)
	var out Snapshot
	err := p.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		var body []byte
		if err := tx.QueryRow(ctx, q, args...).Scan(&body); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		s, err := scanSnapshot(t, body)
		if err != nil {
			return err
		}
		out = s
		return nil
	})
	if err != nil {
		return Snapshot{}, err
	}
	return out, nil
}

func (p *pgStore) Get(ctx context.Context, tenant, deviceID, id string) (Snapshot, error) {
	if _, err := parseUUID(id); err != nil {
		return Snapshot{}, ErrNotFound // a malformed id is the same not-found as a foreign one
	}
	return p.one(ctx, tenant, `SELECT body FROM device_baselines
	    WHERE tenant_id = $1 AND device_id = $2 AND id = $3`, NormTenant(tenant), deviceID, id)
}

func (p *pgStore) Latest(ctx context.Context, tenant, deviceID string) (Snapshot, error) {
	return p.one(ctx, tenant, `SELECT body FROM device_baselines
	    WHERE tenant_id = $1 AND device_id = $2 ORDER BY taken_at DESC, id DESC LIMIT 1`, NormTenant(tenant), deviceID)
}

func (p *pgStore) List(ctx context.Context, tenant, deviceID string) ([]Summary, error) {
	t := NormTenant(tenant)
	out := []Summary{}
	err := p.db.WithTenant(ctx, t, false, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT body FROM device_baselines
		    WHERE tenant_id = $1 AND device_id = $2 ORDER BY taken_at DESC, id DESC LIMIT $3`, t, deviceID, MaxPerDevice)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var body []byte
			if err := rows.Scan(&body); err != nil {
				return err
			}
			s, err := scanSnapshot(t, body)
			if err != nil {
				return err
			}
			out = append(out, s.Summarize())
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// parseUUID accepts the canonical 8-4-4-4-12 hex form only.
func parseUUID(s string) (string, error) {
	if len(s) != 36 {
		return "", errors.New("not a uuid")
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return "", errors.New("not a uuid")
			}
		default:
			if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
				return "", errors.New("not a uuid")
			}
		}
	}
	return strings.ToLower(s), nil
}

var _ Store = (*FileStore)(nil)
var _ Store = (*pgStore)(nil)
