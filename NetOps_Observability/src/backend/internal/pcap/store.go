// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"netops/backend/internal/platformdb"
)

// store.go — the capture METADATA register. Two backends behind ONE interface
// (the configstore/rcafeedback convention): FileStore for the default build and
// tests, pgStore for STORE_BACKEND=postgres (migration 0039, pcap_captures,
// tenant_iso FORCE-RLS through the injected WithTenant seam).
//
// §3a rule 4: isolation is enforced IN the store. Postgres by the RLS policy;
// the file backend by a tenant-keyed map that every read walks through
// visible(). There is no unscoped "list all" on this interface — the closest
// thing, ActiveFor, takes a tenant and a device.
//
// What is NOT here: a single packet. Rows carry tenant/device/interface/times/
// status/counters/blob-ref — never payload (§8).

// Store is the capture register.
type Store interface {
	// List returns one device's captures, NEWEST FIRST, bounded by limit.
	// Cross-tenant callers see every tenant's rows for that device id; scoped
	// callers see only their own (and therefore an empty list for a foreign
	// device).
	List(ctx context.Context, tenant string, cross bool, deviceID string, limit int) ([]Capture, error)
	// Get returns one capture. A foreign or absent (device, id) is ErrNotFound —
	// the two are deliberately indistinguishable (§3a rule 1).
	Get(ctx context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error)
	// Put inserts or refreshes a capture row. c.TenantID must already carry the
	// owner derived from the DEVICE record (§3a rule 2).
	Put(ctx context.Context, tenant string, cross bool, c Capture) error
	// Delete removes one capture row, returning it so the caller can delete the
	// blob. A foreign or absent id is ErrNotFound.
	Delete(ctx context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error)
	// ActiveFor returns the device's RUNNING capture, if any. This is the
	// one-at-a-time gate's durable half.
	ActiveFor(ctx context.Context, tenant string, cross bool, deviceID string) (Capture, bool, error)
	// Prune enforces per-device retention, returning the rows it removed so the
	// caller can delete their blobs. A RUNNING capture is never pruned.
	Prune(ctx context.Context, tenant string, cross bool, deviceID string, keep int) ([]Capture, error)
}

// clampLimit bounds a caller-supplied page size (§9).
func clampLimit(n int) int {
	switch {
	case n <= 0:
		return DefaultListLimit
	case n > MaxListLimit:
		return MaxListLimit
	default:
		return n
	}
}

// newestFirst orders a device listing: started_at desc, id asc as the
// deterministic tiebreak for two captures in the same instant.
func newestFirst(rows []Capture) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].StartedAt.Equal(rows[j].StartedAt) {
			return rows[i].StartedAt.After(rows[j].StartedAt)
		}
		return rows[i].ID < rows[j].ID
	})
}

// ── file backend (default build; tenant-filtered IN the store) ───────────────

type deviceKey struct{ tenant, device string }

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory.
type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[deviceKey][]Capture
}

// NewFileStore loads the persisted register; a missing or corrupt file starts
// empty (this state is an index over blobs that still exist, and a parse failure
// must not block boot).
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[deviceKey][]Capture{}}
	if path == "" {
		return s
	}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var list []Capture
		if json.Unmarshal(b, &list) == nil {
			for _, c := range list {
				s.insertLocked(c)
			}
		}
	}
	return s
}

func (s *FileStore) insertLocked(c Capture) {
	c.TenantID = NormTenant(c.TenantID)
	k := deviceKey{c.TenantID, c.DeviceID}
	for i, existing := range s.rows[k] {
		if existing.ID == c.ID {
			s.rows[k][i] = c
			return
		}
	}
	s.rows[k] = append(s.rows[k], c)
}

// flushLocked persists the whole register. A failure is RETURNED, never
// swallowed: a row the file does not hold would leave a sealed blob nothing
// references (§10).
func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	list := []Capture{}
	for _, rows := range s.rows {
		list = append(list, rows...)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].DeviceID != list[j].DeviceID {
			return list[i].DeviceID < list[j].DeviceID
		}
		return list[i].ID < list[j].ID
	})
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

// visibleRows collects every row for a device the caller may see.
func (s *FileStore) visibleRows(tenant string, cross bool, deviceID string) []Capture {
	out := []Capture{}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		out = append(out, rows...)
	}
	newestFirst(out)
	return out
}

// List implements Store.
func (s *FileStore) List(_ context.Context, tenant string, cross bool, deviceID string, limit int) ([]Capture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rows := s.visibleRows(tenant, cross, deviceID)
	if n := clampLimit(limit); len(rows) > n {
		rows = rows[:n]
	}
	return rows, nil
}

// Get implements Store.
func (s *FileStore) Get(_ context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.visibleRows(tenant, cross, deviceID) {
		if c.ID == captureID {
			return c, nil
		}
	}
	return Capture{}, ErrNotFound
}

// ActiveFor implements Store.
func (s *FileStore) ActiveFor(_ context.Context, tenant string, cross bool, deviceID string) (Capture, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, c := range s.visibleRows(tenant, cross, deviceID) {
		if c.Active() {
			return c, true, nil
		}
	}
	return Capture{}, false, nil
}

// Put implements Store.
func (s *FileStore) Put(_ context.Context, tenant string, cross bool, c Capture) error {
	if c.DeviceID == "" || !ValidateCaptureID(c.ID) {
		return errors.New("pcap: a capture row needs a device id and a minted capture id")
	}
	if !visible(tenant, cross, c.TenantID) {
		// A write outside the caller's scope is refused HERE too, not only at
		// the handler: the store is the independent second line (§3a rule 4).
		return ErrNotFound
	}
	if c.StartedAt.IsZero() {
		c.StartedAt = time.Now().UTC()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.insertLocked(c)
	return s.flushLocked()
}

// Delete implements Store.
func (s *FileStore) Delete(_ context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		for i, c := range rows {
			if c.ID != captureID {
				continue
			}
			s.rows[k] = append(rows[:i:i], rows[i+1:]...)
			if len(s.rows[k]) == 0 {
				delete(s.rows, k)
			}
			if err := s.flushLocked(); err != nil {
				return Capture{}, err
			}
			return c, nil
		}
	}
	return Capture{}, ErrNotFound
}

// Prune implements Store.
func (s *FileStore) Prune(_ context.Context, tenant string, cross bool, deviceID string, keep int) ([]Capture, error) {
	keep = ClampKeep(keep)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := []Capture{}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		newestFirst(rows)
		kept := make([]Capture, 0, len(rows))
		for _, c := range rows {
			// A running capture is never pruned: its device is still working.
			if c.Active() || len(kept) < keep {
				kept = append(kept, c)
				continue
			}
			removed = append(removed, c)
		}
		s.rows[k] = kept
	}
	if len(removed) == 0 {
		return removed, nil
	}
	if err := s.flushLocked(); err != nil {
		return nil, err
	}
	return removed, nil
}

// ── Postgres backend (STORE_BACKEND=postgres) ───────────────────────────────

// DB is the tenant-scoped transaction seam (platformdb's shape), injected so
// this package never opens a connection of its own.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed capture register.
func NewPGStore(db DB) Store { return &pgStore{db: db} }

const pgCaptureCols = `tenant_id, device_id, capture_id, iface, filter_expr,
	duration_s, max_packets, started_at, expires_at, ended_at, status,
	packets, bytes, error_text, blob_ref, actor, remote_path, platform`

func scanCapture(rows pgx.Rows) (Capture, error) {
	var c Capture
	var ended *time.Time
	if err := rows.Scan(&c.TenantID, &c.DeviceID, &c.ID, &c.Interface, &c.Filter,
		&c.DurationSec, &c.MaxPackets, &c.StartedAt, &c.ExpiresAt, &ended, &c.Status,
		&c.Packets, &c.Bytes, &c.Error, &c.BlobRef, &c.Actor, &c.RemotePath, &c.Platform); err != nil {
		return Capture{}, err
	}
	c.StartedAt = c.StartedAt.UTC()
	c.ExpiresAt = c.ExpiresAt.UTC()
	if ended != nil {
		at := ended.UTC()
		c.EndedAt = &at
	}
	return c, nil
}

func (p *pgStore) query(ctx context.Context, tenant string, cross bool, sql string, args ...any) ([]Capture, error) {
	out := []Capture{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			c, err := scanCapture(rows)
			if err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool, deviceID string, limit int) ([]Capture, error) {
	return p.query(ctx, tenant, cross, `SELECT `+pgCaptureCols+`
	    FROM pcap_captures WHERE device_id = $1
	    ORDER BY started_at DESC, capture_id ASC LIMIT $2`, deviceID, clampLimit(limit))
}

func (p *pgStore) Get(ctx context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error) {
	rows, err := p.query(ctx, tenant, cross, `SELECT `+pgCaptureCols+`
	    FROM pcap_captures WHERE device_id = $1 AND capture_id = $2`, deviceID, captureID)
	if err != nil {
		return Capture{}, err
	}
	if len(rows) == 0 {
		return Capture{}, ErrNotFound
	}
	return rows[0], nil
}

func (p *pgStore) ActiveFor(ctx context.Context, tenant string, cross bool, deviceID string) (Capture, bool, error) {
	rows, err := p.query(ctx, tenant, cross, `SELECT `+pgCaptureCols+`
	    FROM pcap_captures WHERE device_id = $1 AND status = $2
	    ORDER BY started_at DESC LIMIT 1`, deviceID, StatusRunning)
	if err != nil || len(rows) == 0 {
		return Capture{}, false, err
	}
	return rows[0], true, nil
}

func (p *pgStore) Put(ctx context.Context, tenant string, cross bool, c Capture) error {
	if c.DeviceID == "" || !ValidateCaptureID(c.ID) {
		return errors.New("pcap: a capture row needs a device id and a minted capture id")
	}
	c.TenantID = NormTenant(c.TenantID)
	if c.StartedAt.IsZero() {
		c.StartedAt = time.Now().UTC()
	}
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO pcap_captures
		        (tenant_id, device_id, capture_id, iface, filter_expr, duration_s,
		         max_packets, started_at, expires_at, ended_at, status, packets,
		         bytes, error_text, blob_ref, actor, remote_path, platform)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		    ON CONFLICT (tenant_id, device_id, capture_id) DO UPDATE SET
		        ended_at    = EXCLUDED.ended_at,
		        status      = EXCLUDED.status,
		        packets     = EXCLUDED.packets,
		        bytes       = EXCLUDED.bytes,
		        error_text  = EXCLUDED.error_text,
		        blob_ref    = EXCLUDED.blob_ref,
		        remote_path = EXCLUDED.remote_path`,
			c.TenantID, c.DeviceID, c.ID, c.Interface, c.Filter, c.DurationSec,
			c.MaxPackets, c.StartedAt, c.ExpiresAt, c.EndedAt, c.Status, c.Packets,
			c.Bytes, c.Error, c.BlobRef, c.Actor, c.RemotePath, c.Platform)
		return err
	})
}

func (p *pgStore) Delete(ctx context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error) {
	existing, err := p.Get(ctx, tenant, cross, deviceID, captureID)
	if err != nil {
		return Capture{}, err
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, derr := tx.Exec(ctx, `DELETE FROM pcap_captures WHERE device_id = $1 AND capture_id = $2`,
			deviceID, captureID)
		return derr
	})
	if err != nil {
		return Capture{}, err
	}
	return existing, nil
}

func (p *pgStore) Prune(ctx context.Context, tenant string, cross bool, deviceID string, keep int) ([]Capture, error) {
	keep = ClampKeep(keep)
	rows, err := p.List(ctx, tenant, cross, deviceID, MaxListLimit)
	if err != nil {
		return nil, err
	}
	removed := []Capture{}
	kept := 0
	for _, c := range rows {
		if c.Active() || kept < keep {
			kept++
			continue
		}
		if _, derr := p.Delete(ctx, tenant, cross, c.DeviceID, c.ID); derr != nil {
			return nil, derr
		}
		removed = append(removed, c)
	}
	return removed, nil
}
