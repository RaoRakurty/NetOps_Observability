// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package pcap

import (
	"context"
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

// retentionSplit applies the per-device retention rule to a NEWEST-FIRST
// listing and returns the rows to keep and the rows to drop.
//
// There are TWO budgets, and that is the point:
//
//   - `keep` protects STORED captures. Each one owns a sealed blob, and
//     dropping the row is what deletes the blob.
//   - maxFailedCaptures protects the attempt timeline. A failed capture holds
//     no packets and owns no blob, and a device that has stopped answering
//     mints one per attempt.
//
// They used to share one budget over a newest-first ordering, so a run of failed
// attempts filled it and the next successful capture pruned away every real
// capture and every sealed blob with it. An outage must not be able to destroy
// the captures it merely failed to add to.
//
// A RUNNING capture is never dropped: its device is still working. It occupies a
// stored-capture slot, as it always has.
func retentionSplit(ordered []Capture, keep int) (kept, doomed []Capture) {
	kept = make([]Capture, 0, len(ordered))
	stored, failed := 0, 0
	for _, c := range ordered {
		switch {
		case c.Active():
			kept = append(kept, c)
			stored++
		case c.Status == StatusFailed:
			if failed < maxFailedCaptures {
				kept = append(kept, c)
				failed++
				continue
			}
			doomed = append(doomed, c)
		case stored < keep:
			kept = append(kept, c)
			stored++
		default:
			doomed = append(doomed, c)
		}
	}
	return kept, doomed
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

// ErrRegisterUnreadable is returned by every write while the register file
// exists but could not be read or parsed at start-up. It is a REFUSAL, not a
// failure of the write itself: the file's real contents were never established,
// so a flush would not update it, it would REPLACE it with whatever this process
// happens to hold — which after such a load is nothing at all.
//
// Why REFUSE here rather than let the operator overwrite: this register is the
// only index over the SEALED CAPTURE BLOBS on disk. A row it does not hold is a
// packet capture nothing can find, download or prune, and nothing rebuilds it —
// the traffic it recorded is not on the wire any more. The repair is an operator
// act — fix the file's permissions, or remove it deliberately — and the api
// picks it up on the next start.
var ErrRegisterUnreadable = errors.New("pcap: the capture register could not be read at start-up, so writes are refused until it is repaired or removed")

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory.
type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[deviceKey][]Capture
	// loadErr is set when the register file EXISTS but its contents could not
	// be established — an I/O or permission failure, or JSON we could not
	// parse. It is NOT set for an absent file, which is simply a register
	// nobody has written yet.
	loadErr error
}

// NewFileStore loads the persisted register. A MISSING file starts empty; a file
// that exists but could not be read or parsed starts empty, is LOGGED, and
// refuses every write from then on, so the file it could not read is never
// replaced by an empty one.
func NewFileStore(path string) *FileStore {
	s := &FileStore{path: path, rows: map[deviceKey][]Capture{}}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: nothing has been captured yet. That is the normal
		// first-boot state and an empty register is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folding the two together started the
		// register empty with nothing logged, and the first capture then
		// renamed a temp file over a file whose contents were never read.
		s.loadErr = fmt.Errorf("pcap: the capture register could not be read: %w", err)
		applog.Error("pcap", "stored capture register could not be read; it starts EMPTY and every write is refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		// Present but empty: nothing stored yet, nothing broken.
		return s
	}
	var list []Capture
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = fmt.Errorf("pcap: the capture register could not be parsed: %w", uerr)
		applog.Error("pcap", "stored capture register could not be parsed; it starts EMPTY and every write is refused until the file is repaired or removed",
			map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, c := range list {
		s.insertLocked(c)
	}
	return s
}

// LoadErr reports why the register could not be read, or nil. A reader uses it
// to say "unknown" instead of reporting the empty register as a device nobody
// ever captured on.
func (s *FileStore) LoadErr() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
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
func (s *FileStore) flushLocked() error { return s.flushViewLocked(nil) }

// flushViewLocked persists the register as it WOULD BE with `replace` applied,
// WITHOUT touching s.rows. It exists for Prune: the in-memory register must not
// change until the write that makes the change durable has succeeded, because a
// prune applied in memory and then failing to flush loses the rows silently and
// the next successful write persists that loss.
//
// Note that this is not a rollback. Nothing is mutated and then put back, so
// there is no aliased backing array to restore wrongly.
// refuseIfUnreadable is the guard every mutating method opens with, BEFORE it
// touches s.rows: a refused write must change nothing at all, in memory or on
// disk. The file's real contents are unknown, so a flush would not update it —
// it would REPLACE it with what this process holds, which after an unreadable
// load is nothing. Call it with the write lock held.
func (s *FileStore) refuseIfUnreadable() error {
	if s.loadErr == nil {
		return nil
	}
	return fmt.Errorf("%w: %w", ErrRegisterUnreadable, s.loadErr)
}

func (s *FileStore) flushViewLocked(replace map[deviceKey][]Capture) error {
	// Repeated here because this is the choke point that protects the FILE: a
	// future write path that forgets the guard above still cannot overwrite a
	// register nobody read.
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	if s.path == "" {
		return nil
	}
	list := []Capture{}
	for k, rows := range s.rows {
		if kept, ok := replace[k]; ok {
			list = append(list, kept...)
			continue
		}
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
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	s.insertLocked(c)
	return s.flushLocked()
}

// Delete implements Store.
func (s *FileStore) Delete(_ context.Context, tenant string, cross bool, deviceID, captureID string) (Capture, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return Capture{}, err
	}
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
	if err := s.refuseIfUnreadable(); err != nil {
		return nil, err
	}
	removed := []Capture{}
	survivors := map[deviceKey][]Capture{}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		ordered := append([]Capture(nil), rows...)
		newestFirst(ordered)
		kept, doomed := retentionSplit(ordered, keep)
		removed = append(removed, doomed...)
		survivors[k] = kept
	}
	if len(removed) == 0 {
		return removed, nil
	}
	// Persist FIRST, adopt SECOND. The other order lost the pruned rows from
	// memory whenever the flush failed: the caller correctly kept the blobs,
	// because Prune returned an error and deleted nothing, but the register no
	// longer listed the captures those blobs belong to, and the next successful
	// write wrote that loss to disk (§10).
	if err := s.flushViewLocked(survivors); err != nil {
		return nil, err
	}
	for k, kept := range survivors {
		s.rows[k] = kept
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
	// List already returns the device NEWEST FIRST, which is the order the
	// retention rule is written against. Both backends share it so the two can
	// never disagree about what retention means.
	_, doomed := retentionSplit(rows, keep)
	removed := []Capture{}
	for _, c := range doomed {
		if _, derr := p.Delete(ctx, tenant, cross, c.DeviceID, c.ID); derr != nil {
			return nil, derr
		}
		removed = append(removed, c)
	}
	return removed, nil
}
