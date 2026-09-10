// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package configstore

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

// store.go — the version METADATA register. Two backends behind ONE interface
// (the rcafeedback/maintenance convention): FileStore for the default build and
// tests, pgStore for STORE_BACKEND=postgres (migration 0038, tenant_iso
// FORCE-RLS through the injected WithTenant seam).
//
// §3a rule 4: isolation is enforced IN the store. Postgres by the RLS policy;
// the file backend by a tenant-keyed map that every read walks through
// visible(). There is no unscoped "list all" on this interface — the closest
// thing, ScheduleTargets, takes a tenant and returns only that tenant's rows.
//
// What is NOT here: the configuration text. Rows carry device/tenant/sha/time/
// size/blob-ref/status — never a byte of config (§8).

// Store is the version register.
type Store interface {
	// List returns one device's versions, NEWEST FIRST. Cross-tenant callers
	// see every tenant's rows for that device id; scoped callers see only their
	// own (and therefore an empty list for a foreign device).
	List(ctx context.Context, tenant string, cross bool, deviceID string) ([]Version, error)
	// Get returns one version. A foreign or absent (device, sha) is ErrNotFound
	// — the two are deliberately indistinguishable (§3a rule 1).
	Get(ctx context.Context, tenant string, cross bool, deviceID, sha string) (Version, error)
	// Latest returns the newest SUCCESSFUL version for a device.
	Latest(ctx context.Context, tenant string, cross bool, deviceID string) (Version, bool, error)
	// Golden returns the device's golden baseline, if one is marked.
	Golden(ctx context.Context, tenant string, cross bool, deviceID string) (Version, bool, error)
	// Put inserts or refreshes a version row. v.TenantID must already carry the
	// owner derived from the DEVICE record (§3a rule 2).
	Put(ctx context.Context, tenant string, cross bool, v Version) error
	// SetGolden marks one version golden and clears the previous mark. A foreign
	// or absent (device, sha) is ErrNotFound.
	SetGolden(ctx context.Context, tenant string, cross bool, deviceID, sha string) error
	// RecordDrift stamps the drift verdict a capture produced onto its version
	// row (written by internal/configdrift through the manager).
	RecordDrift(ctx context.Context, tenant string, cross bool, deviceID, sha, drift string, added, removed int) error
	// Prune enforces per-device retention, returning the rows it removed so the
	// caller can delete their blobs. The golden version is NEVER pruned.
	Prune(ctx context.Context, tenant string, cross bool, deviceID string, keep int) ([]Version, error)
}

// clampKeep bounds the retention knob (§9 all queues bounded — a "keep 0"
// would delete the artifact the module exists to produce).
func clampKeep(keep int) int {
	switch {
	case keep < minKeepVersions:
		return minKeepVersions
	case keep > maxKeepVersions:
		return maxKeepVersions
	default:
		return keep
	}
}

// retentionSplit applies the per-device retention rule to a NEWEST-FIRST
// listing and returns the rows to keep and the rows to drop.
//
// There are TWO budgets, and that is the point:
//
//   - `keep` protects CAPTURED versions. Each one owns a sealed blob, and
//     dropping the row is what deletes the blob.
//   - maxFailedVersions protects the outage timeline. A failed capture holds no
//     configuration and owns no blob, and a long outage mints one every sweep.
//
// They used to share one budget over a newest-first ordering, so a month of
// failed sweeps filled it and the next successful capture pruned away every real
// version and every sealed blob with it. An outage must not be able to destroy
// the history it merely failed to add to.
//
// The golden baseline is never dropped: it is the reference every drift verdict
// is made against. It still occupies a captured-version slot, as it always has.
func retentionSplit(ordered []Version, keep int) (kept, doomed []Version) {
	kept = make([]Version, 0, len(ordered))
	captured, failed := 0, 0
	for _, v := range ordered {
		switch {
		case v.Golden:
			kept = append(kept, v)
			captured++
		case v.Status != StatusOK:
			if failed < maxFailedVersions {
				kept = append(kept, v)
				failed++
				continue
			}
			doomed = append(doomed, v)
		case captured < keep:
			kept = append(kept, v)
			captured++
		default:
			doomed = append(doomed, v)
		}
	}
	return kept, doomed
}

// newestFirst orders a device listing: captured_at desc, sha asc as the
// deterministic tiebreak for two captures in the same instant.
func newestFirst(rows []Version) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].CapturedAt.Equal(rows[j].CapturedAt) {
			return rows[i].CapturedAt.After(rows[j].CapturedAt)
		}
		return rows[i].SHA < rows[j].SHA
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
// only index over the SEALED CONFIG BLOBS on disk. A row it does not hold is a
// device configuration version nothing can find or diff any more, and no later
// capture rebuilds the history it lost. The repair is an operator act — fix the
// file's permissions, or remove it deliberately — and the api picks it up on the
// next start.
var ErrRegisterUnreadable = errors.New("configstore: the version register could not be read at start-up, so writes are refused until it is repaired or removed")

// FileStore is the non-Postgres backend. Path "" keeps it purely in memory.
type FileStore struct {
	mu   sync.RWMutex
	path string
	rows map[deviceKey][]Version
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
	s := &FileStore{path: path, rows: map[deviceKey][]Version{}}
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
		s.loadErr = fmt.Errorf("configstore: the version register could not be read: %w", err)
		applog.Error("configstore", "stored config version register could not be read; it starts EMPTY and every write is refused until the file is repaired or removed",
			map[string]any{"err": err.Error(), "path": path})
		return s
	case len(b) == 0:
		// Present but empty: nothing stored yet, nothing broken.
		return s
	}
	var list []Version
	if uerr := json.Unmarshal(b, &list); uerr != nil {
		s.loadErr = fmt.Errorf("configstore: the version register could not be parsed: %w", uerr)
		applog.Error("configstore", "stored config version register could not be parsed; it starts EMPTY and every write is refused until the file is repaired or removed",
			map[string]any{"err": uerr.Error(), "path": path})
		return s
	}
	for _, v := range list {
		s.insertLocked(v)
	}
	return s
}

// LoadErr reports why the register could not be read, or nil. A reader uses it
// to say "unknown" instead of reporting the empty register as a device nobody
// ever captured.
func (s *FileStore) LoadErr() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

func (s *FileStore) insertLocked(v Version) {
	v.TenantID = NormTenant(v.TenantID)
	k := deviceKey{v.TenantID, v.DeviceID}
	for i, existing := range s.rows[k] {
		if existing.SHA == v.SHA {
			s.rows[k][i] = v
			return
		}
	}
	s.rows[k] = append(s.rows[k], v)
}

// flushLocked persists the whole register. A failure is RETURNED, never
// swallowed: a version row the file does not hold would leave a sealed blob
// nothing references (§10).
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

func (s *FileStore) flushViewLocked(replace map[deviceKey][]Version) error {
	// Repeated here because this is the choke point that protects the FILE: a
	// future write path that forgets the guard above still cannot overwrite a
	// register nobody read.
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	if s.path == "" {
		return nil
	}
	list := []Version{}
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
		return list[i].SHA < list[j].SHA
	})
	b, err := json.Marshal(list)
	if err != nil {
		return fmt.Errorf("encode config versions: %w", err)
	}
	return platformdb.Save(s.path, b)
}

// visibleRows collects every row for a device the caller may see.
func (s *FileStore) visibleRows(tenant string, cross bool, deviceID string) []Version {
	out := []Version{}
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
func (s *FileStore) List(_ context.Context, tenant string, cross bool, deviceID string) ([]Version, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.visibleRows(tenant, cross, deviceID), nil
}

// Get implements Store.
func (s *FileStore) Get(_ context.Context, tenant string, cross bool, deviceID, sha string) (Version, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.visibleRows(tenant, cross, deviceID) {
		if v.SHA == sha {
			return v, nil
		}
	}
	return Version{}, ErrNotFound
}

// Latest implements Store.
func (s *FileStore) Latest(_ context.Context, tenant string, cross bool, deviceID string) (Version, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.visibleRows(tenant, cross, deviceID) {
		if v.Status == StatusOK {
			return v, true, nil
		}
	}
	return Version{}, false, nil
}

// Golden implements Store.
func (s *FileStore) Golden(_ context.Context, tenant string, cross bool, deviceID string) (Version, bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, v := range s.visibleRows(tenant, cross, deviceID) {
		if v.Golden {
			return v, true, nil
		}
	}
	return Version{}, false, nil
}

// Put implements Store.
func (s *FileStore) Put(_ context.Context, _ string, _ bool, v Version) error {
	if v.DeviceID == "" || (v.Status == StatusOK && !validSHA(v.SHA)) {
		return errors.New("configstore: version needs a device id and a valid sha")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	s.insertLocked(v)
	return s.flushLocked()
}

// SetGolden implements Store.
//
// FIND FIRST, MUTATE SECOND. The scan used to clear each row's mark as it went
// and only discover afterwards that the requested version was not there, so
// every 404 — a mistyped sha, one retention had already pruned, or the synthetic
// sha of a FAILED capture row, which is well-formed and passes validation but is
// never eligible — left the device with NO golden at all. The golden mark is
// OPERATOR INTENT: nothing recomputes it, and the only way back is a human
// finding the right version again. A refusal must therefore change nothing.
// The Postgres backend never had the hole, because its refusal rolls the
// transaction back.
func (s *FileStore) SetGolden(_ context.Context, tenant string, cross bool, deviceID, sha string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	if !s.goldenTargetExistsLocked(tenant, cross, deviceID, sha) {
		return ErrNotFound
	}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		for i := range rows {
			rows[i].Golden = rows[i].SHA == sha && rows[i].Status == StatusOK
		}
	}
	return s.flushLocked()
}

// goldenTargetExistsLocked reports whether the caller may mark (device, sha)
// golden: the row has to be visible to this scope AND be a SUCCESSFUL capture.
// Call it with the lock held.
func (s *FileStore) goldenTargetExistsLocked(tenant string, cross bool, deviceID, sha string) bool {
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		for i := range rows {
			if rows[i].SHA == sha && rows[i].Status == StatusOK {
				return true
			}
		}
	}
	return false
}

// RecordDrift implements Store.
func (s *FileStore) RecordDrift(_ context.Context, tenant string, cross bool, deviceID, sha, drift string, added, removed int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return err
	}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		for i := range rows {
			if rows[i].SHA != sha {
				continue
			}
			rows[i].Drift, rows[i].Added, rows[i].Removed = drift, added, removed
			return s.flushLocked()
		}
	}
	return ErrNotFound
}

// Prune implements Store.
func (s *FileStore) Prune(_ context.Context, tenant string, cross bool, deviceID string, keep int) ([]Version, error) {
	keep = clampKeep(keep)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.refuseIfUnreadable(); err != nil {
		return nil, err
	}
	removed := []Version{}
	survivors := map[deviceKey][]Version{}
	for k, rows := range s.rows {
		if k.device != deviceID || !visible(tenant, cross, k.tenant) {
			continue
		}
		ordered := append([]Version(nil), rows...)
		newestFirst(ordered)
		kept, doomed := retentionSplit(ordered, keep)
		removed = append(removed, doomed...)
		survivors[k] = kept
	}
	if len(removed) == 0 {
		return nil, nil
	}
	// Persist FIRST, adopt SECOND. The other order lost the pruned rows from
	// memory whenever the flush failed: the caller correctly kept the blobs,
	// because Prune returned an error and deleted nothing, but the register no
	// longer listed the versions those blobs belong to, and the next successful
	// write wrote that loss to disk (§10).
	if err := s.flushViewLocked(survivors); err != nil {
		return nil, err
	}
	for k, kept := range survivors {
		s.rows[k] = kept
	}
	return removed, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via WithTenant, migration 0038) ───

// DB is the injected relational seam (the rcafeedback/maintenance idiom): run fn
// in a transaction whose row-level security is bound to the caller's scope.
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type pgStore struct{ db DB }

// NewPGStore builds the Postgres-backed version register.
func NewPGStore(db DB) Store { return &pgStore{db: db} }

const pgVersionCols = `tenant_id, device_id, version_sha, captured_at, size_bytes,
	blob_ref, vendor, status, error_text, golden, drift_state, lines_added, lines_removed`

func scanVersion(rows pgx.Rows) (Version, error) {
	var v Version
	if err := rows.Scan(&v.TenantID, &v.DeviceID, &v.SHA, &v.CapturedAt, &v.SizeBytes,
		&v.BlobRef, &v.Vendor, &v.Status, &v.Error, &v.Golden, &v.Drift, &v.Added, &v.Removed); err != nil {
		return Version{}, err
	}
	v.CapturedAt = v.CapturedAt.UTC()
	return v, nil
}

func (p *pgStore) query(ctx context.Context, tenant string, cross bool, sql string, args ...any) ([]Version, error) {
	out := []Version{}
	err := p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, sql, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			v, err := scanVersion(rows)
			if err != nil {
				return err
			}
			out = append(out, v)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (p *pgStore) List(ctx context.Context, tenant string, cross bool, deviceID string) ([]Version, error) {
	return p.query(ctx, tenant, cross, `SELECT `+pgVersionCols+`
	    FROM config_backup_versions WHERE device_id = $1
	    ORDER BY captured_at DESC, version_sha ASC`, deviceID)
}

func (p *pgStore) Get(ctx context.Context, tenant string, cross bool, deviceID, sha string) (Version, error) {
	rows, err := p.query(ctx, tenant, cross, `SELECT `+pgVersionCols+`
	    FROM config_backup_versions WHERE device_id = $1 AND version_sha = $2`, deviceID, sha)
	if err != nil {
		return Version{}, err
	}
	if len(rows) == 0 {
		return Version{}, ErrNotFound
	}
	return rows[0], nil
}

func (p *pgStore) Latest(ctx context.Context, tenant string, cross bool, deviceID string) (Version, bool, error) {
	rows, err := p.query(ctx, tenant, cross, `SELECT `+pgVersionCols+`
	    FROM config_backup_versions WHERE device_id = $1 AND status = $2
	    ORDER BY captured_at DESC, version_sha ASC LIMIT 1`, deviceID, StatusOK)
	if err != nil || len(rows) == 0 {
		return Version{}, false, err
	}
	return rows[0], true, nil
}

func (p *pgStore) Golden(ctx context.Context, tenant string, cross bool, deviceID string) (Version, bool, error) {
	rows, err := p.query(ctx, tenant, cross, `SELECT `+pgVersionCols+`
	    FROM config_backup_versions WHERE device_id = $1 AND golden LIMIT 1`, deviceID)
	if err != nil || len(rows) == 0 {
		return Version{}, false, err
	}
	return rows[0], true, nil
}

func (p *pgStore) Put(ctx context.Context, tenant string, cross bool, v Version) error {
	if v.DeviceID == "" || (v.Status == StatusOK && !validSHA(v.SHA)) {
		return errors.New("configstore: version needs a device id and a valid sha")
	}
	v.TenantID = NormTenant(v.TenantID)
	if v.CapturedAt.IsZero() {
		v.CapturedAt = time.Now().UTC()
	}
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO config_backup_versions
		        (tenant_id, device_id, version_sha, captured_at, size_bytes, blob_ref,
		         vendor, status, error_text, drift_state, lines_added, lines_removed)
		    VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		    ON CONFLICT (tenant_id, device_id, version_sha) DO UPDATE SET
		        captured_at = EXCLUDED.captured_at,
		        size_bytes  = EXCLUDED.size_bytes,
		        blob_ref    = EXCLUDED.blob_ref,
		        vendor      = EXCLUDED.vendor,
		        status      = EXCLUDED.status,
		        error_text  = EXCLUDED.error_text`,
			v.TenantID, v.DeviceID, v.SHA, v.CapturedAt, v.SizeBytes, v.BlobRef,
			v.Vendor, v.Status, v.Error, v.Drift, v.Added, v.Removed)
		return err
	})
}

func (p *pgStore) SetGolden(ctx context.Context, tenant string, cross bool, deviceID, sha string) error {
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// Clear first, then set: the partial unique index allows exactly one
		// golden per (tenant, device), so the order is what keeps the statement
		// pair legal.
		if _, err := tx.Exec(ctx, `UPDATE config_backup_versions SET golden = FALSE
		    WHERE device_id = $1 AND golden`, deviceID); err != nil {
			return err
		}
		tag, err := tx.Exec(ctx, `UPDATE config_backup_versions SET golden = TRUE
		    WHERE device_id = $1 AND version_sha = $2 AND status = $3`, deviceID, sha, StatusOK)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (p *pgStore) RecordDrift(ctx context.Context, tenant string, cross bool, deviceID, sha, drift string, added, removed int) error {
	return p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE config_backup_versions
		    SET drift_state = $3, lines_added = $4, lines_removed = $5
		    WHERE device_id = $1 AND version_sha = $2`, deviceID, sha, drift, added, removed)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

func (p *pgStore) Prune(ctx context.Context, tenant string, cross bool, deviceID string, keep int) ([]Version, error) {
	keep = clampKeep(keep)
	all, err := p.List(ctx, tenant, cross, deviceID)
	if err != nil {
		return nil, err
	}
	// List already returns the device NEWEST FIRST, which is the order the
	// retention rule is written against. Both backends share it so the two can
	// never disagree about what retention means.
	_, doomed := retentionSplit(all, keep)
	if len(doomed) == 0 {
		return nil, nil
	}
	shas := make([]string, 0, len(doomed))
	for _, v := range doomed {
		shas = append(shas, v.SHA)
	}
	err = p.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `DELETE FROM config_backup_versions
		    WHERE device_id = $1 AND version_sha = ANY($2) AND NOT golden`, deviceID, shas)
		return err
	})
	if err != nil {
		return nil, err
	}
	return doomed, nil
}

var (
	_ Store = (*FileStore)(nil)
	_ Store = (*pgStore)(nil)
)
