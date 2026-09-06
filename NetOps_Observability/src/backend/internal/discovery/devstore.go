// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package discovery

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"netops/backend/models"
)

// device_persist.go — durable storage for OPERATOR-DEFINED devices.
//
// THE DEFECT. The discovery aggregator's inventory lived only in
// `discovery.DiscoveryAggregator.cache`, a plain in-memory map with no persistence
// anywhere. Devices that a SOURCE reports (SNMP scan, NetBox, static YAML) are
// rebuilt on the next poll, so they survive by accident. Devices created
// through `POST /api/devices` have no source to rebuild them: the API returned
// 201 Created and the device evaporated on the next restart, container
// recreate, crash, deploy, or documented UPGRADE.md upgrade. That is a 2xx for
// a write that was never persisted — the same class as F-62/F-63/F-78, in a
// subsystem the audit never reached.
//
// It also made per-tenant device ownership undurable in general: the static
// YAML source (the only "durable" path) has no tenant field at all, so every
// statically-defined device lands in global/Provider. There was NO way to own a
// device in a tenant across a restart.
//
// WHAT PERSISTS, AND WHAT DELIBERATELY DOES NOT. Only manual devices. A
// source-reported device is NOT persisted: the source is its authority, and
// writing a copy here would resurrect devices that the source has legitimately
// dropped — pollOnce prunes exactly those, and a persisted shadow would fight
// it every poll.
//
// TOMBSTONES (audit F-69). `DELETE /api/devices/{id}` returned 204 and the
// device reappeared within 60s, because Delete only removed the cache entry and
// the owning source re-added it on the next poll. Deleting a source-owned
// device therefore records a SUPPRESSION, which pollOnce honours — so a delete
// means what it says. Suppressions are the reason this store is consulted even
// when no manual device exists.
//
// PER-RECORD PERSISTENCE (GA scale P0). The original layout marshalled the
// ENTIRE fleet as one JSON blob on EVERY Put/Remove — O(N) bytes per write,
// O(N²) for bulk onboarding (measured: 155 devices/s at small N collapsing to
// 14/s by 3.3k devices; GA needs 10k+ linear). When the backend implements the
// prefix capability (platformdb.PrefixBackend — both production backends do),
// each device and each tombstone is its own record:
//
//	<path>.d/manual/<sha256hex(id)>      — the models.Device JSON
//	<path>.d/suppressed/<sha256hex(id)>  — {"id":…, "deleted_at":…, "tenant":…, "last_hit":…}
//	<path>.d/migrated                    — legacy-blob migration marker
//
// The record NAME is the SHA-256 hex of the device id, because ids are
// operator/scan-derived and may contain characters unsafe as a filename or
// awkward as a row key ("/", "..", "%", unicode); the hex name is fixed-width,
// collision-free and safe in both key spaces. The id itself lives INSIDE the
// record, which is authoritative at load (a record whose name does not match
// its content is refused as corruption — two records can then never claim the
// same id).
//
// Hot path after the fix: Put = 1 record Save (+1 tombstone Delete when
// clearing a suppression); Remove = 1 tombstone Save (+1 record Delete). No
// full-fleet write exists anywhere except the one-time migration.
//
// CRASH ATOMICITY (tombstone-wins). A Put persists the record BEFORE deleting
// the tombstone; a Remove persists the tombstone BEFORE deleting the record.
// Either crash window therefore leaves BOTH records on disk, and load resolves
// that as "the tombstone wins": a deleted device must never resurrect, and a
// Put that never returned success is treated as never-happened. The shadowed
// stale record is swept (best-effort) at the next load.
//
// A backend WITHOUT the prefix capability (e.g. a plain test fake) keeps the
// original whole-blob behaviour unchanged.
//
// TOMBSTONE RETENTION (tracker 175). Nothing removed a suppression record, so
// the set grew without bound — 35,427 records / 142 MB for zero real devices in
// a lab that had run the scale ladder. devstore_compact.go bounds it, and its
// header is where the resurrection semantics that make ANY bound delicate are
// worked out. Read it before touching tombstoneRecord, Remove or IsSuppressed.

// KV abstracts where the store persists (the platform kv layer).
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// PrefixKV mirrors platformdb.PrefixBackend at this seam: the optional
// per-record capability. NewDevStore type-asserts for it at construction and
// falls back to whole-blob persistence when absent.
type PrefixKV interface {
	KV
	LoadPrefix(prefix string) (map[string][]byte, error)
	Delete(key string) error
}

type DevStore struct {
	kv KV
	// pkv is non-nil when the backend supports per-record persistence; nil
	// keeps the legacy whole-blob path (test fakes, future blob-only backends).
	pkv        PrefixKV
	errf       func(component, msg string, fields map[string]any)
	mu         sync.RWMutex
	path       string
	manual     map[string]models.Device
	suppressed map[string]*tombstone
	// lim is the injected tombstone-retention policy; bootAt/evictQ/evictScanAt
	// and the evicted* counters are its incremental-compaction state
	// (devstore_compact.go). All are guarded by mu.
	lim            TombstoneLimits
	bootAt         time.Time
	evictQ         []string
	evictScanAt    time.Time
	evictedExpired int
	evictedCap     int
	// loadErr is set when the stored state could NOT be read at boot. An empty
	// store then means "we do not know what was stored", NOT "no manual devices
	// and no tombstones" — the two used to share a branch, so a boot read failure
	// resurrected deliberately-deleted devices and the first write flushed the
	// empty maps over the survivors (§10).
	loadErr error
	// Durable-hit flush machinery (ultra 9 — see the "DURABLE HIT FLUSH"
	// section of devstore_compact.go). Per-record mode only: flushKick == nil
	// in whole-blob mode, whose record format carries no last_hit to persist.
	// hitFlushEvery/hitFlushDue are the injected-clock cadence a hit uses to
	// kick the background flusher; stopFlush/flushDone bracket its lifetime;
	// hitsFlushed (guarded by mu) is the §10 counter.
	hitFlushEvery time.Duration
	hitFlushDue   atomic.Int64
	flushKick     chan struct{}
	flushSync     chan chan struct{}
	stopFlush     chan struct{}
	flushDone     chan struct{}
	closeOnce     sync.Once
	hitsFlushed   int
}

// devPersistFile is the legacy whole-blob shape (still written in fallback
// mode, still read once for migration). Split into two maps so a suppression
// survives independently of whether a manual record exists for the same id.
type devPersistFile struct {
	Manual     map[string]models.Device `json:"manual"`
	Suppressed map[string]time.Time     `json:"suppressed,omitempty"`
}

// tombstoneRecord is the per-record shape of one suppression. The id is
// inside the record (the record name is its hash — see the header).
//
// Tenant and LastHit were added for the retention bound (tracker 175,
// devstore_compact.go). Both are omitempty and both decode as their zero value
// from a pre-175 record: an untenanted tombstone lands in the platform-scoped
// ("") partition, which is exactly what deviceTenantKey means by "", and a
// never-hit tombstone is retained on its deleted_at until a source hits it.
type tombstoneRecord struct {
	ID        string    `json:"id"`
	DeletedAt time.Time `json:"deleted_at"`
	// Tenant is the owning tenant, stamped from the record the caller already
	// owns (never from a request body) — §3a rule 2. It scopes cap-tier
	// eviction so one tenant's churn cannot evict another's suppressions.
	Tenant string `json:"tenant,omitempty"`
	// LastHit is the last time this tombstone actually suppressed a
	// source-reported device. Durable but rate-limited; see the compaction
	// header for why retention is measured from it and not from DeletedAt.
	LastHit time.Time `json:"last_hit,omitempty"`
}

// tombstone is one suppression in memory.
//
// lastHit is an atomic unix-nano so IsSuppressed can record a hit while holding
// only the READ lock — the poll path calls it three times per reported device
// and must not serialize on the store's write lock. Every other field is
// immutable after construction except hitSaved, which only compaction and the
// background hit flusher touch under the write lock. A re-Remove of the same id
// installs a NEW *tombstone rather than mutating this one, so no field is ever
// written concurrently.
type tombstone struct {
	tenant    string
	deletedAt time.Time
	lastHit   atomic.Int64
	// hitSaved is the lastHit value already durable in the record; the gap
	// between them is what rate-limits the persist.
	hitSaved int64
}

func newTombstone(tenant string, deletedAt, lastHit time.Time) *tombstone {
	t := &tombstone{tenant: tenant, deletedAt: deletedAt}
	if !lastHit.IsZero() {
		t.lastHit.Store(lastHit.UnixNano())
		t.hitSaved = lastHit.UnixNano()
	}
	return t
}

// lastActivity is "the last time this suppression was created or actually
// needed" — the instant retention is measured from.
func (t *tombstone) lastActivity() time.Time {
	if h := t.lastHit.Load(); h != 0 {
		if hs := time.Unix(0, h).UTC(); hs.After(t.deletedAt) {
			return hs
		}
	}
	return t.deletedAt
}

func (t *tombstone) record(id string) tombstoneRecord {
	r := tombstoneRecord{ID: id, DeletedAt: t.deletedAt, Tenant: t.tenant}
	if h := t.lastHit.Load(); h != 0 {
		r.LastHit = time.Unix(0, h).UTC()
	}
	return r
}

// KV abstracts persistence (the platform kv layer); Errorf is the structured
// error sink. Both required — this store fails loudly, never silently (F-69).
func NewDevStore(path string, kv KV, errf func(component, msg string, fields map[string]any)) *DevStore {
	return NewDevStoreWithLimits(path, kv, errf, TombstoneLimits{})
}

// NewDevStoreWithLimits is NewDevStore with an explicit tombstone-retention
// policy (tracker 175). The zero TombstoneLimits is the production default;
// tests inject tighter bounds and a fake clock so retention is deterministic.
func NewDevStoreWithLimits(path string, kv KV, errf func(component, msg string, fields map[string]any), lim TombstoneLimits) *DevStore {
	if errf == nil {
		errf = func(string, string, map[string]any) {}
	}
	lim = lim.withDefaults()
	s := &DevStore{
		path:       path,
		kv:         kv,
		errf:       errf,
		manual:     map[string]models.Device{},
		suppressed: map[string]*tombstone{},
		lim:        lim,
		bootAt:     lim.Now(),
	}
	if pkv, ok := kv.(PrefixKV); ok && path != "" {
		s.pkv = pkv
	}
	var err error
	if s.pkv != nil {
		err = s.loadRecords()
	} else {
		err = s.load()
	}
	if err != nil {
		s.loadErr = err
		s.errf("devices", "device store unreadable at boot — deleted devices may reappear and writes are refused until it is repaired", map[string]any{"error": err.Error()})
	}
	if s.pkv != nil {
		// Ultra 9: start the background durable-hit flusher (per-record mode
		// only — the blob format has no last_hit field). Started AFTER the load
		// so the maps are fully built before another goroutine can see them.
		// The wall-clock ticker is the safety net for a deployment whose hits
		// stop arriving; the routine cadence is hit-driven (IsSuppressed kicks
		// on the injected clock), so tests never depend on real time. Stopped
		// (with a final flush) by Close.
		s.hitFlushEvery = s.lim.hitFlushInterval()
		s.hitFlushDue.Store(s.bootAt.Add(s.hitFlushEvery).UnixNano())
		s.flushKick = make(chan struct{}, 1)
		s.flushSync = make(chan chan struct{})
		s.stopFlush = make(chan struct{})
		s.flushDone = make(chan struct{})
		go s.hitFlushLoop(time.NewTicker(s.hitFlushEvery))
	}
	return s
}

// ---- key derivation --------------------------------------------------------

// recName hashes a device id into a name safe as BOTH a filesystem path
// segment and a PG row key (see the header for why ids themselves are not).
func recName(id string) string {
	h := sha256.Sum256([]byte(id))
	return hex.EncodeToString(h[:])
}

func (s *DevStore) recPrefix() string        { return s.path + ".d/" }
func (s *DevStore) manualPrefix() string     { return s.recPrefix() + "manual/" }
func (s *DevStore) suppressedPrefix() string { return s.recPrefix() + "suppressed/" }
func (s *DevStore) manualKey(id string) string {
	return s.manualPrefix() + recName(id)
}
func (s *DevStore) suppressedKey(id string) string {
	return s.suppressedPrefix() + recName(id)
}

// markerKey is the migration-completed marker. Present ⇒ the per-record store
// is authoritative and the legacy blob (if any) is a frozen pre-migration
// snapshot, ignored forever after.
func (s *DevStore) markerKey() string { return s.recPrefix() + "migrated" }

// ---- load ------------------------------------------------------------------

// load reads the persisted legacy blob. THREE states, never two (the
// cloud_monitor_eval.go shape): the store did not answer (error) / it answered
// with nothing (absent key or empty blob — a fresh install) / loaded.
func (s *DevStore) load() error {
	b, err := s.kv.Load(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil // absent key = fresh install, genuinely nothing persisted
	}
	if err != nil {
		return fmt.Errorf("read device store: %w", err)
	}
	if len(b) == 0 {
		return nil // present but empty = nothing persisted yet
	}
	var f devPersistFile
	if err := json.Unmarshal(b, &f); err != nil {
		return fmt.Errorf("decode device store: %w", err)
	}
	if f.Manual != nil {
		s.manual = f.Manual
	}
	for id, at := range f.Suppressed {
		// The blob shape carries no tenant and no last-hit: an id deleted
		// before per-record persistence lands in the platform-scoped ("")
		// retention partition on its deleted_at. The blob format is left
		// byte-identical so a downgraded binary still reads it.
		s.suppressed[id] = newTombstone("", at.UTC(), time.Time{})
	}
	return nil
}

// loadRecords reads the per-record store, migrating from the legacy blob the
// first time. Constructor-only (the store is not yet shared; no lock held).
func (s *DevStore) loadRecords() error {
	recs, err := s.pkv.LoadPrefix(s.recPrefix())
	if err != nil {
		return fmt.Errorf("read device store records: %w", err)
	}
	if _, migrated := recs[s.markerKey()]; !migrated {
		// Never (fully) migrated: the legacy blob — if present — is the
		// authority. A crash mid-migration lands here again and re-runs; the
		// upserts plus the stray-sweep make every re-run converge to the
		// blob's exact content, so no device or tombstone is ever half-lost.
		if err := s.load(); err != nil {
			return err
		}
		// No compaction on the migration path: a one-time format change must
		// not also garbage-collect, or a crash-rerun and a retention pass would
		// be arguing about the same records. The very next boot takes the adopt
		// path below and compacts there.
		return s.migrate(recs)
	}
	if err := s.adoptRecords(recs); err != nil {
		return err
	}
	// ONE bounded compaction pass at boot (tracker 175). Bounded on purpose:
	// an accumulated residue drains over a few boots rather than turning the
	// boot read into a 35k-unlink stall — the 6b79ea58 wedge must not come back
	// through this door. The cap tier is inert here (zero uptime), so boot only
	// ever evicts tombstones expired on their DURABLE deleted_at/last_hit.
	// Constructor-only: the store is not yet shared, so the "caller holds mu"
	// contract is satisfied vacuously.
	s.compactLocked(s.lim.BootBudget)
	return nil
}

// adoptRecords parses per-record state into the in-memory maps. Any
// undecodable or misnamed record refuses the whole load (loadErr semantics —
// a partially-read store must not accept writes), matching the legacy
// corrupt-blob behaviour.
func (s *DevStore) adoptRecords(recs map[string][]byte) error {
	for key, b := range recs {
		switch {
		case key == s.markerKey():
			continue
		case strings.HasPrefix(key, s.manualPrefix()):
			var d models.Device
			if err := json.Unmarshal(b, &d); err != nil {
				return fmt.Errorf("decode device record %s: %w", key, err)
			}
			if want := s.manualKey(d.ID); want != key {
				return fmt.Errorf("device record %s carries id %q which names %s — record name and content disagree", key, d.ID, want)
			}
			s.manual[d.ID] = d
		case strings.HasPrefix(key, s.suppressedPrefix()):
			var ts tombstoneRecord
			if err := json.Unmarshal(b, &ts); err != nil {
				return fmt.Errorf("decode device tombstone %s: %w", key, err)
			}
			if want := s.suppressedKey(ts.ID); want != key {
				return fmt.Errorf("device tombstone %s carries id %q which names %s — record name and content disagree", key, ts.ID, want)
			}
			s.suppressed[ts.ID] = newTombstone(ts.Tenant, ts.DeletedAt.UTC(), ts.LastHit.UTC())
		default:
			// Unknown record class under our prefix: tolerate (forward
			// compatibility with a newer schema) but say so.
			s.errf("devices", "ignoring unknown record under the device store prefix", map[string]any{"key": key})
		}
	}
	// Crash-window resolution: an id present as BOTH record and tombstone is a
	// Put or Remove that crashed between its two writes. The tombstone wins —
	// a deleted device must never resurrect, and the interrupted Put never
	// returned success. Sweep the shadowed record best-effort; it is inert
	// either way.
	for id := range s.suppressed {
		if _, both := s.manual[id]; both {
			delete(s.manual, id)
			if err := s.pkv.Delete(s.manualKey(id)); err != nil {
				s.errf("devices", "could not sweep a tombstone-shadowed device record; it stays inert until the next boot", map[string]any{"id": id, "error": err.Error()})
			}
		}
	}
	return nil
}

// migrate splits the already-loaded legacy state into per-record keys.
// One-way, crash-safe, idempotent:
//  1. every manual device and every tombstone is upserted as its own record;
//  2. stray per-record keys NOT in the legacy state (residue of a crashed
//     earlier migration) are deleted, so the re-run converges exactly;
//  3. only then is the completion marker written. A crash anywhere before the
//     marker re-runs the whole split on the next boot from the legacy blob,
//     which is never modified or deleted.
//
// Any failure refuses the boot-load (loadErr ⇒ writes refused): accepting
// writes without the marker would let a later re-migration sweep them away.
//
// DOWNGRADE NOTE: the legacy blob stays in place as a frozen pre-migration
// snapshot, so a downgraded binary still boots (it reads the blob and sees
// pre-migration state). On re-upgrade the marker keeps the per-record store
// authoritative; blob writes made by the downgraded binary are ignored. The
// migration is one-way by design.
func (s *DevStore) migrate(existing map[string][]byte) error {
	for id, d := range s.manual {
		b, err := json.Marshal(d)
		if err != nil {
			return fmt.Errorf("encode device record %q: %w", id, err)
		}
		key := s.manualKey(id)
		if err := s.kv.Save(key, b); err != nil {
			return fmt.Errorf("migrate device record %q: %w", id, err)
		}
		delete(existing, key)
	}
	for id, ts := range s.suppressed {
		b, err := json.Marshal(ts.record(id))
		if err != nil {
			return fmt.Errorf("encode device tombstone %q: %w", id, err)
		}
		key := s.suppressedKey(id)
		if err := s.kv.Save(key, b); err != nil {
			return fmt.Errorf("migrate device tombstone %q: %w", id, err)
		}
		delete(existing, key)
	}
	for key := range existing {
		if err := s.pkv.Delete(key); err != nil {
			return fmt.Errorf("sweep stray device record %s: %w", key, err)
		}
	}
	marker, err := json.Marshal(map[string]string{"migrated_at": time.Now().UTC().Format(time.RFC3339)})
	if err != nil {
		return fmt.Errorf("encode device store migration marker: %w", err)
	}
	if err := s.kv.Save(s.markerKey(), marker); err != nil {
		return fmt.Errorf("persist device store migration marker: %w", err)
	}
	return nil
}

// unreadable reports the boot-time load failure, if any. Callers use it to
// distinguish "no tombstone for this id" from "we could not read the
// tombstones".
// Unreadable reports the boot-time load failure, if any (writes are refused
// while set — a deleted device must not resurrect; F-69/boot contract).
func (s *DevStore) Unreadable() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadErr
}

// writeAllowedLocked is the F-62/F-69 gate shared by both persistence modes:
// the in-memory maps are not the stored state when the boot read failed, so
// flushing them (or editing records around them) would erase manual devices
// and deletion tombstones that are still stored. Refuse; caller answers 5xx.
func (s *DevStore) writeAllowedLocked() error {
	if s.loadErr != nil {
		return fmt.Errorf("refusing to overwrite the device store: its stored contents were never read: %w", s.loadErr)
	}
	return nil
}

// saveLocked persists both maps as the legacy whole blob (fallback mode only —
// per-record mode never calls it). Caller holds s.mu. Returns error so callers
// can refuse to report success for a write that did not land (F-62 class); the
// guard in architecture_guards_test.go enforces the shape.
func (s *DevStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := s.writeAllowedLocked(); err != nil {
		return err
	}
	sup := make(map[string]time.Time, len(s.suppressed))
	for id, ts := range s.suppressed {
		sup[id] = ts.deletedAt
	}
	b, err := json.MarshalIndent(devPersistFile{Manual: s.manual, Suppressed: sup}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device store: %w", err)
	}
	if err := s.kv.Save(s.path, b); err != nil {
		return fmt.Errorf("persist device store: %w", err)
	}
	return nil
}

// put stores an operator-created device. The caller has already stamped
// TenantID from the authenticated principal (never the request body, §3a rule
// 2) — this layer keys by id and does not re-derive ownership.
//
// Per-record mode writes exactly ONE record (+1 tombstone delete when the id
// was suppressed) — never the fleet. Persistence-before-mutation: the maps
// change only after the backend accepted the write, so a failure needs no
// rollback and RAM never claims a device the store does not have.
func (s *DevStore) Put(d models.Device) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pkv != nil {
		if err := s.writeAllowedLocked(); err != nil {
			return err
		}
		b, err := json.Marshal(d)
		if err != nil {
			return fmt.Errorf("encode device record: %w", err)
		}
		// ORDER: record first, tombstone delete second. A crash or failure
		// between the two leaves both stored; load's tombstone-wins rule reads
		// that as "the Put never happened" — matching the error we return.
		if err := s.kv.Save(s.manualKey(d.ID), b); err != nil {
			return fmt.Errorf("persist device record: %w", err)
		}
		if _, wasSuppressed := s.suppressed[d.ID]; wasSuppressed {
			// Creating a device that was previously deleted clears its
			// tombstone, otherwise the suppression would hide the new record.
			if err := s.pkv.Delete(s.suppressedKey(d.ID)); err != nil {
				return fmt.Errorf("clear device tombstone: %w", err)
			}
		}
		s.manual[d.ID] = d
		delete(s.suppressed, d.ID)
		return nil
	}
	// Legacy whole-blob fallback: mutate, flush, roll back on failure.
	prev, had := s.manual[d.ID]
	prevSuppressed, wasSuppressed := s.suppressed[d.ID]
	s.manual[d.ID] = d
	delete(s.suppressed, d.ID)
	if err := s.saveLocked(); err != nil {
		if had {
			s.manual[d.ID] = prev
		} else {
			delete(s.manual, d.ID)
		}
		if wasSuppressed {
			s.suppressed[d.ID] = prevSuppressed
		}
		return err
	}
	return nil
}

// remove deletes a manual device AND records a tombstone so a source-owned
// device stays deleted instead of reappearing on the next poll (F-69).
//
// Per-record mode: ONE tombstone Save (+1 record delete when a manual record
// exists). The tombstone is written FIRST — it is the fact that must survive;
// once it is durable the delete is effective even if the shadowed record's
// cleanup fails (load sweeps it).
func (s *DevStore) Remove(id string) error {
	return s.RemoveOwned("", id)
}

// RemoveOwned is Remove with the owning tenant supplied by a caller that
// already knows it — the discovery aggregator knows a source-owned device's
// tenant from its cache, where this store has no record to read it from.
//
// §3a rule 2: the tenant is stamped from a record the caller owns (the cached
// device, whose TenantID the create path stamped from the authenticated
// principal), NEVER from a request body. An empty tenant falls back to the
// stored manual record's, then to "" — which is not a wildcard but the
// platform-scoped partition (deviceTenantKey). The tenant scopes cap-tier
// compaction only; it never widens or narrows what a suppression suppresses.
func (s *DevStore) RemoveOwned(tenant, id string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if tenant == "" {
		tenant = deviceTenantKey(s.manual[id])
	}
	if s.pkv != nil {
		if err := s.writeAllowedLocked(); err != nil {
			return err
		}
		now := s.lim.Now()
		ts := newTombstone(tenant, now, time.Time{})
		b, err := json.Marshal(ts.record(id))
		if err != nil {
			return fmt.Errorf("encode device tombstone: %w", err)
		}
		if err := s.kv.Save(s.suppressedKey(id), b); err != nil {
			return fmt.Errorf("persist device tombstone: %w", err)
		}
		if _, had := s.manual[id]; had {
			if err := s.pkv.Delete(s.manualKey(id)); err != nil {
				// The tombstone is durable, so the delete IS effective; the
				// stale record is shadowed (tombstone-wins) and swept at the
				// next load. Loud, not fatal.
				s.errf("devices", "device deleted (tombstone persisted) but its record could not be removed; it is shadowed until the next boot sweeps it", map[string]any{"id": id, "error": err.Error()})
			}
		}
		delete(s.manual, id)
		s.suppressed[id] = ts
		// Growth is Remove-driven, so the bound is too: one bounded incremental
		// pass per delete, AFTER the delete has been made durable (tracker 175).
		// It cannot fail this call — see compactLocked.
		s.compactLocked(s.lim.Budget)
		return nil
	}
	// Legacy whole-blob fallback (no compaction: this path rewrites the whole
	// blob on every write and is not a scale path — see the compaction header).
	prev, had := s.manual[id]
	delete(s.manual, id)
	s.suppressed[id] = newTombstone(tenant, s.lim.Now(), time.Time{})
	if err := s.saveLocked(); err != nil {
		if had {
			s.manual[id] = prev
		}
		delete(s.suppressed, id)
		return err
	}
	return nil
}

// saveTombstoneLocked re-persists one tombstone record (used by compaction to
// make an in-memory last-hit durable). Caller holds s.mu (write).
func (s *DevStore) saveTombstoneLocked(id string, ts *tombstone) error {
	b, err := json.Marshal(ts.record(id))
	if err != nil {
		return fmt.Errorf("encode device tombstone: %w", err)
	}
	return s.kv.Save(s.suppressedKey(id), b)
}

// devices returns the persisted manual inventory, for the aggregator to seed
// its cache at startup.
func (s *DevStore) Devices() []models.Device {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]models.Device, 0, len(s.manual))
	for _, d := range s.manual {
		out = append(out, d)
	}
	return out
}

// isSuppressed reports whether an id was explicitly deleted by an operator.
//
// When unreadable() != nil the tombstone set is UNKNOWN rather than empty: this
// still answers false (there is no safe way to suppress an unknown set without
// hiding the whole inventory), but the boot-time error log records exactly that
// and the write gate refuses to flush the empty map, so the stored tombstones
// survive the degraded window instead of being erased by the first write.
func (s *DevStore) IsSuppressed(id string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ts, ok := s.suppressed[id]
	if !ok {
		return false
	}
	// A hit is the ONLY evidence that this suppression is still load-bearing:
	// something tried to resurrect the id and was stopped. Retention is
	// measured from it (tracker 175, devstore_compact.go). Recorded atomically
	// under the READ lock — this is the poll path (three calls per reported
	// device) and must not serialize on the write lock, and must not do IO.
	now := s.lim.Now()
	ts.lastHit.Store(now.UnixNano())
	// Still no IO, ever (ultra 9): when a durable-hit flush has come due, hand
	// the work to the background flusher — one atomic CAS (so exactly one
	// caller per deadline wins) plus a non-blocking send. The poll path never
	// blocks and never touches the backend.
	if s.flushKick != nil {
		if due := s.hitFlushDue.Load(); now.UnixNano() >= due &&
			s.hitFlushDue.CompareAndSwap(due, now.Add(s.hitFlushEvery).UnixNano()) {
			select {
			case s.flushKick <- struct{}{}:
			default:
			}
		}
	}
	return true
}
