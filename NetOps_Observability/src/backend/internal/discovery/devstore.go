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
//	<path>.d/suppressed/<sha256hex(id)>  — {"id":..., "deleted_at":...}
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
	suppressed map[string]time.Time
	// loadErr is set when the stored state could NOT be read at boot. An empty
	// store then means "we do not know what was stored", NOT "no manual devices
	// and no tombstones" — the two used to share a branch, so a boot read failure
	// resurrected deliberately-deleted devices and the first write flushed the
	// empty maps over the survivors (§10).
	loadErr error
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
type tombstoneRecord struct {
	ID        string    `json:"id"`
	DeletedAt time.Time `json:"deleted_at"`
}

// KV abstracts persistence (the platform kv layer); Errorf is the structured
// error sink. Both required — this store fails loudly, never silently (F-69).
func NewDevStore(path string, kv KV, errf func(component, msg string, fields map[string]any)) *DevStore {
	if errf == nil {
		errf = func(string, string, map[string]any) {}
	}
	s := &DevStore{
		path:       path,
		kv:         kv,
		errf:       errf,
		manual:     map[string]models.Device{},
		suppressed: map[string]time.Time{},
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
	if f.Suppressed != nil {
		s.suppressed = f.Suppressed
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
		return s.migrate(recs)
	}
	return s.adoptRecords(recs)
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
			s.suppressed[ts.ID] = ts.DeletedAt
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
		b, err := json.Marshal(tombstoneRecord{ID: id, DeletedAt: ts})
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
	b, err := json.MarshalIndent(devPersistFile{Manual: s.manual, Suppressed: s.suppressed}, "", "  ")
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
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pkv != nil {
		if err := s.writeAllowedLocked(); err != nil {
			return err
		}
		now := time.Now().UTC()
		b, err := json.Marshal(tombstoneRecord{ID: id, DeletedAt: now})
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
		s.suppressed[id] = now
		return nil
	}
	// Legacy whole-blob fallback.
	prev, had := s.manual[id]
	delete(s.manual, id)
	s.suppressed[id] = time.Now().UTC()
	if err := s.saveLocked(); err != nil {
		if had {
			s.manual[id] = prev
		}
		delete(s.suppressed, id)
		return err
	}
	return nil
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
	_, ok := s.suppressed[id]
	return ok
}
