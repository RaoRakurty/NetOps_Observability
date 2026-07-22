package main

import (
	"encoding/json"
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
// `DiscoveryAggregator.cache`, a plain in-memory map with no persistence
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

// deviceStore holds operator-created devices and deletion tombstones, persisted
// through the shared kv backend (file or Postgres) like every other store.
type deviceStore struct {
	mu         sync.RWMutex
	path       string
	manual     map[string]models.Device
	suppressed map[string]time.Time
}

// devicesPath resolves the store's kv key. Absolute by construction — a
// relative key resolves against the container WORKDIR rather than /data and is
// silently lost (F-63); kv_paths_test.go guards this for the whole family.
func devicesPath() string {
	if p := strings.TrimSpace(os.Getenv("DEVICES_STORE_PATH")); p != "" {
		return p
	}
	return "/data/devices.json"
}

// devicePersistFile is the on-disk shape. Split into two maps so a suppression
// survives independently of whether a manual record exists for the same id.
type devicePersistFile struct {
	Manual     map[string]models.Device `json:"manual"`
	Suppressed map[string]time.Time     `json:"suppressed,omitempty"`
}

func newDeviceStore(path string) *deviceStore {
	s := &deviceStore{
		path:       path,
		manual:     map[string]models.Device{},
		suppressed: map[string]time.Time{},
	}
	s.load()
	return s
}

func (s *deviceStore) load() {
	b, err := kvLoad(s.path)
	if err != nil || len(b) == 0 {
		return
	}
	var f devicePersistFile
	if json.Unmarshal(b, &f) != nil {
		return
	}
	if f.Manual != nil {
		s.manual = f.Manual
	}
	if f.Suppressed != nil {
		s.suppressed = f.Suppressed
	}
}

// saveLocked persists both maps. Caller holds s.mu. Returns error so callers can
// refuse to report success for a write that did not land (F-62 class); the
// guard in architecture_guards_test.go enforces the shape.
func (s *deviceStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(devicePersistFile{Manual: s.manual, Suppressed: s.suppressed}, "", "  ")
	if err != nil {
		return fmt.Errorf("encode device store: %w", err)
	}
	if err := kvSave(s.path, b); err != nil {
		return fmt.Errorf("persist device store: %w", err)
	}
	return nil
}

// put stores an operator-created device. The caller has already stamped
// TenantID from the authenticated principal (never the request body, §3a rule
// 2) — this layer keys by id and does not re-derive ownership.
func (s *deviceStore) put(d models.Device) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.manual[d.ID]
	// Creating a device that was previously deleted clears its tombstone,
	// otherwise the suppression would immediately hide the new record.
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
func (s *deviceStore) remove(id string) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
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
func (s *deviceStore) devices() []models.Device {
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
func (s *deviceStore) isSuppressed(id string) bool {
	if s == nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.suppressed[id]
	return ok
}
