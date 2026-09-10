// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// promotion_store.go — the manual-promotion register behind #113 point 3
// (extracted P2 RA.6): an RCA DOCUMENT renders only for a promoted case, and a
// manual promotion is an explicit, audited operator decision. Tenant isolation
// (§3a rule 4): the map is keyed tenant → correlation id in the store itself
// and the only listing is tenant-keyed — no cross-tenant or unscoped
// enumeration exists.

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// PromotionStore is a file-backed map keyed tenant → correlation id → record.
type PromotionStore struct {
	mu   sync.RWMutex
	m    map[string]map[string]PromotionRecord
	path string
	// unreadable is set when the file EXISTS but its contents could not be
	// established. An UNREADABLE register is not an EMPTY one: see
	// store_unreadable.go for why every write is refused while it is set.
	unreadable error
}

// NewPromotionStore opens the register at path ("" = memory-only, tests). A
// MISSING file starts empty; a file that exists but could not be read or parsed
// starts empty, is LOGGED, and refuses every write from then on, so the file it
// could not read is never replaced by an empty one.
func NewPromotionStore(path string) *PromotionStore {
	s := &PromotionStore{m: map[string]map[string]PromotionRecord{}, path: path}
	b, err := loadRegister(path, "rca promotions")
	if err != nil {
		s.unreadable = err
		return s
	}
	if len(b) == 0 {
		return s
	}
	var m map[string]map[string]PromotionRecord
	if uerr := json.Unmarshal(b, &m); uerr != nil {
		s.unreadable = unparsedRegister("rca promotions", uerr)
		return s
	}
	s.m = m
	return s
}

// Unavailable reports why the stored register could not be read, or nil. A
// caller uses it to say "unknown" instead of reporting the empty register as a
// deliberate "nothing was ever promoted".
func (s *PromotionStore) Unavailable() error {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.unreadable
}

// F-62/F-63: returns error. A swallowed persist failure here made the
// handler structurally unable to report that the write did not land — 200
// with nothing saved. Callers roll back and answer 500.
func (s *PromotionStore) saveLocked() error {
	// The file's real contents are unknown, so a save would not update it — it
	// would REPLACE it with what this process holds, which after an unreadable
	// load is nothing. Refuse: the caller rolls its change back and answers 500,
	// so the operator gets an error instead of a silent loss.
	if err := refuseUnreadable(s.unreadable); err != nil {
		return err
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rca promotions: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("rca", "persist rca promotions failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist rca promotions: %w", err)
	}
	return nil
}

// Get returns the tenant's manual promotion for one correlation. Nil-safe.
func (s *PromotionStore) Get(tenant, id string) (PromotionRecord, bool) {
	if s == nil {
		return PromotionRecord{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	rec, ok := s.m[tenant][id]
	return rec, ok
}

// List returns ONE tenant's manually promoted correlation ids, sorted for
// determinism. §3a rule 4: the only listing is tenant-keyed. Nil-safe.
func (s *PromotionStore) List(tenant string) []string {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	ids := make([]string, 0, len(s.m[tenant]))
	for id := range s.m[tenant] {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// Set records a manual promotion; a failed persist rolls back (never a lie).
func (s *PromotionStore) Set(tenant, id string, rec PromotionRecord) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.m[tenant] == nil {
		s.m[tenant] = map[string]PromotionRecord{}
	}
	prev, had := s.m[tenant][id]
	s.m[tenant][id] = rec
	if err := s.saveLocked(); err != nil {
		if had {
			s.m[tenant][id] = prev
		} else {
			delete(s.m[tenant], id)
		}
		return err
	}
	return nil
}

// Remove revokes a manual promotion; a failed persist rolls back.
func (s *PromotionStore) Remove(tenant, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, had := s.m[tenant][id]
	byTenant, hadTenant := s.m[tenant]
	delete(s.m[tenant], id)
	if len(s.m[tenant]) == 0 {
		delete(s.m, tenant)
	}
	if err := s.saveLocked(); err != nil {
		if hadTenant {
			s.m[tenant] = byTenant
		}
		if had {
			if s.m[tenant] == nil {
				s.m[tenant] = map[string]PromotionRecord{}
			}
			s.m[tenant][id] = prev
		}
		return err
	}
	return nil
}
