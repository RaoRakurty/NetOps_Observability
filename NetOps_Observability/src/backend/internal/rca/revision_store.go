// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// revision_store.go — the immutable report-revision register (postmortem spec
// "Additional mandatory" + §7, extracted P2 RA.6). A published document is an
// immutable status snapshot: a regeneration whose analysis or content differs
// is a NEW revision; an identical regeneration reuses the existing row
// (idempotent). Tenant isolation (§3a rule 4): tenant key lives in the store
// itself; no unscoped listing exists.

import (
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"netops/backend/internal/applog"
	"netops/backend/internal/platformdb"
)

// ReportRevision is ONE immutable generation record.
type ReportRevision struct {
	Revision  int             `json:"revision"`
	ReportID  string          `json:"report_id"`
	Format    string          `json:"format"` // html | pdf
	Integrity ReportIntegrity `json:"integrity"`
	CreatedAt string          `json:"created_at"`
	CreatedBy string          `json:"created_by"`
}

// RevisionsMaxPerCase bounds the register (§9). When full, generation still
// works — the register just refuses NEW rows and the caller is told.
const RevisionsMaxPerCase = 200

// RevisionStore is a file-backed register keyed tenant → correlation id →
// ordered revisions.
type RevisionStore struct {
	mu   sync.RWMutex
	m    map[string]map[string][]ReportRevision
	path string
}

// NewRevisionStore opens the register at path ("" = memory-only, tests).
func NewRevisionStore(path string) *RevisionStore {
	s := &RevisionStore{m: map[string]map[string][]ReportRevision{}, path: path}
	if b, err := platformdb.Load(path); err == nil && len(b) > 0 {
		var m map[string]map[string][]ReportRevision
		if json.Unmarshal(b, &m) == nil {
			s.m = m
		}
	}
	return s
}

// F-62/F-63: returns error; callers roll back and answer 500.
func (s *RevisionStore) saveLocked() error {
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.m, "", "  ")
	if err != nil {
		return fmt.Errorf("encode rca revisions: %w", err)
	}
	if err := platformdb.Save(s.path, b); err != nil {
		applog.Error("rca", "persist rca revisions failed", map[string]any{"err": err.Error()})
		return fmt.Errorf("persist rca revisions: %w", err)
	}
	return nil
}

// List returns ONE tenant's revision register for one case, oldest first.
func (s *RevisionStore) List(tenant, corrID string) []ReportRevision {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	revs := s.m[tenant][corrID]
	out := make([]ReportRevision, len(revs))
	copy(out, revs)
	return out
}

// Record appends a NEW revision unless an existing one already carries the
// same analysis snapshot, content, template and policy (idempotent re-render).
// Returns the effective revision and whether it was newly created.
// FindBySnapshot returns the existing revision generated from the SAME
// analysis (snapshot hash + policy + template) in the same format, if any —
// content hash is deliberately ignored. The renderer uses it to reproduce an
// unchanged analysis byte-for-byte (re-rendering with the original revision's
// generation stamp): the rendered document embeds its generation timestamp, so
// without this every re-render in a later wall-clock second hashed differently
// and appended a junk revision per view until the register hit
// RevisionsMaxPerCase (rare -race CI failure, 2026-08-12).
func (s *RevisionStore) FindBySnapshot(tenant, corrID string, integ ReportIntegrity, format string) (ReportRevision, bool) {
	if s == nil {
		return ReportRevision{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, ex := range s.m[tenant][corrID] {
		if ex.Integrity.AnalysisSnapshotHash == integ.AnalysisSnapshotHash &&
			ex.Integrity.TemplateVersion == integ.TemplateVersion &&
			ex.Integrity.PolicyVersion == integ.PolicyVersion &&
			ex.Format == format {
			return ex, true
		}
	}
	return ReportRevision{}, false
}

func (s *RevisionStore) Record(tenant, corrID string, rev ReportRevision) (ReportRevision, bool, error) {
	if s == nil {
		return ReportRevision{}, false, errors.New("revision store unavailable")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, ex := range s.m[tenant][corrID] {
		if ex.Integrity.AnalysisSnapshotHash == rev.Integrity.AnalysisSnapshotHash &&
			ex.Integrity.ContentHash == rev.Integrity.ContentHash &&
			ex.Integrity.TemplateVersion == rev.Integrity.TemplateVersion &&
			ex.Integrity.PolicyVersion == rev.Integrity.PolicyVersion &&
			ex.Format == rev.Format {
			return ex, false, nil // identical regeneration — the revision is immutable and reused
		}
	}
	if len(s.m[tenant][corrID]) >= RevisionsMaxPerCase {
		return ReportRevision{}, false, fmt.Errorf("revision register full for this case (max %d)", RevisionsMaxPerCase)
	}
	if s.m[tenant] == nil {
		s.m[tenant] = map[string][]ReportRevision{}
	}
	rev.Revision = len(s.m[tenant][corrID]) + 1
	prev := s.m[tenant][corrID]
	s.m[tenant][corrID] = append(append([]ReportRevision(nil), prev...), rev)
	if err := s.saveLocked(); err != nil {
		// The register exists SPECIFICALLY to prove a report was not mutated. An
		// unpersisted revision must never be reported as registered.
		s.m[tenant][corrID] = prev
		return ReportRevision{}, false, err
	}
	return rev, true, nil
}
