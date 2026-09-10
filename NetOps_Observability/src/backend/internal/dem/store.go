// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

// store.go — the target catalogue's non-Postgres backend.
//
// Isolation lives IN the store (§3a rule 4): rows are held in a tenant-keyed
// map, so a lookup for tenant A can only ever walk A's bucket. There is no
// "list everything" on the tenant surface — the only cross-tenant read is
// ListAll, which exists solely for the prober's target projector (the fleet's
// work queue) and which the HTTP layer must never call. Writes take a CONCRETE
// tenant or fail: "" and "*" are refused here, so no future caller can
// reintroduce a wildcard write.
//
// Persistence goes through platformdb (the same seam the users/saved/watchlist
// stores use), so the file backend and its Postgres twin are a wiring choice,
// not a rewrite.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
)

// Catalogue is the target-store seam. Both backends satisfy it; the HTTP layer
// and the projector know nothing else about storage.
//
// Every method takes the caller's CONCRETE tenant. Get/Update/Delete return
// ErrNotFound for an id owned by another tenant — a cross-tenant id must never
// be confirmed to exist (§3a rule 1).
type Catalogue interface {
	List(ctx context.Context, tenant string) ([]Target, error)
	Get(ctx context.Context, tenant, id string) (Target, error)
	Create(ctx context.Context, t Target) (Target, error)
	Update(ctx context.Context, tenant, id string, patch Patch) (Target, error)
	Delete(ctx context.Context, tenant, id string) error
	// ListAll is the PLATFORM read: every tenant's targets, for the prober's
	// work queue. It is the deliberate mirror of the Postgres backend running
	// under the '*' RLS scope, and no HTTP handler may call it.
	ListAll(ctx context.Context) ([]Target, error)
}

// Patch is a partial update. A nil field means "leave it alone"; this is what
// lets "pause" be a one-field write that cannot accidentally blank a budget.
// TenantID is deliberately absent — ownership is stamped from the token at
// create and is immutable thereafter (§3a rule 2).
type Patch struct {
	Name                  *string  `json:"name,omitempty"`
	Host                  *string  `json:"host,omitempty"`
	Port                  *int     `json:"port,omitempty"`
	Resolver              *string  `json:"resolver,omitempty"`
	IntervalSec           *int     `json:"interval_sec,omitempty"`
	Site                  *string  `json:"site,omitempty"`
	App                   *string  `json:"app,omitempty"`
	ExpectStatus          *int     `json:"expect_status,omitempty"`
	LatencyBudgetMs       *float64 `json:"latency_budget_ms,omitempty"`
	AvailabilityBudgetPct *float64 `json:"availability_budget_pct,omitempty"`
	Paused                *bool    `json:"paused,omitempty"`
}

// apply folds the patch onto a copy of t. The KIND is immutable: changing an
// icmp target into an http one would silently orphan every series already
// recorded under its id, so a kind change is a delete plus a create.
func (p Patch) apply(t Target) Target {
	if p.Name != nil {
		t.Name = *p.Name
	}
	if p.Host != nil {
		t.Host = *p.Host
	}
	if p.Port != nil {
		t.Port = *p.Port
	}
	if p.Resolver != nil {
		t.Resolver = *p.Resolver
	}
	if p.IntervalSec != nil {
		t.IntervalSec = *p.IntervalSec
	}
	if p.Site != nil {
		t.Site = *p.Site
	}
	if p.App != nil {
		t.App = *p.App
	}
	if p.ExpectStatus != nil {
		t.ExpectStatus = *p.ExpectStatus
	}
	if p.LatencyBudgetMs != nil {
		t.LatencyBudgetMs = *p.LatencyBudgetMs
	}
	if p.AvailabilityBudgetPct != nil {
		t.AvailabilityBudgetPct = *p.AvailabilityBudgetPct
	}
	if p.Paused != nil {
		t.Paused = *p.Paused
	}
	return t
}

// EnvCatalogueFile is the file backend's path knob.
const EnvCatalogueFile = "DEM_TARGETS_FILE"

// FileStore is the non-Postgres catalogue. Path "" keeps it purely in memory
// (tests, and a dev build with no persistence configured).
type FileStore struct {
	mu   sync.RWMutex
	path string
	// rows is tenant → id → target. The tenant key IS the isolation boundary.
	rows    map[string]map[string]Target
	loadErr error
	// writesRefused is set when the file holds data this process did NOT load,
	// so a flush would not update the file — it would replace it with a
	// smaller catalogue and make the loss durable. Two conditions reach it:
	//
	//   - the contents could not be established at all (an I/O or permission
	//     failure, or JSON we could not parse), so we hold nothing;
	//   - a tenant bucket was over MaxTargetsPerTenant, so we hold the first
	//     MaxTargetsPerTenant rows and the rest are still only in the file.
	//
	// It is the stricter half of loadErr: loadErr also covers rows we read and
	// deliberately dropped (an unparseable row, a non-concrete bucket), where
	// rewriting the file IS the intended repair.
	writesRefused error
	now           func() time.Time
}

var _ Catalogue = (*FileStore)(nil)

// NewFileStore loads the persisted catalogue. A MISSING file starts empty; a
// file that exists but could not be read or parsed starts empty AND records the
// error, which the integrator logs — a catalogue that failed to load must never
// look like one a tenant never wrote (§10) — AND refuses every write from then
// on, so the file it could not read is never replaced by an empty one.
func NewFileStore(path string) *FileStore {
	s := &FileStore{
		path: path,
		rows: map[string]map[string]Target{},
		now:  func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: nobody has written this catalogue yet. That is the
		// normal first-boot state and an empty catalogue is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folding the two together starts empty with
		// nothing logged, and the first write then renames a temp file over a
		// file whose contents were never read.
		s.loadErr = fmt.Errorf("dem: the target file could not be read: %w", err)
		s.writesRefused = s.loadErr
		return s
	}
	var rows map[string][]Target
	if err := json.Unmarshal(b, &rows); err != nil {
		s.loadErr = fmt.Errorf("dem: the target file could not be parsed: %w", err)
		s.writesRefused = s.loadErr
		return s
	}
	// overCap records, per tenant, how many targets the file holds. It is
	// reported AFTER the whole file is read so the message can name every
	// affected tenant and the real count, the way ImportFile does.
	overCap := map[string]int{}
	for rawTenant, list := range rows {
		t, err := concreteTenant(rawTenant)
		if err != nil {
			// A persisted "" or "*" bucket is not a tenant's data and must
			// never become one; drop it and say so rather than serving it.
			s.loadErr = errors.New("dem: the target file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, tgt := range list {
			tgt.TenantID = t // the bucket is authoritative, never the row's own field
			if err := tgt.Validate(); err != nil || tgt.ID == "" {
				// A row that cannot be made safe is DROPPED, not repaired into
				// something the tenant never wrote.
				s.loadErr = errors.New("dem: the target file holds an invalid row; it was dropped")
				continue
			}
			if s.rows[t] == nil {
				s.rows[t] = map[string]Target{}
			}
			if len(s.rows[t]) >= MaxTargetsPerTenant {
				// OVER CAP IS NOT A QUIET TRIM. Before 2026-09-08 this was a
				// bare break: the excess targets were unmeasured, nothing said
				// so, and the next write flushed the whole catalogue and made
				// the truncation durable. Keep counting so the operator is
				// told how many, and refuse writes until the file is trimmed.
				overCap[t]++
				continue
			}
			s.rows[t][tgt.ID] = tgt
		}
	}
	if len(overCap) > 0 {
		names := make([]string, 0, len(overCap))
		for t := range overCap {
			names = append(names, fmt.Sprintf("%s holds %d", t, len(s.rows[t])+overCap[t]))
		}
		sort.Strings(names)
		s.loadErr = fmt.Errorf("%w (%s)", ErrCatalogueOverCap, strings.Join(names, "; "))
		s.writesRefused = s.loadErr
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileStore) LoadErr() error { return s.loadErr }

// refusalLocked is the error every write answers with while the file holds rows
// this process never loaded. Callers hold a lock.
func (s *FileStore) refusalLocked() error {
	if errors.Is(s.writesRefused, ErrCatalogueOverCap) {
		return s.writesRefused
	}
	return fmt.Errorf("%w: %w", ErrCatalogueUnreadable, s.writesRefused)
}

// flushLocked persists the whole catalogue. Callers hold the write lock and
// roll their change back when this fails, so a failed write never leaves the
// in-memory view ahead of the file.
func (s *FileStore) flushLocked() error {
	if s.writesRefused != nil {
		// The file holds rows this process never loaded, so a flush would not
		// update it — it would REPLACE it with what this process happens to
		// hold. Refuse, and say why: the caller rolls its change back and the
		// operator gets an error instead of a silent loss.
		return s.refusalLocked()
	}
	if s.path == "" {
		return nil
	}
	out := make(map[string][]Target, len(s.rows))
	for tenant, bucket := range s.rows {
		list := make([]Target, 0, len(bucket))
		for _, t := range bucket {
			list = append(list, t)
		}
		sortTargets(list)
		out[tenant] = list
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) List(_ context.Context, tenant string) ([]Target, error) {
	out := []Target{}
	t, err := concreteTenant(tenant)
	if err != nil {
		return out, nil // default-closed: no scope, no rows (never a 500)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, tgt := range s.rows[t] {
		out = append(out, tgt)
	}
	sortTargets(out)
	return out, nil
}

func (s *FileStore) ListAll(context.Context) ([]Target, error) {
	out := []Target{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, bucket := range s.rows {
		for _, tgt := range bucket {
			out = append(out, tgt)
		}
	}
	sortTargets(out)
	return out, nil
}

func (s *FileStore) Get(_ context.Context, tenant, id string) (Target, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Target{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	tgt, ok := s.rows[t][id]
	if !ok {
		return Target{}, ErrNotFound
	}
	return tgt, nil
}

func (s *FileStore) Create(_ context.Context, in Target) (Target, error) {
	if err := in.Validate(); err != nil {
		return Target{}, err
	}
	now := s.now()
	in.ID = newTargetID()
	in.CreatedAt, in.UpdatedAt = now, now
	in.CreatedBy = clip(in.CreatedBy, 128)
	s.mu.Lock()
	defer s.mu.Unlock()
	// Ask the file-state question BEFORE the cap question. A catalogue whose
	// file holds rows this process never loaded is always AT the cap, so
	// without this the operator is told the catalogue is full when the real
	// answer is that the file was truncated at load and must be repaired.
	if s.writesRefused != nil {
		return Target{}, s.refusalLocked()
	}
	if s.rows[in.TenantID] == nil {
		s.rows[in.TenantID] = map[string]Target{}
	}
	if len(s.rows[in.TenantID]) >= MaxTargetsPerTenant {
		return Target{}, ErrCatalogueFull
	}
	s.rows[in.TenantID][in.ID] = in
	if err := s.flushLocked(); err != nil {
		delete(s.rows[in.TenantID], in.ID)
		return Target{}, err
	}
	return in, nil
}

func (s *FileStore) Update(_ context.Context, tenant, id string, patch Patch) (Target, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Target{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.rows[t][id]
	if !ok {
		return Target{}, ErrNotFound
	}
	next := patch.apply(prev)
	next.TenantID, next.ID, next.Kind = prev.TenantID, prev.ID, prev.Kind
	next.CreatedAt, next.CreatedBy = prev.CreatedAt, prev.CreatedBy
	// A patch may clear the port the old host:port supplied, so re-derive from
	// the patched fields and refuse an update that would make the target
	// unmeasurable.
	if err := next.Validate(); err != nil {
		return Target{}, err
	}
	next.UpdatedAt = s.now()
	s.rows[t][id] = next
	if err := s.flushLocked(); err != nil {
		s.rows[t][id] = prev
		return Target{}, err
	}
	return next, nil
}

func (s *FileStore) Delete(_ context.Context, tenant, id string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.rows[t][id]
	if !ok {
		return ErrNotFound
	}
	delete(s.rows[t], id)
	if err := s.flushLocked(); err != nil {
		s.rows[t][id] = prev
		return err
	}
	return nil
}

// newTargetID mints an opaque 16-byte hex id. Opaque on purpose: it becomes a
// metric label, and a label derived from the host would leak a rename into the
// series identity.
func newTargetID() string {
	var b [16]byte
	_, _ = rand.Read(b[:]) // crypto/rand.Read cannot fail (Go 1.24+ aborts instead)
	return "dem-" + hex.EncodeToString(b[:])
}
