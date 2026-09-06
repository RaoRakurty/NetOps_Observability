// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package bgpwatch

// watchlist.go — the WATCHLIST itself: which prefixes/ASNs a tenant asked us to
// keep an eye on. It is the second half of this feature's mutable state (the
// first is the alert POLICY in state.go), and it follows the same two-backends-
// behind-one-interface shape: the Postgres store (migration 0035, `bgp_watchlist`
// with tenant_iso FORCE-RLS) lives with its SQL in the root package's
// bgp_ops.go, and THIS file is the non-Postgres twin.
//
// Why it matters that this exists at all: before it, a deployment with no
// DATABASE_URL had `s.bgpWatch == nil`, so /api/bgp/watchlist answered 503, the
// RPKI-over-watchlist and feed views had nothing to read, and the whole
// evaluator in evaluate.go could never see a single prefix — the alerting
// feature was dead on every single-box install. The watchlist is now durable on
// BOTH backends.
//
// Isolation lives IN the store (§3a rule 4), exactly as the policy FileStore
// does: rows are held in a tenant-keyed map, so a lookup for tenant A can only
// ever walk A's bucket. There is no "list everything" method — the ONLY way to
// see across tenants is List with cross=true, which the API boundary sets solely
// for the platform owner's Global view and which is the deliberate mirror of the
// Postgres backend's `app.tenant_id = '*'` RLS scope (the pcap.FileStore
// precedent). Writes take a CONCRETE tenant or fail: "" and "*" are refused at
// the store, so no future caller can reintroduce a wildcard write.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
)

// WatchEntry is one watched resource. The field/JSON shape is the Postgres
// table's, byte-for-byte, so the API response is identical on both backends.
type WatchEntry struct {
	Resource  string    `json:"resource"`
	Kind      string    `json:"kind"` // prefix | asn
	Note      string    `json:"note"`
	AddedBy   string    `json:"added_by"`
	CreatedAt time.Time `json:"created_at"`
}

// Store bounds (§9 — operator input is still bounded input). The Postgres table
// is unbounded TEXT; these are the FILE backend's own storage bounds, and they
// are refusals rather than silent truncations of the row set.
const (
	// MaxWatchEntriesPerTenant caps one tenant's watchlist. The evaluator makes
	// one bounded outbound measurement per watched PREFIX per pass, so an
	// unbounded list is an unbounded work queue.
	MaxWatchEntriesPerTenant = 500
	// MaxWatchNoteBytes mirrors the API's note cap (bgpNoteMaxBytes). Applied
	// again here because the store is the independent second line.
	MaxWatchNoteBytes = 300
	// MaxWatchResourceBytes bounds the key. A canonical prefix or "AS4294967295"
	// is far inside this; anything longer never came from bgpNormalizeResource.
	MaxWatchResourceBytes = 64
)

// ErrWatchlistFull is returned when a tenant is at MaxWatchEntriesPerTenant and
// adds a NEW resource. Updating an existing one always succeeds.
var ErrWatchlistFull = fmt.Errorf("bgpwatch: watchlist is full (max %d resources per tenant)", MaxWatchEntriesPerTenant)

// validWatchKind is the closed set the store accepts. The handler already
// derives kind from bgpNormalizeResource; the store re-checks it because it
// does not trust its callers (§3).
func validWatchKind(kind string) bool { return kind == "prefix" || kind == "asn" }

// WatchFileStore is the non-Postgres watchlist backend. Path "" keeps it purely
// in memory (tests, and a dev build with no persistence configured).
type WatchFileStore struct {
	mu   sync.RWMutex
	path string
	// rows is tenant → resource → entry. The tenant key is the isolation
	// boundary: no read or write can reach a bucket it was not handed.
	rows    map[string]map[string]WatchEntry
	loadErr error
	now     func() time.Time
}

// NewWatchFileStore loads the persisted watchlist. A missing file starts empty;
// a CORRUPT file starts empty AND records the error, which the integrator logs —
// a watchlist that failed to load must never look like a watchlist a tenant
// never wrote (§10). It is never silently overwritten either: the first
// successful Add rewrites the file, and the operator has been told why.
func NewWatchFileStore(path string) *WatchFileStore {
	s := &WatchFileStore{
		path: path,
		rows: map[string]map[string]WatchEntry{},
		now:  func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	if err != nil {
		return s // absent store → empty, not an error
	}
	var rows map[string][]WatchEntry
	if err := json.Unmarshal(b, &rows); err != nil {
		s.loadErr = err
		return s
	}
	for rawTenant, list := range rows {
		t, err := concreteTenant(rawTenant)
		if err != nil {
			// A persisted "" or "*" bucket is not a tenant's data and must never
			// become one; drop it and say so rather than serving it to someone.
			s.loadErr = errors.New("bgpwatch: watchlist file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, e := range list {
			e, ok := sanitizeWatchEntry(e)
			if !ok {
				continue
			}
			if s.rows[t] == nil {
				s.rows[t] = map[string]WatchEntry{}
			}
			if len(s.rows[t]) >= MaxWatchEntriesPerTenant {
				break
			}
			s.rows[t][e.Resource] = e
		}
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *WatchFileStore) LoadErr() error { return s.loadErr }

// sanitizeWatchEntry bounds and validates one row read off disk or off a caller.
// A row that cannot be made safe is DROPPED, not repaired into something the
// tenant never wrote.
func sanitizeWatchEntry(e WatchEntry) (WatchEntry, bool) {
	e.Resource = clip(e.Resource, MaxWatchResourceBytes)
	if e.Resource == "" || !validWatchKind(e.Kind) {
		return WatchEntry{}, false
	}
	e.Note = clip(e.Note, MaxWatchNoteBytes)
	e.AddedBy = clip(e.AddedBy, 128)
	e.CreatedAt = e.CreatedAt.UTC()
	return e, true
}

// List returns the entries the caller may see, newest first.
//
// cross=true is the platform owner's Global view and is the ONLY cross-tenant
// read — the exact mirror of the Postgres backend running under the '*' RLS
// scope. With cross=false a non-concrete tenant reads NOTHING (default-closed,
// and what RLS would do with an empty GUC) rather than everything.
func (s *WatchFileStore) List(_ context.Context, tenant string, cross bool) ([]WatchEntry, error) {
	out := []WatchEntry{}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if cross {
		for _, bucket := range s.rows {
			for _, e := range bucket {
				out = append(out, e)
			}
		}
		sortWatchEntries(out)
		return out, nil
	}
	t, err := concreteTenant(tenant)
	if err != nil {
		return out, nil // default-closed: no scope, no rows (never an error 500)
	}
	for _, e := range s.rows[t] {
		out = append(out, e)
	}
	sortWatchEntries(out)
	return out, nil
}

// sortWatchEntries orders newest-first, matching the Postgres
// `ORDER BY created_at DESC`, with a resource tie-break so a page rendered from
// the file backend is stable across restarts (map iteration is not).
func sortWatchEntries(rows []WatchEntry) {
	sort.Slice(rows, func(i, j int) bool {
		if !rows[i].CreatedAt.Equal(rows[j].CreatedAt) {
			return rows[i].CreatedAt.After(rows[j].CreatedAt)
		}
		return rows[i].Resource < rows[j].Resource
	})
}

// Add upserts ONE tenant's row. It mirrors the Postgres
// `ON CONFLICT (tenant_id, resource) DO UPDATE SET note`: re-adding a resource
// updates only the note and keeps the original created_at and added_by, so the
// page's "watched since" does not silently reset.
func (s *WatchFileStore) Add(_ context.Context, tenant string, e WatchEntry) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return err
	}
	clean, ok := sanitizeWatchEntry(e)
	if !ok {
		return errors.New("bgpwatch: a watchlist row needs a resource and a kind of prefix|asn")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.rows[t]
	if bucket == nil {
		bucket = map[string]WatchEntry{}
	}
	prev, had := bucket[clean.Resource]
	if had {
		prev.Note = clean.Note
		clean = prev
	} else {
		if len(bucket) >= MaxWatchEntriesPerTenant {
			return ErrWatchlistFull
		}
		if clean.CreatedAt.IsZero() {
			clean.CreatedAt = s.now()
		}
	}
	bucket[clean.Resource] = clean
	s.rows[t] = bucket
	if err := s.flushLocked(); err != nil {
		// Roll the in-memory state back to what the file still holds: a row the
		// file does not have must not be alerted on as if it were durable (§10).
		if had {
			bucket[clean.Resource] = prev
		} else {
			delete(bucket, clean.Resource)
			if len(bucket) == 0 {
				delete(s.rows, t)
			}
		}
		return err
	}
	return nil
}

// Delete removes ONE tenant's row and reports whether it existed. A resource
// another tenant watches is simply not in this tenant's bucket, so a
// cross-tenant delete returns (false, nil) — the handler turns that into a 404,
// which is also the §3a answer: another tenant's row does not exist for you.
func (s *WatchFileStore) Delete(_ context.Context, tenant string, resource string) (bool, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	bucket := s.rows[t]
	prev, had := bucket[resource]
	if !had {
		return false, nil
	}
	delete(bucket, resource)
	if len(bucket) == 0 {
		delete(s.rows, t)
	}
	if err := s.flushLocked(); err != nil {
		if s.rows[t] == nil {
			s.rows[t] = map[string]WatchEntry{}
		}
		s.rows[t][resource] = prev
		return false, err
	}
	return true, nil
}

// flushLocked persists the whole register through the platform KV seam (atomic
// temp-file + rename on the file backend). A failure is RETURNED, never
// swallowed.
func (s *WatchFileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	// Persist tenant-keyed: the FILE itself carries the ownership, so a row can
	// never be reloaded into the wrong bucket.
	out := make(map[string][]WatchEntry, len(s.rows))
	for t, bucket := range s.rows {
		list := make([]WatchEntry, 0, len(bucket))
		for _, e := range bucket {
			list = append(list, e)
		}
		sort.Slice(list, func(i, j int) bool { return list[i].Resource < list[j].Resource })
		out[t] = list
	}
	b, err := json.Marshal(out)
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}
