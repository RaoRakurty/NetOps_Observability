// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package metering

// store.go — the durable home of the daily rows, and its non-Postgres backend.
//
// ISOLATION LIVES IN THE STORE (CLAUDE.md §3a rule 4). Every read takes the
// caller's (tenant, cross) pair and there is NO unscoped "list everything":
//
//	cross = true              every row, including the installation row. Only a
//	                          cross-tenant principal ever gets this.
//	cross = false, tenant ""  NOTHING. Default-closed: a principal with no
//	                          resolved scope reads no rows, rather than falling
//	                          through to the installation row (which is "" too).
//	cross = false, tenant X   X's rows and nothing else.
//
// That shape is the BGP watchlist's, reused rather than re-derived: a second
// implementation of "which rows may this caller see" is a second thing that can
// silently be wrong.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// EnvFile is the file backend's path knob.
const EnvFile = "METERING_FILE"

// DefaultFile is where the file backend keeps its rows. Beside the licence and
// its overage register: they are one operational object, and an operator
// copying /data/api out gets all three.
const DefaultFile = "/data/api/metering.json"

// RetentionDays bounds how much history is kept: 400 daily rows per tenant,
// which is thirteen months — enough that an annual true-up can look back over
// a full contract year plus the month it is being discussed in, and no more.
// Documented in docs/design/METERING_2026-09-05.md; a bound is not optional
// (CLAUDE.md §9).
const RetentionDays = 400

// Store is the metering seam. Both backends satisfy it; the recorder and the
// HTTP layer know nothing else about storage.
type Store interface {
	// Record folds one snapshot into the day's rows. It is the PLATFORM write
	// path — it writes every tenant's row plus the installation row — and no
	// HTTP handler may call it.
	Record(ctx context.Context, at time.Time, byTenant map[string][]Reading) error
	// List returns the rows a caller may see, from..to inclusive (UTC day
	// keys), ordered by day then tenant.
	List(ctx context.Context, tenant string, cross bool, from, to string) ([]DailyRecord, error)
	// Rows is the total number of persisted daily rows, for the metric.
	Rows(ctx context.Context) (int, error)
	// Prune drops every row whose day is strictly before `before`. Returns how
	// many went.
	Prune(ctx context.Context, before string) (int, error)
}

// ─────────────────────────────────────────────────────────────────────────────
// File backend
// ─────────────────────────────────────────────────────────────────────────────

// FileStore is the non-Postgres backend: one JSON document holding every row.
//
// Path "" keeps it purely in memory (tests, and a dev build with no
// persistence configured) — the same contract internal/dem's FileStore offers.
type FileStore struct {
	mu   sync.Mutex
	path string
	// rows is tenant → day → record. The tenant key IS the isolation boundary:
	// a scoped read can only ever walk one bucket.
	rows    map[string]map[string]DailyRecord
	loaded  bool
	loadErr error
}

var _ Store = (*FileStore)(nil)

// NewFileStore builds the file backend over path. It does NOT touch the disk:
// the first call loads, so construction cannot fail and a missing file is the
// normal first run.
func NewFileStore(path string) *FileStore {
	return &FileStore{path: path, rows: map[string]map[string]DailyRecord{}}
}

// Path is where the rows live, for the runbook and the admin page.
func (s *FileStore) Path() string {
	if s == nil {
		return ""
	}
	return s.path
}

// LoadErr reports a corrupt or unreadable store. The store still SERVES (an
// empty history), because metering must never be able to take a page down —
// but it says so, so an operator can tell a store that failed to load from one
// nobody has written to yet.
func (s *FileStore) LoadErr() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	return s.loadErr
}

// meteringFile is the on-disk shape: a wrapper object rather than a bare slice
// so the format can grow a version or a note without breaking the parse.
type meteringFile struct {
	Records []DailyRecord `json:"records"`
}

func (s *FileStore) loadLocked() {
	if s.loaded {
		return
	}
	s.loaded = true
	if s.path == "" {
		return
	}
	// #nosec G304 G703 -- `s.path` is the operator-configured METERING_FILE (or the
	// packaged default), fixed at construction from the process environment. No
	// request, tenant or caller string ever reaches it, so there is nothing here
	// for a traversal to traverse; gosec's taint analysis cannot see that the
	// value came from env rather than from input.
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			s.loadErr = err
		}
		return
	}
	var f meteringFile
	if err := json.Unmarshal(raw, &f); err != nil {
		s.loadErr = err
		return
	}
	for _, r := range f.Records {
		if !ValidDay(r.Day) {
			continue
		}
		t := NormaliseTenant(r.TenantID)
		if s.rows[t] == nil {
			s.rows[t] = map[string]DailyRecord{}
		}
		r.TenantID = t
		s.rows[t][r.Day] = r
	}
}

func (s *FileStore) flushLocked() error {
	if s.path == "" {
		return nil
	}
	f := meteringFile{Records: make([]DailyRecord, 0, 64)}
	for _, byDay := range s.rows {
		for _, r := range byDay {
			f.Records = append(f.Records, r)
		}
	}
	sortRecords(f.Records)
	body, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(s.path, append(body, '\n'))
}

// Record folds a snapshot into the day's rows.
func (s *FileStore) Record(_ context.Context, at time.Time, byTenant map[string][]Reading) error {
	if s == nil {
		return errors.New("metering: no store")
	}
	at = at.UTC()
	day := at.Format(DayFormat)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	for tenant, readings := range byTenant {
		t := NormaliseTenant(tenant)
		if s.rows[t] == nil {
			s.rows[t] = map[string]DailyRecord{}
		}
		row, ok := s.rows[t][day]
		if !ok {
			row = DailyRecord{Day: day, TenantID: t}
		}
		next, err := Fold(row, readings, at)
		if err != nil {
			return err
		}
		s.rows[t][day] = next
		// Seal every OTHER day this tenant holds. A closed day's identity sets
		// are dead weight, and sealing them here means the cleanup rides the
		// write that was happening anyway rather than needing its own sweep.
		for d, other := range s.rows[t] {
			if d != day && !other.Sealed() {
				s.rows[t][d] = other.Seal()
			}
		}
	}
	return s.flushLocked()
}

// List returns the rows the caller may see.
func (s *FileStore) List(_ context.Context, tenant string, cross bool, from, to string) ([]DailyRecord, error) {
	if s == nil {
		return nil, errors.New("metering: no store")
	}
	if err := checkRange(from, to); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	out := []DailyRecord{}
	if cross {
		for _, byDay := range s.rows {
			collectRange(byDay, from, to, &out)
		}
		sortRecords(out)
		return out, nil
	}
	t := NormaliseTenant(tenant)
	if t == ScopeInstallation {
		// Default-closed. A caller with no resolved tenant scope reads nothing
		// — in particular NOT the installation row, whose key is also "".
		return out, nil
	}
	collectRange(s.rows[t], from, to, &out)
	sortRecords(out)
	return out, nil
}

// Rows is the number of persisted daily rows.
func (s *FileStore) Rows(context.Context) (int, error) {
	if s == nil {
		return 0, errors.New("metering: no store")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	n := 0
	for _, byDay := range s.rows {
		n += len(byDay)
	}
	return n, nil
}

// Prune drops rows older than `before`.
func (s *FileStore) Prune(_ context.Context, before string) (int, error) {
	if s == nil {
		return 0, errors.New("metering: no store")
	}
	if !ValidDay(before) {
		return 0, fmt.Errorf("metering: %q is not a UTC day", before)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loadLocked()
	n := 0
	for t, byDay := range s.rows {
		for d := range byDay {
			if d < before {
				delete(byDay, d)
				n++
			}
		}
		if len(byDay) == 0 {
			delete(s.rows, t)
		}
	}
	if n == 0 {
		return 0, nil
	}
	return n, s.flushLocked()
}

func collectRange(byDay map[string]DailyRecord, from, to string, out *[]DailyRecord) {
	for d, r := range byDay {
		if d < from || d > to {
			continue
		}
		*out = append(*out, r.Seal())
	}
}

func sortRecords(rows []DailyRecord) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Day != rows[j].Day {
			return rows[i].Day < rows[j].Day
		}
		return rows[i].TenantID < rows[j].TenantID
	})
}

// checkRange validates a period. Both ends are required and well-formed UTC
// days, and `from` may not be after `to` — a silently-empty answer to a
// malformed period is exactly the kind of quiet wrong number this contract
// exists to avoid.
func checkRange(from, to string) error {
	if !ValidDay(from) || !ValidDay(to) {
		return fmt.Errorf("metering: from and to must both be UTC days (%s)", DayFormat)
	}
	if from > to {
		return fmt.Errorf("metering: from (%s) is after to (%s)", from, to)
	}
	return nil
}

// PruneHorizon is the day before which rows are dropped, given a clock and the
// retention bound.
func PruneHorizon(now time.Time) string {
	return now.UTC().AddDate(0, 0, -RetentionDays).Format(DayFormat)
}

// atomicWrite is the durable-write contract used by the licence store, applied
// to the metering file: a UNIQUE temp name in the same directory, then a
// rename. The unique name matters — two concurrent writers of a fixed
// "<path>.tmp" corrupt each other and one write is silently lost.
func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	committed := false
	defer func() {
		if committed {
			return
		}
		_ = tmp.Close()     // best-effort: closing an abandoned temp; the write error is what matters
		_ = os.Remove(name) // best-effort: unlink of an uncommitted temp
	}()
	if err := tmp.Chmod(0o600); err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	committed = true
	return nil
}
