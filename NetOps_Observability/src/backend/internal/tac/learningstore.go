// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// learningstore.go — where the learning backlog and its candidates live.
//
// ISOLATION LIVES IN THE STORE (§3a rule 4), exactly as it does for templates:
// rows are held in a TENANT-KEYED map, so a lookup for tenant A can only ever
// walk A's bucket, and there is deliberately no "list every tenant's rows" on
// this seam at all. Writes take a CONCRETE tenant or fail — "" and "*" are not
// tenants and can never own a row.
//
// OWNERSHIP IS STAMPED, NEVER ACCEPTED (§3a rule 2). Both wire types are
// written without a tenant field; the store sets TenantID from the resolved
// principal the handler authorised on.
//
// WHY FILE-BACKED. A learning record is an artifact OF a collection, and its
// sibling — the bundle itself (store.go) — is file-backed for the same reason:
// it is per-collection evidence with a retention ceiling, not control-plane
// state that other queries join against. Persistence goes through platformdb,
// the same seam the template store uses, so a Postgres twin is a wiring change
// and not a rewrite.
//
// BOUNDED, AND OLDEST-FIRST (§9). MaxRecordsPerTenant records and
// MaxCandidatesPerTenant candidates per tenant; a record past the ceiling
// evicts the OLDEST, because the backlog's value is what was collected
// recently. A candidate at the ceiling REFUSES instead — an operator's written
// proposal is not something this store may silently drop.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"sync"
	"time"

	"netops/backend/internal/platformdb"
)

// ErrStoreUnreadable is returned by every write of BOTH file stores in this
// package (the learning backlog here and the templates in templatestore.go)
// while their file exists but could not be read or parsed at start-up. It is a
// REFUSAL, not a failure of the write itself: the file's real contents were
// never established, so a save would not update the file, it would REPLACE it
// with whatever this process happens to hold — which after such a load is
// nothing at all. The operator repairs or removes the file and the api picks it
// up on the next start.
var ErrStoreUnreadable = errors.New("tac: the stored file could not be read at start-up, so writes are refused until it is repaired or removed")

// MaxRecordsPerTenant bounds a tenant's learning backlog.
const MaxRecordsPerTenant = 200

// EnvLearningFile is the file backend's path knob.
const EnvLearningFile = "TAC_LEARNING_FILE"

// LearningStore is the seam. Every method takes the caller's CONCRETE tenant;
// a foreign id is ErrCandidateNotFound, never a 403 (§3a rule 1).
type LearningStore interface {
	// PutRecord files one collection's unrecognised output.
	PutRecord(ctx context.Context, rec LearningRecord) error
	// Records lists this tenant's backlog, newest collection first.
	Records(ctx context.Context, tenant string) ([]LearningRecord, error)
	// Candidates lists this tenant's proposals.
	Candidates(ctx context.Context, tenant string) ([]Candidate, error)
	// Candidate reads one.
	Candidate(ctx context.Context, tenant, id string) (Candidate, error)
	// CreateCandidate stores a new proposal (id minted here).
	CreateCandidate(ctx context.Context, c Candidate) (Candidate, error)
	// UpdateCandidate replaces one, keeping its identity and created stamps.
	UpdateCandidate(ctx context.Context, tenant, id string, c Candidate) (Candidate, error)
	// DeleteCandidate removes one.
	DeleteCandidate(ctx context.Context, tenant, id string) error
}

// newLearningID mints a random id. Random rather than derived so two tenants'
// records never collide and an id is not guessable from a device name.
func newLearningID(prefix string) string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		// A predictable fallback id would make ids enumerable. The caller sees
		// the write fail, which is the honest outcome.
		return ""
	}
	return prefix + hex.EncodeToString(b[:])
}

// NewRecordID mints an id for a learning record.
func NewRecordID() string { return newLearningID("lr-") }

type learningBucket struct {
	Records    []LearningRecord `json:"records"`
	Candidates []Candidate      `json:"candidates"`
}

// FileLearningStore is the non-Postgres backend. Path "" keeps it purely in
// memory (tests, and a build with no persistence configured).
type FileLearningStore struct {
	mu   sync.RWMutex
	path string
	// rows is tenant → bucket. The tenant key IS the isolation boundary.
	rows    map[string]*learningBucket
	loadErr error
	// unreadable is the stricter half of loadErr: it is set only when the file
	// EXISTS but its contents could not be established — an I/O or permission
	// failure, or JSON we could not parse. loadErr on its own also covers rows
	// we read and deliberately dropped, where rewriting the file IS the
	// intended repair. When the contents are unknown, every write is refused.
	unreadable error
	now        func() time.Time
}

var _ LearningStore = (*FileLearningStore)(nil)

// NewFileLearningStore loads the persisted backlog. A MISSING file starts
// empty; a file that exists but could not be read or parsed starts empty AND
// records the error, which the integrator logs — a backlog that failed to load
// must never look like one nothing was ever filed into (§10) — AND refuses
// every write from then on, so the file it could not read is never replaced by
// an empty one.
func NewFileLearningStore(path string) *FileLearningStore {
	s := &FileLearningStore{
		path: path,
		rows: map[string]*learningBucket{},
		now:  func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: nothing has been filed yet. That is the normal
		// first-boot state and an empty backlog is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folding the two together starts empty with
		// nothing logged, and the first write then renames a temp file over a
		// file whose contents were never read.
		s.loadErr = fmt.Errorf("tac: the learning file could not be read: %w", err)
		s.unreadable = s.loadErr
		return s
	case len(b) == 0:
		// Present but empty: nothing stored yet, nothing broken.
		return s
	}
	var raw map[string]*learningBucket
	if uerr := json.Unmarshal(b, &raw); uerr != nil {
		s.loadErr = fmt.Errorf("tac: the learning file could not be parsed: %w", uerr)
		s.unreadable = s.loadErr
		return s
	}
	for rawTenant, bucket := range raw {
		t, terr := concreteTenantID(rawTenant)
		if terr != nil || bucket == nil {
			s.loadErr = errors.New("tac: the learning file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		clean := &learningBucket{}
		for _, rec := range bucket.Records {
			if rec.ID == "" || !candIDRE.MatchString(rec.ID) {
				s.loadErr = errors.New("tac: the learning file holds an invalid record; it was dropped")
				continue
			}
			rec.TenantID = t // the bucket is authoritative, never the row's field
			clean.Records = append(clean.Records, rec)
			if len(clean.Records) >= MaxRecordsPerTenant {
				break
			}
		}
		for _, c := range bucket.Candidates {
			if c.ID == "" || !candIDRE.MatchString(c.ID) || !validCandidateStatus(c.Status) {
				s.loadErr = errors.New("tac: the learning file holds an invalid candidate; it was dropped")
				continue
			}
			c.TenantID = t
			clean.Candidates = append(clean.Candidates, c)
			if len(clean.Candidates) >= MaxCandidatesPerTenant {
				break
			}
		}
		s.rows[t] = clean
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileLearningStore) LoadErr() error { return s.loadErr }

func (s *FileLearningStore) bucketLocked(t string) *learningBucket {
	if s.rows[t] == nil {
		s.rows[t] = &learningBucket{}
	}
	return s.rows[t]
}

// flushLocked persists everything. Callers hold the write lock and roll their
// change back when this fails, so a failed write never leaves the in-memory
// view ahead of the file.
func (s *FileLearningStore) flushLocked() error {
	if s.unreadable != nil {
		// The file's real contents are unknown, so a flush would not update it
		// — it would REPLACE it with what this process holds, which after an
		// unreadable load is nothing. Refuse, and say why: the caller rolls its
		// change back and the operator gets an error instead of a silent loss.
		return fmt.Errorf("%w: %w", ErrStoreUnreadable, s.unreadable)
	}
	if s.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(s.rows, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileLearningStore) PutRecord(_ context.Context, rec LearningRecord) error {
	t, err := concreteTenantID(rec.TenantID)
	if err != nil {
		return err
	}
	if rec.ID == "" || !candIDRE.MatchString(rec.ID) {
		return errors.New("tac: a learning record needs an id")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucketLocked(t)
	rec.TenantID = t
	// The next log is built in ITS OWN array. Saving the live slice HEADER and
	// putting it back on a failed flush restored a mutated array under the old
	// length — `append` writes into spare capacity and sortRecords permutes in
	// place — so the refused record stayed in the log and the oldest kept one
	// fell out of it, and the next successful flush made both durable (§10).
	next := make([]LearningRecord, 0, len(b.Records)+1)
	next = append(next, b.Records...)
	next = append(next, rec)
	sortRecords(next)
	if len(next) > MaxRecordsPerTenant {
		// Newest-first ordering means the tail is the oldest.
		next = next[:MaxRecordsPerTenant]
	}
	before := b.Records
	b.Records = next
	if ferr := s.flushLocked(); ferr != nil {
		b.Records = before
		return ferr
	}
	return nil
}

func (s *FileLearningStore) Records(_ context.Context, tenant string) ([]LearningRecord, error) {
	out := []LearningRecord{}
	t, err := concreteTenantID(tenant)
	if err != nil {
		return out, nil // default-closed: no scope, no rows (never a 500)
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b := s.rows[t]; b != nil {
		out = append(out, b.Records...)
	}
	sortRecords(out)
	return out, nil
}

func (s *FileLearningStore) Candidates(_ context.Context, tenant string) ([]Candidate, error) {
	out := []Candidate{}
	t, err := concreteTenantID(tenant)
	if err != nil {
		return out, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if b := s.rows[t]; b != nil {
		out = append(out, b.Candidates...)
	}
	SortCandidates(out)
	return out, nil
}

func (s *FileLearningStore) Candidate(_ context.Context, tenant, id string) (Candidate, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Candidate{}, ErrCandidateNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	b := s.rows[t]
	if b == nil {
		return Candidate{}, ErrCandidateNotFound
	}
	for _, c := range b.Candidates {
		if c.ID == id {
			return c, nil
		}
	}
	return Candidate{}, ErrCandidateNotFound
}

func (s *FileLearningStore) CreateCandidate(_ context.Context, in Candidate) (Candidate, error) {
	t, err := concreteTenantID(in.TenantID)
	if err != nil {
		return Candidate{}, err
	}
	id := newLearningID("cand-")
	if id == "" {
		return Candidate{}, errors.New("tac: a candidate id could not be minted")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.bucketLocked(t)
	if len(b.Candidates) >= MaxCandidatesPerTenant {
		return Candidate{}, ErrCandidateLimit
	}
	now := s.now().UTC()
	in.ID, in.TenantID = id, t
	in.CreatedAt, in.UpdatedAt = now, now
	before := b.Candidates
	b.Candidates = append(b.Candidates, in)
	if ferr := s.flushLocked(); ferr != nil {
		b.Candidates = before
		return Candidate{}, ferr
	}
	return in, nil
}

func (s *FileLearningStore) UpdateCandidate(_ context.Context, tenant, id string, in Candidate) (Candidate, error) {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return Candidate{}, ErrCandidateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.rows[t]
	if b == nil {
		return Candidate{}, ErrCandidateNotFound
	}
	for i, have := range b.Candidates {
		if have.ID != id {
			continue
		}
		// Identity and provenance are IMMUTABLE across an update: an edit
		// changes what a proposal says, never who wrote it or when.
		in.ID, in.TenantID = have.ID, t
		in.CreatedAt, in.CreatedBy = have.CreatedAt, have.CreatedBy
		in.UpdatedAt = s.now().UTC()
		b.Candidates[i] = in
		if ferr := s.flushLocked(); ferr != nil {
			b.Candidates[i] = have
			return Candidate{}, ferr
		}
		return in, nil
	}
	return Candidate{}, ErrCandidateNotFound
}

func (s *FileLearningStore) DeleteCandidate(_ context.Context, tenant, id string) error {
	t, err := concreteTenantID(tenant)
	if err != nil {
		return ErrCandidateNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b := s.rows[t]
	if b == nil {
		return ErrCandidateNotFound
	}
	for i, have := range b.Candidates {
		if have.ID != id {
			continue
		}
		before := b.Candidates
		next := append(append([]Candidate{}, b.Candidates[:i]...), b.Candidates[i+1:]...)
		b.Candidates = next
		if ferr := s.flushLocked(); ferr != nil {
			b.Candidates = before
			return ferr
		}
		return nil
	}
	return ErrCandidateNotFound
}

// sortRecords orders newest collection first, breaking ties on the id so the
// order is total and a listing is stable across reads.
func sortRecords(r []LearningRecord) {
	sort.SliceStable(r, func(i, j int) bool {
		if !r[i].CollectedAt.Equal(r[j].CollectedAt) {
			return r[i].CollectedAt.After(r[j].CollectedAt)
		}
		return r[i].ID < r[j].ID
	})
}
