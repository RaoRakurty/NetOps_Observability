// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package experience

// store.go — the Store seam and its file backend.
//
// TWO OBJECTS ARE PERSISTED HERE and nothing else: the JOURNEY DEFINITIONS an
// operator declares, and the CHANGE EVENTS producers report. Everything else in
// this package — evidence, hypotheses, incidents, scores — is DERIVED from
// immutable facts at read time, so there is nothing to keep in sync and no
// window in which a stored conclusion contradicts the evidence under it.
//
// §3a RULE 4: isolation lives in the STORE. The file backend keys rows by
// tenant, so a lookup for A can only ever walk A's bucket; the Postgres twin
// (pg.go, migration dem_journeys/dem_change_events) runs every statement inside
// WithTenant so the FORCE-RLS policy always has its GUC. There is no
// "list every tenant's journeys" method on this interface at all.

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

// ErrNotFound is the store's miss. Every HTTP path turns it into 404 —
// including for another tenant's id, so an id is never confirmed to exist.
var ErrNotFound = errors.New("experience: not found")

// ErrFull is returned when a tenant is at its journey ceiling.
var ErrFull = fmt.Errorf("experience: the journey catalogue is full (max %d journeys per tenant)", MaxJourneysPerTenant)

// ErrStoreUnreadable is returned by every write while the store file exists but
// could not be read or parsed at start-up. It is a REFUSAL, not a failure of
// the write itself: the operator repairs or removes the file, and the api picks
// it up on the next start.
var ErrStoreUnreadable = errors.New("experience: the store file could not be read at start-up, so writes are refused until it is repaired or removed")

// ErrPromotionsFull is returned when a tenant is at its promotion ceiling.
var ErrPromotionsFull = fmt.Errorf("experience: the promoted-incident table is full (max %d per tenant)", MaxPromotionsPerTenant)

// ChangeQuery bounds a change listing.
type ChangeQuery struct {
	Since time.Time
	Types []string
	App   string
	Site  string
	Limit int
}

// Store is the persistence seam.
type Store interface {
	ListJourneys(ctx context.Context, tenant string) ([]JourneyDefinition, error)
	GetJourney(ctx context.Context, tenant, id string) (JourneyDefinition, error)
	CreateJourney(ctx context.Context, in JourneyDefinition) (JourneyDefinition, error)
	UpdateJourney(ctx context.Context, tenant, id string, in JourneyDefinition) (JourneyDefinition, error)
	DeleteJourney(ctx context.Context, tenant, id string) error

	ListChanges(ctx context.Context, tenant string, q ChangeQuery) ([]ChangeEvent, error)
	RecordChange(ctx context.Context, in ChangeEvent) (ChangeEvent, error)

	// Promotions are the THIRD persisted object (tracker 255): the durable link
	// from a derived experience incident to the platform incident record it
	// became, plus the evidence packet as it stood at that moment. It is
	// persisted for the same reason the other two are — an operator's decision
	// is a fact, not a derivation.
	ListPromotions(ctx context.Context, tenant string) ([]Promotion, error)
	GetPromotion(ctx context.Context, tenant, experienceID string) (Promotion, error)
	// SavePromotion is idempotent on (tenant, experience_id): re-promoting the
	// same window returns the row already stored rather than minting a second
	// link to a second incident.
	SavePromotion(ctx context.Context, in Promotion) (Promotion, error)
}

// EnvStoreFile is the file backend's path knob.
const EnvStoreFile = "DEM_EXPERIENCE_FILE"

// changeRetention bounds the file backend's change log per tenant. Changes are
// an append-only feed and would otherwise grow without limit; the OLDEST are
// dropped, which is the right end to lose — a change from last month cannot be
// the cause of an incident inside the lookback.
const changeRetention = 2000

// MaxPromotionsPerTenant bounds the file backend's promotion table. Promotions
// are operator decisions, so the ceiling is generous and hitting it is a
// REFUSAL rather than a silent eviction: dropping an operator's record of why
// an incident was raised is not a bound, it is data loss.
const MaxPromotionsPerTenant = 5000

// FileStore is the non-Postgres backend. Path "" keeps it in memory (tests, and
// a dev build with no persistence configured).
type FileStore struct {
	mu   sync.RWMutex
	path string
	// journeys / changes are tenant → …; the tenant key IS the isolation
	// boundary, exactly as in internal/dem's catalogue.
	journeys map[string]map[string]JourneyDefinition
	changes  map[string][]ChangeEvent
	// promotions is tenant → derived incident id → the durable link.
	promotions map[string]map[string]Promotion
	loadErr    error
	// unreadable is set when the store file EXISTS but its contents could not
	// be established — an I/O or permission failure, or JSON we could not
	// parse. It is the stricter half of loadErr: loadErr also covers rows we
	// read and deliberately dropped, where rewriting the file is the intended
	// repair. When the contents are unknown, every write is refused, because a
	// flush would replace the whole file with what this process happens to
	// hold, which after such a load is nothing at all.
	unreadable error
	now        func() time.Time
}

var _ Store = (*FileStore)(nil)

type filePayload struct {
	Journeys   map[string][]JourneyDefinition `json:"journeys"`
	Changes    map[string][]ChangeEvent       `json:"changes"`
	Promotions map[string][]Promotion         `json:"promotions,omitempty"`
}

// NewFileStore loads the persisted state. A MISSING file starts empty; a file
// that exists but could not be read or parsed starts empty AND records the
// error for the integrator to log — a store that failed to load must never look
// like one a tenant never wrote — AND refuses every write from then on, so the
// file it could not read is never replaced by an empty one.
func NewFileStore(path string) *FileStore {
	s := &FileStore{
		path:       path,
		journeys:   map[string]map[string]JourneyDefinition{},
		changes:    map[string][]ChangeEvent{},
		promotions: map[string]map[string]Promotion{},
		now:        func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		// Genuinely absent: nobody has written this store yet. That is the
		// normal first-boot state and an empty store is the right answer.
		return s
	case err != nil:
		// UNREADABLE IS NOT ABSENT. Folding the two together starts empty with
		// nothing logged, and the first write then renames a temp file over a
		// file whose contents were never read.
		s.loadErr = fmt.Errorf("experience: the store file could not be read: %w", err)
		s.unreadable = s.loadErr
		return s
	}
	var payload filePayload
	if err := json.Unmarshal(b, &payload); err != nil {
		s.loadErr = fmt.Errorf("experience: the store file could not be parsed: %w", err)
		s.unreadable = s.loadErr
		return s
	}
	for rawTenant, list := range payload.Journeys {
		t := normTenant(rawTenant)
		if t == "" || t == "*" {
			s.loadErr = errors.New("experience: the store file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, j := range list {
			j.TenantID = t // the bucket is authoritative, never the row's own field
			if err := j.Validate(); err != nil || j.ID == "" {
				s.loadErr = errors.New("experience: the store file holds an invalid journey; it was dropped")
				continue
			}
			if s.journeys[t] == nil {
				s.journeys[t] = map[string]JourneyDefinition{}
			}
			if len(s.journeys[t]) >= MaxJourneysPerTenant {
				break
			}
			s.journeys[t][j.ID] = j
		}
	}
	for rawTenant, list := range payload.Changes {
		t := normTenant(rawTenant)
		if t == "" || t == "*" {
			s.loadErr = errors.New("experience: the store file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, c := range list {
			c.TenantID = t
			if err := c.Validate(); err != nil {
				s.loadErr = errors.New("experience: the store file holds an invalid change; it was dropped")
				continue
			}
			s.changes[t] = append(s.changes[t], c)
		}
		s.changes[t] = trimChanges(s.changes[t])
	}
	for rawTenant, list := range payload.Promotions {
		t := normTenant(rawTenant)
		if t == "" || t == "*" {
			s.loadErr = errors.New("experience: the store file holds a non-concrete tenant bucket; it was dropped")
			continue
		}
		for _, p := range list {
			p.TenantID = t // the bucket is authoritative, never the row's own field
			if err := p.Validate(); err != nil {
				s.loadErr = errors.New("experience: the store file holds an invalid promotion; it was dropped")
				continue
			}
			if s.promotions[t] == nil {
				s.promotions[t] = map[string]Promotion{}
			}
			s.promotions[t][p.ExperienceID] = p
		}
	}
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileStore) LoadErr() error { return s.loadErr }

// flushLocked persists the whole store as it currently stands.
func (s *FileStore) flushLocked() error { return s.flushViewLocked(nil) }

// flushViewLocked persists the store as it WOULD BE with the change log of each
// tenant in `replace` swapped for the supplied one, WITHOUT touching s.changes.
// It exists for RecordChange: the in-memory log must not change until the write
// that makes the change durable has succeeded.
//
// This is deliberately not a rollback. Nothing is mutated and then put back, so
// there is no shared backing array to restore wrongly. The old order did the
// other thing and corrupted the log every time the write failed (see
// RecordChange).
func (s *FileStore) flushViewLocked(replace map[string][]ChangeEvent) error {
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
	out := filePayload{Journeys: map[string][]JourneyDefinition{}, Changes: map[string][]ChangeEvent{}}
	for tenant, bucket := range s.journeys {
		list := make([]JourneyDefinition, 0, len(bucket))
		for _, j := range bucket {
			list = append(list, j)
		}
		sortJourneys(list)
		out.Journeys[tenant] = list
	}
	for tenant, list := range s.changes {
		if _, ok := replace[tenant]; ok {
			continue
		}
		out.Changes[tenant] = list
	}
	for tenant, view := range replace {
		out.Changes[tenant] = view
	}
	if len(s.promotions) > 0 {
		out.Promotions = map[string][]Promotion{}
		for tenant, bucket := range s.promotions {
			list := make([]Promotion, 0, len(bucket))
			for _, p := range bucket {
				list = append(list, p)
			}
			sortPromotions(list)
			out.Promotions[tenant] = list
		}
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	return platformdb.Save(s.path, b)
}

func (s *FileStore) ListJourneys(_ context.Context, tenant string) ([]JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []JourneyDefinition{}, nil // default-closed: no scope, no rows
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]JourneyDefinition, 0, len(s.journeys[t]))
	for _, j := range s.journeys[t] {
		out = append(out, j)
	}
	sortJourneys(out)
	return out, nil
}

func (s *FileStore) GetJourney(_ context.Context, tenant, id string) (JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return JourneyDefinition{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.journeys[t][id]
	if !ok {
		return JourneyDefinition{}, ErrNotFound
	}
	return j, nil
}

func (s *FileStore) CreateJourney(_ context.Context, in JourneyDefinition) (JourneyDefinition, error) {
	if err := in.Validate(); err != nil {
		return JourneyDefinition{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := in.TenantID
	if len(s.journeys[t]) >= MaxJourneysPerTenant {
		return JourneyDefinition{}, ErrFull
	}
	now := s.now()
	in.ID, in.Version = newJourneyID(), 1
	in.CreatedAt, in.UpdatedAt = now, now
	if s.journeys[t] == nil {
		s.journeys[t] = map[string]JourneyDefinition{}
	}
	s.journeys[t][in.ID] = in
	if err := s.flushLocked(); err != nil {
		delete(s.journeys[t], in.ID) // a failed write never leaves memory ahead of the file
		return JourneyDefinition{}, err
	}
	return in, nil
}

func (s *FileStore) UpdateJourney(_ context.Context, tenant, id string, in JourneyDefinition) (JourneyDefinition, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return JourneyDefinition{}, ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.journeys[t][id]
	if !ok {
		return JourneyDefinition{}, ErrNotFound
	}
	in.TenantID, in.ID = prev.TenantID, prev.ID
	in.CreatedAt, in.CreatedBy = prev.CreatedAt, prev.CreatedBy
	in.Version = prev.Version + 1
	if err := in.Validate(); err != nil {
		return JourneyDefinition{}, err
	}
	in.UpdatedAt = s.now()
	s.journeys[t][id] = in
	if err := s.flushLocked(); err != nil {
		s.journeys[t][id] = prev
		return JourneyDefinition{}, err
	}
	return in, nil
}

func (s *FileStore) DeleteJourney(_ context.Context, tenant, id string) error {
	t, err := concreteTenant(tenant)
	if err != nil {
		return ErrNotFound
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	prev, ok := s.journeys[t][id]
	if !ok {
		return ErrNotFound
	}
	delete(s.journeys[t], id)
	if err := s.flushLocked(); err != nil {
		s.journeys[t][id] = prev
		return err
	}
	return nil
}

func (s *FileStore) ListChanges(_ context.Context, tenant string, q ChangeQuery) ([]ChangeEvent, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []ChangeEvent{}, nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return filterChanges(s.changes[t], q), nil
}

func (s *FileStore) RecordChange(_ context.Context, in ChangeEvent) (ChangeEvent, error) {
	if in.ID == "" {
		in.ID = newChangeID()
	}
	if err := in.Validate(); err != nil {
		return ChangeEvent{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := in.TenantID
	for _, c := range s.changes[t] {
		if c.ID == in.ID {
			// Changes are IMMUTABLE facts. A repeat of the same id is accepted
			// idempotently and does not rewrite the recorded one.
			return c, nil
		}
	}
	// Build the next log in ITS OWN array. `append` on the live slice would
	// write into any spare capacity, and trimChanges sorts in place, so both
	// would reorder the log the store is still serving before we know the write
	// will succeed.
	next := make([]ChangeEvent, 0, len(s.changes[t])+1)
	next = append(next, s.changes[t]...)
	next = trimChanges(append(next, in))
	// Persist FIRST, adopt SECOND. The other order put a SAVED SLICE HEADER back
	// on failure, which restores a mutated array under the old length: the
	// refused change stayed in the log and the oldest kept change fell out of
	// it, and the next successful write made both durable (§10).
	if err := s.flushViewLocked(map[string][]ChangeEvent{t: next}); err != nil {
		return ChangeEvent{}, err
	}
	s.changes[t] = next
	return in, nil
}

func (s *FileStore) ListPromotions(_ context.Context, tenant string) ([]Promotion, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return []Promotion{}, nil // default-closed: no scope, no rows
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Promotion, 0, len(s.promotions[t]))
	for _, p := range s.promotions[t] {
		out = append(out, p)
	}
	sortPromotions(out)
	return out, nil
}

func (s *FileStore) GetPromotion(_ context.Context, tenant, experienceID string) (Promotion, error) {
	t, err := concreteTenant(tenant)
	if err != nil {
		return Promotion{}, ErrNotFound
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	p, ok := s.promotions[t][experienceID]
	if !ok {
		return Promotion{}, ErrNotFound
	}
	return p, nil
}

func (s *FileStore) SavePromotion(_ context.Context, in Promotion) (Promotion, error) {
	if err := in.Validate(); err != nil {
		return Promotion{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t := in.TenantID
	if prev, ok := s.promotions[t][in.ExperienceID]; ok {
		// Idempotent: the first promotion is the one that happened. Returning
		// the stored row is what makes a double-click cost nothing, and what
		// keeps the frozen packet from being rewritten by a later derivation.
		return prev, nil
	}
	if len(s.promotions[t]) >= MaxPromotionsPerTenant {
		return Promotion{}, ErrPromotionsFull
	}
	if s.promotions[t] == nil {
		s.promotions[t] = map[string]Promotion{}
	}
	s.promotions[t][in.ExperienceID] = in
	if err := s.flushLocked(); err != nil {
		delete(s.promotions[t], in.ExperienceID)
		return Promotion{}, err
	}
	return in, nil
}

// ── shared helpers used by both backends ────────────────────────────────────

func sortPromotions(list []Promotion) {
	sort.SliceStable(list, func(i, j int) bool {
		if !list[i].PromotedAt.Equal(list[j].PromotedAt) {
			return list[i].PromotedAt.After(list[j].PromotedAt)
		}
		return list[i].ExperienceID < list[j].ExperienceID
	})
}

func filterChanges(list []ChangeEvent, q ChangeQuery) []ChangeEvent {
	types := map[string]bool{}
	for _, t := range q.Types {
		types[strings.ToUpper(strings.TrimSpace(t))] = true
	}
	out := make([]ChangeEvent, 0, len(list))
	for _, c := range list {
		if !q.Since.IsZero() && c.EventAt.Before(q.Since) {
			continue
		}
		if len(types) > 0 && !types[c.Type] {
			continue
		}
		if q.App != "" && c.App != q.App {
			continue
		}
		if q.Site != "" && c.Site != q.Site {
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].EventAt.After(out[j].EventAt)
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out
}

func trimChanges(list []ChangeEvent) []ChangeEvent {
	sort.SliceStable(list, func(i, j int) bool {
		return list[i].EventAt.After(list[j].EventAt)
	})
	if len(list) > changeRetention {
		list = list[:changeRetention]
	}
	return list
}

func sortJourneys(list []JourneyDefinition) {
	sort.Slice(list, func(i, j int) bool {
		if wi, wj := ImportanceWeight(list[i].BusinessImportance), ImportanceWeight(list[j].BusinessImportance); wi != wj {
			return wi > wj
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}

// normTenant is this package's ONE tenant-key normalization, matching the API
// boundary's. Duplicated rather than shared through a "utils" package.
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// concreteTenant fails CLOSED on an access that has no single tenant to scope
// to. "" and "*" are refused at the store, so no future caller can reintroduce
// a wildcard (§3a).
func concreteTenant(t string) (string, error) {
	n := normTenant(t)
	if n == "" || n == "*" {
		return "", errors.New("experience: a concrete tenant is required (cross-tenant access is refused)")
	}
	return n, nil
}

func newJourneyID() string { return "jny-" + randomHex(16) }
func newChangeID() string  { return "chg-" + randomHex(16) }

// randomHex mints an opaque id. crypto/rand only: a predictable id is a
// guessable URL, and the store's 404-on-foreign-id promise is worth more when
// the id could not have been guessed in the first place.
func randomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing is not a condition to paper over with a weaker
		// source; the caller sees an id it can detect as invalid.
		return ""
	}
	return hex.EncodeToString(b)
}

// ValidJourneyID / ValidChangeID accept only ids this package mints, checked
// BEFORE the store is touched so a path-traversal-shaped id never reaches a
// key lookup.
func ValidJourneyID(id string) bool { return validPrefixedID(id, "jny-", 32) }

// ValidChangeID reports whether id has the shape this package mints.
func ValidChangeID(id string) bool { return validPrefixedID(id, "chg-", 32) }

func validPrefixedID(id, prefix string, hexLen int) bool {
	if len(id) != len(prefix)+hexLen || !strings.HasPrefix(id, prefix) {
		return false
	}
	for _, r := range id[len(prefix):] {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
