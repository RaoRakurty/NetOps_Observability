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
}

// EnvStoreFile is the file backend's path knob.
const EnvStoreFile = "DEM_EXPERIENCE_FILE"

// changeRetention bounds the file backend's change log per tenant. Changes are
// an append-only feed and would otherwise grow without limit; the OLDEST are
// dropped, which is the right end to lose — a change from last month cannot be
// the cause of an incident inside the lookback.
const changeRetention = 2000

// FileStore is the non-Postgres backend. Path "" keeps it in memory (tests, and
// a dev build with no persistence configured).
type FileStore struct {
	mu   sync.RWMutex
	path string
	// journeys / changes are tenant → …; the tenant key IS the isolation
	// boundary, exactly as in internal/dem's catalogue.
	journeys map[string]map[string]JourneyDefinition
	changes  map[string][]ChangeEvent
	loadErr  error
	now      func() time.Time
}

var _ Store = (*FileStore)(nil)

type filePayload struct {
	Journeys map[string][]JourneyDefinition `json:"journeys"`
	Changes  map[string][]ChangeEvent       `json:"changes"`
}

// NewFileStore loads the persisted state. A missing file starts empty; a
// CORRUPT one starts empty AND records the error for the integrator to log — a
// store that failed to load must never look like one a tenant never wrote.
func NewFileStore(path string) *FileStore {
	s := &FileStore{
		path:     path,
		journeys: map[string]map[string]JourneyDefinition{},
		changes:  map[string][]ChangeEvent{},
		now:      func() time.Time { return time.Now().UTC() },
	}
	if path == "" {
		return s
	}
	b, err := platformdb.Load(path)
	if err != nil {
		return s
	}
	var payload filePayload
	if err := json.Unmarshal(b, &payload); err != nil {
		s.loadErr = err
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
	return s
}

// LoadErr reports a corrupt-file condition for the integrator to log.
func (s *FileStore) LoadErr() error { return s.loadErr }

func (s *FileStore) flushLocked() error {
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
		out.Changes[tenant] = list
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
	prev := s.changes[t]
	for _, c := range prev {
		if c.ID == in.ID {
			// Changes are IMMUTABLE facts. A repeat of the same id is accepted
			// idempotently and does not rewrite the recorded one.
			return c, nil
		}
	}
	s.changes[t] = trimChanges(append(prev, in))
	if err := s.flushLocked(); err != nil {
		s.changes[t] = prev
		return ChangeEvent{}, err
	}
	return in, nil
}

// ── shared helpers used by both backends ────────────────────────────────────

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
