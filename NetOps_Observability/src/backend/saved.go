package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"sync"
	"time"
)

// Saved-objects store — savable searches, dashboards, and reports.
//
// File-backed (data/saved.json) for the same reason the user store is: the
// scaffold avoids a Postgres driver dependency to stay stdlib-only. The
// interface (List/Get/Create/Update/Delete) mirrors what a real backend
// would expose, so swapping to Postgres later is a single-file change with
// no API-surface impact. Body is opaque JSON owned by the frontend (a saved
// search's query+filters, a dashboard's panels, a report's schedule).

type SavedObject struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"` // saved_search | dashboard | report
	Name      string          `json:"name"`
	Owner     string          `json:"owner"`
	TenantID  string          `json:"tenant_id,omitempty"` // owning tenant ("" = global/shared)
	Body      json.RawMessage `json:"body"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

var validSavedTypes = map[string]bool{
	"saved_search": true,
	"dashboard":    true,
	"report":       true,
}

// savedRepo is the saved-object store seam (mirroring usersRepo/auditRepo, #33).
// List is tenant-scoped: a scoped principal passes its tenant (RLS on the pg
// backend / an in-memory filter on the file backend); infrastructure callers
// (the report scheduler) pass ("", true) for the platform view. Get/Create/
// Update/Delete operate by id; the HTTP layer enforces per-object authz
// (canSeeSaved/canMutateSaved) before mutating, so they need no scope arg.
type savedRepo interface {
	List(typ, tenant string, cross bool) []SavedObject
	Get(id string) (SavedObject, bool)
	Create(typ, name, owner, tenant string, body json.RawMessage) (SavedObject, error)
	Update(id, name string, body json.RawMessage) (SavedObject, error)
	Delete(id string) error
}

type savedStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]SavedObject
}

// newSavedStore selects the saved-object backend: under STORE_BACKEND=postgres a
// per-row, RLS-scoped repository (saved_pg.go); otherwise the file store.
func newSavedStore(path string) (savedRepo, error) {
	if ps, ok := backend.(*pgStore); ok {
		return newPgSavedStore(ps.db), nil
	}
	if path == "" {
		path = "/data/saved.json"
	}
	s := &savedStore{path: path, items: make(map[string]SavedObject)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *savedStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []SavedObject
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, o := range list {
		s.items[o.ID] = o
	}
	return nil
}

func (s *savedStore) flushLocked() error {
	list := make([]SavedObject, 0, len(s.items))
	for _, o := range s.items {
		list = append(list, o)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// List returns objects, newest first, optionally filtered by type.
// List returns saved objects of the given type visible to the tenant scope
// (the file backend filters in memory; the pg backend uses RLS). typ=="" lists
// all types; cross=true (platform) sees every tenant's objects.
func (s *savedStore) List(typ, tenant string, cross bool) []SavedObject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SavedObject, 0, len(s.items))
	for _, o := range s.items {
		if typ != "" && o.Type != typ {
			continue
		}
		if !sameTenant(o.TenantID, tenant, cross) {
			continue
		}
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].UpdatedAt.After(out[j].UpdatedAt) })
	return out
}

func (s *savedStore) Get(id string) (SavedObject, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.items[id]
	return o, ok
}

func (s *savedStore) Create(typ, name, owner, tenant string, body json.RawMessage) (SavedObject, error) {
	if !validSavedTypes[typ] {
		return SavedObject{}, errors.New("invalid type")
	}
	if name == "" {
		return SavedObject{}, errors.New("name required")
	}
	now := time.Now().UTC()
	o := SavedObject{
		ID:        randID(),
		Type:      typ,
		Name:      name,
		Owner:     owner,
		TenantID:  tenant,
		Body:      body,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[o.ID] = o
	if err := s.flushLocked(); err != nil {
		delete(s.items, o.ID)
		return SavedObject{}, err
	}
	return o, nil
}

func (s *savedStore) Update(id, name string, body json.RawMessage) (SavedObject, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.items[id]
	if !ok {
		return SavedObject{}, errors.New("not found")
	}
	prev := o
	if name != "" {
		o.Name = name
	}
	if len(body) > 0 {
		o.Body = body
	}
	o.UpdatedAt = time.Now().UTC()
	s.items[id] = o
	if err := s.flushLocked(); err != nil {
		s.items[id] = prev
		return SavedObject{}, err
	}
	return o, nil
}

func (s *savedStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.items[id]
	if !ok {
		return errors.New("not found")
	}
	delete(s.items, id)
	if err := s.flushLocked(); err != nil {
		s.items[id] = o
		return err
	}
	return nil
}

// randID returns a 16-byte hex identifier (stdlib crypto/rand).
func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
