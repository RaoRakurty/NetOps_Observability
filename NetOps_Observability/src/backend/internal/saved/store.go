package saved

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"os"
	"sort"
	"strings"
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

type Object struct {
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

// Repo is the saved-object store seam (mirroring usersRepo/auditRepo, #33).
// List is tenant-scoped: a scoped principal passes its tenant (RLS on the pg
// backend / an in-memory filter on the file backend); infrastructure callers
// (the report scheduler) pass ("", true) for the platform view. Get/Create/
// Update/Delete operate by id; the HTTP layer enforces per-object authz
// (canSeeSaved/canMutateSaved) before mutating, so they need no scope arg.
type Repo interface {
	List(typ, tenant string, cross bool) []Object
	Get(id string) (Object, bool)
	Create(typ, name, owner, tenant string, body json.RawMessage) (Object, error)
	Update(id, name string, body json.RawMessage) (Object, error)
	Delete(id string) error
}

type Store struct {
	mu    sync.RWMutex
	path  string
	kv    KV
	items map[string]Object
}

// NewStore selects the saved-object backend: under STORE_BACKEND=postgres a
// per-row, RLS-scoped repository (saved_pg.go); otherwise the file store.
// KV abstracts persistence (the platform kv layer).
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

// NewFileStore opens the file-backed store (backend selection is main's job).
func NewFileStore(path string, kv KV) (Repo, error) {
	if kv == nil {
		return nil, errors.New("saved.NewFileStore: kv is required")
	}
	if path == "" {
		path = "/data/saved.json"
	}
	s := &Store{path: path, kv: kv, items: make(map[string]Object)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := s.kv.Load(s.path)
	if err != nil {
		return err
	}
	var list []Object
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, o := range list {
		s.items[o.ID] = o
	}
	return nil
}

func (s *Store) flushLocked() error {
	list := make([]Object, 0, len(s.items))
	for _, o := range s.items {
		list = append(list, o)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return s.kv.Save(s.path, b)
}

// List returns objects, newest first, optionally filtered by type.
// List returns saved objects of the given type visible to the tenant scope
// (the file backend filters in memory; the pg backend uses RLS). typ=="" lists
// all types; cross=true (platform) sees every tenant's objects.
func (s *Store) List(typ, tenant string, cross bool) []Object {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Object, 0, len(s.items))
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

func (s *Store) Get(id string) (Object, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.items[id]
	return o, ok
}

func (s *Store) Create(typ, name, owner, tenant string, body json.RawMessage) (Object, error) {
	if !validSavedTypes[typ] {
		return Object{}, errors.New("invalid type")
	}
	if name == "" {
		return Object{}, errors.New("name required")
	}
	now := time.Now().UTC()
	o := Object{
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
		return Object{}, err
	}
	return o, nil
}

func (s *Store) Update(id, name string, body json.RawMessage) (Object, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.items[id]
	if !ok {
		return Object{}, errors.New("not found")
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
		return Object{}, err
	}
	return o, nil
}

func (s *Store) Delete(id string) error {
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
// sameTenant mirrors the integrator's tenancy filter (duplicated).
func sameTenant(resourceTenant, tenant string, cross bool) bool {
	if cross {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(tenant))
}

func randID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
