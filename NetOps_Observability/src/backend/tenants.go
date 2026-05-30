package main

// tenants.go — multi-tenancy. A tenant is a logical isolation boundary; users,
// devices, dashboards and alerts are scoped to one. File-backed (tenants.json),
// same pattern as the other stores. See docs/IDENTITY_ACCESS.md.

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// TenantGlobal is the seeded root tenant that owns shared defaults.
const TenantGlobal = "global"

type Tenant struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	Note      string    `json:"note,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

type tenantStore struct {
	mu      sync.RWMutex
	path    string
	tenants map[string]Tenant
}

func newTenantStore(path string) (*tenantStore, error) {
	if path == "" {
		path = "/data/tenants.json"
	}
	s := &tenantStore{path: path, tenants: make(map[string]Tenant)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, ok := s.tenants[TenantGlobal]; !ok {
		s.tenants[TenantGlobal] = Tenant{
			ID: TenantGlobal, Name: "Global", Slug: TenantGlobal,
			Note: "Root tenant — owns shared infrastructure & defaults.", CreatedAt: time.Now().UTC(),
		}
		if err := s.flushLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *tenantStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []Tenant
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, t := range list {
		s.tenants[t.ID] = t
	}
	return nil
}

func (s *tenantStore) flushLocked() error {
	list := make([]Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		list = append(list, t)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

func (s *tenantStore) List() []Tenant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Tenant, 0, len(s.tenants))
	for _, t := range s.tenants {
		out = append(out, t)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID == TenantGlobal != (out[j].ID == TenantGlobal) {
			return out[i].ID == TenantGlobal // Global first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *tenantStore) Get(id string) (Tenant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tenants[id]
	return t, ok
}

func (s *tenantStore) Create(name, note string) (Tenant, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Tenant{}, errors.New("tenant name required")
	}
	id := slugify(name)
	if id == "" {
		return Tenant{}, errors.New("tenant name must contain letters or digits")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[id]; ok {
		return Tenant{}, errors.New("tenant already exists")
	}
	t := Tenant{ID: id, Name: name, Slug: id, Note: note, CreatedAt: time.Now().UTC()}
	s.tenants[id] = t
	if err := s.flushLocked(); err != nil {
		delete(s.tenants, id)
		return Tenant{}, err
	}
	return t, nil
}

func (s *tenantStore) Delete(id string) error {
	if id == TenantGlobal {
		return errors.New("cannot delete the Global tenant")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tenants[id]; !ok {
		return errors.New("no such tenant")
	}
	delete(s.tenants, id)
	return s.flushLocked()
}
