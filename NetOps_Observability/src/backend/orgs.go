package main

// orgs.go — the Organization layer that sits ABOVE tenants. An Org is the
// top-level customer/account boundary; each Tenant belongs to exactly one Org.
// This mirrors how SaaS control planes separate "who you are billed/governed as"
// (the Org) from "an isolation boundary for data" (the Tenant): SSO, data
// residency (home_region) and org-administrators are bound at the Org; telemetry
// isolation stays at the Tenant.
//
// File-backed (orgs.json) via the same kv seam as the other stores, so it works
// stdlib-only today and promotes to Postgres unchanged. No isolation behavior
// changes in this layer — it is an in-app directory/governance entity.

import (
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// OrgGlobal is the seeded root org that owns the Global tenant and platform
// defaults. It can never be deleted.
const OrgGlobal = "global"

type Org struct {
	ID         string `json:"id"`   // slug, stable
	Name       string `json:"name"`
	Slug       string `json:"slug"`
	Note       string `json:"note,omitempty"`
	// HomeRegion is where this org's tenants' data resides by default (data
	// residency). Recorded now for governance/display; per-region routing is a
	// later phase. Always a member of the known region set.
	HomeRegion Region `json:"home_region"`
	// SSOConnection optionally binds this org to a named identity-provider
	// connection (set up under Identity & Access). Empty = uses platform default
	// login. Binding SSO at the Org is the enterprise pattern: one customer, one
	// identity source, inherited by all its tenants.
	SSOConnection string    `json:"sso_connection,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
}

type orgStore struct {
	mu   sync.RWMutex
	path string
	orgs map[string]Org
}

func newOrgStore(path string) (*orgStore, error) {
	if path == "" {
		path = "/data/orgs.json"
	}
	s := &orgStore{path: path, orgs: make(map[string]Org)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if _, ok := s.orgs[OrgGlobal]; !ok {
		s.orgs[OrgGlobal] = Org{
			ID: OrgGlobal, Name: "Provider", Slug: OrgGlobal,
			Note:       "The provider (platform-owner) realm — root of all organizations.",
			HomeRegion: RegionDefault, CreatedAt: time.Now().UTC(),
		}
		if err := s.flushLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *orgStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return err
	}
	var list []Org
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, o := range list {
		s.orgs[o.ID] = o
	}
	return nil
}

func (s *orgStore) flushLocked() error {
	list := make([]Org, 0, len(s.orgs))
	for _, o := range s.orgs {
		list = append(list, o)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// List returns all orgs, Global first then alphabetical by name.
func (s *orgStore) List() []Org {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Org, 0, len(s.orgs))
	for _, o := range s.orgs {
		out = append(out, o)
	}
	sort.Slice(out, func(i, j int) bool {
		if (out[i].ID == OrgGlobal) != (out[j].ID == OrgGlobal) {
			return out[i].ID == OrgGlobal
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *orgStore) Get(id string) (Org, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	o, ok := s.orgs[strings.ToLower(strings.TrimSpace(id))]
	return o, ok
}

func (s *orgStore) Create(name, note, homeRegion, ssoConnection string) (Org, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Org{}, errors.New("organization name required")
	}
	id := slugify(name)
	if id == "" {
		return Org{}, errors.New("organization name must contain letters or digits")
	}
	region, err := normalizeRegion(homeRegion)
	if err != nil {
		return Org{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[id]; ok {
		return Org{}, errors.New("organization already exists")
	}
	o := Org{
		ID: id, Name: name, Slug: id, Note: strings.TrimSpace(note),
		HomeRegion: region, SSOConnection: strings.TrimSpace(ssoConnection),
		CreatedAt: time.Now().UTC(),
	}
	s.orgs[id] = o
	if err := s.flushLocked(); err != nil {
		delete(s.orgs, id)
		return Org{}, err
	}
	return o, nil
}

// orgUpdate carries the mutable org fields; nil pointers are left unchanged.
type orgUpdate struct {
	Note          *string `json:"note"`
	HomeRegion    *string `json:"home_region"`
	SSOConnection *string `json:"sso_connection"`
}

func (s *orgStore) Update(id string, u orgUpdate) (Org, error) {
	id = strings.ToLower(strings.TrimSpace(id))
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.orgs[id]
	if !ok {
		return Org{}, errors.New("organization not found")
	}
	if u.Note != nil {
		o.Note = strings.TrimSpace(*u.Note)
	}
	if u.HomeRegion != nil {
		region, err := normalizeRegion(*u.HomeRegion)
		if err != nil {
			return Org{}, err
		}
		o.HomeRegion = region
	}
	if u.SSOConnection != nil {
		o.SSOConnection = strings.TrimSpace(*u.SSOConnection)
	}
	s.orgs[id] = o
	if err := s.flushLocked(); err != nil {
		return Org{}, err
	}
	return o, nil
}

// Delete removes an org. The Global org is permanent. Refusing to delete an org
// that still owns tenants is enforced by the caller (it has the tenant store).
func (s *orgStore) Delete(id string) error {
	id = strings.ToLower(strings.TrimSpace(id))
	if id == OrgGlobal {
		return errors.New("cannot delete the Global organization")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.orgs[id]; !ok {
		return errors.New("no such organization")
	}
	delete(s.orgs, id)
	return s.flushLocked()
}
