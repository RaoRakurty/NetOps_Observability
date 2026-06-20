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

// Get resolves an org by id OR slug — the legacy compatibility resolver (see
// tenantStore.Get). Resolution only; authorization uses the resolved opaque id.
func (s *orgStore) Get(ref string) (Org, bool) { return s.Resolve(ref) }

// Create makes a new org. The id is an OPAQUE, IMMUTABLE, cryptographically-
// random key (mintOrgID) — never derived from name/slug. The slug is a human
// handle: taken from `slug` if supplied, else derived from the display name, and
// validated to the full contract either way. Slugs are globally unique.
func (s *orgStore) Create(name, slug, note, homeRegion, ssoConnection string) (Org, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return Org{}, errors.New("organization name required")
	}
	cand := strings.TrimSpace(slug)
	if cand == "" {
		cand = slugFromName(name)
	}
	cleanSlug, err := validateSlug(cand)
	if err != nil {
		return Org{}, err
	}
	region, err := normalizeRegion(homeRegion)
	if err != nil {
		return Org{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.slugTakenLocked(cleanSlug) {
		return Org{}, errors.New("organization slug already exists")
	}
	id := mintOrgID()
	for {
		if _, ok := s.orgs[id]; !ok {
			break
		}
		id = mintOrgID() // astronomically unlikely; guard anyway
	}
	o := Org{
		ID: id, Name: name, Slug: cleanSlug, Note: strings.TrimSpace(note),
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

// slugTakenLocked reports whether an org slug is already in use (globally unique).
// Checks both the Slug field and the id map key (legacy id==slug). Caller holds lock.
func (s *orgStore) slugTakenLocked(slug string) bool {
	if _, ok := s.orgs[slug]; ok {
		return true
	}
	for _, o := range s.orgs {
		if o.Slug == slug {
			return true
		}
	}
	return false
}

// Resolve maps an UNTRUSTED id-or-slug reference to the canonical org (id first —
// opaque org_ id, global sentinel, or legacy id==slug — then slug). Resolve
// before authorizing; never authorize on a raw slug.
func (s *orgStore) Resolve(ref string) (Org, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resolveLocked(ref)
}

// resolveLocked is Resolve's lock-free core for write methods. Caller holds s.mu.
func (s *orgStore) resolveLocked(ref string) (Org, bool) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	if ref == "" {
		return Org{}, false
	}
	if o, ok := s.orgs[ref]; ok {
		return o, true
	}
	for _, o := range s.orgs {
		if o.Slug == ref {
			return o, true
		}
	}
	return Org{}, false
}

// orgUpdate carries the mutable org fields; nil pointers are left unchanged.
type orgUpdate struct {
	Note          *string `json:"note"`
	HomeRegion    *string `json:"home_region"`
	SSOConnection *string `json:"sso_connection"`
}

func (s *orgStore) Update(ref string, u orgUpdate) (Org, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return Org{}, errors.New("organization not found")
	}
	id := o.ID
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
func (s *orgStore) Delete(ref string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	o, ok := s.resolveLocked(ref) // id or slug
	if !ok {
		return errors.New("no such organization")
	}
	id := o.ID
	if id == OrgGlobal {
		return errors.New("cannot delete the Global organization")
	}
	delete(s.orgs, id)
	return s.flushLocked()
}
