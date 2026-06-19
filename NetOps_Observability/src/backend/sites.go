package main

// sites.go — the internal Source-of-Truth sites store: operator-declared sites
// (name, slug, coordinates) persisted in the platform itself, so geo / placement
// intent works with NO external CMDB. This is the data behind the DEFAULT
// (internal) SoTProvider; NetBox, when configured, supersedes it as the authority.
//
// Modeled on deviceLocationStore: kv-backed (file or Postgres via kvSave/kvLoad),
// in-memory map keyed by the stable slug, tenancy enforced at the HTTP boundary.

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Site is one operator-declared site (the internal SoT row). It is OWNED by a
// tenant: TenantID scopes visibility and edit rights exactly like Device.TenantID
// (a non-owner principal only ever sees/edits its own tenant's sites; "" /
// TenantGlobal is platform-owned, visible only to the cross-tenant platform owner).
type Site struct {
	TenantID  string    `json:"tenant_id,omitempty"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status,omitempty"`
	Lat       float64   `json:"lat"`
	Lng       float64   `json:"lng"`
	HasCoords bool      `json:"has_coords"`
	UpdatedBy string    `json:"updated_by,omitempty"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (s Site) validate() error {
	if strings.TrimSpace(s.Slug) == "" {
		return errors.New("site slug is required")
	}
	if strings.TrimSpace(s.Name) == "" {
		return errors.New("site name is required")
	}
	if len(s.Name) > 120 {
		return errors.New("site name too long (max 120)")
	}
	if s.HasCoords {
		if s.Lat < -90 || s.Lat > 90 {
			return errors.New("lat must be within [-90, 90]")
		}
		if s.Lng < -180 || s.Lng > 180 {
			return errors.New("lng must be within [-180, 180]")
		}
	}
	return nil
}

// toSoT projects a stored site into the provider contract (Source = "internal").
func (s Site) toSoT() SoTSite {
	return SoTSite{
		Slug: s.Slug, Name: s.Name, Status: s.Status,
		Lat: s.Lat, Lng: s.Lng, HasCoords: s.HasCoords, Source: "internal",
	}
}

// slugify derives a stable, URL-safe slug from a free-form name.
func siteSlug(in string) string {
	in = strings.ToLower(strings.TrimSpace(in))
	var b strings.Builder
	prevDash := false
	for _, r := range in {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		case r == ' ' || r == '-' || r == '_' || r == '.' || r == '/':
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

type sitesStore struct {
	mu    sync.RWMutex
	path  string
	items map[string]Site // (tenant\x00slug) → site
}

// siteKey composes the tenant-scoped storage key so the same slug can exist in
// different tenants without collision.
func siteKey(tenant, slug string) string { return tenant + "\x00" + slug }

func newSitesStore(path string) (*sitesStore, error) {
	if path == "" {
		path = "/data/sites.json"
	}
	s := &sitesStore{path: path, items: make(map[string]Site)}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *sitesStore) load() error {
	b, err := kvLoad(s.path)
	if err != nil {
		return nil // absent store → empty
	}
	var list []Site
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, st := range list {
		if st.Slug != "" {
			s.items[siteKey(st.TenantID, st.Slug)] = st
		}
	}
	return nil
}

func (s *sitesStore) flushLocked() error {
	list := make([]Site, 0, len(s.items))
	for _, st := range s.items {
		list = append(list, st)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].TenantID != list[j].TenantID {
			return list[i].TenantID < list[j].TenantID
		}
		return list[i].Slug < list[j].Slug
	})
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// visible reports whether a principal scoped to (tenant, cross) may see a site.
func siteVisible(st Site, tenant string, cross bool) bool {
	return cross || st.TenantID == tenant
}

// All returns the sites VISIBLE to the (tenant, cross) principal, sorted. A
// non-cross caller sees ONLY its own tenant's sites (zero cross-tenant leakage).
func (s *sitesStore) All(tenant string, cross bool) []Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Site, 0, len(s.items))
	for _, st := range s.items {
		if siteVisible(st, tenant, cross) {
			out = append(out, st)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// Get returns a site only if the (tenant, cross) principal may see it.
func (s *sitesStore) Get(tenant string, cross bool, slug string) (Site, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, ok := s.items[siteKey(tenant, slug)]; ok {
		return st, true
	}
	if cross {
		// Platform owner: a slug may live under any tenant — find the first match.
		for _, st := range s.items {
			if st.Slug == slug {
				return st, true
			}
		}
	}
	return Site{}, false
}

// Upsert validates and stores a site. The caller stamps st.TenantID from the
// authenticated principal (never from request input) before calling.
func (s *sitesStore) Upsert(st Site) (Site, error) {
	if err := st.validate(); err != nil {
		return Site{}, err
	}
	st.UpdatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[siteKey(st.TenantID, st.Slug)] = st
	if err := s.flushLocked(); err != nil {
		return Site{}, err
	}
	return st, nil
}

// Delete removes a site within the caller's tenant (cross may delete any tenant's).
func (s *sitesStore) Delete(tenant string, cross bool, slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[siteKey(tenant, slug)]; ok {
		delete(s.items, siteKey(tenant, slug))
		return s.flushLocked()
	}
	if cross {
		for k, st := range s.items {
			if st.Slug == slug {
				delete(s.items, k)
				return s.flushLocked()
			}
		}
	}
	return errors.New("no such site")
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// handleSites serves /api/sites: GET (list) and POST (create/update). Tenant-
// scoped: a non-owner principal only ever sees/edits its OWN tenant's sites.
// Writes require infrastructure:write.
func (s *server) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		writeJSON(w, http.StatusOK, map[string]any{
			"sites":  s.sites.All(tenant, cross),
			"active": s.activeSoT().Name(),
		})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		st, err := s.decodeSite(w, r, claims, "")
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.sites.Upsert(st)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleSiteByID serves /api/sites/{slug}: PUT (update) and DELETE. A caller may
// only touch a site within its own tenant — a slug it can't see returns 404 (never
// reveal another tenant's resource, never allow a cross-tenant overwrite).
func (s *server) handleSiteByID(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/sites/")
	if slug == "" || strings.Contains(slug, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		st, found := s.sites.Get(tenant, cross, slug)
		if !found {
			http.NotFound(w, r) // 404, never reveal another tenant's site exists
			return
		}
		writeJSON(w, http.StatusOK, st)
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		// The site must already exist within the caller's scope — otherwise a PUT
		// could mint or hijack a slug across tenants.
		if _, found := s.sites.Get(tenant, cross, slug); !found {
			http.NotFound(w, r)
			return
		}
		st, err := s.decodeSite(w, r, claims, slug)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.sites.Upsert(st)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		if err := s.sites.Delete(tenant, cross, slug); err != nil {
			http.NotFound(w, r)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, PUT or DELETE"))
	}
}

// decodeSite parses a site create/update body and STAMPS the owning tenant from
// the authenticated principal (never from request input — zero-trust). lat/lng are
// pointers so an omitted coordinate is distinguishable from 0,0 (a valid, if
// unlikely, location). When forceSlug is set (PUT /{slug}) it wins; otherwise the
// slug is taken from the body or derived from the name.
func (s *server) decodeSite(w http.ResponseWriter, r *http.Request, claims jwtClaims, forceSlug string) (Site, error) {
	var req struct {
		Slug   string   `json:"slug"`
		Name   string   `json:"name"`
		Status string   `json:"status"`
		Lat    *float64 `json:"lat"`
		Lng    *float64 `json:"lng"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		return Site{}, fmt.Errorf("bad body: %w", err)
	}
	slug := forceSlug
	if slug == "" {
		slug = siteSlug(req.Slug)
	}
	if slug == "" {
		slug = siteSlug(req.Name)
	}
	tenant, _ := principalTenant(claims)
	st := Site{
		TenantID:  tenant, // owning tenant from the token, NOT the request body
		Slug:      slug,
		Name:      strings.TrimSpace(req.Name),
		Status:    strings.TrimSpace(req.Status),
		UpdatedBy: claims.Sub,
	}
	if req.Lat != nil && req.Lng != nil {
		st.Lat, st.Lng, st.HasCoords = *req.Lat, *req.Lng, true
	}
	return st, nil
}
