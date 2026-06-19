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

// Site is one operator-declared site (the internal SoT row).
type Site struct {
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
	items map[string]Site // slug → site
}

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
			s.items[st.Slug] = st
		}
	}
	return nil
}

func (s *sitesStore) flushLocked() error {
	list := make([]Site, 0, len(s.items))
	for _, st := range s.items {
		list = append(list, st)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Slug < list[j].Slug })
	b, err := json.Marshal(list)
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
}

// All returns every site, sorted by slug (deterministic).
func (s *sitesStore) All() []Site {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Site, 0, len(s.items))
	for _, st := range s.items {
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

func (s *sitesStore) Get(slug string) (Site, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	st, ok := s.items[slug]
	return st, ok
}

// Upsert validates and stores a site keyed by slug.
func (s *sitesStore) Upsert(st Site) (Site, error) {
	if err := st.validate(); err != nil {
		return Site{}, err
	}
	st.UpdatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.items[st.Slug] = st
	if err := s.flushLocked(); err != nil {
		return Site{}, err
	}
	return st, nil
}

func (s *sitesStore) Delete(slug string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[slug]; !ok {
		return errors.New("no such site")
	}
	delete(s.items, slug)
	return s.flushLocked()
}

// Empty reports whether any site exists (drives geo onboarding).
func (s *sitesStore) Empty() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items) == 0
}

// ── HTTP ──────────────────────────────────────────────────────────────────────

// handleSites serves /api/sites: GET (list) and POST (create/update). The list is
// always returned (even when NetBox is the active authority) so the operator can
// curate the internal fallback. Writes require infrastructure:write.
func (s *server) handleSites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"sites":  s.sites.All(),
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

// handleSiteByID serves /api/sites/{slug}: PUT (update) and DELETE.
func (s *server) handleSiteByID(w http.ResponseWriter, r *http.Request) {
	slug := strings.TrimPrefix(r.URL.Path, "/api/sites/")
	if slug == "" || strings.Contains(slug, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPut:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
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
		if _, ok := s.requirePerm(w, r, "infrastructure", LevelWrite); !ok {
			return
		}
		if err := s.sites.Delete(slug); err != nil {
			writeError(w, http.StatusNotFound, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("PUT or DELETE"))
	}
}

// decodeSite parses a site create/update body. lat/lng are pointers so an omitted
// coordinate is distinguishable from 0,0 (a valid, if unlikely, location). When
// forceSlug is set (PUT /{slug}) it wins; otherwise the slug is taken from the
// body or derived from the name.
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
	st := Site{
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
