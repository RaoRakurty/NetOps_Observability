package main

// appid_overrides.go — Application Identification: operator-defined app catalog
// (#81 P1c). Closes the "internal apps resolve to unknown" gap. An operator names
// an internal app by declaring (prefix → app) overrides in app_catalog; the
// resolver layers the caller's tenant overrides over the global vendor catalog and
// fuses them. Operator-declared entries are AUTHORITATIVE (appid.SrcOperator →
// confirmed) — the owner explicitly said so, unlike a vendor IP-range guess.
//
//   GET/POST   /api/appid/catalog        list / add an override
//   DELETE     /api/appid/catalog/{id}   remove one
//
// Overrides are loaded per-request from the tenant-scoped store (RLS returns the
// tenant's own rows + shared global tenant_id='' rows), built into a small
// in-memory appid.Catalog, and resolved alongside the global feeds. app_catalog is
// small (operator-curated), so per-request build is cheap; the P4 cache optimizes it.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"netops/backend/appid"
)

var validMatchKind = map[string]bool{"prefix": true, "domain": true, "asn": true, "port": true}

// AppCatalogEntry is one operator override row.
type AppCatalogEntry struct {
	CatalogID  string    `json:"catalog_id"`
	TenantID   string    `json:"tenant_id"`
	MatchKind  string    `json:"match_kind"`
	MatchValue string    `json:"match_value"`
	AppLabel   string    `json:"app_label"`
	Confidence float64   `json:"confidence"`
	Source     string    `json:"source"`
	Version    int       `json:"version"`
	CreatedAt  time.Time `json:"created_at"`
}

// validateAppCatalogInput is a pure guard (unit-tested).
func validateAppCatalogInput(kind, value, app string) error {
	if !validMatchKind[kind] {
		return errors.New("match_kind must be one of prefix|domain|asn|port")
	}
	if strings.TrimSpace(value) == "" {
		return errors.New("match_value is required")
	}
	if strings.TrimSpace(app) == "" {
		return errors.New("app_label is required")
	}
	switch kind {
	case "prefix":
		if !isCIDRToken(value) {
			return errors.New("prefix match_value must be a valid IPv4 CIDR or address")
		}
	case "port":
		if n, err := parsePort(value); err != nil || n < 0 || n > 65535 {
			return errors.New("port match_value must be 0..65535")
		}
	}
	return nil
}

func parsePort(s string) (int, error) {
	n := 0
	for _, c := range strings.TrimSpace(s) {
		if c < '0' || c > '9' {
			return 0, errors.New("not a number")
		}
		n = n*10 + int(c-'0')
	}
	return n, nil
}

type appCatalogStore interface {
	List(ctx context.Context, tenant string, cross bool) ([]AppCatalogEntry, error)
	Create(ctx context.Context, tenant string, cross bool, in AppCatalogEntry) (AppCatalogEntry, error)
	Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error)
}

func newAppCatalogStore() appCatalogStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgAppCatalogStore{db: ps.db}
	}
	return &memAppCatalogStore{by: map[string]AppCatalogEntry{}}
}

// tenantOverrides bundles the per-tenant operator overrides built from app_catalog:
// a prefix catalog (IP→app) and a domain matcher (host→app), both SrcOperator
// (authoritative). asn/port kinds are reserved for later phases.
type tenantOverrides struct {
	prefixes *appid.Catalog
	domains  *appid.DomainIndex
}

// buildOverrides turns operator entries into the per-tenant override structures.
func buildOverrides(entries []AppCatalogEntry) tenantOverrides {
	ces := make([]appid.CatalogEntry, 0, len(entries))
	di := appid.NewDomainIndex()
	for _, e := range entries {
		switch e.MatchKind {
		case "prefix":
			ces = append(ces, appid.CatalogEntry{
				Prefix: e.MatchValue, App: e.AppLabel, Source: appid.SrcOperator,
				Feed: "operator", Confidence: 0.9,
			})
		case "domain":
			di.Add(e.MatchValue, e.AppLabel, appid.SrcOperator, 0.9)
		}
	}
	return tenantOverrides{prefixes: appid.NewCatalog(ces), domains: di}
}

// ── in-memory backend ──────────────────────────────────────────────────────────

type memAppCatalogStore struct {
	mu sync.RWMutex
	by map[string]AppCatalogEntry // catalog_id → entry
}

func (m *memAppCatalogStore) visible(e AppCatalogEntry, tenant string, cross bool) bool {
	// RLS-equivalent: cross sees all; a scoped tenant sees its own rows + shared global.
	return cross || e.TenantID == normTenant(tenant) || e.TenantID == ""
}

func (m *memAppCatalogStore) List(_ context.Context, tenant string, cross bool) ([]AppCatalogEntry, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []AppCatalogEntry{}
	for _, e := range m.by {
		if m.visible(e, tenant, cross) {
			out = append(out, e)
		}
	}
	return out, nil
}

func (m *memAppCatalogStore) Create(_ context.Context, _ string, _ bool, in AppCatalogEntry) (AppCatalogEntry, error) {
	id, err := newUUIDv4()
	if err != nil {
		return AppCatalogEntry{}, err
	}
	in.CatalogID = id
	in.TenantID = normTenant(in.TenantID)
	if in.Confidence <= 0 {
		in.Confidence = 0.9
	}
	if in.Source == "" {
		in.Source = "operator"
	}
	if in.Version <= 0 {
		in.Version = 1
	}
	in.CreatedAt = time.Now().UTC()
	m.mu.Lock()
	defer m.mu.Unlock()
	m.by[id] = in
	return in, nil
}

func (m *memAppCatalogStore) Delete(_ context.Context, tenant string, cross bool, id string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.by[id]
	if !ok {
		return false, nil
	}
	if !cross && e.TenantID != normTenant(tenant) { // can't delete another tenant's / shared global row
		return false, nil
	}
	delete(m.by, id)
	return true, nil
}

// ── Postgres backend (tenant_iso FORCE-RLS via withTenant) ──────────────────────

type pgAppCatalogStore struct{ db *pgDB }

func (st *pgAppCatalogStore) List(ctx context.Context, tenant string, cross bool) ([]AppCatalogEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out := make([]AppCatalogEntry, 0)
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT catalog_id, tenant_id, match_kind, match_value, app_label, confidence, source, version, created_at
              FROM app_catalog ORDER BY created_at DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var e AppCatalogEntry
			if err := rows.Scan(&e.CatalogID, &e.TenantID, &e.MatchKind, &e.MatchValue, &e.AppLabel, &e.Confidence, &e.Source, &e.Version, &e.CreatedAt); err != nil {
				return err
			}
			out = append(out, e)
		}
		return rows.Err()
	})
	return out, err
}

func (st *pgAppCatalogStore) Create(ctx context.Context, tenant string, cross bool, in AppCatalogEntry) (AppCatalogEntry, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	id, err := newUUIDv4()
	if err != nil {
		return AppCatalogEntry{}, err
	}
	in.CatalogID = id
	if in.Confidence <= 0 {
		in.Confidence = 0.9
	}
	if in.Source == "" {
		in.Source = "operator"
	}
	if in.Version <= 0 {
		in.Version = 1
	}
	err = st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO app_catalog (catalog_id, tenant_id, match_kind, match_value, app_label, confidence, source, version)
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING created_at`,
			in.CatalogID, in.TenantID, in.MatchKind, in.MatchValue, in.AppLabel, in.Confidence, in.Source, in.Version)
		return row.Scan(&in.CreatedAt)
	})
	return in, err
}

func (st *pgAppCatalogStore) Delete(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM app_catalog WHERE catalog_id = $1`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

// ── handlers ────────────────────────────────────────────────────────────────

func (s *server) handleAppIDCatalog(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.appOverrides.List(r.Context(), tenant, cross)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"entries": out, "count": len(out)})
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in AppCatalogEntry
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := validateAppCatalogInput(in.MatchKind, in.MatchValue, in.AppLabel); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates; body tenant ignored
		}
		out, err := s.appOverrides.Create(r.Context(), tenant, cross, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleAppIDCatalogByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/appid/catalog/")
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid catalog id"))
		return
	}
	if r.Method != http.MethodDelete {
		writeError(w, http.StatusMethodNotAllowed, errors.New("DELETE only"))
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	ok2, err := s.appOverrides.Delete(r.Context(), tenant, cross, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	if !ok2 {
		writeError(w, http.StatusNotFound, errNotFound)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"deleted": id})
}

// overridesFor loads the caller's tenant override entries and builds the per-tenant
// prefix + domain override structures (SrcOperator). Empty on error/none (resolve
// still works off the global feeds + NGFW). Cheap: app_catalog is operator-curated.
func (s *server) overridesFor(ctx context.Context, tenant string, cross bool) tenantOverrides {
	if s.appOverrides == nil {
		return tenantOverrides{}
	}
	entries, err := s.appOverrides.List(ctx, tenant, cross)
	if err != nil || len(entries) == 0 {
		return tenantOverrides{}
	}
	return buildOverrides(entries)
}
