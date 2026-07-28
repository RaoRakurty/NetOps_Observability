package main

import (
	"errors"
	"net/http"
	"netops/backend/internal/platformdb"
	"strings"

	"netops/backend/portintel"
)

// port_handlers.go — Port Intelligence API (#94 P5). Enhances the existing
// Infrastructure surface (owner constraint: no new nav tree). All endpoints are
// tenant-scoped via requirePerm(infrastructure:read) + the portStore's RLS/
// tenant filter; server-side paginated; the filter set maps to PortFilter.
// Rows are empty until the collectors populate the 0019 tables on real hardware
// (the virtual lab has no optics) — the shapes + scoping are what P5 delivers.
// The store itself lives in portintel (store.go); this file keeps the HTTP
// surface and the backend-selection wiring.

// newPortStore picks the store backend: pg (RLS-scoped via the portintel.DB
// adapter below) when the relational app-state store is active, else in-memory.
func newPortStore() portintel.Store {
	if ps, ok := platformdb.ActivePG(); ok {
		return portintel.NewPGStore(ps.DB())
	}
	return portintel.NewMemStore()
}

// handlePortInterfaces: GET /api/infrastructure/interfaces — the workbench table
// (server-side paginated + filtered). Also serves the per-device list when
// ?device= is set.
func (s *server) handlePortInterfaces(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	limit, err := intQuery(r, "limit", 100, 1, 500)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	offset, err := intQuery(r, "offset", 0, 0, 1<<30)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	f := portintel.PortFilter{
		Device:      strings.TrimSpace(r.URL.Query().Get("device")),
		Seam:        strings.TrimSpace(r.URL.Query().Get("seam")),
		Role:        strings.TrimSpace(r.URL.Query().Get("role")),
		MediaType:   strings.TrimSpace(r.URL.Query().Get("media_type")),
		FormFactor:  strings.TrimSpace(r.URL.Query().Get("form_factor")),
		Supported:   strings.TrimSpace(r.URL.Query().Get("supported_status")),
		OperStatus:  strings.TrimSpace(r.URL.Query().Get("oper_status")),
		RCAAttached: r.URL.Query().Get("rca_attached") == "true",
		Limit:       limit,
		Offset:      offset,
	}
	rows, total, err := s.portStore.ListPorts(r.Context(), tenant, cross, f)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if rows == nil {
		rows = []portintel.PortRow{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"interfaces": rows, "total": total, "limit": f.Limit, "offset": f.Offset,
	})
}

// handlePortInterfaceDetail: GET /api/infrastructure/interfaces/{device}:{port}
// — the detail-drawer payload. A foreign or unknown id returns 404 (never
// reveal another tenant's port).
func (s *server) handlePortInterfaceDetail(w http.ResponseWriter, r *http.Request) {
	// The RCA path-resolution shares this prefix route (P7).
	if strings.HasSuffix(r.URL.Path, "/path") {
		s.handlePortPath(w, r)
		return
	}
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	id := strings.TrimPrefix(r.URL.Path, "/api/infrastructure/interfaces/")
	dev, port, found := strings.Cut(id, ":")
	if !found || dev == "" || port == "" {
		writeError(w, http.StatusBadRequest, errors.New("interface id must be device:port"))
		return
	}
	row, ok2, err := s.portStore.GetPort(r.Context(), tenant, cross, dev, dev+":"+port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	if !ok2 {
		writeError(w, http.StatusNotFound, errors.New("interface not found"))
		return
	}
	writeJSON(w, http.StatusOK, row)
}

// handlePortPath: GET /api/infrastructure/interfaces/{device:port}/path — the
// RCA path-resolution (#94 P7): maps an incident endpoint to its physical port,
// fiber path (circuit/panel/cassette/polarity, far endpoint) and neighbor. The
// RCA Inspector uses this to point an incident at the exact optic/strand/
// cross-connect. Tenant-scoped; a foreign endpoint resolves to nothing (never
// reveals another tenant's cabling).
func (s *server) handlePortPath(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/api/infrastructure/interfaces/"), "/path")
	dev, port, found := strings.Cut(id, ":")
	if !found || dev == "" || port == "" {
		writeError(w, http.StatusBadRequest, errors.New("interface id must be device:port"))
		return
	}
	pc, err := s.portStore.ResolvePath(r.Context(), tenant, cross, dev, dev+":"+port)
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	writeJSON(w, http.StatusOK, pc)
}

// handlePortSummary: GET /api/infrastructure/port-summary — fleet health rollup
// for the heatmap (counts by health state, tenant-scoped).
func (s *server) handlePortSummary(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	rows, total, err := s.portStore.ListPorts(r.Context(), tenant, cross, portintel.PortFilter{})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	byState := map[string]int{"ok": 0, "watch": 0, "degraded": 0, "critical": 0}
	rcaAttached := 0
	for _, p := range rows {
		st := p.HealthState
		if st == "" {
			st = "ok"
		}
		byState[st]++
		if p.MatchedSig != "" {
			rcaAttached++
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total_ports": total, "by_state": byState, "rca_attached": rcaAttached,
	})
}

// handleModuleTypes: GET /api/infrastructure/module-types — the normalized
// module/media/PMD/connector taxonomies the UI filters + legends use (static
// reference; from the portintel enums so UI + backend never drift).
func (s *server) handleModuleTypes(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, portintel.TaxonomyReference())
}

// handlePortFilterOptions: GET /api/infrastructure/port-filter-options — the
// distinct values present in the caller's fleet, for the filter chips (so the UI
// only offers filters that would return rows).
func (s *server) handlePortFilterOptions(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
	if !ok {
		return
	}
	tenant, cross := principalTenant(claims)
	rows, _, err := s.portStore.ListPorts(r.Context(), tenant, cross, portintel.PortFilter{})
	if err != nil {
		writeError(w, http.StatusBadGateway, err)
		return
	}
	uniq := func(get func(portintel.PortRow) string) []string {
		seen := map[string]bool{}
		var out []string
		for _, p := range rows {
			if v := get(p); v != "" && !seen[v] {
				seen[v] = true
				out = append(out, v)
			}
		}
		return out
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"device":      uniq(func(p portintel.PortRow) string { return p.DeviceID }),
		"seam":        uniq(func(p portintel.PortRow) string { return p.Seam }),
		"role":        uniq(func(p portintel.PortRow) string { return p.Role }),
		"media_type":  uniq(func(p portintel.PortRow) string { return p.MediaType }),
		"form_factor": uniq(func(p portintel.PortRow) string { return p.FormFactor }),
		"vendor_name": uniq(func(p portintel.PortRow) string { return p.VendorName }),
	})
}

// handlePortSignatureCatalog: GET /api/infrastructure/port-signatures — the
// sig.ent.spdc physical-layer catalog (id/name/operator+manager phrase) for the
// playbook drawer + the RCA-Evidence section. Sourced from the shipped catalog.
func (s *server) handlePortSignatureCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"signatures": portintel.SignatureCatalog()})
}
