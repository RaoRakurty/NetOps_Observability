package backend

// Service catalog (#69 §2, P2) — the semantic lens over the truth streams.
// Postgres-backed (lifecycle/catalog state, RLS tenant-isolated), nil on the file
// backend like incidents/seams. Three split objects: services (stable identity),
// service_selectors (versioned, append-only grouping rule), service_bindings
// (operational attachments). REST:
//   GET/POST    /api/services
//   GET/DELETE  /api/services/{id}                 (DELETE = archive, never hard-delete)
//   GET/POST    /api/services/{id}/selectors       (POST = new version)
//   GET/POST    /api/services/{id}/bindings
//   DELETE      /api/services/{id}/bindings/{bindingId}

import (
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/servicecat"
	"strings"
)

var errServiceStoreOff = errors.New("service catalog requires the PostgreSQL backend")

// The catalog domain moved to internal/servicecat (Phase-2 W1). Aliases keep
// the main-package consumers (rollup worker, backfill, handlers) source-
// compatible; errNotFound aliases the SAME sentinel object so errors.Is
// matches across the boundary — it predates the move as main's package-wide
// not-found error and other domains still return it.
type (
	Service         = servicecat.Service
	ServiceSelector = servicecat.ServiceSelector
	ServiceBinding  = servicecat.ServiceBinding
	svcSelectorSet  = servicecat.SelectorSet
	pgServiceStore  = servicecat.Store
)

var errNotFound = servicecat.ErrNotFound

// ── backend selector ─────────────────────────────────────────────────────────

func newServiceStore() *pgServiceStore {
	if ps, ok := platformdb.ActivePG(); ok {
		return servicecat.NewStore(ps.DB())
	}
	return nil // Postgres backend only
}

// ── handlers ────────────────────────────────────────────────────────────────

func (s *server) handleServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.services == nil {
			writeError(w, http.StatusNotImplemented, errServiceStoreOff)
			return
		}
		tenant, cross := principalTenant(claims)
		includeArchived := r.URL.Query().Get("archived") == "true"
		out, err := s.services.ListServices(r.Context(), tenant, cross, includeArchived)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		if s.services == nil {
			writeError(w, http.StatusNotImplemented, errServiceStoreOff)
			return
		}
		var in Service
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := servicecat.ValidateInput(in.Name, in.Criticality); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates; only platform may stamp another tenant
		}
		out, err := s.services.CreateService(r.Context(), tenant, cross, in)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

// handleServiceByID routes /api/services/{id}[/selectors|/bindings[/{bindingId}]].
func (s *server) handleServiceByID(w http.ResponseWriter, r *http.Request) {
	if s.services == nil {
		writeError(w, http.StatusNotImplemented, errServiceStoreOff)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/services/")
	parts := strings.Split(rest, "/")
	id := parts[0]
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid service id"))
		return
	}
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	switch sub {
	case "":
		s.serveServiceRoot(w, r, id)
	case "selectors":
		// /api/services/{id}/selectors/{version}/backfill → the audited
		// re-attribution job (#69 §3.3, svc_backfill.go).
		if len(parts) > 3 && parts[3] == "backfill" {
			s.serveSelectorBackfill(w, r, id, parts[2])
			return
		}
		s.serveServiceSelectors(w, r, id)
	case "bindings":
		bindingID := ""
		if len(parts) > 2 {
			bindingID = parts[2]
		}
		s.serveServiceBindings(w, r, id, bindingID)
	default:
		writeError(w, http.StatusNotFound, errors.New("unknown subresource"))
	}
}

func (s *server) serveServiceRoot(w http.ResponseWriter, r *http.Request, id string) {
	// Shared GET/DELETE-by-id shape with applications (serveGetOrArchive, appid.go).
	serveGetOrArchive(s, w, r, id, serviceRegistry, s.services.GetService, s.services.ArchiveService)
}

func (s *server) serveServiceSelectors(w http.ResponseWriter, r *http.Request, id string) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.services.ListSelectors(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var body struct {
			Spec map[string]any `json:"spec"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 256<<10)).Decode(&body); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		sel, err := s.services.AddSelector(r.Context(), tenant, cross, id, body.Spec, claims.Sub)
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, sel)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) serveServiceBindings(w http.ResponseWriter, r *http.Request, id, bindingID string) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.services.ListBindings(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		var in ServiceBinding
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 32<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if !servicecat.ValidBindingKind[in.Kind] {
			writeError(w, http.StatusBadRequest, errors.New("kind must be one of probe|path|seam"))
			return
		}
		if strings.TrimSpace(in.Ref) == "" {
			writeError(w, http.StatusBadRequest, errors.New("ref is required"))
			return
		}
		tenant, cross := principalTenant(claims)
		b, err := s.services.AddBinding(r.Context(), tenant, cross, id, in.Kind, strings.TrimSpace(in.Ref))
		if errors.Is(err, errNotFound) {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusCreated, b)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		if !isUUIDToken(bindingID) {
			writeError(w, http.StatusBadRequest, errors.New("invalid binding id"))
			return
		}
		tenant, cross := principalTenant(claims)
		ok2, err := s.services.DeleteBinding(r.Context(), tenant, cross, id, bindingID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !ok2 {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"deleted": bindingID})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET, POST or DELETE"))
	}
}
