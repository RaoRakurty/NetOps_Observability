package main

// seam_handlers.go — REST surface for the seam inventory (#67 build ⑤).
// Suggest→confirm→active lifecycle for seams and redundancy groups, gated on
// infrastructure:read/write like the rest of the topology plane. The
// correlation service pulls its grounding inventory from
// GET /api/seams?state=active; the UI lists state=suggested as the review
// queue (shared surface with the engine's topology-gap hints — a hint's
// "define a seam?" action POSTs a pre-filled suggestion here).

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/jackc/pgx/v5"
	"net/http"
	"netops/backend/internal/incident"
	"netops/backend/internal/seam"
	"strings"
)

// newSeamStore picks the store backend: Postgres only, like incidents — the
// inventory rides FORCE-RLS via the seamPG adapter (nil on the file backend).
func newSeamStore() *seam.Store {
	if ps, ok := backend.(*pgStore); ok {
		return seam.NewPGStore(seamPG{db: ps.db})
	}
	return nil
}

// seamPG adapts package main's pg plumbing to the seam.DB seam — the package
// owns the inventory, not how this platform scopes its transactions.
type seamPG struct{ db *pgDB }

func (a seamPG) WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error {
	return a.db.withTenant(ctx, tenant, cross, fn)
}

// errSeamStoreOff is returned on the file backend: the inventory is
// lifecycle state and lives in Postgres only (same stance as incidents).
var errSeamStoreOff = errors.New("seam inventory requires the Postgres backend (STORE_BACKEND=postgres)")

func (s *server) handleSeams(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if state != "" && !seam.ValidEnum(state, seam.SeamStates) {
			writeError(w, http.StatusBadRequest, errors.New("invalid 'state' filter"))
			return
		}
		seamType := strings.ToUpper(strings.TrimSpace(r.URL.Query().Get("type")))
		if seamType != "" && !seam.ValidEnum(seamType, seam.SeamTypes) {
			writeError(w, http.StatusBadRequest, errors.New("invalid 'type' filter"))
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.seams.List(r.Context(), tenant, cross, state, seamType)
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
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		var in seam.Seam
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		// A scoped principal owns what it creates; only the platform owner may
		// stamp another tenant (or leave '' = platform-owned).
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant
		}
		// Owner-authored rows have no suggestion key; a pre-filled suggestion
		// from a topology-gap hint may carry one (and then enters as suggested,
		// keeping the rejection-memory contract).
		if in.SuggestionKey != "" {
			in.State = "suggested"
		}
		in.UpdatedBy = incident.ActorOr(claims.Sub)
		created, err := s.seams.Create(r.Context(), tenant, cross, in)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSeamByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/seams/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		tenant, cross := principalTenant(claims)
		sm, found, err := s.seams.Get(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, seam.ErrNotFound)
			return
		}
		writeJSON(w, http.StatusOK, sm)
	case http.MethodPatch:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		var p seam.SeamPatch
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		sm, err := s.seams.Update(r.Context(), tenant, cross, id, claims.Sub, p)
		if errors.Is(err, seam.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, sm)
	default:
		w.Header().Set("Allow", "GET, PATCH")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSeamGroups(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		state := strings.TrimSpace(r.URL.Query().Get("state"))
		if state != "" && !seam.ValidEnum(state, seam.SeamStates) {
			writeError(w, http.StatusBadRequest, errors.New("invalid 'state' filter"))
			return
		}
		tenant, cross := principalTenant(claims)
		out, err := s.seams.ListGroups(r.Context(), tenant, cross, state)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	default:
		w.Header().Set("Allow", "GET")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleSeamGroupByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/seams/groups/")
	if id == "" || strings.Contains(id, "/") {
		http.NotFound(w, r)
		return
	}
	switch r.Method {
	case http.MethodPatch:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		if s.seams == nil {
			writeError(w, http.StatusNotImplemented, errSeamStoreOff)
			return
		}
		var p seam.GroupPatch
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		g, err := s.seams.UpdateGroup(r.Context(), tenant, cross, id, claims.Sub, p)
		if errors.Is(err, seam.ErrNotFound) {
			writeError(w, http.StatusNotFound, err)
			return
		}
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, g)
	default:
		w.Header().Set("Allow", "PATCH")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
