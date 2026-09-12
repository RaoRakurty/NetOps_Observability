// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

// appid.go — Application Identification registry HTTP surface (#81 P0).
//   GET/POST    /api/applications
//   GET/DELETE  /api/applications/{id}     (DELETE = archive, never hard-delete)
//   GET         /api/registries/status    → which backend stores each registry
// The catalog feeds + LPM-trie resolver + flow→app enrichment land in P1; this is
// the registry half of the P0 contract. All tenant-scoped via principalTenant; the
// store enforces isolation (CLAUDE.md §3a) and the cross-org test is appid_isolation_test.go.
//
// STORAGE TRUTHFULNESS (tracker 245). s.applications is NIL when the configured
// backend has no implementation for this registry (today: the file backend —
// there is no applications file store, and inventing an in-memory one is how the
// registry came to acknowledge writes it then lost on restart). Every method
// refuses first, with a stable code, so "no applications" and "nowhere to put an
// application" can never render the same. A store error while the configured
// backend is unreachable answers 503, not 500 and not an empty 200.

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"netops/backend/appid"
	"netops/backend/internal/platformdb"
	"netops/backend/internal/registrystatus"
	"strings"
)

func (s *server) handleApplications(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		if !s.applicationStoreReady(w) {
			return
		}
		tenant, cross := principalTenant(claims)
		includeArchived := r.URL.Query().Get("archived") == "true"
		out, err := s.applications.List(r.Context(), tenant, cross, includeArchived)
		if err != nil {
			writeStorageError(w, r, applicationRegistry, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		if !s.applicationStoreReady(w) {
			return
		}
		var in appid.Application
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&in); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if err := appid.ValidateApplicationInput(in.Name, in.Criticality); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		tenant, cross := principalTenant(claims)
		if !cross {
			in.TenantID = tenant // scoped principal owns what it creates; tenant in the body is ignored
		}
		out, err := s.applications.Create(r.Context(), tenant, cross, in)
		if err != nil {
			writeStorageError(w, r, applicationRegistry, err)
			return
		}
		writeJSON(w, http.StatusCreated, out)
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or POST"))
	}
}

func (s *server) handleApplicationByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/applications/")
	if i := strings.IndexByte(id, '/'); i >= 0 {
		id = id[:i]
	}
	if !isUUIDToken(id) {
		writeError(w, http.StatusBadRequest, errors.New("invalid application id"))
		return
	}
	if !s.applicationStoreReady(w) {
		return
	}
	serveGetOrArchive(s, w, r, id, applicationRegistry, s.applications.Get, s.applications.Archive)
}

// serveGetOrArchive is the shared GET/DELETE surface for a tenant-scoped
// resource by id (#147 T4; used by applications here and serveServiceRoot in
// services.go). DELETE archives — never hard-deletes. §3a: an absent or
// cross-tenant id reads as 404 in both methods.
func serveGetOrArchive[T any](s *server, w http.ResponseWriter, r *http.Request, id, registry string,
	get func(ctx context.Context, tenant string, cross bool, id string) (T, bool, error),
	archive func(ctx context.Context, tenant string, cross bool, id string) (bool, error)) {
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		v, found, err := get(r.Context(), tenant, cross, id)
		if err != nil {
			writeStorageError(w, r, registry, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, v)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		ok2, err := archive(r.Context(), tenant, cross, id)
		if err != nil {
			writeStorageError(w, r, registry, err)
			return
		}
		if !ok2 {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"archived": id})
	default:
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET or DELETE"))
	}
}

// ── registry storage truthfulness (tracker 245) ──────────────────────────────

// Registry ids. They double as the prefix of the machine-readable error codes
// the SPA branches on (APPLICATION_REGISTRY_BACKEND_UNSUPPORTED, …).
const (
	applicationRegistry = "applications"
	serviceRegistry     = "service_catalog"
	bizServiceRegistry  = "business_services"
)

// registrySpecs declares, for every registry the Registries page shows, the
// backends that have a REAL implementation for it. A backend missing from a
// spec is unsupported — the registry then reports unavailable rather than being
// silently re-pointed at another backend.
//
// applications: pg (RLS rows, migration 0015) + the explicit ephemeral memory
// store. No file implementation exists — see newApplicationStore.
// service catalog / business services: Postgres only (newServiceStore,
// newBusinessServiceStore return nil elsewhere) and they have said so with a
// 501 since they shipped.
func registrySpecs() []registrystatus.Spec {
	return []registrystatus.Spec{
		{Registry: applicationRegistry, Label: "Application registry",
			Backends: []string{registrystatus.BackendPostgres, registrystatus.BackendMemory}},
		{Registry: serviceRegistry, Label: "Service catalog",
			Backends: []string{registrystatus.BackendPostgres}},
		{Registry: bizServiceRegistry, Label: "Cloud business services",
			Backends: []string{registrystatus.BackendPostgres}},
	}
}

// errApplicationStoreOff is the operator-facing sentence for a deployment whose
// configured backend cannot store applications. It names the backend and the
// remedy, the way errServiceStoreOff does for the service catalog.
var errApplicationStoreOff = errors.New(
	"the application registry needs PostgreSQL storage on this deployment " +
		"(STORE_BACKEND=postgres); the configured storage cannot hold it")

// applicationStoreReady refuses the request when no backend is storing this
// registry. 501 (not 200-with-nothing, not 500): the deployment is configured
// in a way this registry does not implement, which is exactly what
// "Not Implemented" means, and it is the status the SPA already understands for
// the sibling service catalog.
func (s *server) applicationStoreReady(w http.ResponseWriter) bool {
	if s.applications != nil {
		return true
	}
	writeJSONError(w, http.StatusNotImplemented, errApplicationStoreOff.Error(),
		"APPLICATION_REGISTRY_BACKEND_UNSUPPORTED")
	return false
}

// writeStorageError distinguishes "the storage is down" from "the request went
// wrong". A configured persistent backend that cannot answer is a 503 with a
// stable code — never a 500 that reads like a bug, and never an empty 200 that
// reads like an empty tenant. The message is fixed text: driver errors can carry
// the connection string.
func writeStorageError(w http.ResponseWriter, r *http.Request, registry string, err error) {
	if healthy, reason := platformdb.Health(r.Context()); !healthy {
		if reason == "" {
			reason = registrystatus.ReasonUnavailable
		}
		writeJSONError(w, http.StatusServiceUnavailable,
			"registry storage is unavailable ("+reason+")",
			strings.ToUpper(registry)+"_STORAGE_UNAVAILABLE")
		return
	}
	writeError(w, http.StatusInternalServerError, err)
}

// handleRegistriesStatus reports which backend is responsible for each
// registry's records, whether that backend persists them, and whether it can
// serve right now. It exposes no DSN, credential or topology — only the backend
// KIND — and is gated by the same permission as the registry data itself, so the
// Registries page can render the truth for the operator who reads it.
func (s *server) handleRegistriesStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, errors.New("GET only"))
		return
	}
	if _, ok := s.requirePerm(w, r, "infrastructure", LevelRead); !ok {
		return
	}
	healthy, reason := platformdb.Health(r.Context())
	writeJSON(w, http.StatusOK,
		registrystatus.Build(registrySpecs(), platformdb.Kind(), healthy, reason))
}
