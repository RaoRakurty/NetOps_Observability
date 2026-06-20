package main

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
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var errServiceStoreOff = errors.New("service catalog requires the PostgreSQL backend")

var validCriticality = map[string]bool{"critical": true, "high": true, "normal": true, "low": true}
var validBindingKind = map[string]bool{"probe": true, "path": true, "seam": true}

// Service — stable identity. Renames don't break attribution history; archive,
// never hard-delete.
type Service struct {
	ServiceID   string     `json:"service_id"`
	TenantID    string     `json:"tenant_id"`
	Name        string     `json:"name"`
	Criticality string     `json:"criticality"`
	Description string     `json:"description"`
	CreatedAt   time.Time  `json:"created_at"`
	ArchivedAt  *time.Time `json:"archived_at,omitempty"`
}

// ServiceSelector — the versioned grouping rule. spec carries the predicates
// (dst_prefixes/ports/protocols/remote_asns/domains/tags).
type ServiceSelector struct {
	ServiceID     string         `json:"service_id"`
	Version       int            `json:"version"`
	EffectiveFrom time.Time      `json:"effective_from"`
	Spec          map[string]any `json:"spec"`
	CreatedBy     string         `json:"created_by"`
	CreatedAt     time.Time      `json:"created_at"`
}

// ServiceBinding — what we operate for the service (probe/path/seam).
type ServiceBinding struct {
	BindingID string    `json:"binding_id"`
	ServiceID string    `json:"service_id"`
	Kind      string    `json:"kind"`
	Ref       string    `json:"ref"`
	CreatedAt time.Time `json:"created_at"`
}

// newUUIDv4 generates a random UUID (stdlib crypto/rand; no dependency).
func newUUIDv4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// validateServiceInput is a pure guard (unit-tested) for create/update.
func validateServiceInput(name, criticality string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return errors.New("service name is required")
	}
	if len(name) > 120 {
		return errors.New("service name too long (max 120)")
	}
	if criticality != "" && !validCriticality[criticality] {
		return errors.New("criticality must be one of critical|high|normal|low")
	}
	return nil
}

// ── store ─────────────────────────────────────────────────────────────────────

type pgServiceStore struct{ db *pgDB }

func newServiceStore() *pgServiceStore {
	if ps, ok := backend.(*pgStore); ok {
		return &pgServiceStore{db: ps.db}
	}
	return nil // Postgres backend only
}

func (st *pgServiceStore) ListServices(ctx context.Context, tenant string, cross bool, includeArchived bool) ([]Service, error) {
	out := make([]Service, 0)
	q := `SELECT service_id, tenant_id, name, criticality, description, created_at, archived_at
            FROM services`
	if !includeArchived {
		q += ` WHERE archived_at IS NULL`
	}
	q += ` ORDER BY created_at DESC`
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, q)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s Service
			if err := rows.Scan(&s.ServiceID, &s.TenantID, &s.Name, &s.Criticality, &s.Description, &s.CreatedAt, &s.ArchivedAt); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

func (st *pgServiceStore) GetService(ctx context.Context, tenant string, cross bool, id string) (Service, bool, error) {
	var s Service
	found := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `SELECT service_id, tenant_id, name, criticality, description, created_at, archived_at
              FROM services WHERE service_id = $1`, id)
		e := row.Scan(&s.ServiceID, &s.TenantID, &s.Name, &s.Criticality, &s.Description, &s.CreatedAt, &s.ArchivedAt)
		if errors.Is(e, pgx.ErrNoRows) {
			return nil
		}
		if e != nil {
			return e
		}
		found = true
		return nil
	})
	return s, found, err
}

func (st *pgServiceStore) CreateService(ctx context.Context, tenant string, cross bool, in Service) (Service, error) {
	id, err := newUUIDv4()
	if err != nil {
		return Service{}, err
	}
	in.ServiceID = id
	if in.Criticality == "" {
		in.Criticality = "normal"
	}
	err = st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		row := tx.QueryRow(ctx, `INSERT INTO services (service_id, tenant_id, name, criticality, description)
              VALUES ($1,$2,$3,$4,$5) RETURNING created_at`, in.ServiceID, in.TenantID, in.Name, in.Criticality, in.Description)
		return row.Scan(&in.CreatedAt)
	})
	return in, err
}

// ArchiveService soft-deletes (sets archived_at) — never a hard DELETE, because
// flow attribution history references the service_id. Returns false if not found.
func (st *pgServiceStore) ArchiveService(ctx context.Context, tenant string, cross bool, id string) (bool, error) {
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `UPDATE services SET archived_at = now() WHERE service_id = $1 AND archived_at IS NULL`, id)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

func (st *pgServiceStore) ListSelectors(ctx context.Context, tenant string, cross bool, serviceID string) ([]ServiceSelector, error) {
	out := make([]ServiceSelector, 0)
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT service_id, version, effective_from, spec, created_by, created_at
              FROM service_selectors WHERE service_id = $1 ORDER BY version DESC`, serviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var sel ServiceSelector
			var spec []byte
			if err := rows.Scan(&sel.ServiceID, &sel.Version, &sel.EffectiveFrom, &spec, &sel.CreatedBy, &sel.CreatedAt); err != nil {
				return err
			}
			if err := json.Unmarshal(spec, &sel.Spec); err != nil {
				return fmt.Errorf("selector %s v%d spec: %w", sel.ServiceID, sel.Version, err)
			}
			out = append(out, sel)
		}
		return rows.Err()
	})
	return out, err
}

// AddSelector appends a NEW version (max+1) — selectors are append-only so past
// attribution stays reproducible. effective_from defaults to now.
func (st *pgServiceStore) AddSelector(ctx context.Context, tenant string, cross bool, serviceID string, spec map[string]any, createdBy string) (ServiceSelector, error) {
	if spec == nil {
		spec = map[string]any{}
	}
	specJSON, err := json.Marshal(spec)
	if err != nil {
		return ServiceSelector{}, err
	}
	sel := ServiceSelector{ServiceID: serviceID, Spec: spec, CreatedBy: createdBy}
	err = st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		// service must exist + be visible under RLS (FK-by-policy + honest 404 upstream)
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT true FROM services WHERE service_id = $1`, serviceID).Scan(&exists); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return errNotFound
			}
			return e
		}
		row := tx.QueryRow(ctx, `INSERT INTO service_selectors (tenant_id, service_id, version, spec, created_by)
              VALUES (current_setting('app.tenant_id', true), $1,
                      (SELECT coalesce(max(version),0)+1 FROM service_selectors WHERE service_id = $1), $2, $3)
              RETURNING version, effective_from, created_at`, serviceID, specJSON, createdBy)
		return row.Scan(&sel.Version, &sel.EffectiveFrom, &sel.CreatedAt)
	})
	return sel, err
}

func (st *pgServiceStore) ListBindings(ctx context.Context, tenant string, cross bool, serviceID string) ([]ServiceBinding, error) {
	out := make([]ServiceBinding, 0)
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT binding_id, service_id, kind, ref, created_at
              FROM service_bindings WHERE service_id = $1 ORDER BY created_at`, serviceID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var b ServiceBinding
			if err := rows.Scan(&b.BindingID, &b.ServiceID, &b.Kind, &b.Ref, &b.CreatedAt); err != nil {
				return err
			}
			out = append(out, b)
		}
		return rows.Err()
	})
	return out, err
}

func (st *pgServiceStore) AddBinding(ctx context.Context, tenant string, cross bool, serviceID, kind, ref string) (ServiceBinding, error) {
	id, err := newUUIDv4()
	if err != nil {
		return ServiceBinding{}, err
	}
	b := ServiceBinding{BindingID: id, ServiceID: serviceID, Kind: kind, Ref: ref}
	err = st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		var exists bool
		if e := tx.QueryRow(ctx, `SELECT true FROM services WHERE service_id = $1`, serviceID).Scan(&exists); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return errNotFound
			}
			return e
		}
		row := tx.QueryRow(ctx, `INSERT INTO service_bindings (binding_id, tenant_id, service_id, kind, ref)
              VALUES ($1, current_setting('app.tenant_id', true), $2, $3, $4) RETURNING created_at`,
			id, serviceID, kind, ref)
		return row.Scan(&b.CreatedAt)
	})
	return b, err
}

func (st *pgServiceStore) DeleteBinding(ctx context.Context, tenant string, cross bool, serviceID, bindingID string) (bool, error) {
	affected := false
	err := st.db.withTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx, `DELETE FROM service_bindings WHERE binding_id = $1 AND service_id = $2`, bindingID, serviceID)
		if e != nil {
			return e
		}
		affected = ct.RowsAffected() > 0
		return nil
	})
	return affected, err
}

var errNotFound = errors.New("not found")

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
		if err := validateServiceInput(in.Name, in.Criticality); err != nil {
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
	switch r.Method {
	case http.MethodGet:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelRead)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		svc, found, err := s.services.GetService(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		if !found {
			writeError(w, http.StatusNotFound, errNotFound)
			return
		}
		writeJSON(w, http.StatusOK, svc)
	case http.MethodDelete:
		claims, ok := s.requirePerm(w, r, "infrastructure", LevelWrite)
		if !ok {
			return
		}
		tenant, cross := principalTenant(claims)
		ok2, err := s.services.ArchiveService(r.Context(), tenant, cross, id)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
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
		if !validBindingKind[in.Kind] {
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
