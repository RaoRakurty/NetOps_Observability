package main

// identity_handlers.go — admin CRUD for users, roles, tenants and API keys.
// All routes here require the caller to hold administration:admin (super-admin
// always qualifies). See docs/IDENTITY_ACCESS.md + docs/API_ACCESS.md.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

// requireAdmin gates a handler on administration:admin. Returns the caller's
// claims on success; writes 401/403 and returns ok=false otherwise.
func (s *server) requireAdmin(w http.ResponseWriter, r *http.Request) (jwtClaims, bool) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return jwtClaims{}, false
	}
	if !s.roles.Allows(claims.Role, "administration", LevelAdmin) {
		writeError(w, http.StatusForbidden, errors.New("administration admin permission required"))
		return jwtClaims{}, false
	}
	return claims, true
}

// handlePermissions returns the caller's effective module→level grid so the
// SPA can gate navigation. Available to any authenticated user.
func (s *server) handlePermissions(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	perms := map[string]int{}
	for _, m := range Modules {
		switch {
		case isSuperAdminRole(claims.Role):
			perms[m] = LevelAdmin
		default:
			if role, ok := s.roles.Get(claims.Role); ok {
				perms[m] = role.Permissions[m]
			}
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"role": claims.Role, "permissions": perms})
}

// ---- users -----------------------------------------------------------------

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	Role        string `json:"role"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	TenantID    string `json:"tenant_id"`
	Status      string `json:"status"`
}

func (s *server) handleUsers(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		users := s.users.List()
		out := make([]publicUser, 0, len(users))
		for _, u := range users {
			out = append(out, toPublic(u))
		}
		writeJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req createUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		role := req.Role
		if role == "" {
			role = RoleReadOnly
		}
		if _, ok := s.roles.Get(role); !ok {
			writeError(w, http.StatusBadRequest, errors.New("unknown role"))
			return
		}
		u, err := s.users.CreateFull(User{
			Username: req.Username, Role: role, Email: req.Email,
			DisplayName: req.DisplayName, TenantID: req.TenantID, Status: req.Status,
		}, req.Password)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("identity", "user created", map[string]any{"user": u.Username, "role": u.Role})
		writeJSON(w, http.StatusCreated, toPublic(u))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

type updateUserRequest struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
	TenantID    string `json:"tenant_id"`
	Status      string `json:"status"`
	Password    string `json:"password"` // optional admin reset
}

func (s *server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/users/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid username"))
		return
	}
	switch r.Method {
	case http.MethodPatch, http.MethodPut:
		var req updateUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Role != "" {
			if _, ok := s.roles.Get(req.Role); !ok {
				writeError(w, http.StatusBadRequest, errors.New("unknown role"))
				return
			}
		}
		u, err := s.users.Update(id, User{
			Role: req.Role, Email: req.Email, DisplayName: req.DisplayName,
			TenantID: req.TenantID, Status: req.Status,
		})
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		if req.Password != "" {
			if err := s.users.ResetPassword(id, req.Password); err != nil {
				writeError(w, http.StatusBadRequest, err)
				return
			}
		}
		writeJSON(w, http.StatusOK, toPublic(u))
	case http.MethodDelete:
		if err := s.users.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PATCH, PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- roles -----------------------------------------------------------------

func (s *server) handleRoles(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"modules": Modules, "roles": s.roles.List()})
	case http.MethodPost:
		var role Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		saved, err := s.roles.Upsert(role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, saved)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleRoleByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/roles/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid role id"))
		return
	}
	switch r.Method {
	case http.MethodPut:
		var role Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		role.ID = id
		saved, err := s.roles.Upsert(role)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusOK, saved)
	case http.MethodDelete:
		if err := s.roles.Delete(id); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.Header().Set("Allow", "PUT, DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ---- tenants ---------------------------------------------------------------

type createTenantRequest struct {
	Name string `json:"name"`
	Note string `json:"note"`
}

func (s *server) handleTenants(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.tenants.List())
	case http.MethodPost:
		var req createTenantRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		t, err := s.tenants.Create(req.Name, req.Note)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		writeJSON(w, http.StatusCreated, t)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleTenantByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/tenants/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid tenant id"))
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.tenants.Delete(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---- api keys --------------------------------------------------------------

type createAPIKeyRequest struct {
	Label    string   `json:"label"`
	TenantID string   `json:"tenant_id"`
	Scopes   []string `json:"scopes"`
}

func (s *server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	claims, ok := s.requireAdmin(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.apiKeys.List())
	case http.MethodPost:
		var req createAPIKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		rec, secret, err := s.apiKeys.Create(req.TenantID, req.Label, claims.Sub, req.Scopes)
		if err != nil {
			writeError(w, http.StatusBadRequest, err)
			return
		}
		logInfo("identity", "api key created", map[string]any{"id": rec.ID, "by": claims.Sub})
		// The plaintext secret is returned exactly once here.
		writeJSON(w, http.StatusCreated, map[string]any{"key": rec, "secret": secret})
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *server) handleAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.requireAdmin(w, r); !ok {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/apikeys/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, errors.New("invalid key id"))
		return
	}
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", "DELETE")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := s.apiKeys.Revoke(id); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
