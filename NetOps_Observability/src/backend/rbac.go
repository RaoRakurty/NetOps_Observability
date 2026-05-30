package main

// rbac.go — granular, module-level role-based access control.
//
// File-backed (roles.json) in the same spirit as the user/saved stores: no
// database dependency, swappable to Postgres later behind the same methods.
// See docs/IDENTITY_ACCESS.md for the model. Modules map to product nav
// sections; permission levels form a monotonic ladder none<read<write<admin.

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Modules are the gated product areas (match the frontend nav sections).
var Modules = []string{
	"overview", "explore", "alerts", "infrastructure", "topology", "reports", "administration",
}

// Permission levels (monotonic — each implies the ones below it).
const (
	LevelNone  = 0
	LevelRead  = 1
	LevelWrite = 2
	LevelAdmin = 3
)

func levelName(l int) string {
	switch l {
	case LevelAdmin:
		return "admin"
	case LevelWrite:
		return "write"
	case LevelRead:
		return "read"
	default:
		return "none"
	}
}

func levelValue(name string) int {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "admin":
		return LevelAdmin
	case "write":
		return LevelWrite
	case "read":
		return LevelRead
	default:
		return LevelNone
	}
}

// Role is a named permission grid. Built-in roles are seeded and protected.
type Role struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Builtin     bool           `json:"builtin"`
	Description string         `json:"description"`
	Permissions map[string]int `json:"permissions"` // module -> level
}

// Built-in role IDs.
const (
	RoleSuperAdmin = "super-admin"
	RoleOperator   = "operator"
	RoleReadOnly   = "read-only"
)

// isSuperAdminRole maps both the new role id and the legacy "admin" value onto
// super-admin, so pre-existing users.json accounts keep full access.
func isSuperAdminRole(role string) bool {
	r := strings.ToLower(strings.TrimSpace(role))
	return r == RoleSuperAdmin || r == "admin"
}

// legacyRoleAlias normalizes the historical "admin"/"viewer" values onto the
// new built-in role ids during permission resolution.
func legacyRoleAlias(role string) string {
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "admin":
		return RoleSuperAdmin
	case "viewer", "":
		return RoleReadOnly
	default:
		return role
	}
}

func builtinRoles() []Role {
	all := func(l int) map[string]int {
		m := map[string]int{}
		for _, mod := range Modules {
			m[mod] = l
		}
		return m
	}
	operator := all(LevelRead)
	operator["alerts"] = LevelWrite
	operator["infrastructure"] = LevelWrite
	operator["administration"] = LevelNone
	readonly := all(LevelRead)
	readonly["administration"] = LevelNone
	return []Role{
		{ID: RoleSuperAdmin, Name: "Super Admin", Builtin: true,
			Description: "Full control across all tenants, including identity.", Permissions: all(LevelAdmin)},
		{ID: RoleOperator, Name: "Operator", Builtin: true,
			Description: "Acknowledge/silence alerts, run discovery, manage devices.", Permissions: operator},
		{ID: RoleReadOnly, Name: "Read-only", Builtin: true,
			Description: "View everything, change nothing.", Permissions: readonly},
	}
}

type roleStore struct {
	mu    sync.RWMutex
	path  string
	roles map[string]Role
}

func newRoleStore(path string) (*roleStore, error) {
	if path == "" {
		path = "/data/roles.json"
	}
	s := &roleStore{path: path, roles: make(map[string]Role)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// Always (re)seed built-ins so upgrades pick up new defaults; custom roles
	// are preserved.
	changed := false
	for _, r := range builtinRoles() {
		if _, ok := s.roles[r.ID]; !ok {
			s.roles[r.ID] = r
			changed = true
		}
	}
	if changed {
		if err := s.flushLocked(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *roleStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []Role
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, r := range list {
		s.roles[r.ID] = r
	}
	return nil
}

func (s *roleStore) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	list := make([]Role, 0, len(s.roles))
	for _, r := range s.roles {
		list = append(list, r)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *roleStore) List() []Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]Role, 0, len(s.roles))
	for _, r := range s.roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Builtin != out[j].Builtin {
			return out[i].Builtin // built-ins first
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func (s *roleStore) Get(id string) (Role, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	r, ok := s.roles[legacyRoleAlias(id)]
	return r, ok
}

func slugify(name string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(name)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '_':
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// Upsert creates or replaces a custom role. Built-in roles cannot be created
// or overwritten through this path.
func (s *roleStore) Upsert(r Role) (Role, error) {
	if strings.TrimSpace(r.Name) == "" {
		return Role{}, errors.New("role name required")
	}
	if r.ID == "" {
		r.ID = slugify(r.Name)
	}
	if r.ID == "" {
		return Role{}, errors.New("role name must contain letters or digits")
	}
	r.Builtin = false
	clean := map[string]int{}
	for _, mod := range Modules {
		clean[mod] = r.Permissions[mod] // defaults to 0 (none)
	}
	r.Permissions = clean
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.roles[r.ID]; ok && existing.Builtin {
		return Role{}, errors.New("cannot overwrite a built-in role")
	}
	s.roles[r.ID] = r
	if err := s.flushLocked(); err != nil {
		return Role{}, err
	}
	return r, nil
}

func (s *roleStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.roles[id]
	if !ok {
		return errors.New("no such role")
	}
	if r.Builtin {
		return errors.New("cannot delete a built-in role")
	}
	delete(s.roles, id)
	return s.flushLocked()
}

// Allows reports whether a role grants at least `need` on a module. Super-admin
// (and the legacy "admin" value) always passes.
func (s *roleStore) Allows(roleID, module string, need int) bool {
	if isSuperAdminRole(roleID) {
		return true
	}
	r, ok := s.Get(roleID)
	if !ok {
		return false
	}
	return r.Permissions[module] >= need
}
