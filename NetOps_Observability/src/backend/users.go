package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// User store, persisted to /data/users.json.
//
// File-backed because the scaffold avoids dragging in a Postgres
// driver dependency. The store implements the same Create/Get/Update
// operations a real backend would, so swapping to Postgres later is a
// single-file change with no API surface impact.

type User struct {
	Username     string    `json:"username"`
	Role         string    `json:"role"`           // role id (legacy: "admin" | "viewer")
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Status       string    `json:"status,omitempty"` // active | invited | disabled
	AuthSource   string    `json:"auth_source,omitempty"` // local | oidc | saml | ldap
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	LastLoginAt  time.Time `json:"last_login_at,omitempty"`
}

type userStore struct {
	mu    sync.RWMutex
	path  string
	users map[string]User
}

func newUserStore(path string) (*userStore, error) {
	if path == "" {
		path = "/data/users.json"
	}
	s := &userStore{path: path, users: make(map[string]User)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *userStore) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var list []User
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	for _, u := range list {
		s.users[strings.ToLower(u.Username)] = u
	}
	return nil
}

func (s *userStore) flushLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	// Atomic write: write to temp file then rename.
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func (s *userStore) Get(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(username)]
	return u, ok
}

func (s *userStore) Create(username, password, role string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if len(password) < 8 {
		return User{}, errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(password)
	if err != nil {
		return User{}, err
	}
	u := User{
		Username:     username,
		Role:         role,
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[strings.ToLower(username)]; exists {
		return User{}, fmt.Errorf("user %q already exists", username)
	}
	s.users[strings.ToLower(username)] = u
	if err := s.flushLocked(); err != nil {
		delete(s.users, strings.ToLower(username))
		return User{}, err
	}
	return u, nil
}

// List returns all users sorted by username (passwords never included by the
// handler, which maps through toPublic).
func (s *userStore) List() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

// CreateFull creates a user with the richer identity fields. An empty password
// produces an account with no usable local password (e.g. an invited or
// federated user) — login simply never matches until a password is set.
func (s *userStore) CreateFull(u User, password string) (User, error) {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		return User{}, errors.New("username required")
	}
	if password != "" {
		if len(password) < 8 {
			return User{}, errors.New("password must be at least 8 characters")
		}
		hash, err := hashPassword(password)
		if err != nil {
			return User{}, err
		}
		u.PasswordHash = hash
	}
	if u.Status == "" {
		u.Status = "active"
	}
	if u.AuthSource == "" {
		u.AuthSource = "local"
	}
	u.CreatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[strings.ToLower(u.Username)]; exists {
		return User{}, fmt.Errorf("user %q already exists", u.Username)
	}
	s.users[strings.ToLower(u.Username)] = u
	if err := s.flushLocked(); err != nil {
		delete(s.users, strings.ToLower(u.Username))
		return User{}, err
	}
	return u, nil
}

// Update applies a patch to mutable profile fields (role, email, display name,
// tenant, status). Admin-safe: refuses to demote or disable the last user who
// holds the super-admin role, so an operator can never lock everyone out.
func (s *userStore) Update(username string, patch User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := s.users[key]
	if !ok {
		return User{}, errors.New("no such user")
	}
	demoting := patch.Role != "" && patch.Role != u.Role && isSuperAdminRole(u.Role)
	disabling := patch.Status == "disabled" && isSuperAdminRole(u.Role)
	if (demoting || disabling) && s.countSuperAdminsLocked() <= 1 {
		return User{}, errors.New("cannot demote or disable the last super-admin")
	}
	if patch.Role != "" {
		u.Role = patch.Role
	}
	if patch.Email != "" {
		u.Email = patch.Email
	}
	if patch.DisplayName != "" {
		u.DisplayName = patch.DisplayName
	}
	if patch.TenantID != "" {
		u.TenantID = patch.TenantID
	}
	if patch.Status != "" {
		u.Status = patch.Status
	}
	s.users[key] = u
	if err := s.flushLocked(); err != nil {
		return User{}, err
	}
	return u, nil
}

// Delete removes a user. Admin-safe: the last super-admin cannot be deleted.
func (s *userStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := s.users[key]
	if !ok {
		return errors.New("no such user")
	}
	if isSuperAdminRole(u.Role) && s.countSuperAdminsLocked() <= 1 {
		return errors.New("cannot delete the last super-admin")
	}
	delete(s.users, key)
	return s.flushLocked()
}

func (s *userStore) countSuperAdminsLocked() int {
	n := 0
	for _, u := range s.users {
		if isSuperAdminRole(u.Role) && u.Status != "disabled" {
			n++
		}
	}
	return n
}

// ResetPassword sets a new password for any user (admin action — no current
// password required). Distinct from ChangePassword, which is self-service.
func (s *userStore) ResetPassword(username, newPassword string) error {
	return s.ChangePassword(username, newPassword)
}

func (s *userStore) ChangePassword(username, newPassword string) error {
	if len(newPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return errors.New("no such user")
	}
	u.PasswordHash = hash
	s.users[strings.ToLower(username)] = u
	return s.flushLocked()
}

func (s *userStore) TouchLogin(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return
	}
	u.LastLoginAt = time.Now().UTC()
	s.users[strings.ToLower(username)] = u
	_ = s.flushLocked()
}

func (s *userStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// SeedAdmin creates the bootstrap admin user if the store is empty.
// Called once on server start with credentials from env.
func (s *userStore) SeedAdmin(username, password string) error {
	if username == "" || password == "" {
		return nil // nothing to do
	}
	if s.Count() > 0 {
		return nil
	}
	_, err := s.Create(username, password, "admin")
	return err
}
