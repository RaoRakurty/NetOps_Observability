package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// User store.
//
// Two backends implement the usersRepo seam (mirroring auditRepo, #32):
//   - userStore (file/default, below): the whole collection lives in memory and
//     is flushed as one JSON blob. Fine for single-node dev/lab.
//   - pgUsersStore (STORE_BACKEND=postgres, users_pg.go): one row per user in an
//     RLS-protected table; reads are query-driven, the tenant-scoped List is
//     enforced per request by Row-Level Security (not just an app-layer filter),
//     and mutations are partial UPDATEs instead of rewrite-the-whole-collection.
//
// The domain invariants that must hold identically across both backends —
// patch application, federated-account refresh, the last-super-admin guard, and
// password validation — are factored into the pure helpers near the bottom of
// this file and shared by both implementations so they cannot drift.

// usersRepo is the user-store seam. Reads split by tenant scope:
//   - List(tenant, cross) is PER-REQUEST tenant-scoped: a scoped admin sees only
//     its own tenant's users (RLS-enforced on the pg backend; the same
//     sameTenant filter on the file backend). The platform owner ('*') sees all.
//   - Get is tenant-BLIND by design: username is a global identity key, and login
//     resolves a user's tenant FROM the record before any tenant scope exists, so
//     the lookup must span all tenants. Authorization on the resolved user stays
//     at the handler/Authorize() chokepoint.
// Mutations likewise run at platform scope on the pg backend (global username PK,
// platform-wide super-admin invariant); the handler gates who may mutate whom.
type usersRepo interface {
	Get(username string) (User, bool)
	List(tenant string, cross bool) []User
	Create(username, password, role string) (User, error)
	CreateFull(u User, password string) (User, error)
	Update(username string, patch User) (User, error)
	Delete(username string) error
	UpsertFederated(username, email, displayName, role, source, tenant string) (User, error)
	ChangePassword(username, newPassword string) error
	ResetPassword(username, newPassword string) error
	TouchLogin(username string)
	Count() int
	SeedAdmin(username, password string) error
}

// newUsersStore selects the user-store backend, mirroring newAuditStore: under
// STORE_BACKEND=postgres it returns the per-row pgUsersStore; otherwise the
// file-backed userStore. The choice keys off the already-initialized process
// backend, so initStoreBackend must have run first (it does — main.go wires it
// before constructing stores).
func newUsersStore(path string) (usersRepo, error) {
	if ps, ok := backend.(*pgStore); ok {
		return newPgUsersStore(ps.db), nil
	}
	return newUserStore(path)
}

type User struct {
	Username     string    `json:"username"`
	Role         string    `json:"role"` // role id (legacy: "admin" | "viewer")
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Status       string    `json:"status,omitempty"`      // active | invited | disabled
	AuthSource   string    `json:"auth_source,omitempty"` // local | oidc | saml | ldap
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	LastLoginAt  time.Time `json:"last_login_at,omitempty"`
}

type userStore struct {
	mu       sync.RWMutex
	path     string
	users    map[string]User
	maxUsers int // 0 = unlimited
}

func newUserStore(path string) (*userStore, error) {
	if path == "" {
		path = "/data/users.json"
	}
	s := &userStore{path: path, users: make(map[string]User), maxUsers: maxUsersLimit()}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// maxUsersLimit reads the configurable account cap from MAX_USERS (0/unset =
// unlimited). A cap is best practice for abuse/resource control and licensing —
// e.g. Versa caps a single VOS at 256 tenants — so the limit is exposed but
// defaults to unlimited to preserve existing behavior. Negative/garbage → 0.
func maxUsersLimit() int {
	if v := os.Getenv("MAX_USERS"); v != "" {
		if n, err := parseIntStrict(v); err == nil && n > 0 {
			return n
		}
	}
	return 0
}

// atCapLocked reports whether adding another LOCAL/admin-created account would
// exceed the configured cap. Caller must hold s.mu. Federated JIT provisioning
// (UpsertFederated) is intentionally exempt so the cap never locks out SSO.
func (s *userStore) atCapLocked() bool {
	return s.maxUsers > 0 && len(s.users) >= s.maxUsers
}

func (s *userStore) load() error {
	b, err := kvLoad(s.path)
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
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return kvSave(s.path, b)
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
	if err := validatePassword(password); err != nil {
		return User{}, err
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
	if s.atCapLocked() {
		return User{}, fmt.Errorf("user limit reached (MAX_USERS=%d)", s.maxUsers)
	}
	s.users[strings.ToLower(username)] = u
	if err := s.flushLocked(); err != nil {
		delete(s.users, strings.ToLower(username))
		return User{}, err
	}
	return u, nil
}

// List returns the users visible to the caller, sorted by username (passwords
// never included by the handler, which maps through toPublic). The platform
// owner ('*') sees all; a scoped admin sees only its own tenant's users —
// strict isolation, mirroring the RLS the pg backend enforces in-database.
func (s *userStore) List(tenant string, cross bool) []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.users))
	for _, u := range s.users {
		if !sameTenant(u.TenantID, tenant, cross) {
			continue
		}
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
		if err := validatePassword(password); err != nil {
			return User{}, err
		}
		hash, err := hashPassword(password)
		if err != nil {
			return User{}, err
		}
		u.PasswordHash = hash
	}
	u = applyCreateDefaults(u)
	u.CreatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[strings.ToLower(u.Username)]; exists {
		return User{}, fmt.Errorf("user %q already exists", u.Username)
	}
	if s.atCapLocked() {
		return User{}, fmt.Errorf("user limit reached (MAX_USERS=%d)", s.maxUsers)
	}
	s.users[strings.ToLower(u.Username)] = u
	if err := s.flushLocked(); err != nil {
		delete(s.users, strings.ToLower(u.Username))
		return User{}, err
	}
	return u, nil
}

// UpsertFederated provisions or refreshes a user authenticated by an external
// IdP (via Keycloak). On first login it creates a passwordless account
// (auth_source != local); on subsequent logins it refreshes the profile and the
// IdP-derived role so Keycloak role/group changes propagate. A pre-existing
// LOCAL account of the same name is never silently converted or re-roled — the
// federated login is accepted against it but local management wins.
func (s *userStore) UpsertFederated(username, email, displayName, role, source, tenant string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if source == "" {
		source = "oidc"
	}
	key := strings.ToLower(username)
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.users[key]; ok {
		if u.AuthSource != "local" {
			// Federated account — keep it in sync with the IdP.
			u = mergeFederated(u, email, displayName, role, source)
			s.users[key] = u
			if err := s.flushLocked(); err != nil {
				return User{}, err
			}
		}
		return u, nil
	}
	if tenant == "" {
		tenant = TenantGlobal
	}
	u := User{
		Username: username, Role: role, Email: email, DisplayName: displayName,
		TenantID: tenant, Status: "active", AuthSource: source, CreatedAt: time.Now().UTC(),
	}
	s.users[key] = u
	if err := s.flushLocked(); err != nil {
		delete(s.users, key)
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
		return User{}, errNoSuchUser
	}
	if updateTouchesLastSuperAdmin(u, patch) && s.countSuperAdminsLocked() <= 1 {
		return User{}, errLastSuperAdmin
	}
	u = applyUserPatch(u, patch)
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
		return errNoSuchUser
	}
	if isSuperAdminRole(u.Role) && s.countSuperAdminsLocked() <= 1 {
		return errLastSuperAdminDelete
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
	if err := validatePassword(newPassword); err != nil {
		return err
	}
	hash, err := hashPassword(newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return errNoSuchUser
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

// ---- shared domain logic (backend-agnostic) --------------------------------
//
// These pure helpers and sentinel errors encode the user-store invariants that
// MUST behave identically whether the backing store is the in-memory file map
// or normalized Postgres rows. Both userStore and pgUsersStore call them so the
// rules can't drift apart.

// maxPasswordLen caps password length to bound the work the PBKDF2 KDF
// (pbkdf2Iter = 600k HMAC-SHA256 rounds) performs per login/change. Without an
// upper bound, a multi-MB "password" forces the server to hash the whole input
// 600k times per request — an amplification DoS on the (unauthenticated) login
// path (SR-013). 128 chars comfortably exceeds any real passphrase.
const maxPasswordLen = 128

var (
	errShortPassword        = errors.New("password must be at least 8 characters")
	errLongPassword         = errors.New("password must be at most 128 characters")
	errLastSuperAdmin       = errors.New("cannot demote or disable the last super-admin")
	errLastSuperAdminDelete = errors.New("cannot delete the last super-admin")
	errNoSuchUser           = errors.New("no such user")
)

// validatePassword enforces the minimum password length (a non-empty password
// must be at least 8 characters). Empty is handled by the callers (CreateFull
// permits a passwordless/invited account; Create/ChangePassword require one).
func validatePassword(password string) error {
	if len(password) < 8 {
		return errShortPassword
	}
	if len(password) > maxPasswordLen {
		return errLongPassword
	}
	return nil
}

// applyCreateDefaults fills the create-time defaults for a rich-profile user:
// an active, local account unless the caller said otherwise. Pure.
func applyCreateDefaults(u User) User {
	if u.Status == "" {
		u.Status = "active"
	}
	if u.AuthSource == "" {
		u.AuthSource = "local"
	}
	return u
}

// applyUserPatch applies a mutable-field patch (role, email, display name,
// tenant, status) onto a user; empty patch fields leave the current value. Pure
// — the last-super-admin guard is the caller's responsibility (it needs a count).
func applyUserPatch(u, patch User) User {
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
	return u
}

// updateTouchesLastSuperAdmin reports whether a patch would demote (change the
// role of) or disable a super-admin — the two operations that must be refused
// when only one super-admin remains, so an operator can never lock everyone out.
func updateTouchesLastSuperAdmin(u, patch User) bool {
	demoting := patch.Role != "" && patch.Role != u.Role && isSuperAdminRole(u.Role)
	disabling := patch.Status == "disabled" && isSuperAdminRole(u.Role)
	return demoting || disabling
}

// mergeFederated refreshes a federated (non-local) account from its IdP: any
// non-empty incoming attribute overwrites, and the auth source is updated so a
// user that moved IdPs (oidc→ldap) is re-tagged. Pure. A pre-existing LOCAL
// account is never passed here — local management wins (see UpsertFederated).
func mergeFederated(u User, email, displayName, role, source string) User {
	if email != "" {
		u.Email = email
	}
	if displayName != "" {
		u.DisplayName = displayName
	}
	if role != "" {
		u.Role = role
	}
	u.AuthSource = source
	return u
}
