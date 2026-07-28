package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"netops/backend/internal/token"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// User store.
//
// Two backends implement the Repo seam (mirroring auditRepo, #32):
//   - FileStore (file/default, below): the whole collection lives in memory and
//     is flushed as one JSON blob. Fine for single-node dev/lab.
//   - PGStore (STORE_BACKEND=postgres, users_pg.go): one row per user in an
//     RLS-protected table; reads are query-driven, the tenant-scoped List is
//     enforced per request by Row-Level Security (not just an app-layer filter),
//     and mutations are partial UPDATEs instead of rewrite-the-whole-collection.
//
// The domain invariants that must hold identically across both backends —
// patch application, federated-account refresh, the last-super-admin guard, and
// password validation — are factored into the pure helpers near the bottom of
// this file and shared by both implementations so they cannot drift.

// Repo is the user-store seam. Reads split by tenant scope:
//   - List(tenant, cross) is PER-REQUEST tenant-scoped: a scoped admin sees only
//     its own tenant's users (RLS-enforced on the pg backend; the same
//     sameTenant filter on the file backend). The platform owner ('*') sees all.
//   - Get is tenant-BLIND by design: username is a global identity key, and login
//     resolves a user's tenant FROM the record before any tenant scope exists, so
//     the lookup must span all tenants. Authorization on the resolved user stays
//     at the handler/Authorize() chokepoint.
//
// Mutations likewise run at platform scope on the pg backend (global username PK,
// platform-wide super-admin invariant); the handler gates who may mutate whom.
type Repo interface {
	Get(username string) (User, bool)
	List(tenant string, cross bool) []User
	Create(username, password, role string) (User, error)
	CreateFull(u User, password string) (User, error)
	Update(username string, patch User) (User, error)
	Delete(username string) error
	UpsertFederated(username, email, displayName, role, source, tenant string) (User, error)
	ChangePassword(username, newPassword string) error
	ResetPassword(username, newPassword string) error
	// RehashPassword re-wraps the SAME secret at the current cost (SR-029). It
	// updates only the hash — never PasswordChangedAt, never the history — so
	// rehash-on-login cannot silently reset the password_expire_days clock.
	RehashPassword(username, samePassword string) error
	// SetMFA sets the account's MFA state atomically (secret/pending already sealed
	// by the caller). enabled=false + empty strings clears MFA.
	SetMFA(username string, enabled bool, secret, pending string) error
	TouchLogin(username string)
	Count() int
	SeedAdmin(username, password string) error
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

	// MFA (TOTP) for local accounts. MFASecret/MFAPending hold the base32 seed
	// SEALED at rest (platform DEK) — never returned to clients. MFAPending is the
	// not-yet-confirmed seed during enrollment; on confirm it becomes MFASecret and
	// MFAEnabled flips true. Federated users don't use these (their IdP owns MFA).
	MFAEnabled bool   `json:"mfa_enabled,omitempty"`
	MFASecret  string `json:"mfa_secret,omitempty"`
	MFAPending string `json:"mfa_pending,omitempty"`

	// Account-lifecycle state backing the Security Settings that F-68 found
	// stored-but-unenforced. See account_policy.go for the rules these feed.
	//
	// PasswordChangedAt is stamped by a REAL password change only — never by the
	// SR-029 rehash-on-login, which would otherwise reset the expiry clock every
	// time the user signed in and make password_expire_days unreachable forever.
	// ZERO means "unknown": the expiry rule then declines to fire rather than
	// force a fleet-wide reset on the first boot after upgrade (the F-58 lesson —
	// a converge step must not destroy the estate it is converging).
	PasswordChangedAt time.Time `json:"password_changed_at,omitempty"`
	// PasswordHistory holds prior hashes, newest first, bounded to
	// passwordHistoryDepth. Only consulted when password_history is on.
	PasswordHistory []string `json:"password_history,omitempty"`
	// MustChangePassword forces a reset before a session is issued. Set at create
	// time under reset_on_first_login, and by the expiry rule at login.
	MustChangePassword bool `json:"must_change_password,omitempty"`
}

// KV abstracts where the file backend persists its JSON blob (the platform kv
// layer; a missing key must return an os.ErrNotExist-wrapped error).
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// Deps are the cross-domain inputs the store must not own: persistence, the
// structured error sink, the SR-025 federated-role guard, the role predicate
// behind the last-super-admin invariant, account_policy's password-change
// stamping, the tenant default for federated JIT, and the MAX_USERS cap.
type Deps struct {
	KV                  KV
	Errorf              func(component, msg string, fields map[string]any)
	GuardRole           func(role, tenant, username, source string) string
	IsSuperAdmin        func(role string) bool
	ApplyPasswordChange func(u *User, hash string, now time.Time)
	DefaultTenant       string
	MaxUsers            int // 0 = unlimited
}

func (d Deps) validate() error {
	if d.Errorf == nil || d.GuardRole == nil || d.IsSuperAdmin == nil || d.ApplyPasswordChange == nil || d.DefaultTenant == "" {
		return errors.New("users: Errorf, GuardRole, IsSuperAdmin, ApplyPasswordChange and DefaultTenant are required")
	}
	return nil
}

type FileStore struct {
	mu    sync.RWMutex
	path  string
	deps  Deps
	users map[string]User
}

// NewFileStore opens the file-backed store (Deps.KV required).
func NewFileStore(path string, d Deps) (*FileStore, error) {
	if path == "" {
		path = "/data/users.json"
	}
	if err := d.validate(); err != nil {
		return nil, err
	}
	if d.KV == nil {
		return nil, errors.New("users.NewFileStore: Deps.KV is required")
	}
	s := &FileStore{path: path, deps: d, users: make(map[string]User)}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

// atCapLocked reports whether adding another LOCAL/admin-created account would
// exceed the configured cap. Caller must hold s.mu. Federated JIT provisioning
// (UpsertFederated) is intentionally exempt so the cap never locks out SSO.
func (s *FileStore) atCapLocked() bool {
	return s.deps.MaxUsers > 0 && len(s.users) >= s.deps.MaxUsers
}

func (s *FileStore) load() error {
	b, err := s.deps.KV.Load(s.path)
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

func (s *FileStore) flushLocked() error {
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return s.deps.KV.Save(s.path, b)
}

func (s *FileStore) Get(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[strings.ToLower(username)]
	return u, ok
}

func (s *FileStore) Create(username, password, role string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if err := ValidatePassword(password); err != nil {
		return User{}, err
	}
	hash, err := token.HashPassword(password)
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
		return User{}, fmt.Errorf("user limit reached (MAX_USERS=%d)", s.deps.MaxUsers)
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
func (s *FileStore) List(tenant string, cross bool) []User {
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
func (s *FileStore) CreateFull(u User, password string) (User, error) {
	u.Username = strings.TrimSpace(u.Username)
	if u.Username == "" {
		return User{}, errors.New("username required")
	}
	if password != "" {
		if err := ValidatePassword(password); err != nil {
			return User{}, err
		}
		hash, err := token.HashPassword(password)
		if err != nil {
			return User{}, err
		}
		u.PasswordHash = hash
	}
	u = ApplyCreateDefaults(u)
	u.CreatedAt = time.Now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.users[strings.ToLower(u.Username)]; exists {
		return User{}, fmt.Errorf("user %q already exists", u.Username)
	}
	if s.atCapLocked() {
		return User{}, fmt.Errorf("user limit reached (MAX_USERS=%d)", s.deps.MaxUsers)
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

func (s *FileStore) UpsertFederated(username, email, displayName, role, source, tenant string) (User, error) {
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
			// Federated account — keep it in sync with the IdP (SR-025: guard the
			// IdP-mapped role against silent platform-owner escalation, using the
			// account's existing tenant).
			u = MergeFederated(u, email, displayName, s.deps.GuardRole(role, u.TenantID, username, source), source)
			s.users[key] = u
			if err := s.flushLocked(); err != nil {
				return User{}, err
			}
		}
		return u, nil
	}
	if tenant == "" {
		tenant = s.deps.DefaultTenant
	}
	role = s.deps.GuardRole(role, tenant, username, source)
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
func (s *FileStore) Update(username string, patch User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := s.users[key]
	if !ok {
		return User{}, ErrNoSuchUser
	}
	if UpdateTouchesLastSuperAdmin(u, patch, s.deps.IsSuperAdmin) && s.countSuperAdminsLocked() <= 1 {
		return User{}, ErrLastSuperAdmin
	}
	u = ApplyUserPatch(u, patch)
	s.users[key] = u
	if err := s.flushLocked(); err != nil {
		return User{}, err
	}
	return u, nil
}

// Delete removes a user. Admin-safe: the last super-admin cannot be deleted.
func (s *FileStore) Delete(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(username)
	u, ok := s.users[key]
	if !ok {
		return ErrNoSuchUser
	}
	if s.deps.IsSuperAdmin(u.Role) && s.countSuperAdminsLocked() <= 1 {
		return ErrLastSuperAdminDelete
	}
	delete(s.users, key)
	return s.flushLocked()
}

func (s *FileStore) countSuperAdminsLocked() int {
	n := 0
	for _, u := range s.users {
		if s.deps.IsSuperAdmin(u.Role) && u.Status != "disabled" {
			n++
		}
	}
	return n
}

// ResetPassword sets a new password for any user (admin action — no current
// password required). Distinct from ChangePassword, which is self-service.
func (s *FileStore) ResetPassword(username, newPassword string) error {
	return s.ChangePassword(username, newPassword)
}

func (s *FileStore) ChangePassword(username, newPassword string) error {
	return s.setPassword(username, newPassword, true)
}

// RehashPassword re-wraps the same secret at the current cost — hash only.
func (s *FileStore) RehashPassword(username, samePassword string) error {
	return s.setPassword(username, samePassword, false)
}

// setPassword is the single write path for both. `stamp` distinguishes a real
// change (history + expiry clock) from a cost rehash (hash only).
func (s *FileStore) setPassword(username, newPassword string, stamp bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := token.HashPassword(newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return ErrNoSuchUser
	}
	if stamp {
		s.deps.ApplyPasswordChange(&u, hash, time.Now().UTC())
	} else {
		u.PasswordHash = hash
	}
	s.users[strings.ToLower(username)] = u
	return s.flushLocked()
}

func (s *FileStore) SetMFA(username string, enabled bool, secret, pending string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return ErrNoSuchUser
	}
	u.MFAEnabled, u.MFASecret, u.MFAPending = enabled, secret, pending
	s.users[strings.ToLower(username)] = u
	return s.flushLocked()
}

func (s *FileStore) TouchLogin(username string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.users[strings.ToLower(username)]
	if !ok {
		return
	}
	u.LastLoginAt = time.Now().UTC()
	s.users[strings.ToLower(username)] = u
	// F-30 class: this was `_ = s.flushLocked()`. It matters more than it looks
	// since F-68 — account_inactivity_days LOCKS an account from LastLoginAt, so
	// a silently unpersisted login stamp would eventually lock out an actively
	// used account. Still best-effort (a login must not fail because the
	// timestamp did not write), but never silent.
	if err := s.flushLocked(); err != nil {
		s.deps.Errorf("users", "login timestamp persist failed — account_inactivity_days reads this field",
			map[string]any{"user": username, "err": err.Error()})
	}
}

func (s *FileStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.users)
}

// SeedAdmin creates the bootstrap admin user if the store is empty.
// Called once on server start with credentials from env.
func (s *FileStore) SeedAdmin(username, password string) error {
	if username == "" || password == "" {
		return nil // nothing to do
	}
	if s.Count() > 0 {
		return nil
	}
	_, err := s.Create(username, password, "admin")
	return err
}

// sameTenant mirrors the integrator's tenancy filter (duplicated per the
// no-shared-utils rule): cross sees all; otherwise the resource's tenant must
// equal the caller's (case-insensitive; blank resource = global/platform-owned,
// visible only cross).
func sameTenant(resourceTenant, tenant string, cross bool) bool {
	if cross {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(resourceTenant), strings.TrimSpace(tenant))
}

// ---- shared domain logic (backend-agnostic) --------------------------------
//
// These pure helpers and sentinel errors encode the user-store invariants that
// MUST behave identically whether the backing store is the in-memory file map
// or normalized Postgres rows. Both FileStore and PGStore call them so the
// rules can't drift apart.

// The password length cap (SR-013 amplification-DoS bound) lives with the KDF
// as token.MaxPasswordLen; ValidatePassword below enforces it at creation/change.

var (
	ErrShortPassword        = errors.New("password must be at least 8 characters")
	ErrLongPassword         = errors.New("password must be at most 128 characters")
	ErrLastSuperAdmin       = errors.New("cannot demote or disable the last super-admin")
	ErrLastSuperAdminDelete = errors.New("cannot delete the last super-admin")
	ErrNoSuchUser           = errors.New("no such user")
)

// ValidatePassword enforces the minimum password length (a non-empty password
// must be at least 8 characters). Empty is handled by the callers (CreateFull
// permits a passwordless/invited account; Create/ChangePassword require one).
func ValidatePassword(password string) error {
	if len(password) < 8 {
		return ErrShortPassword
	}
	if len(password) > token.MaxPasswordLen {
		return ErrLongPassword
	}
	return nil
}

// ApplyCreateDefaults fills the create-time defaults for a rich-profile user:
// an active, local account unless the caller said otherwise. Pure.
func ApplyCreateDefaults(u User) User {
	if u.Status == "" {
		u.Status = "active"
	}
	if u.AuthSource == "" {
		u.AuthSource = "local"
	}
	return u
}

// ApplyUserPatch applies a mutable-field patch (role, email, display name,
// tenant, status) onto a user; empty patch fields leave the current value. Pure
// — the last-super-admin guard is the caller's responsibility (it needs a count).
func ApplyUserPatch(u, patch User) User {
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

// UpdateTouchesLastSuperAdmin reports whether a patch would demote (change the
// role of) or disable a super-admin — the two operations that must be refused
// when only one super-admin remains, so an operator can never lock everyone out.
func UpdateTouchesLastSuperAdmin(u, patch User, isSuper func(string) bool) bool {
	demoting := patch.Role != "" && patch.Role != u.Role && isSuper(u.Role)
	disabling := patch.Status == "disabled" && isSuper(u.Role)
	return demoting || disabling
}

// MergeFederated refreshes a federated (non-local) account from its IdP: any
// non-empty incoming attribute overwrites, and the auth source is updated so a
// user that moved IdPs (oidc→ldap) is re-tagged. Pure. A pre-existing LOCAL
// account is never passed here — local management wins (see UpsertFederated).
func MergeFederated(u User, email, displayName, role, source string) User {
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
