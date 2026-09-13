// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"netops/backend/internal/token"
	"os"
	"path/filepath"
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
//   - PGStore (STORE_BACKEND=postgres, pg.go): one row per user in an
//     RLS-protected table; reads are query-driven, the tenant-scoped List is
//     enforced per request by Row-Level Security (not just an app-layer filter),
//     and mutations are partial UPDATEs instead of rewrite-the-whole-collection.
//
// The domain invariants that must hold identically across both backends —
// patch application, federated-account refresh, the last-super-admin guard, and
// password validation — are factored into the pure helpers near the bottom of
// this file and shared by both implementations so they cannot drift.
//
// THE IDENTITY KEY (tracker 300, docs/design/IDENTITY_NAMESPACING_2026-09-13.md).
// A principal is identified by User.ID, and an account is RESOLVED from a
// verified assertion by the canonical tuple (tenant_id, issuer, subject) — never
// by username and never by email. Local authentication is its own issuer
// namespace, so a local username is unique PER TENANT. identity.go holds the key
// material and the derivations; the two backends enforce the same two
// constraints — PK(tenant, issuer, subject) and one identity per user — the
// database with a PRIMARY KEY and a UNIQUE, the file store with indexes checked
// inside its lock.

// Repo is the user-store seam. Reads split by tenant scope:
//   - List(tenant, cross) is PER-REQUEST tenant-scoped: a scoped admin sees only
//     its own tenant's users (RLS-enforced on the pg backend; the same
//     sameTenant filter on the file backend). The platform owner ('*') sees all.
//   - Get is tenant-BLIND by design: it takes the internal principal id, and
//     login resolves a user's tenant FROM the record before any tenant scope
//     exists, so the lookup must span all tenants. Authorization on the resolved
//     user stays at the handler/Authorize() chokepoint.
//
// Mutations likewise run at platform scope on the pg backend (the id is a global
// primary key, the super-admin floor is a platform-wide invariant); the handler
// gates who may mutate whom.
//
// EVERY MUTATOR IS KEYED BY User.ID, not by username. For every account that
// exists today the two strings are equal (legacy rows keep `ID == lower(username)`,
// design §2.1), so no stored value and no caller changes meaning; new accounts
// get an opaque id and the username stops being a key at all.
type Repo interface {
	// Get resolves the internal principal id (User.ID). Tenant-blind.
	Get(id string) (User, bool)

	// LookupLocal resolves a LOCAL login handle inside ONE tenant — the
	// per-tenant sign-in path. It never returns a federated account.
	LookupLocal(tenant, username string) (User, bool)

	// LookupLocalAny resolves a LOCAL login handle across every tenant, for the
	// unbound (tenant-less) login form. It returns 0, 1 or MANY: the caller must
	// refuse a >1 result generically (never naming the tenants — that would be a
	// cross-tenant account-existence oracle) and tell the user to use their
	// organisation's sign-in URL.
	LookupLocalAny(username string) ([]User, bool)

	List(tenant string, cross bool) []User
	Count() int

	// ResolveFederated is the ONLY way a verified federated assertion becomes an
	// account on a TENANT-BOUND connection: find by the canonical tuple, else
	// (provision=true) mint one. provision=false is the read-only door (elevation):
	// a tuple miss is ErrNoSuchUser and nothing is written — it never binds by
	// username again.
	//
	// §2.5 Amendment (2026-09-13): on a realm-CONSTRAINED flow an exact-tuple miss
	// also looks (issuer, subject) up across the tenants that realm reaches, so one
	// person with two connections in one org is one account. Exactly one match
	// signs in; more than one is ErrAmbiguousIdentity. An UNCONSTRAINED realm gets
	// no cross-tenant reach at all — see realmScopedOwner for why that is the
	// fail-closed reading, not a gap.
	ResolveFederated(a Assertion, realm Realm, provision bool) (User, error)

	// ResolveFederatedUnbound is the platform-default-connection form: the
	// account is found by (issuer, subject) ACROSS tenants, because one platform
	// config (bearer JWT, the single LDAP/TACACS+ directory) legitimately signs
	// in users of every tenant. More than one match is ErrAmbiguousIdentity —
	// never a guess.
	ResolveFederatedUnbound(a Assertion) (User, error)

	Create(username, password, role string) (User, error)
	CreateFull(u User, password string) (User, error)
	SeedAdmin(username, password string) error

	Update(id string, patch User) (User, error)
	Delete(id string) error
	ChangePassword(id, newPassword string) error
	ResetPassword(id, newPassword string) error
	// RehashPassword re-wraps the SAME secret at the current cost (SR-029). It
	// updates only the hash — never PasswordChangedAt, never the history — so
	// rehash-on-login cannot silently reset the password_expire_days clock.
	RehashPassword(id, samePassword string) error
	// SetMFA sets the account's MFA state atomically (secret/pending already sealed
	// by the caller). enabled=false + empty strings clears MFA.
	SetMFA(id string, enabled bool, secret, pending string) error
	TouchLogin(id string)

	// VerifyIdentityInvariants is the §3 "Enforce" gate, called at boot: every
	// LOCAL account has an identity, and no account has two. It REFUSES rather
	// than repairing — a converge step must not destroy the estate it is
	// converging (the F-58 lesson).
	VerifyIdentityInvariants() error
}

type User struct {
	// ID is the IMMUTABLE internal principal id: what sessions, the JWT `sub`,
	// role bindings, the audit actor, API handles and every future foreign key
	// reference. Legacy rows carry `ID == lower(username)` — preserved on
	// purpose, so nothing that references a user today changes value. New local
	// accounts get an opaque `u_<32 hex>`; federated accounts get the
	// deterministic `fed_<tenant-fragment>_<hash>` of their tuple (§2.4).
	ID string `json:"id,omitempty"`
	// Username is the login/display HANDLE, not a key. For a local account it is
	// the typed name, unique per tenant; for a federated account it equals the
	// opaque id and is never displayed and never accepted at a login form.
	Username     string    `json:"username"`
	Role         string    `json:"role"` // role id (legacy: "admin" | "viewer")
	Email        string    `json:"email,omitempty"`
	DisplayName  string    `json:"display_name,omitempty"`
	TenantID     string    `json:"tenant_id,omitempty"`
	Status       string    `json:"status,omitempty"`      // active | invited | disabled
	AuthSource   string    `json:"auth_source,omitempty"` // local | oidc | saml | ldap | tacacs
	PasswordHash string    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	LastLoginAt  time.Time `json:"last_login_at,omitempty"`

	// Identity is the canonical identity tuple of this account (§2.5). NIL means
	// PENDING: a pre-migration federated row that carries no issuer/subject and
	// cannot have one derived offline (§2.6).
	//
	// On the FILE backend this field IS the storage — it is persisted inside the
	// user JSON. On the POSTGRES backend it is a READ-ONLY VIEW loaded by joining
	// `user_identities`, and it is deliberately stripped before the `data` column
	// is written so the row and the table can never disagree.
	Identity *Identity `json:"identity,omitempty"`

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

// IdentityPending reports whether the account still has no canonical identity —
// the `identity_status: pending` the admin surface shows (§2.7).
func (u User) IdentityPending() bool { return u.Identity == nil }

// KV abstracts where the file backend persists its JSON blob (the platform kv
// layer; a missing key must return an os.ErrNotExist-wrapped error).
type KV interface {
	Load(key string) ([]byte, error)
	Save(key string, data []byte) error
}

// Deps are the cross-domain inputs the store must not own: persistence, the
// structured error sink, the SR-025 federated-role guard, the role predicate
// behind the last-super-admin invariant, account_policy's password-change
// stamping, the tenant default for federated JIT, the MAX_USERS cap, the id
// minter, the migration epoch and the legacy-bind event sink.
type Deps struct {
	KV                  KV
	Errorf              func(component, msg string, fields map[string]any)
	GuardRole           func(role, tenant, username, source string) string
	IsSuperAdmin        func(role string) bool
	ApplyPasswordChange func(u *User, hash string, now time.Time)
	DefaultTenant       string
	MaxUsers            int // 0 = unlimited

	// MintID mints the opaque id of a NEW LOCAL account (the integrator passes
	// mintUserID from identity_ids.go — `u_` + 16 random bytes hex).
	//
	// NIL IS A DELIBERATE STAGING SEAM, not an oversight. With no minter the
	// store falls back to the LEGACY id shape (`ID == lower(username)`), which is
	// what every row already in an estate carries, so the store can namespace
	// identities (Phase 2/3) before the doors stop keying on the username
	// (Phase 4). The doors change wires MintID in the same commit that teaches
	// handleLogin to call LookupLocal.
	MintID func() string

	// MigrationMarker is the identity-migration epoch: an account created BEFORE
	// it may be adopted by the bounded §2.6 lazy bind, an account created after
	// it never may. ZERO means "read it from the backend at construction" (the
	// `identity_migration` table on Postgres, a KV key beside users.json on the
	// file backend); a non-zero value overrides that, which is how a test pins
	// the epoch without sleeping.
	MigrationMarker time.Time

	// OnLegacyBound is called AFTER the write commits and OUTSIDE the store's
	// lock/transaction, whenever the §2.6 lazy bind adopts a legacy account, so the
	// integrator can emit the `identity.legacy_bound` audit event and increment
	// its counter. The store must not import audit, so it reports instead.
	OnLegacyBound func(u User, a Assertion)
}

func (d Deps) validate() error {
	if d.Errorf == nil || d.GuardRole == nil || d.IsSuperAdmin == nil || d.ApplyPasswordChange == nil || d.DefaultTenant == "" {
		return errors.New("users: Errorf, GuardRole, IsSuperAdmin, ApplyPasswordChange and DefaultTenant are required")
	}
	return nil
}

// mintID returns a new principal id for a local account. See Deps.MintID for why
// a nil minter falls back to the legacy shape.
func (d Deps) mintID(username string) string {
	if d.MintID != nil {
		return d.MintID()
	}
	return legacyUserID(username)
}

// legacyUserID is the pre-tracker-300 id shape: lower(username). It stays the
// id of every account that already exists, and identity resolution no longer
// depends on it.
func legacyUserID(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

// normID canonicalises a principal-id lookup key. Ids minted by this package are
// already lowercase; the fold keeps a legacy `Get("ALICE")` working, exactly as
// the username-keyed map did.
func normID(id string) string { return strings.ToLower(strings.TrimSpace(id)) }

type FileStore struct {
	mu    sync.RWMutex
	path  string
	deps  Deps
	users map[string]User // keyed by normID(User.ID)

	// byTuple is the file backend's PRIMARY KEY (tenant, issuer, subject) →
	// User.ID, and byLocalLogin is the per-tenant local-username uniqueness
	// index. Both are rebuilt from the persisted collection at load and checked
	// INSIDE s.mu on every write, so the file store refuses exactly what the
	// database's PK and UNIQUE refuse. "One identity per user" is structural
	// here: User.Identity is a single field.
	byTuple      map[identityKey]string
	byLocalLogin map[localLoginKey]string

	// markerAt is the identity-migration epoch (Deps.MigrationMarker).
	markerAt time.Time
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
	s := &FileStore{
		path:         path,
		deps:         d,
		users:        make(map[string]User),
		byTuple:      make(map[identityKey]string),
		byLocalLogin: make(map[localLoginKey]string),
	}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	// The epoch is established even on a store whose blob does not exist yet: on
	// a FRESH install the marker is the install time, so every account is
	// post-marker and the §2.6 lazy bind can never fire. Fail-closed by default.
	if err := s.ensureMarker(); err != nil {
		return nil, err
	}
	return s, nil
}

// identityMarkerKey is the KV key holding the file backend's migration epoch —
// the twin of Postgres' one-row `identity_migration` table. It sits beside the
// users blob so a store moved between hosts carries its epoch with it.
func identityMarkerKey(usersPath string) string {
	return filepath.Join(filepath.Dir(usersPath), "identity_migration.json")
}

type identityMarker struct {
	StartedAt time.Time `json:"started_at"`
}

// ensureMarker reads the epoch, writing it ONCE if absent. Write-once is what
// makes it idempotent: a re-run must never move the epoch forward, because that
// would widen the lazy-bind window to accounts created since.
func (s *FileStore) ensureMarker() error {
	if !s.deps.MigrationMarker.IsZero() {
		s.markerAt = s.deps.MigrationMarker.UTC()
		return nil
	}
	key := identityMarkerKey(s.path)
	b, err := s.deps.KV.Load(key)
	switch {
	case err == nil:
		var m identityMarker
		if err := json.Unmarshal(b, &m); err != nil {
			return fmt.Errorf("users: identity migration marker unreadable (%s): %w", key, err)
		}
		s.markerAt = m.StartedAt.UTC()
		return nil
	case errors.Is(err, os.ErrNotExist):
		m := identityMarker{StartedAt: time.Now().UTC()}
		enc, err := json.Marshal(m)
		if err != nil {
			return err
		}
		if err := s.deps.KV.Save(key, enc); err != nil {
			return err
		}
		s.markerAt = m.StartedAt
		return nil
	default:
		return err
	}
}

// atCapLocked reports whether adding another LOCAL/admin-created account would
// exceed the configured cap. Caller must hold s.mu. Federated JIT provisioning
// is intentionally exempt so the cap never locks out SSO.
func (s *FileStore) atCapLocked() bool {
	return s.deps.MaxUsers > 0 && len(s.users) >= s.deps.MaxUsers
}

// load reads the collection, runs the compare-then-write backfills, and builds
// the identity indexes.
//
// The backfills are IDEMPOTENT by construction (each converts only what is not
// already converted, and the blob is rewritten only if something changed), so a
// second load is a no-op — the migration-idempotency requirement of §3.
func (s *FileStore) load() error {
	b, err := s.deps.KV.Load(s.path)
	if err != nil {
		return err
	}
	var list []User
	if err := json.Unmarshal(b, &list); err != nil {
		return err
	}
	migrated := false
	now := time.Now().UTC()
	for _, u := range list {
		// One-time migration (H1): Create/SeedAdmin historically never stamped
		// AuthSource, so pre-existing LOCAL rows (including the bootstrap admin)
		// carry "". The username-keyed federated upsert used to read that "" as
		// "not local" and merge an IdP identity — role, source and all — straight
		// into the local account. Every write path now stamps the source explicitly, and legacy
		// rows are normalized here so the local/federated split is unambiguous.
		if u.AuthSource == "" {
			u.AuthSource = ProtocolLocal
			migrated = true
		}
		// Tracker 300 expand: a row written before User.ID existed keeps the id
		// it has always effectively had — lower(username) — so every session,
		// binding, audit actor and API handle that references it keeps its value.
		if u.ID == "" {
			u.ID = legacyUserID(u.Username)
			migrated = true
		}
		// Tracker 300 backfill (§3): a LOCAL account's issuer and subject ARE
		// derivable offline with certainty, so it gets its identity now.
		// A FEDERATED row does not — it carries no issuer/subject and nothing may
		// be guessed (rule 6) — so it stays PENDING until §2.6 binds it or an
		// operator remediates it.
		if u.Identity == nil && IsLocalSource(u.AuthSource) {
			id := localIdentity(u.TenantID, u.Username, ProvenanceBackfilledLocal, now)
			u.Identity = &id
			migrated = true
		}
		if u.Identity != nil {
			norm := u.Identity.normalized()
			u.Identity = &norm
		}
		if _, dup := s.users[normID(u.ID)]; dup {
			return fmt.Errorf("users: duplicate account id %q in %s", u.ID, s.path)
		}
		if err := s.indexLocked(u); err != nil {
			return err
		}
		s.users[normID(u.ID)] = u
	}
	if migrated {
		// Persist the normalization once at load. Safe without s.mu: load runs
		// inside NewFileStore, before the store is shared.
		return s.flushLocked()
	}
	return nil
}

// indexLocked registers a user's IDENTITY in the two indexes that mirror the
// database's constraints — PRIMARY KEY (tenant, issuer, subject) and per-tenant
// local-username uniqueness — refusing a duplicate exactly as the PK would.
// Caller holds s.mu (or load()'s exclusive use before the store is shared).
//
// Account-ID uniqueness is the caller's check, because only an INSERT can
// violate it (an in-place update re-indexes an id that is already present).
//
// A refusal at load FAILS THE OPEN of the store rather than dropping a row: a
// converge step must not destroy the estate it is converging (F-58).
func (s *FileStore) indexLocked(u User) error {
	key := normID(u.ID)
	if key == "" {
		return errors.New("users: stored account has no id")
	}
	if u.Identity == nil {
		return nil
	}
	if err := u.Identity.validate(); err != nil {
		return fmt.Errorf("users: account %q: %w", u.ID, err)
	}
	tk := u.Identity.key()
	if other, dup := s.byTuple[tk]; dup {
		return fmt.Errorf("users: identity (%s, %s, %s) claimed by both %q and %q",
			tk.tenant, tk.issuer, tk.subject, other, u.ID)
	}
	s.byTuple[tk] = key
	if u.Identity.Issuer == LocalIssuer {
		lk := u.Identity.localKey()
		if other, dup := s.byLocalLogin[lk]; dup {
			return fmt.Errorf("users: local login %q in tenant %q claimed by both %q and %q",
				lk.username, lk.tenant, other, u.ID)
		}
		s.byLocalLogin[lk] = key
	}
	return nil
}

// unindexLocked removes a user's index entries. Caller holds s.mu.
func (s *FileStore) unindexLocked(u User) {
	if u.Identity == nil {
		return
	}
	tk := u.Identity.key()
	if s.byTuple[tk] == normID(u.ID) {
		delete(s.byTuple, tk)
	}
	if u.Identity.Issuer == LocalIssuer {
		lk := u.Identity.localKey()
		if s.byLocalLogin[lk] == normID(u.ID) {
			delete(s.byLocalLogin, lk)
		}
	}
}

// putLocked replaces a user in place. It reindexes only when the identity
// changed, so a profile write cannot disturb the constraints.
func (s *FileStore) putLocked(u User) {
	s.users[normID(u.ID)] = u
}

func (s *FileStore) flushLocked() error {
	list := make([]User, 0, len(s.users))
	for _, u := range s.users {
		list = append(list, u)
	}
	// Stable order: the blob is diffed by operators and compared by the
	// idempotency tests, so map iteration order must not leak into it.
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return s.deps.KV.Save(s.path, b)
}

// Get resolves the internal principal id.
func (s *FileStore) Get(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.users[normID(id)]
	return u, ok
}

// LookupLocal resolves a local login handle inside one tenant (§2.5).
func (s *FileStore) LookupLocal(tenant, username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.byLocalLogin[localKeyFor(tenant, username)]
	if !ok {
		return User{}, false
	}
	u, ok := s.users[id]
	return u, ok
}

// LookupLocalAny resolves a local login handle across every tenant — the
// unbound login form. MORE THAN ONE result is not an error here: the caller
// refuses it generically and audits it, because a message that distinguished
// "ambiguous" from "unknown" would be a cross-tenant existence oracle.
func (s *FileStore) LookupLocalAny(username string) ([]User, bool) {
	name := strings.ToLower(strings.TrimSpace(username))
	if name == "" {
		return nil, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []User
	for lk, id := range s.byLocalLogin {
		if lk.username != name {
			continue
		}
		if u, ok := s.users[id]; ok {
			out = append(out, u)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, len(out) > 0
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
		AuthSource:   ProtocolLocal, // H1: stamp explicitly — "" must never be read as federated
		PasswordHash: hash,
		CreatedAt:    time.Now().UTC(),
	}
	return s.createLocal(u)
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
	return s.createLocal(u)
}

// createLocal is the single write path for an administratively-created account.
// It mints the id and registers the (tenant, "local", lower(username)) identity
// IN THE SAME WRITE, so an account can never exist without its namespace entry,
// and refuses a duplicate local username WITHIN THE TENANT (ErrUsernameTaken)
// while allowing the same name in another tenant (§0 rule 3).
func (s *FileStore) createLocal(u User) (User, error) {
	if !IsLocalSource(u.AuthSource) {
		return User{}, ErrFederatedCreate
	}
	u.ID = s.deps.mintID(u.Username)
	ident := localIdentity(u.TenantID, u.Username, ProvenanceAsserted, u.CreatedAt)
	u.Identity = &ident

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byLocalLogin[ident.localKey()]; exists {
		return User{}, fmt.Errorf("user %q already exists: %w", u.Username, ErrUsernameTaken)
	}
	if _, exists := s.users[normID(u.ID)]; exists {
		return User{}, fmt.Errorf("user %q already exists: %w", u.Username, ErrUsernameTaken)
	}
	if s.atCapLocked() {
		return User{}, fmt.Errorf("user limit reached (MAX_USERS=%d)", s.deps.MaxUsers)
	}
	if err := s.indexLocked(u); err != nil {
		return User{}, err
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		s.unindexLocked(u)
		delete(s.users, normID(u.ID))
		return User{}, err
	}
	return u, nil
}

// Update applies a patch to mutable profile fields (role, email, display name,
// tenant, status). Admin-safe: refuses to demote or disable the last user who
// holds the super-admin role, so an operator can never lock everyone out.
//
// A TENANT MOVE carries the identity with it: the identity tuple is re-keyed
// inside the same lock, and the move is refused if the destination tenant
// already holds that local username (the PK would refuse it too).
func (s *FileStore) Update(id string, patch User) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return User{}, ErrNoSuchUser
	}
	if UpdateTouchesLastSuperAdmin(u, patch, s.deps.IsSuperAdmin) && s.countSuperAdminsLocked() <= 1 {
		return User{}, ErrLastSuperAdmin
	}
	before := u
	u = ApplyUserPatch(u, patch)
	if u.Identity != nil && normTenant(u.Identity.TenantID) != normTenant(u.TenantID) {
		moved := *u.Identity
		moved.TenantID = normTenant(u.TenantID)
		u.Identity = &moved
	}
	// The conflict is checked BEFORE anything is mutated, so a refusal needs no
	// rollback: the destination tenant already holding that local name is the same
	// refusal the database's PRIMARY KEY gives.
	if err := s.identityMoveConflictLocked(before, u); err != nil {
		return User{}, err
	}
	s.unindexLocked(before)
	delete(s.users, key)
	if err := s.indexLocked(u); err != nil {
		return User{}, err
	}
	s.putLocked(u)
	if err := s.flushLocked(); err != nil {
		return User{}, err
	}
	return u, nil
}

// identityMoveConflictLocked reports whether re-keying `after`'s identity would
// collide with a DIFFERENT account. Caller holds s.mu.
func (s *FileStore) identityMoveConflictLocked(before, after User) error {
	if after.Identity == nil {
		return nil
	}
	self := normID(after.ID)
	if before.Identity == nil || before.Identity.key() != after.Identity.key() {
		if other, dup := s.byTuple[after.Identity.key()]; dup && other != self {
			return fmt.Errorf("identity already claimed by another account: %w", ErrUsernameTaken)
		}
	}
	if after.Identity.Issuer != LocalIssuer {
		return nil
	}
	lk := after.Identity.localKey()
	if before.Identity == nil || before.Identity.localKey() != lk {
		if other, dup := s.byLocalLogin[lk]; dup && other != self {
			return fmt.Errorf("user %q already exists in tenant %q: %w", after.Username, lk.tenant, ErrUsernameTaken)
		}
	}
	return nil
}

// Delete removes a user. Admin-safe: the last super-admin cannot be deleted.
// The identity entry goes with it — the file twin of ON DELETE CASCADE.
func (s *FileStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return ErrNoSuchUser
	}
	if s.deps.IsSuperAdmin(u.Role) && s.countSuperAdminsLocked() <= 1 {
		return ErrLastSuperAdminDelete
	}
	s.unindexLocked(u)
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
func (s *FileStore) ResetPassword(id, newPassword string) error {
	return s.ChangePassword(id, newPassword)
}

func (s *FileStore) ChangePassword(id, newPassword string) error {
	return s.setPassword(id, newPassword, true)
}

// RehashPassword re-wraps the same secret at the current cost — hash only.
func (s *FileStore) RehashPassword(id, samePassword string) error {
	return s.setPassword(id, samePassword, false)
}

// setPassword is the single write path for both. `stamp` distinguishes a real
// change (history + expiry clock) from a cost rehash (hash only).
func (s *FileStore) setPassword(id, newPassword string, stamp bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := token.HashPassword(newPassword)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return ErrNoSuchUser
	}
	if stamp {
		s.deps.ApplyPasswordChange(&u, hash, time.Now().UTC())
	} else {
		u.PasswordHash = hash
	}
	s.putLocked(u)
	return s.flushLocked()
}

func (s *FileStore) SetMFA(id string, enabled bool, secret, pending string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return ErrNoSuchUser
	}
	u.MFAEnabled, u.MFASecret, u.MFAPending = enabled, secret, pending
	s.putLocked(u)
	return s.flushLocked()
}

func (s *FileStore) TouchLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return
	}
	now := time.Now().UTC()
	u.LastLoginAt = now
	if u.Identity != nil {
		touched := *u.Identity
		touched.LastLoginAt = now
		u.Identity = &touched
	}
	s.putLocked(u)
	// F-30 class: this was `_ = s.flushLocked()`. It matters more than it looks
	// since F-68 — account_inactivity_days LOCKS an account from LastLoginAt, so
	// a silently unpersisted login stamp would eventually lock out an actively
	// used account. Still best-effort (a login must not fail because the
	// timestamp did not write), but never silent. The id is opaque for a
	// federated account, so this log line carries no PII.
	if err := s.flushLocked(); err != nil {
		s.deps.Errorf("users", "login timestamp persist failed — account_inactivity_days reads this field",
			map[string]any{"user": id, "err": err.Error()})
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

// VerifyIdentityInvariants is the §3 Enforce gate (see Repo).
func (s *FileStore) VerifyIdentityInvariants() error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var pending []string
	for _, u := range s.users {
		if IsLocalSource(u.AuthSource) && u.Identity == nil {
			pending = append(pending, u.ID)
		}
	}
	// "No user has two identities" is structural on this backend (one field), so
	// what must be proven is that the INDEX agrees: every tuple points at a
	// distinct, existing account.
	owners := make(map[string]int, len(s.byTuple))
	for tk, owner := range s.byTuple {
		if _, ok := s.users[owner]; !ok {
			return fmt.Errorf("users: identity (%s, %s, %s) points at missing account %q",
				tk.tenant, tk.issuer, tk.subject, owner)
		}
		owners[owner]++
		if owners[owner] > 1 {
			return fmt.Errorf("users: account %q holds %d identities — exactly one is allowed", owner, owners[owner])
		}
	}
	if len(pending) > 0 {
		sort.Strings(pending)
		return fmt.Errorf("%w: %d local account(s) without an identity (%s)",
			ErrIdentityBackfillIncomplete, len(pending), strings.Join(pending, ", "))
	}
	return nil
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
	// ErrLocalAccount is the typed refusal when a federated assertion would act
	// on a LOCALLY-managed account (H1). The caller decides the HTTP shape; the
	// store only guarantees the local record is untouched.
	ErrLocalAccount = errors.New("account is managed locally; federated sign-in refused")
	// ErrForeignTenant is the typed refusal when the existing account belongs to
	// a tenant the flow's realm does not reach. The store guarantees the account
	// is untouched; the caller decides the HTTP shape, and must not repeat this
	// reason to the browser (it would be a cross-tenant account-existence oracle).
	ErrForeignTenant = errors.New("account belongs to another realm; federated sign-in refused")
	// ErrUsernameTaken is the per-tenant local-username collision (§0 rule 3).
	// The SAME name in ANOTHER tenant is not a collision and is allowed.
	ErrUsernameTaken = errors.New("username already taken in this tenant")
	// ErrIdentityConflict is a lost race on the canonical tuple, or a federated
	// id collision that survived §4.3's extension. Never resolved by guessing.
	ErrIdentityConflict = errors.New("identity conflict")
	// ErrAmbiguousIdentity is an unbound lookup that matched more than one
	// account. The caller must refuse GENERICALLY: naming the tenants would be a
	// cross-tenant existence oracle.
	ErrAmbiguousIdentity = errors.New("identity is ambiguous across tenants")
	// ErrFederatedCreate refuses an administratively-created FEDERATED account:
	// a federated account exists only as the result of a verified Assertion
	// (§2.5), because only a door can know its issuer and subject.
	ErrFederatedCreate = errors.New("a federated account is provisioned from a verified assertion, not created")
	// ErrIdentityBackfillIncomplete is VerifyIdentityInvariants' refusal. It is a
	// REFUSAL, never a repair: the estate is left exactly as found.
	ErrIdentityBackfillIncomplete = errors.New("identity backfill incomplete")
)

// Realm bounds which accounts a federated sign-in may act on.
//
// The ZERO VALUE CARRIES NO CONSTRAINT, and that is deliberate. A platform-realm
// connection keeps the generic callback and legitimately signs in users of every
// tenant, so a blanket "flow tenant == account tenant" would lock out every
// deployment that predates per-tenant sign-in URLs. Only a flow whose URL names
// one realm hands a constraint down.
//
// The predicate is supplied by the caller rather than computed here because org
// membership lives in the tenant directory, which this package must not import.
type Realm struct {
	// Reaches reports whether an account in accountTenant belongs to this realm.
	// Nil means unconstrained.
	Reaches func(accountTenant string) bool
}

// Permits is the fail-closed read of the constraint: no predicate means no
// constraint, otherwise the predicate decides.
func (rl Realm) Permits(accountTenant string) bool {
	if rl.Reaches == nil {
		return true
	}
	return rl.Reaches(accountTenant)
}

// IsLocalSource reports whether an auth_source marks a LOCALLY-managed account
// (password + MFA owned by us, not an IdP). Mirrors the integrator's
// isLocalAccount predicate (duplicated per the no-shared-utils rule): an empty
// source is a legacy/bootstrap LOCAL account — treating it as federated is
// exactly the H1 hole that let an IdP identity absorb the bootstrap admin.
func IsLocalSource(authSource string) bool {
	s := strings.ToLower(strings.TrimSpace(authSource))
	return s == "" || s == ProtocolLocal
}

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
		u.AuthSource = ProtocolLocal
	}
	return u
}

// ApplyUserPatch applies a mutable-field patch (role, email, display name,
// tenant, status) onto a user; empty patch fields leave the current value. Pure
// — the last-super-admin guard is the caller's responsibility (it needs a count),
// and the identity is NOT patchable: a tuple is asserted, never edited.
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
// user that moved IdPs (oidc→ldap) is re-tagged. Pure. A LOCAL account
// (IsLocalSource) is never passed here — the resolver refuses it with
// ErrLocalAccount before any merge.
//
// EVERYTHING IT TOUCHES IS A PROFILE ATTRIBUTE. Email and display name are
// refreshed on login and are NEVER keys (§2.3) — which is why the same email
// arriving from two issuers produces two accounts, not one.
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
