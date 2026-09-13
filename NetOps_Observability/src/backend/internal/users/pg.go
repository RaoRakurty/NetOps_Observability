// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"netops/backend/internal/token"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// pg.go — the Postgres-backed user repository (#33).
//
// This is the second store (after audit, #32) to graduate off the load-all-blob
// model onto real per-row SQL. The win it delivers:
//   - List(tenant, cross) is enforced PER REQUEST by Row-Level Security: a scoped
//     admin's list runs inside withTenant(tenant) so the database returns only
//     that tenant's rows — RLS stops being a mere backstop under the app filter.
//   - Mutations are partial UPDATEs of a single row, not a rewrite of the whole
//     collection, and there is no in-process cache to go stale across instances.
//
// Scope rules (see the Repo doc in store.go):
//   - Get / Count / every mutation run at PLATFORM scope ('*'). The principal id
//     is the global primary key, so existence/uniqueness checks and the
//     platform-wide last-super-admin invariant must see across tenants. Login
//     also resolves a user's tenant FROM the record before any tenant scope
//     exists. WHO may mutate WHOM is enforced upstream at the
//     handler/Authorize() chokepoint.
//   - Only List is request-tenant-scoped — exactly the cross-tenant enumeration
//     surface RLS needs to fence.
//
// THE IDENTITY TABLE (tracker 300). `user_identities` (migration 0049) is the
// AUTHORITY for the canonical tuple, and its PRIMARY KEY (tenant_id, issuer,
// subject) plus UNIQUE (user_id) are the owner's rules 2 and 4 enforced IN THE
// DATABASE rather than only in code — a second identity cannot be attached to an
// account by any code path, including one that has not been written yet.
// User.Identity is a READ-ONLY VIEW loaded by join and STRIPPED before `data` is
// written, so the JSON row and the table can never disagree.
//
// The domain invariants (patch application, federated refresh, last-super-admin
// guard, password validation, create defaults, the §2.6 conditions) come from the
// shared pure helpers in store.go / resolve.go, so this backend and the file
// backend cannot drift.

// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type PGStore struct {
	db   DB
	deps Deps
	// markerAt is the identity-migration epoch, read once at construction from
	// the one-row `identity_migration` table that migration 0050 writes.
	markerAt time.Time
}

// NewPGStore builds the per-row RLS-backed store (Deps.KV unused here).
func NewPGStore(db DB, d Deps) (*PGStore, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	s := &PGStore{db: db, deps: d}
	if err := s.migrateLocalAuthSource(); err != nil {
		return nil, err
	}
	if err := s.loadMarker(); err != nil {
		return nil, err
	}
	return s, nil
}

// migrateLocalAuthSource is the pg twin of FileStore.load()'s one-time H1
// normalization: rows written by Create/SeedAdmin before the stamp carry an
// empty auth_source, which UpsertFederated used to read as "not local" and
// merge an IdP identity into. Runs at construction, platform scope, and is
// idempotent (matches nothing once every row is stamped). Fail-closed: a store
// that cannot prove its local/federated split does not open.
func (s *PGStore) migrateLocalAuthSource() error {
	ctx, cancel := usersCtx()
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `UPDATE users
			SET data = jsonb_set(data, '{auth_source}', '"local"'), updated_at = now()
			WHERE COALESCE(data->>'auth_source', '') = ''`)
		return err
	})
}

// loadMarker reads the identity-migration epoch written by migration 0050. An
// ABSENT row leaves the epoch zero, which fails closed: the §2.6 lazy bind never
// fires without a known epoch.
func (s *PGStore) loadMarker() error {
	if !s.deps.MigrationMarker.IsZero() {
		s.markerAt = s.deps.MigrationMarker.UTC()
		return nil
	}
	ctx, cancel := usersCtx()
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var at time.Time
		err := tx.QueryRow(ctx, `SELECT started_at FROM identity_migration WHERE singleton`).Scan(&at)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		s.markerAt = at.UTC()
		return nil
	})
}

// normTenant mirrors the integrator's tenant-id normalization (duplicated per
// the no-shared-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

func usersCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// isUniqueViolation reports a Postgres unique_violation (23505) — the race
// backstop behind every in-transaction existence check, and the DB-level form of
// "no auto-linking" when it fires on user_identities.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

// marshalUserRow serialises a user for the `data` column with the identity
// STRIPPED: on this backend `user_identities` is the authority, so persisting a
// second copy inside the JSON would be two sources of truth that drift.
func marshalUserRow(u User) ([]byte, error) {
	u.Identity = nil
	return json.Marshal(u)
}

func (s *PGStore) Get(id string) (User, bool) {
	ctx, cancel := usersCtx()
	defer cancel()
	var u User
	found := false
	// Platform scope: the id is the global key; login resolves the tenant from
	// the row, and authorization on the result is the handler's job.
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		got, err := selectUserTx(ctx, tx, normID(id))
		if errors.Is(err, ErrNoSuchUser) {
			return nil
		}
		if err != nil {
			return err
		}
		u, found = got, true
		return nil
	})
	if err != nil {
		s.deps.Errorf("users", "get", map[string]any{"error": err.Error()})
		return User{}, false
	}
	return u, found
}

// LookupLocal resolves a local login handle inside ONE tenant, through the
// identity table — which is what makes the name unique per tenant rather than
// globally. Platform scope: login has no tenant context yet.
func (s *PGStore) LookupLocal(tenant, username string) (User, bool) {
	ctx, cancel := usersCtx()
	defer cancel()
	lk := localKeyFor(tenant, username)
	var u User
	found := false
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var id string
		err := tx.QueryRow(ctx,
			`SELECT user_id FROM user_identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
			lk.tenant, LocalIssuer, lk.username).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		got, err := selectUserTx(ctx, tx, id)
		if errors.Is(err, ErrNoSuchUser) {
			return nil
		}
		if err != nil {
			return err
		}
		u, found = got, true
		return nil
	})
	if err != nil {
		s.deps.Errorf("users", "lookup local", map[string]any{"error": err.Error()})
		return User{}, false
	}
	return u, found
}

// LookupLocalAny resolves a local login handle across every tenant — the unbound
// login form. MANY is a legitimate answer that the caller must refuse
// generically; see Repo.
func (s *PGStore) LookupLocalAny(username string) ([]User, bool) {
	name := strings.ToLower(strings.TrimSpace(username))
	if name == "" {
		return nil, false
	}
	ctx, cancel := usersCtx()
	defer cancel()
	var out []User
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT user_id FROM user_identities WHERE issuer=$1 AND subject=$2 ORDER BY user_id`,
			LocalIssuer, name)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			u, err := selectUserTx(ctx, tx, id)
			if errors.Is(err, ErrNoSuchUser) {
				continue
			}
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return nil
	})
	if err != nil {
		s.deps.Errorf("users", "lookup local any", map[string]any{"error": err.Error()})
		return nil, false
	}
	return out, len(out) > 0
}

func (s *PGStore) List(tenant string, cross bool) []User {
	ctx, cancel := usersCtx()
	defer cancel()
	var out []User
	// RLS scopes the read: a scoped admin sees only its own tenant; '*' sees all.
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+userIdentityCols+` FROM users u
			LEFT JOIN user_identities i ON i.user_id = u.id`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			u, err := scanUserRow(rows)
			if err != nil {
				return err
			}
			out = append(out, u)
		}
		return rows.Err()
	})
	if err != nil {
		s.deps.Errorf("users", "list", map[string]any{"error": err.Error()})
		return nil
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out
}

func (s *PGStore) Count() int {
	ctx, cancel := usersCtx()
	defer cancel()
	var n int
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n)
	})
	if err != nil {
		s.deps.Errorf("users", "count", map[string]any{"error": err.Error()})
		return 0
	}
	return n
}

func (s *PGStore) Create(username, password, role string) (User, error) {
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
	// AuthSource stamped explicitly (H1) — "" must never be read as federated.
	u := User{Username: username, Role: role, AuthSource: ProtocolLocal, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	return s.createLocal(u)
}

func (s *PGStore) CreateFull(u User, password string) (User, error) {
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

// createLocal inserts an administratively-created LOCAL account and its
// (tenant, "local", lower(username)) identity in ONE TRANSACTION, so an account
// can never exist without its namespace entry. A duplicate local username WITHIN
// the tenant is refused (ErrUsernameTaken); the same name in another tenant is
// not a duplicate (§0 rule 3) and the identity PK is what says so.
func (s *PGStore) createLocal(u User) (User, error) {
	if !IsLocalSource(u.AuthSource) {
		return User{}, ErrFederatedCreate
	}
	u.ID = s.deps.mintID(u.Username)
	ident := localIdentity(u.TenantID, u.Username, ProvenanceAsserted, u.CreatedAt)
	u.Identity = &ident

	ctx, cancel := usersCtx()
	defer cancel()
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var taken bool
		if err := tx.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM user_identities WHERE tenant_id=$1 AND issuer=$2 AND subject=$3)`,
			ident.TenantID, ident.Issuer, ident.Subject).Scan(&taken); err != nil {
			return err
		}
		if taken {
			return fmt.Errorf("user %q already exists: %w", u.Username, ErrUsernameTaken)
		}
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, normID(u.ID)).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("user %q already exists: %w", u.Username, ErrUsernameTaken)
		}
		if s.deps.MaxUsers > 0 {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
				return err
			}
			if n >= s.deps.MaxUsers {
				return fmt.Errorf("user limit reached (MAX_USERS=%d)", s.deps.MaxUsers)
			}
		}
		return insertUserTx(ctx, tx, u)
	})
	if err != nil {
		if isUniqueViolation(err) {
			// The PK/UNIQUE race backstop: the checks above and this are the same
			// rule, one in the application and one in the database.
			return User{}, fmt.Errorf("user %q already exists: %w", u.Username, ErrUsernameTaken)
		}
		return User{}, err
	}
	return u, nil
}

func (s *PGStore) Update(id string, patch User) (User, error) {
	ctx, cancel := usersCtx()
	defer cancel()
	var out User
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, normID(id))
		if err != nil {
			return err
		}
		if UpdateTouchesLastSuperAdmin(u, patch, s.deps.IsSuperAdmin) {
			n, err := countSuperAdminsTx(ctx, tx, s.deps.IsSuperAdmin)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastSuperAdmin
			}
		}
		u = ApplyUserPatch(u, patch)
		// A tenant move carries the identity with it, or the identity row would be
		// invisible to the tenant-scoped RLS join. Refused by the PK if the
		// destination tenant already holds that local username.
		if u.Identity != nil && normTenant(u.Identity.TenantID) != normTenant(u.TenantID) {
			moved := *u.Identity
			moved.TenantID = normTenant(u.TenantID)
			if _, err := tx.Exec(ctx, `UPDATE user_identities SET tenant_id=$2 WHERE user_id=$1`,
				normID(u.ID), moved.TenantID); err != nil {
				return err
			}
			u.Identity = &moved
		}
		out = u
		return writeUserTx(ctx, tx, u)
	})
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, fmt.Errorf("tenant move refused: %w", ErrUsernameTaken)
		}
		return User{}, err
	}
	return out, nil
}

func (s *PGStore) SetMFA(id string, enabled bool, secret, pending string) error {
	ctx, cancel := usersCtx()
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, normID(id))
		if err != nil {
			return err
		}
		u.MFAEnabled, u.MFASecret, u.MFAPending = enabled, secret, pending
		return writeUserTx(ctx, tx, u)
	})
}

// Delete removes a user. The identity row goes with it via
// REFERENCES users(id) ON DELETE CASCADE — the database owns that, not this code.
func (s *PGStore) Delete(id string) error {
	ctx, cancel := usersCtx()
	defer cancel()
	key := normID(id)
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, key)
		if err != nil {
			return err
		}
		if s.deps.IsSuperAdmin(u.Role) {
			n, err := countSuperAdminsTx(ctx, tx, s.deps.IsSuperAdmin)
			if err != nil {
				return err
			}
			if n <= 1 {
				return ErrLastSuperAdminDelete
			}
		}
		_, err = tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, key)
		return err
	})
}

func (s *PGStore) ChangePassword(id, newPassword string) error {
	return s.setPassword(id, newPassword, true)
}

// RehashPassword re-wraps the same secret at the current cost — hash only.
func (s *PGStore) RehashPassword(id, samePassword string) error {
	return s.setPassword(id, samePassword, false)
}

// setPassword mirrors FileStore.setPassword exactly; `stamp` separates a real
// change (history + expiry clock) from a cost rehash. The User row is a JSON
// `data` column, so the new lifecycle fields need no migration.
func (s *PGStore) setPassword(id, newPassword string, stamp bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := token.HashPassword(newPassword)
	if err != nil {
		return err
	}
	ctx, cancel := usersCtx()
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, normID(id))
		if err != nil {
			return err
		}
		if stamp {
			s.deps.ApplyPasswordChange(&u, hash, time.Now().UTC())
		} else {
			u.PasswordHash = hash
		}
		return writeUserTx(ctx, tx, u)
	})
}

// ResetPassword is the admin variant of ChangePassword (no current password
// required); identical persistence, mirroring the file store.
func (s *PGStore) ResetPassword(id, newPassword string) error {
	return s.ChangePassword(id, newPassword)
}

func (s *PGStore) TouchLogin(id string) {
	ctx, cancel := usersCtx()
	defer cancel()
	key := normID(id)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, key)
		if errors.Is(err, ErrNoSuchUser) {
			return nil // best-effort: a removed account shouldn't error a login record
		}
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		u.LastLoginAt = now
		if _, err := tx.Exec(ctx, `UPDATE user_identities SET last_login_at=$2 WHERE user_id=$1`, key, now); err != nil {
			return err
		}
		return writeUserTx(ctx, tx, u)
	})
	if err != nil {
		s.deps.Errorf("users", "touch login", map[string]any{"error": err.Error()})
	}
}

// VerifyIdentityInvariants is the §3 Enforce gate (see Repo). It deliberately
// does NOT rely on the UNIQUE(user_id) constraint existing: the check must still
// be meaningful against a database whose schema drifted.
func (s *PGStore) VerifyIdentityInvariants() error {
	ctx, cancel := usersCtx()
	defer cancel()
	var pending int
	var doubled int
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM users u
			LEFT JOIN user_identities i ON i.user_id = u.id
			WHERE i.user_id IS NULL
			  AND COALESCE(u.data->>'auth_source', '') IN ('', 'local')`).Scan(&pending); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `SELECT count(*) FROM (
			SELECT user_id FROM user_identities GROUP BY user_id HAVING count(*) > 1) dup`).Scan(&doubled)
	})
	if err != nil {
		return err
	}
	if doubled > 0 {
		return fmt.Errorf("users: %d account(s) hold more than one identity — exactly one is allowed", doubled)
	}
	if pending > 0 {
		return fmt.Errorf("%w: %d local account(s) without an identity row", ErrIdentityBackfillIncomplete, pending)
	}
	return nil
}

func (s *PGStore) SeedAdmin(username, password string) error {
	if username == "" || password == "" {
		return nil
	}
	if s.Count() > 0 {
		return nil
	}
	_, err := s.Create(username, password, "admin")
	return err
}

// ---- federated resolution (§2.5/§2.6) --------------------------------------

// ResolveFederated — see Repo. One transaction, rows held FOR UPDATE, so the
// realm refusal and the merge write can never interleave.
func (s *PGStore) ResolveFederated(a Assertion, realm Realm, provision bool) (User, error) {
	return s.resolve(a, realm, provision, false)
}

// ResolveFederatedUnbound — see Repo.
func (s *PGStore) ResolveFederatedUnbound(a Assertion) (User, error) {
	return s.resolve(a, Realm{}, true, true)
}

func (s *PGStore) resolve(a Assertion, realm Realm, provision, unbound bool) (User, error) {
	a.Identity = a.Identity.normalized()
	if err := validateAssertion(a); err != nil {
		return User{}, err
	}
	ctx, cancel := usersCtx()
	defer cancel()
	var (
		out   User
		bound bool
	)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, didBind, err := s.resolveTx(ctx, tx, a, realm, provision, unbound)
		if err != nil {
			return err
		}
		out, bound = u, didBind
		return nil
	})
	if err != nil {
		if isUniqueViolation(err) {
			// A concurrent JIT won the tuple. Re-read it once (§2.5): the retry is
			// by TUPLE, never by username, so a race converges on the same account.
			var retry User
			rerr := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
				owner, err := lookupTupleTx(ctx, tx, a, unbound)
				if err != nil {
					return err
				}
				if owner == "" {
					return ErrIdentityConflict
				}
				u, err := loadUserTx(ctx, tx, owner)
				if err != nil {
					return err
				}
				retry, err = s.refreshTx(ctx, tx, u, a, realm)
				return err
			})
			if rerr != nil {
				return User{}, rerr
			}
			return retry, nil
		}
		return User{}, err
	}
	// Reported after the transaction commits, and outside it: the integrator's
	// audit sink writes to its own store.
	if bound && s.deps.OnLegacyBound != nil {
		s.deps.OnLegacyBound(out, a)
	}
	return out, nil
}

func (s *PGStore) resolveTx(ctx context.Context, tx pgx.Tx, a Assertion, realm Realm, provision, unbound bool) (User, bool, error) {
	owner, err := lookupTupleTx(ctx, tx, a, unbound)
	if err != nil {
		return User{}, false, err
	}
	if owner == "" && !unbound {
		// §2.5 Amendment — see realmScopedOwner. Same decision, same bound, on
		// rows this transaction already holds FOR UPDATE.
		cands, cerr := tupleCandidatesTx(ctx, tx, a)
		if cerr != nil {
			return User{}, false, cerr
		}
		if owner, err = realmScopedOwner(realm, cands); err != nil {
			return User{}, false, err
		}
	}
	if owner != "" {
		u, err := loadUserTx(ctx, tx, owner)
		if err != nil {
			return User{}, false, err
		}
		out, err := s.refreshTx(ctx, tx, u, a, realm)
		return out, false, err
	}
	if !provision {
		// The read-only door (elevation): a tuple miss is a refusal, and nothing
		// is written. It never binds by username again.
		return User{}, false, ErrNoSuchUser
	}
	if u, ok, err := s.bindLegacyTx(ctx, tx, a, realm, unbound); err != nil {
		return User{}, false, err
	} else if ok {
		return u, true, nil
	}
	u, err := s.provisionTx(ctx, tx, a, realm)
	return u, false, err
}

// lookupTupleTx locks the identity row so a concurrent sign-in cannot merge
// against the same account behind us. The unbound form matches (issuer, subject)
// across tenants and refuses an ambiguous result rather than picking one.
func lookupTupleTx(ctx context.Context, tx pgx.Tx, a Assertion, unbound bool) (string, error) {
	if !unbound {
		var id string
		err := tx.QueryRow(ctx,
			`SELECT user_id FROM user_identities
			  WHERE tenant_id=$1 AND issuer=$2 AND subject=$3 FOR UPDATE`,
			a.TenantID, a.Issuer, a.Subject).Scan(&id)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil
		}
		return id, err
	}
	rows, err := tx.Query(ctx,
		`SELECT user_id FROM user_identities WHERE issuer=$1 AND subject=$2 ORDER BY user_id FOR UPDATE`,
		a.Issuer, a.Subject)
	if err != nil {
		return "", err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return "", err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", err
	}
	switch len(ids) {
	case 0:
		return "", nil
	case 1:
		return ids[0], nil
	default:
		return "", ErrAmbiguousIdentity
	}
}

// tupleCandidatesTx is the pg twin of tupleCandidatesLocked: tenant → owning
// account id for every identity matching (issuer, subject). Locked FOR UPDATE
// like the exact lookup, so the realm-scoped decision cannot race a concurrent
// provision in a sibling tenant.
func tupleCandidatesTx(ctx context.Context, tx pgx.Tx, a Assertion) (map[string]string, error) {
	rows, err := tx.Query(ctx,
		`SELECT tenant_id, user_id FROM user_identities
		  WHERE issuer=$1 AND subject=$2 ORDER BY tenant_id FOR UPDATE`,
		a.Issuer, a.Subject)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string, 2)
	for rows.Next() {
		var tenant, id string
		if err := rows.Scan(&tenant, &id); err != nil {
			return nil, err
		}
		out[tenant] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// refreshTx is the tuple-hit path: H1, then the realm, then the profile refresh.
func (s *PGStore) refreshTx(ctx context.Context, tx pgx.Tx, u User, a Assertion, realm Realm) (User, error) {
	if IsLocalSource(u.AuthSource) {
		return User{}, ErrLocalAccount
	}
	if !realm.Permits(u.TenantID) {
		return User{}, ErrForeignTenant
	}
	now := time.Now().UTC()
	u = MergeFederated(u, a.Email, a.DisplayName, s.deps.GuardRole(a.Role, u.TenantID, u.ID, a.Protocol), a.Protocol)
	if u.Identity != nil {
		next := refreshIdentityMeta(*u.Identity, a, now)
		if _, err := tx.Exec(ctx,
			`UPDATE user_identities SET last_login_at=$2, connection_id=$3, subject_kind=$4 WHERE user_id=$1`,
			normID(u.ID), next.LastLoginAt, next.ConnectionID, next.SubjectKind); err != nil {
			return User{}, err
		}
		u.Identity = &next
	}
	if err := writeUserTx(ctx, tx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

// bindLegacyTx is design §2.6 on Postgres: the candidate row is locked FOR
// UPDATE, every condition is evaluated against the locked row, and the identity
// insert rides the same transaction. ok=false means "conditions not met" — the
// caller then provisions a fresh account, which is the "flagged, never guessed"
// outcome.
func (s *PGStore) bindLegacyTx(ctx context.Context, tx pgx.Tx, a Assertion, realm Realm, unbound bool) (User, bool, error) {
	cand := legacyUserID(a.LegacyUsername)
	if cand == "" {
		return User{}, false, nil
	}
	u, err := loadUserTx(ctx, tx, cand)
	if errors.Is(err, ErrNoSuchUser) {
		return User{}, false, nil
	}
	if err != nil {
		return User{}, false, err
	}
	identityTenant := normTenant(a.TenantID)
	if unbound {
		identityTenant = normTenant(u.TenantID)
	}
	if !legacyBindPermitted(u, a, realm, s.markerAt, u.Identity != nil, identityTenant) {
		return User{}, false, nil
	}
	now := time.Now().UTC()
	ident := assertedIdentity(a, identityTenant, ProvenanceLegacyLazyBound, now)
	u.Identity = &ident
	u = MergeFederated(u, a.Email, a.DisplayName, s.deps.GuardRole(a.Role, u.TenantID, u.ID, a.Protocol), a.Protocol)
	if err := insertIdentityTx(ctx, tx, normID(u.ID), ident); err != nil {
		return User{}, false, err
	}
	if err := writeUserTx(ctx, tx, u); err != nil {
		return User{}, false, err
	}
	return u, true, nil
}

// provisionTx mints a brand-new federated account. CAP-EXEMPT on purpose:
// MAX_USERS must never lock an organisation out of SSO.
func (s *PGStore) provisionTx(ctx context.Context, tx pgx.Tx, a Assertion, realm Realm) (User, error) {
	tenant := s.deps.provisioningTenant(a)
	if !realm.Permits(tenant) {
		return User{}, ErrForeignTenant
	}
	id, err := mintFederatedIDTx(ctx, tx, a, tenant)
	if err != nil {
		return User{}, err
	}
	now := time.Now().UTC()
	role := s.deps.GuardRole(a.Role, tenant, id, a.Protocol)
	u := newFederatedUser(a, id, tenant, role, now)
	if err := insertUserTx(ctx, tx, u); err != nil {
		return User{}, err
	}
	return u, nil
}

// mintFederatedIDTx applies §2.4 and §4.3: the deterministic id, extended to the
// full digest if a DIFFERENT identity already holds the short form, refused if
// that is taken too. Never resolved by email or username.
func mintFederatedIDTx(ctx context.Context, tx pgx.Tx, a Assertion, tenant string) (string, error) {
	id := FederatedID(tenant, a.Issuer, a.Subject)
	taken, err := userExistsTx(ctx, tx, id)
	if err != nil {
		return "", err
	}
	if !taken {
		return id, nil
	}
	id = FederatedIDExtended(tenant, a.Issuer, a.Subject)
	taken, err = userExistsTx(ctx, tx, id)
	if err != nil {
		return "", err
	}
	if taken {
		return "", fmt.Errorf("%w: federated id %q already held by a different identity", ErrIdentityConflict, id)
	}
	return id, nil
}

// ---- deprecated username-keyed federated upsert ---------------------------

// UpsertFederated provisions or refreshes a user authenticated by an external
// IdP, keyed by USERNAME.
//
// Deprecated: tracker 300 — username is not an identity. Superseded by
// ResolveFederated / ResolveFederatedUnbound. Kept UNCHANGED in behaviour only
// so the doors keep compiling until the 300-doors change rewrites them.
func (s *PGStore) UpsertFederated(username, email, displayName, role, source, tenant string) (User, error) {
	return s.UpsertFederatedInRealm(username, email, displayName, role, source, tenant, Realm{})
}

// UpsertFederatedInRealm is the pg twin of the FileStore method: the realm is
// checked inside the SAME transaction that holds the row FOR UPDATE, so the
// refusal and the merge write can never interleave.
//
// Deprecated: tracker 300 — see UpsertFederated.
func (s *PGStore) UpsertFederatedInRealm(username, email, displayName, role, source, tenant string, realm Realm) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if source == "" {
		source = ProtocolOIDC
	}
	ctx, cancel := usersCtx()
	defer cancel()
	id := legacyUserID(username)
	var out User
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
		switch {
		case err == nil:
			// Existing account. A LOCAL account (IsLocalSource — "" is local) is
			// REFUSED (H1): merging would bypass the local password + MFA and let
			// the IdP re-role/re-source the record.
			if IsLocalSource(u.AuthSource) {
				return ErrLocalAccount
			}
			if !realm.Permits(u.TenantID) {
				return ErrForeignTenant
			}
			u = MergeFederated(u, email, displayName, s.deps.GuardRole(role, u.TenantID, username, source), source)
			if err := writeUserTx(ctx, tx, u); err != nil {
				return err
			}
			out = u
			return nil
		case errors.Is(err, ErrNoSuchUser):
			// First federated login — provision a passwordless account. Cap-exempt
			// so SSO never locks out at MAX_USERS.
			if tenant == "" {
				tenant = s.deps.DefaultTenant
			}
			if !realm.Permits(tenant) {
				return ErrForeignTenant
			}
			role = s.deps.GuardRole(role, tenant, username, source)
			nu := User{
				ID: id, Username: username, Role: role, Email: email, DisplayName: displayName,
				TenantID: tenant, Status: "active", AuthSource: source, CreatedAt: time.Now().UTC(),
			}
			data, err := marshalUserRow(nu)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1, $2, $3)`,
				id, normTenant(nu.TenantID), data); err != nil {
				return err
			}
			out = nu
			return nil
		default:
			return err
		}
	})
	if err != nil {
		return User{}, err
	}
	return out, nil
}

// ---- transaction helpers (platform-scope tx already open) ------------------

// userIdentityCols is the SELECT list for a user plus its joined identity. The
// identity columns are NULLable: a LEFT JOIN miss is the `identity_status:
// pending` state (§2.7), not an error.
const userIdentityCols = `u.id, u.data,
	i.tenant_id, i.issuer, i.subject, i.protocol, i.connection_id, i.subject_kind,
	i.provenance, i.first_seen_at, i.last_login_at`

// rowScanner is the one method pgx.Row and pgx.Rows share.
type rowScanner interface{ Scan(dest ...any) error }

// scanUserRow materialises one (user, identity?) row. The `id` COLUMN is
// authoritative for User.ID — a legacy `data` blob has no id field at all, and
// filling it from the column is what preserves `ID == lower(username)` for
// everything that already references the account.
func scanUserRow(r rowScanner) (User, error) {
	var (
		id                                                      string
		data                                                    []byte
		tenant, issuer, subject, protocol, conn, subjKind, prov *string
		firstSeen, lastLogin                                    *time.Time
	)
	if err := r.Scan(&id, &data, &tenant, &issuer, &subject, &protocol, &conn, &subjKind, &prov, &firstSeen, &lastLogin); err != nil {
		return User{}, err
	}
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return User{}, err
	}
	u.ID = id
	u.Identity = nil
	if issuer != nil && subject != nil {
		ident := Identity{
			Issuer:   *issuer,
			Subject:  *subject,
			Protocol: derefString(protocol),
		}
		ident.TenantID = derefString(tenant)
		ident.ConnectionID = derefString(conn)
		ident.SubjectKind = derefString(subjKind)
		ident.Provenance = derefString(prov)
		if firstSeen != nil {
			ident.FirstSeenAt = firstSeen.UTC()
		}
		if lastLogin != nil {
			ident.LastLoginAt = lastLogin.UTC()
		}
		u.Identity = &ident
	}
	return u, nil
}

func derefString(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// selectUserTx reads one user WITHOUT locking (the read paths).
func selectUserTx(ctx context.Context, tx pgx.Tx, id string) (User, error) {
	row := tx.QueryRow(ctx, `SELECT `+userIdentityCols+` FROM users u
		LEFT JOIN user_identities i ON i.user_id = u.id
		WHERE u.id = $1`, id)
	u, err := scanUserRow(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSuchUser
	}
	return u, err
}

// loadUserTx reads one user FOR UPDATE inside the caller's transaction, so a
// read-modify-write (Update/Delete/ChangePassword/TouchLogin/resolve) holds the
// row against a concurrent writer. Absent → ErrNoSuchUser (shared sentinel).
//
// The lock is taken on `users` only: locking the LEFT-JOINed identity row is not
// expressible in one statement (FOR UPDATE cannot apply to the null side of an
// outer join), and the identity is locked separately by lookupTupleTx on the path
// that needs it.
func loadUserTx(ctx context.Context, tx pgx.Tx, id string) (User, error) {
	var locked string
	err := tx.QueryRow(ctx, `SELECT id FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&locked)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSuchUser
	}
	if err != nil {
		return User{}, err
	}
	return selectUserTx(ctx, tx, id)
}

func userExistsTx(ctx context.Context, tx pgx.Tx, id string) (bool, error) {
	var exists bool
	err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, normID(id)).Scan(&exists)
	return exists, err
}

// insertUserTx writes a new account AND its identity in the caller's
// transaction — one write, so an account can never exist without its namespace
// entry (§2.5).
func insertUserTx(ctx context.Context, tx pgx.Tx, u User) error {
	data, err := marshalUserRow(u)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1, $2, $3)`,
		normID(u.ID), normTenant(u.TenantID), data); err != nil {
		return err
	}
	if u.Identity == nil {
		return nil
	}
	return insertIdentityTx(ctx, tx, normID(u.ID), *u.Identity)
}

func insertIdentityTx(ctx context.Context, tx pgx.Tx, userID string, i Identity) error {
	if err := i.validate(); err != nil {
		return err
	}
	if i.FirstSeenAt.IsZero() {
		// first_seen_at is NOT NULL in the schema; binding a zero time as NULL
		// would be a constraint violation rather than the column's default.
		i.FirstSeenAt = time.Now().UTC()
	}
	_, err := tx.Exec(ctx, `INSERT INTO user_identities
		(tenant_id, issuer, subject, user_id, protocol, connection_id, subject_kind, provenance, first_seen_at, last_login_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		i.TenantID, i.Issuer, i.Subject, userID, i.Protocol, i.ConnectionID, i.SubjectKind, i.Provenance,
		nullableTime(i.FirstSeenAt), nullableTime(i.LastLoginAt))
	return err
}

// nullableTime maps Go's zero time to SQL NULL: a zero timestamptz would read as
// year 1 and make "never logged in" indistinguishable from a real stamp.
func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

// writeUserTx persists a mutated user, keeping the tenant_id column in step with
// the object so RLS continues to scope it correctly after a tenant move. The
// identity is NOT written here — `user_identities` owns it.
func writeUserTx(ctx context.Context, tx pgx.Tx, u User) error {
	data, err := marshalUserRow(u)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE users SET data=$2, tenant_id=$3, updated_at=now() WHERE id=$1`,
		normID(u.ID), data, normTenant(u.TenantID))
	return err
}

// countSuperAdminsTx counts active super-admins across ALL tenants inside the
// caller's (platform-scope) transaction — the super-admin floor is a
// platform-wide invariant, so it must not be tenant-scoped. Uses the shared
// isSuperAdminRole so the count matches the file store exactly.
func countSuperAdminsTx(ctx context.Context, tx pgx.Tx, isSuper func(string) bool) (int, error) {
	rows, err := tx.Query(ctx, `SELECT data FROM users`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var data []byte
		if err := rows.Scan(&data); err != nil {
			return 0, err
		}
		var u User
		if err := json.Unmarshal(data, &u); err != nil {
			return 0, err
		}
		if isSuper(u.Role) && u.Status != "disabled" {
			n++
		}
	}
	return n, rows.Err()
}
