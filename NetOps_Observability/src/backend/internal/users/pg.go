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

// users_pg.go — the Postgres-backed user repository (#33).
//
// This is the second store (after audit, #32) to graduate off the load-all-blob
// model onto real per-row SQL. The win it delivers:
//   - List(tenant, cross) is enforced PER REQUEST by Row-Level Security: a scoped
//     admin's list runs inside withTenant(tenant) so the database returns only
//     that tenant's rows — RLS stops being a mere backstop under the app filter.
//   - Mutations are partial UPDATEs of a single row, not a rewrite of the whole
//     collection, and there is no in-process cache to go stale across instances.
//
// Scope rules (see the Repo doc in users.go):
//   - Get / Count / every mutation run at PLATFORM scope ('*'). username is the
//     global primary key, so existence/uniqueness checks and the platform-wide
//     last-super-admin invariant must see across tenants. Login also resolves a
//     user's tenant FROM the record before any tenant scope exists. WHO may
//     mutate WHOM is enforced upstream at the handler/Authorize() chokepoint.
//   - Only List is request-tenant-scoped — exactly the cross-tenant enumeration
//     surface RLS needs to fence.
//
// The domain invariants (patch application, federated refresh, last-super-admin
// guard, password validation, create defaults) come from the shared pure helpers
// in users.go, so this backend and the file backend cannot drift.
// DB is the injected relational seam (the portintel.DB idiom).
type DB interface {
	WithTenant(ctx context.Context, tenant string, cross bool, fn func(pgx.Tx) error) error
}

type PGStore struct {
	db   DB
	deps Deps
}

// NewPGStore builds the per-row RLS-backed store (Deps.KV unused here).
func NewPGStore(db DB, d Deps) (*PGStore, error) {
	if err := d.validate(); err != nil {
		return nil, err
	}
	return &PGStore{db: db, deps: d}, nil
}

// normTenant mirrors the integrator's tenant-id normalization (duplicated per
// the no-shared-utils rule).
func normTenant(t string) string { return strings.ToLower(strings.TrimSpace(t)) }

// userID is the primary-key form of a username: lowercased to match the
// case-insensitive keying the file store uses (and the lowerID rowSpec the M0
// importer applied). It does NOT trim — mirroring FileStore's map-key lookup, so
// the two backends resolve the same string to the same (or no) row.
func userID(username string) string { return strings.ToLower(username) }

func usersCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// isUniqueViolation reports a Postgres unique_violation (23505) — the PK race
// backstop behind the in-transaction existence check.
func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func (s *PGStore) Get(username string) (User, bool) {
	ctx, cancel := usersCtx()
	defer cancel()
	var u User
	found := false
	// Platform scope: username is the global key; login resolves tenant from the
	// row, and authorization on the result is the handler's job.
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var data []byte
		err := tx.QueryRow(ctx, `SELECT data FROM users WHERE id=$1`, userID(username)).Scan(&data)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &u); err != nil {
			return err
		}
		found = true
		return nil
	})
	if err != nil {
		s.deps.Errorf("users", "get", map[string]any{"error": err.Error()})
		return User{}, false
	}
	return u, found
}

func (s *PGStore) List(tenant string, cross bool) []User {
	ctx, cancel := usersCtx()
	defer cancel()
	var out []User
	// RLS scopes the read: a scoped admin sees only its own tenant; '*' sees all.
	err := s.db.WithTenant(ctx, tenant, cross, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT data FROM users`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var data []byte
			if err := rows.Scan(&data); err != nil {
				return err
			}
			var u User
			if err := json.Unmarshal(data, &u); err != nil {
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
	u := User{Username: username, Role: role, PasswordHash: hash, CreatedAt: time.Now().UTC()}
	return s.insertNew(u, false)
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
	return s.insertNew(u, false)
}

// insertNew inserts a brand-new user under platform scope. existence + cap +
// insert run in one transaction so the checks and the write are atomic; the PK
// unique-violation is the race backstop. exemptCap skips the MAX_USERS gate
// (federated JIT provisioning must never be locked out — same rule as the file
// store).
func (s *PGStore) insertNew(u User, exemptCap bool) (User, error) {
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(u.Username)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id=$1)`, id).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("user %q already exists", u.Username)
		}
		if !exemptCap && s.deps.MaxUsers > 0 {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil {
				return err
			}
			if n >= s.deps.MaxUsers {
				return fmt.Errorf("user limit reached (MAX_USERS=%d)", s.deps.MaxUsers)
			}
		}
		data, err := json.Marshal(u)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1, $2, $3)`,
			id, normTenant(u.TenantID), data)
		return err
	})
	if err != nil {
		if isUniqueViolation(err) {
			return User{}, fmt.Errorf("user %q already exists", u.Username)
		}
		return User{}, err
	}
	return u, nil
}

func (s *PGStore) Update(username string, patch User) (User, error) {
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	var out User
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
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
		out = u
		return writeUserTx(ctx, tx, u)
	})
	if err != nil {
		return User{}, err
	}
	return out, nil
}

func (s *PGStore) SetMFA(username string, enabled bool, secret, pending string) error {
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
		if err != nil {
			return err
		}
		u.MFAEnabled, u.MFASecret, u.MFAPending = enabled, secret, pending
		return writeUserTx(ctx, tx, u)
	})
}

func (s *PGStore) Delete(username string) error {
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
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
		_, err = tx.Exec(ctx, `DELETE FROM users WHERE id=$1`, id)
		return err
	})
}

func (s *PGStore) ChangePassword(username, newPassword string) error {
	return s.setPassword(username, newPassword, true)
}

// RehashPassword re-wraps the same secret at the current cost — hash only.
func (s *PGStore) RehashPassword(username, samePassword string) error {
	return s.setPassword(username, samePassword, false)
}

// setPassword mirrors FileStore.setPassword exactly; `stamp` separates a real
// change (history + expiry clock) from a cost rehash. The User row is a JSON
// `data` column, so the new lifecycle fields need no migration.
func (s *PGStore) setPassword(username, newPassword string, stamp bool) error {
	if err := ValidatePassword(newPassword); err != nil {
		return err
	}
	hash, err := token.HashPassword(newPassword)
	if err != nil {
		return err
	}
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
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
func (s *PGStore) ResetPassword(username, newPassword string) error {
	return s.ChangePassword(username, newPassword)
}

func (s *PGStore) TouchLogin(username string) {
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
		if errors.Is(err, ErrNoSuchUser) {
			return nil // best-effort: a removed account shouldn't error a login record
		}
		if err != nil {
			return err
		}
		u.LastLoginAt = time.Now().UTC()
		return writeUserTx(ctx, tx, u)
	})
	if err != nil {
		s.deps.Errorf("users", "touch login", map[string]any{"error": err.Error()})
	}
}

func (s *PGStore) UpsertFederated(username, email, displayName, role, source, tenant string) (User, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return User{}, errors.New("username required")
	}
	if source == "" {
		source = "oidc"
	}
	ctx, cancel := usersCtx()
	defer cancel()
	id := userID(username)
	var out User
	err := s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		u, err := loadUserTx(ctx, tx, id)
		switch {
		case err == nil:
			// Existing account. A LOCAL account is never re-roled by federation —
			// local management wins; the federated login is just accepted against it.
			if u.AuthSource != "local" {
				// Federated account — keep it in sync with the IdP (SR-025: guard the
				// IdP-mapped role against silent platform-owner escalation, using the
				// account's existing tenant).
				u = MergeFederated(u, email, displayName, s.deps.GuardRole(role, u.TenantID, username, source), source)
				if err := writeUserTx(ctx, tx, u); err != nil {
					return err
				}
			}
			out = u
			return nil
		case errors.Is(err, ErrNoSuchUser):
			// First federated login — provision a passwordless account. Cap-exempt
			// so SSO never locks out at MAX_USERS.
			if tenant == "" {
				tenant = s.deps.DefaultTenant
			}
			role = s.deps.GuardRole(role, tenant, username, source)
			nu := User{
				Username: username, Role: role, Email: email, DisplayName: displayName,
				TenantID: tenant, Status: "active", AuthSource: source, CreatedAt: time.Now().UTC(),
			}
			data, err := json.Marshal(nu)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1, $2, $3)`,
				userID(nu.Username), normTenant(nu.TenantID), data); err != nil {
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

// ---- transaction helpers (platform-scope tx already open) ------------------

// loadUserTx reads one user FOR UPDATE inside the caller's transaction, so a
// read-modify-write (Update/Delete/ChangePassword/TouchLogin) holds the row
// against a concurrent writer. Absent → ErrNoSuchUser (shared sentinel).
func loadUserTx(ctx context.Context, tx pgx.Tx, id string) (User, error) {
	var data []byte
	err := tx.QueryRow(ctx, `SELECT data FROM users WHERE id=$1 FOR UPDATE`, id).Scan(&data)
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNoSuchUser
	}
	if err != nil {
		return User{}, err
	}
	var u User
	if err := json.Unmarshal(data, &u); err != nil {
		return User{}, err
	}
	return u, nil
}

// writeUserTx persists a mutated user, keeping the tenant_id column in step with
// the object so RLS continues to scope it correctly after a tenant move.
func writeUserTx(ctx context.Context, tx pgx.Tx, u User) error {
	data, err := json.Marshal(u)
	if err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE users SET data=$2, tenant_id=$3, updated_at=now() WHERE id=$1`,
		userID(u.Username), data, normTenant(u.TenantID))
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
