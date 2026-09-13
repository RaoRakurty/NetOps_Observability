// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package users

import (
	"errors"

	"github.com/jackc/pgx/v5"
)

// MutateForTest applies mod to a stored account directly and persists the
// result — the injected-era replacement for tests that used to reach into the
// map to backdate lifecycle timestamps (account-policy rules must be provable
// without sleeping). Keyed by User.ID, like every other mutator. TEST SUPPORT
// ONLY: every production write path goes through the exported methods and their
// invariants.
func (s *FileStore) MutateForTest(id string, mod func(*User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := normID(id)
	u, ok := s.users[key]
	if !ok {
		return errors.New("no such user: " + id)
	}
	mod(&u)
	s.users[key] = u
	return s.flushLocked()
}

// LegacySeeder writes a PRE-TRACKER-300 account: `id == lower(username)`, an
// auth_source, and NO identity row — exactly the shape the username-keyed code
// left behind, which is what the §2.6 lazy bind and the §3 backfill have to cope
// with. TEST SUPPORT ONLY, and deliberately NOT a resolution call:
// the new tests must not exercise the code path they are replacing.
//
// It is an interface so the cross-backend contract can seed both stores.
type LegacySeeder interface {
	SeedLegacyForTest(u User) error
}

// SeedLegacyForTest — see LegacySeeder. The id is derived from the username
// exactly as the legacy code derived it, and CreatedAt is taken from the caller so
// a test can place an account on either side of the migration epoch.
//
// u.IdentityMigration is honoured when set, so a test can seed a row in an
// explicit `unresolved` or `ambiguous` state (owner Decision 2). `ambiguous` is
// otherwise only reachable through a write race, and the rule that the lazy path
// must never touch such a row has to be provable on both backends.
func (s *FileStore) SeedLegacyForTest(u User) error {
	u.ID = legacyUserID(u.Username)
	u.Identity = nil
	if u.ID == "" {
		return errors.New("users: SeedLegacyForTest needs a username")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, dup := s.users[u.ID]; dup {
		return errors.New("users: SeedLegacyForTest: id already present: " + u.ID)
	}
	s.users[u.ID] = u
	return s.flushLocked()
}

// SeedLegacyForTest — see LegacySeeder.
func (s *PGStore) SeedLegacyForTest(u User) error {
	u.ID = legacyUserID(u.Username)
	u.Identity = nil
	if u.ID == "" {
		return errors.New("users: SeedLegacyForTest needs a username")
	}
	ctx, cancel := usersCtx()
	defer cancel()
	return s.db.WithTenant(ctx, "", true, func(tx pgx.Tx) error {
		data, err := marshalUserRow(u)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO users (id, tenant_id, data) VALUES ($1, $2, $3)`,
			u.ID, normTenant(u.TenantID), data); err != nil {
			return err
		}
		if u.IdentityMigration == nil {
			// A legacy row genuinely has NO state row: that is what the migration has
			// to cope with, so the default seed leaves the side table empty.
			return nil
		}
		return upsertStateTx(ctx, tx, u)
	})
}
