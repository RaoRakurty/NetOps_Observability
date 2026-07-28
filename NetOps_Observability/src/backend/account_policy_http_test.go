package main

// account_policy_http_test.go — F-68 through the REAL login handler.
//
// account_policy_test.go proves the rules are right. This file proves they are
// WIRED: that the settings reach the endpoint an operator actually hits. F-68
// existed because nothing connected a correct-looking settings store to the
// auth path, so a unit test of the rules alone would have reproduced the bug at
// a smaller scale.

import (
	"encoding/json"
	"net/http"
	"netops/backend/internal/session"
	"netops/backend/internal/users"
	"strings"
	"testing"
	"time"
)

// backdate mutates a user in the file store directly. The public Update() patch
// path deliberately ignores lifecycle timestamps, and aging an account is
// exactly what these rules need to be provable without sleeping.
func backdateUser(t *testing.T, s *server, username string, mod func(*User)) {
	t.Helper()
	us, ok := s.users.(*users.FileStore)
	if !ok {
		t.Fatalf("expected the file-backed users.FileStore, got %T", s.users)
	}
	if err := us.MutateForTest(username, mod); err != nil {
		t.Fatalf("mutate %q: %v", username, err)
	}
}

func setScopeSettings(t *testing.T, s *server, scope string, mod func(*SecuritySettings)) {
	t.Helper()
	ss := s.securitySettings.Get(scope)
	mod(&ss)
	if _, err := s.securitySettings.Set(scope, ss); err != nil {
		t.Fatalf("set security settings: %v", err)
	}
}

// activeSessions filters by status: ListForUser deliberately returns revoked
// rows too (the admin UI shows them), so counting it directly would report a
// revocation as a no-op.
func activeSessions(s *server, userID string) []session.Session {
	var out []session.Session
	for _, x := range s.sessions.ListForUser(userID) {
		if x.Status == session.StatusActive {
			out = append(out, x)
		}
	}
	return out
}

func postLogin(t *testing.T, base, user, pass string) (int, map[string]any) {
	t.Helper()
	body := strings.NewReader(`{"username":"` + user + `","password":"` + pass + `"}`)
	resp, err := http.Post(base+"/api/auth/login", "application/json", body)
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

const seedUser, seedPass = "admin", "Passw0rd!2345"

// Baseline: with shipped defaults the seeded admin must sign in. If this fails,
// every other assertion here is meaningless.
func TestLoginSucceedsUnderDefaultSecuritySettings(t *testing.T) {
	srv, _ := newTestServerState(t)
	code, out := postLogin(t, srv.URL, seedUser, seedPass)
	if code != http.StatusOK {
		t.Fatalf("login = %d, want 200 (body %v)", code, out)
	}
	if out["token"] == nil {
		t.Fatal("a successful login must return a token")
	}
}

func TestExpiredAccountIsRefusedAtLogin(t *testing.T) {
	srv, s := newTestServerState(t)
	setScopeSettings(t, s, ScopeProvider, func(ss *SecuritySettings) { ss.AccountValidityDays = 30 })
	backdateUser(t, s, seedUser, func(u *User) { u.CreatedAt = time.Now().UTC().AddDate(0, 0, -60) })

	code, out := postLogin(t, srv.URL, seedUser, seedPass)
	if code != http.StatusForbidden {
		t.Fatalf("expired account login = %d, want 403 (body %v)", code, out)
	}
	if out["token"] != nil {
		t.Fatal("a refused login must not return a token")
	}
}

func TestInactiveAccountIsRefusedAtLogin(t *testing.T) {
	srv, s := newTestServerState(t)
	setScopeSettings(t, s, ScopeProvider, func(ss *SecuritySettings) { ss.AccountInactivityDays = 90 })
	backdateUser(t, s, seedUser, func(u *User) { u.LastLoginAt = time.Now().UTC().AddDate(0, 0, -120) })

	code, _ := postLogin(t, srv.URL, seedUser, seedPass)
	if code != http.StatusForbidden {
		t.Fatalf("inactive account login = %d, want 403", code)
	}
}

// The correct credentials with an expired PASSWORD must not yield a session —
// but must not look like a wrong password either.
func TestExpiredPasswordWithholdsTheSession(t *testing.T) {
	srv, s := newTestServerState(t)
	setScopeSettings(t, s, ScopeProvider, func(ss *SecuritySettings) {
		ss.PasswordExpireEnabled, ss.PasswordExpireDays = true, 90
	})
	backdateUser(t, s, seedUser, func(u *User) {
		u.PasswordChangedAt = time.Now().UTC().AddDate(0, 0, -120)
	})

	code, out := postLogin(t, srv.URL, seedUser, seedPass)
	if code != http.StatusOK {
		t.Fatalf("expired password login = %d, want 200 + must_change_password", code)
	}
	if out["must_change_password"] != true {
		t.Fatalf("expected must_change_password, got %v", out)
	}
	if out["token"] != nil {
		t.Fatal("SESSION LEAK: an expired password still minted a token")
	}
	if out["reason"] != acctPolicyPasswordExpired {
		t.Errorf("reason = %v, want %q", out["reason"], acctPolicyPasswordExpired)
	}
}

// The regression that would silently disable password expiry forever: the
// SR-029 rehash-on-login must not restart the expiry clock.
func TestRehashOnLoginDoesNotResetTheExpiryClock(t *testing.T) {
	_, s := newTestServerState(t)
	old := time.Now().UTC().AddDate(0, 0, -120)
	backdateUser(t, s, seedUser, func(u *User) { u.PasswordChangedAt = old })

	if err := s.users.RehashPassword(seedUser, seedPass); err != nil {
		t.Fatalf("rehash: %v", err)
	}
	u, ok := s.users.Get(seedUser)
	if !ok {
		t.Fatal("user vanished")
	}
	if !u.PasswordChangedAt.Equal(old) {
		t.Fatalf("rehash moved PasswordChangedAt %v -> %v; password_expire_days becomes unreachable",
			old, u.PasswordChangedAt)
	}
	if len(u.PasswordHistory) != 0 {
		t.Errorf("rehash must not push history, got %v", u.PasswordHistory)
	}
}

// A real change DOES stamp — the other half of the pair above.
func TestChangePasswordStampsTheClock(t *testing.T) {
	_, s := newTestServerState(t)
	before := time.Now().UTC().Add(-time.Second)
	if err := s.users.ChangePassword(seedUser, "An0therPassw0rd!"); err != nil {
		t.Fatalf("change: %v", err)
	}
	u, _ := s.users.Get(seedUser)
	if u.PasswordChangedAt.Before(before) {
		t.Fatalf("PasswordChangedAt not stamped: %v", u.PasswordChangedAt)
	}
	if len(u.PasswordHistory) == 0 {
		t.Error("the outgoing hash must be retained for password_history")
	}
}

func TestConcurrentLoginDenyRevokesThePriorSession(t *testing.T) {
	srv, s := newTestServerState(t)
	setScopeSettings(t, s, ScopeProvider, func(ss *SecuritySettings) { ss.ConcurrentLogin = "deny" })

	if code, _ := postLogin(t, srv.URL, seedUser, seedPass); code != http.StatusOK {
		t.Fatalf("first login = %d, want 200", code)
	}
	first := activeSessions(s, seedUser)
	if len(first) != 1 {
		t.Fatalf("want 1 session after first login, got %d", len(first))
	}
	if code, _ := postLogin(t, srv.URL, seedUser, seedPass); code != http.StatusOK {
		t.Fatalf("second login = %d, want 200", code)
	}
	after := activeSessions(s, seedUser)
	if len(after) != 1 {
		t.Fatalf("concurrent_login=deny must leave exactly 1 live session, got %d", len(after))
	}
	if after[0].ID == first[0].ID {
		t.Error("the surviving session should be the NEW one, not the stale one")
	}
}

// allow (the default) must not revoke anything — the inverse of the above, so a
// too-eager implementation cannot pass by revoking unconditionally.
func TestConcurrentLoginAllowKeepsBothSessions(t *testing.T) {
	srv, s := newTestServerState(t)
	for i := 0; i < 2; i++ {
		if code, _ := postLogin(t, srv.URL, seedUser, seedPass); code != http.StatusOK {
			t.Fatalf("login %d = %d, want 200", i, code)
		}
	}
	if n := len(activeSessions(s, seedUser)); n != 2 {
		t.Fatalf("concurrent_login=allow must keep both sessions, got %d", n)
	}
}
