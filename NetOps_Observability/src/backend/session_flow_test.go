package backend

import (
	"encoding/json"
	"netops/backend/internal/session"
	"testing"
	"time"

	"netops/backend/policy"
)

// A per-ROLE override (via the #24 policy engine) tightens idle for that role,
// while other roles keep the per-scope default — and it can only harden (shorter).
func TestSessionPolicyPerRole(t *testing.T) {
	dir := t.TempDir()
	ss, err := newSecuritySettingsStore(dir + "/sec.json")
	if err != nil {
		t.Fatal(err)
	}
	sp := policy.NewSecurityStore(dir+"/policy.json", platformKV{}, logError)
	// Role overrides are scoped within an owning tenant (per the policy model).
	if _, err := sp.SetOverride(policy.ScopeRole, "operator", "acme", "session.idle_timeout",
		policy.Override{Value: policy.Value{Kind: policy.KindDuration, Num: 600}}, "test"); err != nil {
		t.Fatalf("set role override: %v", err)
	}
	s := &server{securitySettings: ss, secPolicy: sp}
	if idle, _, _, _ := s.sessionPolicy("acme", "operator"); idle != 10*time.Minute {
		t.Errorf("operator idle = %v, want 10m (per-role override)", idle)
	}
	if idle, _, _, _ := s.sessionPolicy("acme", "read-only"); idle != 30*time.Minute {
		t.Errorf("read-only idle = %v, want 30m (scope default)", idle)
	}
}

// backdate mutates a session's timestamps to simulate the passage of time.
// Server time only — no client clock involved.
func backdate(s *server, sid string, lastActivity, created time.Time) {
	s.sessions.RewindForTest(sid, lastActivity, created)
}

// Idle + absolute are enforced at the refresh boundary, with machine-readable codes.
func TestSessionIdleAndAbsoluteAtRefresh(t *testing.T) {
	srv, s := newTestServerState(t)

	// Idle: a session whose last activity is older than the idle window (default
	// 30m) is rejected on refresh with SESSION_IDLE_TIMEOUT.
	a := login(t, srv, "admin", "Passw0rd!2345")
	sess := s.sessions.ListForUser("admin")
	if len(sess) == 0 {
		t.Fatal("no session created on login")
	}
	backdate(s, sess[0].ID, time.Now().Add(-31*time.Minute), time.Time{})
	st, b := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": a.RefreshToken})
	if st != 401 {
		t.Fatalf("idle refresh: status %d, want 401", st)
	}
	var resp map[string]string
	json.Unmarshal(b, &resp)
	if resp["code"] != "SESSION_IDLE_TIMEOUT" {
		t.Errorf("idle refresh code = %q, want SESSION_IDLE_TIMEOUT", resp["code"])
	}

	// Absolute: a fresh session older than the absolute cap (default 12h) is
	// rejected with SESSION_ABSOLUTE_TIMEOUT even if just active.
	b2 := login(t, srv, "admin", "Passw0rd!2345")
	sess2 := s.sessions.ListForUser("admin")
	var newID string
	for _, x := range sess2 {
		if x.Status == session.StatusActive {
			newID = x.ID
			break
		}
	}
	if newID == "" {
		t.Fatal("no active session after second login")
	}
	backdate(s, newID, time.Now(), time.Now().Add(-13*time.Hour))
	st, body := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": b2.RefreshToken})
	if st != 401 {
		t.Fatalf("absolute refresh: status %d, want 401", st)
	}
	var resp2 map[string]string
	json.Unmarshal(body, &resp2)
	if resp2["code"] != "SESSION_ABSOLUTE_TIMEOUT" {
		t.Errorf("absolute refresh code = %q, want SESSION_ABSOLUTE_TIMEOUT", resp2["code"])
	}
}

// A within-window session refreshes normally and carries a session id.
func TestSessionHappyRefresh(t *testing.T) {
	srv, s := newTestServerState(t)
	a := login(t, srv, "admin", "Passw0rd!2345")
	st, b := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": a.RefreshToken})
	if st != 200 {
		t.Fatalf("happy refresh: status %d: %s", st, b)
	}
	// last_activity advanced.
	for _, x := range s.sessions.ListForUser("admin") {
		if x.Status == session.StatusActive && time.Since(x.LastActivityAt) > time.Minute {
			t.Errorf("refresh did not touch last_activity")
		}
	}
}

// Changing the password revokes ALL of the user's sessions (enterprise-safe).
func TestSessionRevokeAllOnPasswordChange(t *testing.T) {
	srv, s := newTestServerState(t)
	a := login(t, srv, "admin", "Passw0rd!2345")
	if n := countActive(s, "admin"); n < 1 {
		t.Fatalf("expected an active session, got %d", n)
	}
	if st, body := do(t, srv, "POST", "/api/auth/change-password", "",
		map[string]string{"username": "admin", "current_password": "Passw0rd!2345", "new_password": "NewPassw0rd!9"}); st != 200 {
		t.Fatalf("change-password: %d: %s", st, body)
	}
	if n := countActive(s, "admin"); n != 0 {
		t.Errorf("after password change, active sessions = %d, want 0", n)
	}
	// The old session's refresh token is now dead.
	if st, _ := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": a.RefreshToken}); st != 401 {
		t.Errorf("refresh after password change: status %d, want 401", st)
	}
}

// Concurrent sessions are capped per user; the oldest is evicted past the cap.
func TestSessionMaxConcurrent(t *testing.T) {
	srv, s := newTestServerState(t)
	for i := 0; i < session.MaxSessionsPerUser+2; i++ {
		login(t, srv, "admin", "Passw0rd!2345")
	}
	if n := countActive(s, "admin"); n != session.MaxSessionsPerUser {
		t.Errorf("active sessions = %d, want %d (cap)", n, session.MaxSessionsPerUser)
	}
}

// Admin can list live sessions and revoke one — and the revocation is INSTANT
// (the victim's existing access token is rejected on its next request).
func TestSessionAdminListAndRevoke(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, _ := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "victim2", "password": "Victim2-Pass!1", "role": "read-only"}); st != 201 {
		t.Fatal("create user")
	}
	victim := login(t, srv, "victim2", "Victim2-Pass!1")
	if st, _ := do(t, srv, "GET", "/api/auth/me", victim.Token, nil); st != 200 {
		t.Fatal("victim token should work before revoke")
	}
	// Admin lists the victim's sessions.
	st, b := do(t, srv, "GET", "/api/sessions?user=victim2", admin.Token, nil)
	if st != 200 {
		t.Fatalf("list sessions: %d", st)
	}
	var list []map[string]any
	json.Unmarshal(b, &list)
	if len(list) == 0 {
		t.Fatal("expected a session for victim2")
	}
	sid, _ := list[0]["id"].(string)
	// Admin revokes it.
	if st, _ := do(t, srv, "DELETE", "/api/sessions/"+sid, admin.Token, nil); st != 204 {
		t.Fatalf("revoke session: %d", st)
	}
	// Victim's existing access token is now instantly rejected.
	if st, _ := do(t, srv, "GET", "/api/auth/me", victim.Token, nil); st != 401 {
		t.Errorf("revoked session token: status %d, want 401 (instant)", st)
	}
}

func countActive(s *server, user string) int {
	n := 0
	for _, x := range s.sessions.ListForUser(user) {
		if x.Status == session.StatusActive {
			n++
		}
	}
	return n
}

// The store's direct lifecycle unit tests moved to internal/session with the
// store (TestSessionStoreUnit); the HTTP-boundary assertions above stay here.
