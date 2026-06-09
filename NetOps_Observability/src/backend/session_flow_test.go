package main

import (
	"encoding/json"
	"testing"
	"time"
)

// backdate mutates a session's timestamps to simulate the passage of time
// (white-box: same package). Server time only — no client clock involved.
func backdate(s *server, sid string, lastActivity, created time.Time) {
	s.sessions.mu.Lock()
	defer s.sessions.mu.Unlock()
	x := s.sessions.byID[sid]
	if !lastActivity.IsZero() {
		x.LastActivityAt = lastActivity
	}
	if !created.IsZero() {
		x.CreatedAt = created
	}
	s.sessions.byID[sid] = x
}

// Idle + absolute are enforced at the refresh boundary, with machine-readable codes.
func TestSessionIdleAndAbsoluteAtRefresh(t *testing.T) {
	srv, s := newTestServerState(t)

	// Idle: a session whose last activity is older than the idle window (default
	// 30m) is rejected on refresh with SESSION_IDLE_TIMEOUT.
	a := login(t, srv, "admin", "password123")
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
	b2 := login(t, srv, "admin", "password123")
	sess2 := s.sessions.ListForUser("admin")
	var newID string
	for _, x := range sess2 {
		if x.Status == sessionActive {
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
	a := login(t, srv, "admin", "password123")
	st, b := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": a.RefreshToken})
	if st != 200 {
		t.Fatalf("happy refresh: status %d: %s", st, b)
	}
	// last_activity advanced.
	for _, x := range s.sessions.ListForUser("admin") {
		if x.Status == sessionActive && time.Since(x.LastActivityAt) > time.Minute {
			t.Errorf("refresh did not touch last_activity")
		}
	}
}

// Changing the password revokes ALL of the user's sessions (enterprise-safe).
func TestSessionRevokeAllOnPasswordChange(t *testing.T) {
	srv, s := newTestServerState(t)
	a := login(t, srv, "admin", "password123")
	if n := countActive(s, "admin"); n < 1 {
		t.Fatalf("expected an active session, got %d", n)
	}
	if st, body := do(t, srv, "POST", "/api/auth/change-password", "",
		map[string]string{"username": "admin", "current_password": "password123", "new_password": "NewPassw0rd!9"}); st != 200 {
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
	for i := 0; i < maxSessionsPerUser+2; i++ {
		login(t, srv, "admin", "password123")
	}
	if n := countActive(s, "admin"); n != maxSessionsPerUser {
		t.Errorf("active sessions = %d, want %d (cap)", n, maxSessionsPerUser)
	}
}

// Admin can list live sessions and revoke one — and the revocation is INSTANT
// (the victim's existing access token is rejected on its next request).
func TestSessionAdminListAndRevoke(t *testing.T) {
	srv, _ := newTestServerState(t)
	admin := login(t, srv, "admin", "password123")
	if st, _ := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "victim2", "password": "victim2-pass-1", "role": "read-only"}); st != 201 {
		t.Fatal("create user")
	}
	victim := login(t, srv, "victim2", "victim2-pass-1")
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
		if x.Status == sessionActive {
			n++
		}
	}
	return n
}

// Direct unit tests of the session store (no HTTP).
func TestSessionStoreUnit(t *testing.T) {
	ss, err := newSessionStore(t.TempDir() + "/s.json")
	if err != nil {
		t.Fatal(err)
	}
	sess, ev, err := ss.Create("u", "1.2.3.4", "agent", 30*time.Minute, 12*time.Hour)
	if err != nil || len(ev) != 0 {
		t.Fatalf("create: %v evicted=%v", err, ev)
	}
	if _, err := ss.Validate(sess.ID, true, true); err != nil {
		t.Fatalf("fresh session should validate: %v", err)
	}
	// Idle.
	ss.byID[sess.ID] = withTimes(ss.byID[sess.ID], time.Now().Add(-31*time.Minute), time.Time{})
	if _, err := ss.Validate(sess.ID, true, true); err != errSessionIdle {
		t.Errorf("idle validate: %v, want errSessionIdle", err)
	}
	// Absolute (new session; backdate creation).
	s2, _, _ := ss.Create("u2", "", "", 30*time.Minute, 12*time.Hour)
	ss.byID[s2.ID] = withTimes(ss.byID[s2.ID], time.Now(), time.Now().Add(-13*time.Hour))
	if _, err := ss.Validate(s2.ID, true, true); err != errSessionAbsolute {
		t.Errorf("absolute validate: %v, want errSessionAbsolute", err)
	}
	// Revoke.
	s3, _, _ := ss.Create("u3", "", "", time.Minute, time.Hour)
	ss.Revoke(s3.ID)
	if _, err := ss.Validate(s3.ID, true, true); err != errSessionRevoked {
		t.Errorf("revoked validate: %v, want errSessionRevoked", err)
	}
	// RevokeAllForUser.
	ss.Create("multi", "", "", time.Minute, time.Hour)
	ss.Create("multi", "", "", time.Minute, time.Hour)
	if n := ss.RevokeAllForUser("multi"); n != 2 {
		t.Errorf("RevokeAllForUser = %d, want 2", n)
	}
	// Cap eviction.
	for i := 0; i < maxSessionsPerUser+1; i++ {
		ss.Create("capped", "", "", time.Minute, time.Hour)
	}
	active := 0
	for _, x := range ss.ListForUser("capped") {
		if x.Status == sessionActive {
			active++
		}
	}
	if active != maxSessionsPerUser {
		t.Errorf("capped active = %d, want %d", active, maxSessionsPerUser)
	}
}

func withTimes(x Session, lastActivity, created time.Time) Session {
	if !lastActivity.IsZero() {
		x.LastActivityAt = lastActivity
	}
	if !created.IsZero() {
		x.CreatedAt = created
	}
	return x
}
