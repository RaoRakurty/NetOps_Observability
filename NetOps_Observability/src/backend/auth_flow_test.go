package main

// auth_flow_test.go — end-to-end HTTP tests for the whole authentication
// section, exercised through the real router + auth middleware (httptest):
// login, /me, refresh rotation + reuse, logout, change-password, RBAC gating,
// API-key auth, and admin-safe rules.

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	us, err := newUserStore(dir + "/users.json")
	must(err)
	rs, err := newRoleStore(dir + "/roles.json")
	must(err)
	ts, err := newTenantStore(dir + "/tenants.json")
	must(err)
	ks, err := newAPIKeyStore(dir + "/apikeys.json")
	must(err)
	rf, err := newRefreshStore(dir+"/refresh.json", time.Hour)
	must(err)
	sv, err := newSavedStore(dir + "/saved.json")
	must(err)
	sc, err := newSNMPCredStore(dir + "/snmp.json", nil)
	must(err)
	au, err := newAuditStore(dir + "/audit.json")
	must(err)
	sp, err := newSNMPProfileStore(dir + "/snmp_profiles.json")
	must(err)
	s := &server{
		users: us, roles: rs, tenants: ts, apiKeys: ks, refresh: rf,
		saved: sv, snmpCreds: sc, snmpProfiles: sp, discovery: NewDiscoveryAggregator(),
		audit: au, startedAt: time.Now().UTC(),
	}
	must(us.SeedAdmin("admin", "password123"))
	mux := http.NewServeMux()
	s.routes(mux)
	srv := httptest.NewServer(s.withAuth(s.withAudit(mux)))
	t.Cleanup(srv.Close)
	return srv
}

func do(t *testing.T, srv *httptest.Server, method, path, token string, body any) (int, []byte) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, srv.URL+path, r)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

func login(t *testing.T, srv *httptest.Server, user, pass string) loginResponse {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": user, "password": pass})
	if st != 200 {
		t.Fatalf("login %s: status %d: %s", user, st, b)
	}
	var lr loginResponse
	if err := json.Unmarshal(b, &lr); err != nil {
		t.Fatal(err)
	}
	if lr.Token == "" || lr.RefreshToken == "" || lr.ExpiresIn <= 0 {
		t.Fatalf("login response missing fields: %+v", lr)
	}
	return lr
}

func TestLoginBadCredentials(t *testing.T) {
	srv := newTestServer(t)
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "wrong"}); st != 401 {
		t.Errorf("bad password: status %d, want 401", st)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "ghost", "password": "x"}); st != 401 {
		t.Errorf("unknown user: status %d, want 401", st)
	}
}

func TestMeAndUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	if st, _ := do(t, srv, "GET", "/api/users", "", nil); st != 401 {
		t.Errorf("no token to /api/users: status %d, want 401", st)
	}
	lr := login(t, srv, "admin", "password123")
	st, b := do(t, srv, "GET", "/api/auth/me", lr.Token, nil)
	if st != 200 {
		t.Fatalf("/me: status %d: %s", st, b)
	}
	var u publicUser
	json.Unmarshal(b, &u)
	if u.Username != "admin" || u.Role != "admin" {
		t.Errorf("/me unexpected: %+v", u)
	}
	// Admin permissions resolve to admin on every module.
	st, b = do(t, srv, "GET", "/api/auth/permissions", lr.Token, nil)
	if st != 200 {
		t.Fatalf("/permissions: %d", st)
	}
	var pr struct {
		Permissions map[string]int `json:"permissions"`
	}
	json.Unmarshal(b, &pr)
	if pr.Permissions["administration"] != LevelAdmin {
		t.Errorf("admin should have administration:admin, got %+v", pr.Permissions)
	}
}

func TestRefreshRotationAndReuseHTTP(t *testing.T) {
	srv := newTestServer(t)
	lr := login(t, srv, "admin", "password123")

	// Trade the refresh token for a fresh pair.
	st, b := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": lr.RefreshToken})
	if st != 200 {
		t.Fatalf("refresh: %d: %s", st, b)
	}
	var lr2 loginResponse
	json.Unmarshal(b, &lr2)
	if lr2.Token == "" || lr2.RefreshToken == lr.RefreshToken {
		t.Fatal("refresh did not rotate the token")
	}
	// New access token works.
	if st, _ := do(t, srv, "GET", "/api/auth/me", lr2.Token, nil); st != 200 {
		t.Errorf("new access token rejected: %d", st)
	}
	// Reusing the OLD refresh token fails (reuse detection).
	if st, _ := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": lr.RefreshToken}); st != 401 {
		t.Errorf("reused refresh token: status %d, want 401", st)
	}
	// ...which also kills the rotated token's family.
	if st, _ := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": lr2.RefreshToken}); st != 401 {
		t.Errorf("family should be revoked after reuse: status %d, want 401", st)
	}
}

func TestLogoutRevokesRefresh(t *testing.T) {
	srv := newTestServer(t)
	lr := login(t, srv, "admin", "password123")
	if st, _ := do(t, srv, "POST", "/api/auth/logout", "", map[string]string{"refresh_token": lr.RefreshToken}); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": lr.RefreshToken}); st != 401 {
		t.Errorf("refresh after logout: status %d, want 401", st)
	}
}

func TestChangePasswordHTTP(t *testing.T) {
	srv := newTestServer(t)
	lr := login(t, srv, "admin", "password123")
	st, b := do(t, srv, "POST", "/api/auth/change-password", lr.Token,
		map[string]string{"current_password": "password123", "new_password": "newpassword456"})
	if st != 200 {
		t.Fatalf("change-password: %d: %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "password123"}); st != 401 {
		t.Errorf("old password still works: %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "newpassword456"}); st != 200 {
		t.Errorf("new password rejected: %d", st)
	}
}

func TestRBACGating(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "password123")

	// Admin creates an operator.
	st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "op", "password": "operatorpass", "role": "operator",
	})
	if st != 201 {
		t.Fatalf("create operator: %d: %s", st, b)
	}
	op := login(t, srv, "op", "operatorpass")

	// Operator is NOT an administrator: identity endpoints are forbidden.
	if st, _ := do(t, srv, "GET", "/api/users", op.Token, nil); st != 403 {
		t.Errorf("operator GET /api/users: status %d, want 403", st)
	}
	if st, _ := do(t, srv, "POST", "/api/tenants", op.Token, map[string]string{"name": "x"}); st != 403 {
		t.Errorf("operator POST /api/tenants: status %d, want 403", st)
	}
	// But the admin can.
	if st, _ := do(t, srv, "GET", "/api/users", admin.Token, nil); st != 200 {
		t.Errorf("admin GET /api/users: %d", st)
	}
	// Operator's effective permissions match the built-in role.
	_, b = do(t, srv, "GET", "/api/auth/permissions", op.Token, nil)
	var pr struct {
		Permissions map[string]int `json:"permissions"`
	}
	json.Unmarshal(b, &pr)
	if pr.Permissions["alerts"] != LevelWrite || pr.Permissions["administration"] != LevelNone {
		t.Errorf("operator perms wrong: %+v", pr.Permissions)
	}
}

func TestAPIKeyAuth(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "password123")

	st, b := do(t, srv, "POST", "/api/apikeys", admin.Token, map[string]any{
		"label": "ci", "scopes": []string{"read:metrics"},
	})
	if st != 201 {
		t.Fatalf("create key: %d: %s", st, b)
	}
	var created struct {
		Secret string `json:"secret"`
	}
	json.Unmarshal(b, &created)
	if created.Secret == "" {
		t.Fatal("no secret returned")
	}
	// The key authenticates (read-only actor) on a GET.
	if st, _ := do(t, srv, "GET", "/api/auth/permissions", created.Secret, nil); st != 200 {
		t.Errorf("api key GET: status %d, want 200", st)
	}
	// ...but is read-only, so admin actions are forbidden.
	if st, _ := do(t, srv, "POST", "/api/users", created.Secret, map[string]string{"username": "x", "password": "yyyyyyyy"}); st != 403 {
		t.Errorf("api key POST /api/users: status %d, want 403", st)
	}
	// A bogus key is rejected.
	if st, _ := do(t, srv, "GET", "/api/auth/permissions", "ntk_deadbeef", nil); st != 401 {
		t.Errorf("bogus api key: status %d, want 401", st)
	}
}

func TestAdminSafeLastSuperAdmin(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "password123")
	if st, _ := do(t, srv, "DELETE", "/api/users/admin", admin.Token, nil); st != 400 {
		t.Errorf("delete last super-admin: status %d, want 400", st)
	}
}
