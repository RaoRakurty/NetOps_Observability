// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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
	"netops/backend/internal/apikey"
	"netops/backend/internal/dataprotect"
	"netops/backend/internal/discovery"
	"netops/backend/internal/licence"
	"netops/backend/internal/loginguard"
	"netops/backend/internal/metering"
	"netops/backend/internal/session"
	"netops/backend/internal/snmpcred"
	"netops/backend/internal/users"
	"netops/backend/internal/wsticket"
	"netops/backend/wireless"
	"testing"
	"time"
)

func newTestServer(t *testing.T) *httptest.Server {
	srv, _ := newTestServerState(t)
	return srv
}

// newTestServerState is newTestServer but also returns the underlying *server so
// session/lifecycle tests can inspect and backdate state.
func newTestServerState(t *testing.T) (*httptest.Server, *server) {
	t.Helper()
	dir := t.TempDir()
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	us, err := users.NewFileStore(dir+"/users.json", userDeps())
	must(err)
	rs, err := newRoleStore(dir + "/roles.json")
	must(err)
	ts, err := newTenantStore(dir + "/tenants.json")
	must(err)
	os, err := newOrgStore(dir + "/orgs.json")
	must(err)
	bs, err := newBindingStore(dir + "/role_bindings.json")
	must(err)
	ks, err := apikey.NewStore(dir+"/apikeys.json", apikey.DefaultRateLimit, TenantGlobal, platformKV{})
	must(err)
	rf, err := session.NewRefreshStore(dir+"/refresh.json", time.Hour, platformKV{})
	must(err)
	sv, err := newSavedStore(dir + "/saved.json")
	must(err)
	sc, err := snmpcred.NewStore(dir+"/snmp.json", nil, platformKV{})
	must(err)
	au, err := newAuditStore(dir + "/audit.json")
	must(err)
	sp, err := newSNMPProfileStore(dir + "/snmp_profiles.json")
	must(err)
	ss, err := newSecuritySettingsStore(dir + "/security_settings.json")
	must(err)
	sessStore, err := session.NewStore(dir+"/sessions.json", platformKV{}, func(string, string, map[string]any) {})
	must(err)
	s := &server{
		users: us, roles: rs, tenants: ts, orgs: os, bindings: bs, apiKeys: ks, refresh: rf,
		saved: sv, snmpCreds: sc, snmpProfiles: sp, discovery: discovery.NewDiscoveryAggregator(),
		securitySettings: ss, loginThrottle: loginguard.NewThrottle(func(msg string, fields map[string]any) { logWarn("auth", msg, fields) }), sessions: sessStore,
		audit: au, startedAt: time.Now().UTC(),
		wireless:        wireless.NewMemStore(),   // #128: always set, like the runtime wiring
		wirelessActions: newWirelessActionStore(), // #128 Phase 8: dormant unless FEATURE_WIRELESS_ACTIONS
		wsTickets:       wsticket.NewStore(),      // one-time WebSocket tickets (device SSH)
	}
	// LICENCE-BEGIN — the harness is LICENCE-NEUTRAL: every ceiling unlimited,
	// every feature granted, so every existing test behaves exactly as it did
	// before the licence mechanism existed.
	//
	// This is deliberate and it is not a gap. The gates sit on real admission
	// paths (device create, tenant create, watchlist add) and this corpus builds
	// fleets and multi-org fixtures through those same handlers — an isolation
	// test asserting that tenant A cannot see tenant B's rows must assert that
	// at full strength, not fail because its fixture needed a second tenant. The
	// gates are proved separately, against real signed documents, in
	// licence_routes_test.go; internal/licence and internal/entitlement prove the
	// mechanism and the semantics.
	s.entitlements = licence.NewUnlimitedService()
	// LICENCE-END
	must(us.SeedAdmin("admin", "Passw0rd!2345"))
	s.backfillBindings() // PBAC Phase A: mirror seeded users into role_bindings
	// DATA-PROTECTION: the routes are registered off s.dataProtect, so the
	// harness must build it exactly like newServer does. The three file paths
	// are pointed INSIDE the test's temp dir unless the caller already set them
	// (backupTestServer does, and TestOperationHistorySurvivesARestart needs a
	// second server to see the SAME ops file), so no test can touch /data.
	if envOr("SYSTEM_BACKUP_FILE", "") == "" {
		t.Setenv("SYSTEM_BACKUP_FILE", dir+"/system_backup.json")
	}
	if envOr("SNAPSHOT_OPS_FILE", "") == "" {
		t.Setenv("SNAPSHOT_OPS_FILE", dir+"/snapshot_operations.json")
	}
	if envOr("SNAPSHOT_VERIFY_FILE", "") == "" {
		t.Setenv("SNAPSHOT_VERIFY_FILE", dir+"/snapshot_verify.json")
	}
	backupCfg, err := dataprotect.NewFileConfigStore(envOr("SYSTEM_BACKUP_FILE", dir+"/system_backup.json"))
	must(err)
	s.dataProtect = dataprotect.New(s.dataProtectDeps(backupCfg))
	// METERING: the Usage routes are registered off s.meteringAPI, so the
	// harness must build it exactly like newServer does — a nil module would
	// answer 503 everywhere and the isolation guard would pass vacuously. The
	// store and the report key live INSIDE the test's temp dir, so no test can
	// touch /data, and no snapshot worker is started: the tests that need rows
	// record them explicitly.
	s.meteringStore = metering.NewFileStore(dir + "/metering.json")
	s.meteringKey = metering.NewReportKey(dir+"/licence-report-key.json", nil)
	s.meteringRecorder = metering.NewRecorder(s.meteringStore, s.meteringSample, nil)
	s.meteringAPI = metering.New(s.meteringDeps())
	mux := http.NewServeMux()
	s.routes(mux)
	srv := httptest.NewServer(s.withAuth(s.withAudit(mux)))
	t.Cleanup(srv.Close)
	return srv, s
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

// A disabled account must be refused at the password front door — not just on
// refresh/MFA/SSO. Regression for the gap where Lock/Unlock (status=disabled) did
// not actually block sign-in.
func TestLoginDisabledAccountRejected(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "lockme", "password": "Lockme-Pass!1", "role": "read-only",
	}); st != 201 {
		t.Fatalf("create user: status %d: %s", st, b)
	}
	// Active → can sign in.
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "lockme", "password": "Lockme-Pass!1"}); st != 200 {
		t.Fatalf("active user login: status %d, want 200", st)
	}
	// Disable, then the SAME credentials must be refused.
	if st, b := do(t, srv, "PATCH", "/api/users/lockme", admin.Token, map[string]string{"status": "disabled"}); st != 200 {
		t.Fatalf("disable user: status %d: %s", st, b)
	}
	if st, b := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "lockme", "password": "Lockme-Pass!1"}); st != 401 {
		t.Errorf("disabled user login: status %d, want 401 (%s)", st, b)
	}
	// Wrong password on a disabled account still returns the generic error (no
	// account-existence leak before the password is verified).
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "lockme", "password": "nope"}); st != 401 {
		t.Errorf("disabled user wrong pw: status %d, want 401", st)
	}
}

// Instant revocation: an already-issued access token must stop working the moment
// the account is disabled or deleted — not only when the token expires.
func TestInstantRevokeOnDisableAndDelete(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "ghosted", "password": "Ghosted-Pass!1", "role": "read-only"}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	victim := login(t, srv, "ghosted", "Ghosted-Pass!1")
	if st, _ := do(t, srv, "GET", "/api/auth/me", victim.Token, nil); st != 200 {
		t.Fatalf("active token /me: want 200")
	}
	// Disable → the SAME token is rejected on the very next request.
	if st, _ := do(t, srv, "PATCH", "/api/users/ghosted", admin.Token, map[string]string{"status": "disabled"}); st != 200 {
		t.Fatalf("disable: not 200")
	}
	if st, _ := do(t, srv, "GET", "/api/auth/me", victim.Token, nil); st != 401 {
		t.Errorf("disabled user's existing token: status %d, want 401 (instant revoke)", st)
	}
	// Re-enable + fresh token, then delete → existing token rejected immediately.
	do(t, srv, "PATCH", "/api/users/ghosted", admin.Token, map[string]string{"status": "active"})
	again := login(t, srv, "ghosted", "Ghosted-Pass!1")
	do(t, srv, "DELETE", "/api/users/ghosted", admin.Token, nil)
	if st, _ := do(t, srv, "GET", "/api/auth/me", again.Token, nil); st != 401 {
		t.Errorf("deleted user's existing token: status %d, want 401", st)
	}
}

// Account lockout: after login_attempts_allowed consecutive failures the account
// is locked, so even the correct password is refused until the window elapses.
func TestLoginLockout(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, _ := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "brute", "password": "Brute-Pass!1", "role": "read-only"}); st != 201 {
		t.Fatal("create user")
	}
	// Default policy allows 3 attempts; exhaust them with wrong passwords.
	for i := 0; i < 3; i++ {
		if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "brute", "password": "wrong"}); st != 401 {
			t.Fatalf("attempt %d: status %d, want 401", i, st)
		}
	}
	// Now even the correct password is refused (429 locked).
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "brute", "password": "Brute-Pass!1"}); st != 429 {
		t.Errorf("after lockout, correct password: status %d, want 429", st)
	}
}

// change-password must reject a new password identical to the current one.
func TestChangePasswordNoReuse(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, _ := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "reuser", "password": "Reuser-Pass-1", "role": "read-only"}); st != 201 {
		t.Fatal("create user")
	}
	// change-password is public; identify by username + current password.
	st, b := do(t, srv, "POST", "/api/auth/change-password", "", map[string]string{
		"username": "reuser", "current_password": "Reuser-Pass-1", "new_password": "Reuser-Pass-1"})
	if st != 400 {
		t.Errorf("reuse (new==current): status %d, want 400 (%s)", st, b)
	}
	// A genuinely new password still works.
	if st, _ := do(t, srv, "POST", "/api/auth/change-password", "", map[string]string{
		"username": "reuser", "current_password": "Reuser-Pass-1", "new_password": "Reuser-Pass-2-new"}); st != 200 {
		t.Errorf("legit change: status %d, want 200", st)
	}
}

// Admin-create enforces the scope's resolved password policy (R2) — same rules
// the user's own change-password enforces, so an admin can't seed a weak password.
func TestCreateUserEnforcesPasswordPolicy(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")
	// Long but single-class → violates the default complexity policy → rejected.
	if st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "weakcreate", "password": "alllowercaseletters", "role": "read-only"}); st != 400 {
		t.Errorf("weak admin-create: status %d, want 400 (%s)", st, b)
	}
	// A policy-compliant password is accepted.
	if st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "strongcreate", "password": "Compliant-1!", "role": "read-only"}); st != 201 {
		t.Errorf("compliant admin-create: status %d, want 201 (%s)", st, b)
	}
}

func TestMeAndUnauthenticated(t *testing.T) {
	srv := newTestServer(t)
	if st, _ := do(t, srv, "GET", "/api/users", "", nil); st != 401 {
		t.Errorf("no token to /api/users: status %d, want 401", st)
	}
	lr := login(t, srv, "admin", "Passw0rd!2345")
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
	lr := login(t, srv, "admin", "Passw0rd!2345")

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
	lr := login(t, srv, "admin", "Passw0rd!2345")
	if st, _ := do(t, srv, "POST", "/api/auth/logout", "", map[string]string{"refresh_token": lr.RefreshToken}); st != 200 {
		t.Fatalf("logout: %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/refresh", "", map[string]string{"refresh_token": lr.RefreshToken}); st != 401 {
		t.Errorf("refresh after logout: status %d, want 401", st)
	}
}

func TestChangePasswordHTTP(t *testing.T) {
	srv := newTestServer(t)
	// Self-service from the login window: unauthenticated, names the account and
	// proves ownership with the current password (no bearer token).
	st, b := do(t, srv, "POST", "/api/auth/change-password", "",
		map[string]string{"username": "admin", "current_password": "Passw0rd!2345", "new_password": "NewPassw0rd!9"})
	if st != 200 {
		t.Fatalf("change-password: %d: %s", st, b)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "Passw0rd!2345"}); st != 401 {
		t.Errorf("old password still works: %d", st)
	}
	if st, _ := do(t, srv, "POST", "/api/auth/login", "", map[string]string{"username": "admin", "password": "NewPassw0rd!9"}); st != 200 {
		t.Errorf("new password rejected: %d", st)
	}
	// Wrong current password is rejected with a generic credential error.
	if st, _ := do(t, srv, "POST", "/api/auth/change-password", "",
		map[string]string{"username": "admin", "current_password": "wrong", "new_password": "anotherpass789"}); st != 401 {
		t.Errorf("wrong current password accepted: %d", st)
	}
}

func TestRBACGating(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345")

	// Admin creates an operator.
	st, b := do(t, srv, "POST", "/api/users", admin.Token, map[string]string{
		"username": "op", "password": "Operator-Pass!1", "role": "operator",
	})
	if st != 201 {
		t.Fatalf("create operator: %d: %s", st, b)
	}
	op := login(t, srv, "op", "Operator-Pass!1")

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
	admin := login(t, srv, "admin", "Passw0rd!2345")

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
	admin := login(t, srv, "admin", "Passw0rd!2345")
	if st, _ := do(t, srv, "DELETE", "/api/users/admin", admin.Token, nil); st != 400 {
		t.Errorf("delete last super-admin: status %d, want 400", st)
	}
}

// TestWSQueryTokenAuthenticationRemoved is the WS-13 regression: the WebSocket
// hub route no longer accepts a session credential in the query string. The
// device-SSH gateway leaked a reusable JWT into the nginx access log exactly
// because ?token= was accepted for WS routes; that transport is gone. A valid
// token presented the OLD way (query) must be rejected; the same token in the
// Authorization header still authenticates (the REST path the SPA uses).
//
// The route literal is assembled from parts so this auth-focused test never
// lands the hub path in the tenant-isolation corpus scanned by
// route_isolation_coverage_test.go — WS-13 is about credential transport, not
// tenant isolation, and must not spuriously mark the route as isolation-covered.
func TestWSQueryTokenAuthenticationRemoved(t *testing.T) {
	srv := newTestServer(t)
	tok := login(t, srv, "admin", "Passw0rd!2345").Token
	hub := "/api/" + "events"

	// OLD way — token in the query — must NOT authenticate (401).
	req, _ := http.NewRequest("GET", srv.URL+hub+"?token="+tok, nil)
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("query-token WS auth: status %d, want 401 — that transport must be gone", resp.StatusCode)
	}

	// Header auth still gets PAST authentication (the hub then needs a WS
	// upgrade, so a correctly-authenticated request never fails at 401).
	if st, _ := do(t, srv, "GET", hub, tok, nil); st == http.StatusUnauthorized {
		t.Fatalf("Authorization-header request to the hub was rejected as unauthenticated (%d)", st)
	}
}
