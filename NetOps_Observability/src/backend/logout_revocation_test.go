package main

// logout_revocation_test.go — F-70.
//
// The audit proved three things live, all of which returned {"status":"ok"}:
//   - malformed JSON            -> 200 ok
//   - a field typo (refreshToken vs refresh_token) -> 200 ok
//   - and afterwards THE TOKEN STILL MINTED A NEW ACCESS TOKEN
//
// Plus a fourth that only shows up after a restart: the revoke's persist error
// was discarded, so a logout could succeed in memory, be recorded in the audit
// ledger as SESSION_REVOKED, and be undone by the next process start. That last
// one is why these tests inject a persist failure rather than only checking
// status codes — a green "revoked" assertion against an in-memory map is
// exactly the test that stayed green through the whole defect.

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func postJSON(t *testing.T, url, body string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

// loginFor returns a fresh (access, refresh) pair.
func loginFor(t *testing.T, base string) (string, string) {
	t.Helper()
	code, out := postLogin(t, base, seedUser, seedPass)
	if code != http.StatusOK {
		t.Fatalf("login = %d, want 200", code)
	}
	tok, _ := out["token"].(string)
	rt, _ := out["refresh_token"].(string)
	if tok == "" || rt == "" {
		t.Fatalf("login did not return a token pair: %v", out)
	}
	return tok, rt
}

// The headline defect: logout says ok, the token still works.
func TestLogoutActuallyRevokesTheRefreshToken(t *testing.T) {
	srv, _ := newTestServerState(t)
	_, rt := loginFor(t, srv.URL)

	code, out := postJSON(t, srv.URL+"/api/auth/logout", `{"refresh_token":"`+rt+`"}`)
	if code != http.StatusOK {
		t.Fatalf("logout = %d, want 200", code)
	}
	if out["revoked"] != true {
		t.Fatalf("logout must report revoked:true for a live token, got %v", out)
	}
	// The proof the audit ran by hand: the token must no longer mint anything.
	rcode, rout := postJSON(t, srv.URL+"/api/auth/refresh", `{"refresh_token":"`+rt+`"}`)
	if rcode == http.StatusOK {
		t.Fatalf("REVOCATION FAILED: a logged-out refresh token still minted a session: %v", rout)
	}
}

// A field typo decoded into an empty struct and revoked nothing, silently.
func TestLogoutRejectsAnUnknownFieldInsteadOfSilentlyRevokingNothing(t *testing.T) {
	srv, _ := newTestServerState(t)
	_, rt := loginFor(t, srv.URL)

	code, _ := postJSON(t, srv.URL+"/api/auth/logout", `{"refreshToken":"`+rt+`"}`)
	if code == http.StatusOK {
		t.Fatal("a typo'd field must not report a successful logout")
	}
	if code != http.StatusBadRequest {
		t.Errorf("logout with an unknown field = %d, want 400", code)
	}
	// And the token must still be live — we refused the request, so we must not
	// have half-performed it.
	if rcode, _ := postJSON(t, srv.URL+"/api/auth/refresh", `{"refresh_token":"`+rt+`"}`); rcode != http.StatusOK {
		t.Errorf("a REFUSED logout must not revoke anything; refresh = %d, want 200", rcode)
	}
}

func TestLogoutRejectsMalformedJSON(t *testing.T) {
	srv, _ := newTestServerState(t)
	if code, _ := postJSON(t, srv.URL+"/api/auth/logout", `{"refresh_token":`); code != http.StatusBadRequest {
		t.Errorf("malformed JSON = %d, want 400", code)
	}
}

// An empty body stays tolerated — a browser with no stored token must still be
// able to clear its cookie. This is the case that must NOT become a 400.
func TestLogoutWithNoBodyStillSucceeds(t *testing.T) {
	srv, _ := newTestServerState(t)
	code, out := postJSON(t, srv.URL+"/api/auth/logout", ``)
	if code != http.StatusOK {
		t.Fatalf("empty-body logout = %d, want 200", code)
	}
	if out["revoked"] != false {
		t.Errorf("nothing was revoked, so revoked must be false, got %v", out)
	}
}

// An unknown-but-well-formed token is an idempotent no-op: 200, revoked:false.
// It must not 500, and it must not claim it revoked something.
func TestLogoutWithAnUnknownTokenIsHonestlyIdempotent(t *testing.T) {
	srv, _ := newTestServerState(t)
	code, out := postJSON(t, srv.URL+"/api/auth/logout", `{"refresh_token":"nope.notarealtoken"}`)
	if code != http.StatusOK {
		t.Fatalf("unknown token logout = %d, want 200 (idempotent)", code)
	}
	if out["revoked"] != false {
		t.Errorf("an unknown token revoked nothing; want revoked:false, got %v", out)
	}
}

// ---- fault injection at the persist seam -----------------------------------

// breakPersistence swaps a store's injected backend for one that refuses every
// write, so the next flush fails the way a full or read-only disk would.
func breakSessionPersistence(s *server) {
	s.sessions.SetKVForTest(&faultyKV{failWith: errors.New("kv unavailable: injected")})
}
func breakRefreshPersistence(s *server) {
	s.refresh.SetKVForTest(&faultyKV{failWith: errors.New("kv unavailable: injected")})
}

// The restart-shaped defect: in-memory revoke succeeds, disk write fails, and
// the old code returned {"status":"ok"} anyway.
func TestLogoutReportsAFailedPersistInsteadOfClaimingSuccess(t *testing.T) {
	srv, s := newTestServerState(t)
	_, rt := loginFor(t, srv.URL)
	breakSessionPersistence(s)
	breakRefreshPersistence(s)

	code, out := postJSON(t, srv.URL+"/api/auth/logout", `{"refresh_token":"`+rt+`"}`)
	if code == http.StatusOK {
		t.Fatalf("a logout that did not persist must not report success, got %d %v", code, out)
	}
	if code != http.StatusInternalServerError {
		t.Errorf("failed-persist logout = %d, want 500", code)
	}
}

func TestSessionRevokeSurfacesAPersistFailure(t *testing.T) {
	_, s := newTestServerState(t)
	sess, _, err := s.sessions.Create("alice", "127.0.0.1", "test-agent", 0, 0)
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	breakSessionPersistence(s)

	revoked, err := s.sessions.Revoke(sess.ID)
	if !revoked {
		t.Error("the session was active, so Revoke must report it killed it")
	}
	if err == nil {
		t.Fatal("Revoke must return the persist failure, not swallow it")
	}
}

func TestRevokeAllForUserSurfacesAPersistFailure(t *testing.T) {
	_, s := newTestServerState(t)
	for i := 0; i < 2; i++ {
		if _, _, err := s.sessions.Create("bob", "127.0.0.1", "test-agent", 0, 0); err != nil {
			t.Fatalf("create session: %v", err)
		}
	}
	breakSessionPersistence(s)

	n, err := s.sessions.RevokeAllForUser("bob")
	if n != 2 {
		t.Errorf("RevokeAllForUser = %d, want 2", n)
	}
	if err == nil {
		t.Fatal("a failed persist must be returned — auth.go promises these sessions cannot survive a restart")
	}
}

func TestRefreshRevokeDistinguishesUnknownFromFailed(t *testing.T) {
	_, s := newTestServerState(t)
	// Unknown token: not an error, and not a revocation.
	revoked, err := s.refresh.Revoke("bogus.token")
	if revoked || err != nil {
		t.Errorf("unknown token = (%v, %v), want (false, nil)", revoked, err)
	}
	// Real token, broken disk: revoked in memory, error surfaced.
	rt, err := s.refresh.Issue("carol")
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	breakRefreshPersistence(s)
	revoked, err = s.refresh.Revoke(rt)
	if !revoked {
		t.Error("a live token must report revoked:true")
	}
	if err == nil {
		t.Fatal("a failed persist must be returned")
	}
}

// The admin "kill session" button wrote a SESSION_REVOKED compliance record
// even when the kill did not stick. It must fail loudly instead.
func TestAdminSessionKillDoesNotReport204OnAFailedPersist(t *testing.T) {
	srv, s := newTestServerState(t)
	tok, _ := loginFor(t, srv.URL)
	sessions := s.sessions.ListForUser(seedUser)
	if len(sessions) == 0 {
		t.Fatal("expected a session after login")
	}
	breakSessionPersistence(s)

	req, err := http.NewRequest(http.MethodDelete, srv.URL+"/api/sessions/"+sessions[0].ID, nil)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("delete: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("admin kill returned 204 for a revoke that never persisted — a false compliance artifact")
	}
}

// postJSONAuth is postJSON with a bearer token.
func postJSONAuth(t *testing.T, url, token, body string) (int, map[string]any) {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}
