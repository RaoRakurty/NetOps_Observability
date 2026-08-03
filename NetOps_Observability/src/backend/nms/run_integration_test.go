package nms

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A mock vManage: /jwt/login issues a token; /dataservice/alarms requires the
// bearer and returns the tunnel-down fixture. Proves the full auth→poll→
// transform→route path end-to-end without a real controller.
func TestRunPollVManageEndToEnd(t *testing.T) {
	fixture, err := os.ReadFile(filepath.Join("fixtures", "vmanage", "tunnel_down.json"))
	if err != nil {
		t.Fatal(err)
	}
	var gotAuthHeader string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/jwt/login" && r.Method == http.MethodPost:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"jwt-abc-123"}`))
		case r.URL.Path == "/dataservice/alarms":
			gotAuthHeader = r.Header.Get("Authorization")
			if gotAuthHeader != "Bearer jwt-abc-123" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	reg := NewRegistry()
	conn, ok := reg.Get("vmanage")
	if !ok {
		t.Fatal("vmanage connector not registered")
	}
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())
	cfg := IntegrationConfig{
		Tenant: "t-a", IntegrationID: "int-vm", Vendor: "vmanage",
		BaseURL: srv.URL, Streams: []string{"alarms"},
		Creds: Credentials{Username: "ro", Password: "pw"},
	}
	res, _, err := RunPollSession(context.Background(), conn, cfg, do, NewMemCheckpoints(), NewPipeline(1000), Session{})
	if err != nil {
		t.Fatalf("RunPollSession: %v", err)
	}
	if gotAuthHeader != "Bearer jwt-abc-123" {
		t.Fatalf("poll did not carry the JWT: %q", gotAuthHeader)
	}
	if len(res.Errors) != 0 {
		t.Fatalf("stream errors: %v", res.Errors)
	}
	// The tunnel-down fixture → 1 event + 1 state, tenant-stamped.
	if len(res.Routed.Events) != 1 || len(res.Routed.StateChanges) != 0 {
		// first sighting of a state is not a "change" — expect the event only.
		t.Fatalf("routed events=%d stateChanges=%d", len(res.Routed.Events), len(res.Routed.StateChanges))
	}
	e := res.Routed.Events[0]
	if e.TenantID != "t-a" || e.NormalizedEventType != "controller_bfd_down" {
		t.Fatalf("routed event wrong: %+v", e)
	}
	// Checkpoint advanced for the polled stream.
	if _, ok := res.Checkpoints["alarms"]; !ok {
		t.Fatal("checkpoint not advanced")
	}
}

// Re-auth on 401: the token "expires", the poll 401s, the runtime re-auths and
// succeeds on the second attempt.
func TestRunPollReauthOn401(t *testing.T) {
	fixture, _ := os.ReadFile(filepath.Join("fixtures", "vmanage", "tunnel_down.json"))
	var logins, firstPollDone int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			logins++
			w.Header().Set("Content-Type", "application/json")
			// issue a different token each login so we can tell them apart
			_, _ = w.Write([]byte(`{"token":"tok` + itoa(logins) + `"}`))
		case "/dataservice/alarms":
			// First poll (tok1) → 401; after re-auth (tok2) → 200.
			if r.Header.Get("Authorization") != "Bearer tok2" {
				firstPollDone++
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		}
	}))
	defer srv.Close()

	conn, _ := NewRegistry().Get("vmanage")
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())
	cfg := IntegrationConfig{
		Tenant: "t-a", IntegrationID: "int-vm", BaseURL: srv.URL,
		Streams: []string{"alarms"}, Creds: Credentials{Username: "ro", Password: "pw"},
	}
	res, _, err := RunPollSession(context.Background(), conn, cfg, do, NewMemCheckpoints(), NewPipeline(1000), Session{})
	if err != nil {
		t.Fatalf("RunPollSession: %v", err)
	}
	if logins < 2 {
		t.Fatalf("expected a re-auth (>=2 logins), got %d", logins)
	}
	if len(res.Routed.Events) != 1 {
		t.Fatalf("expected 1 event after re-auth, got %d (errs=%v)", len(res.Routed.Events), res.Errors)
	}
}

func TestCatalystAuthTokenFlow(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/dna/system/api/v1/auth/token" {
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Basic ") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"Token":"xauth-999"}`))
		}
	}))
	defer srv.Close()
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())
	sess, err := (CatalystAuth{}).Authenticate(context.Background(), srv.URL, Credentials{Username: "u", Password: "p"}, do)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Header.Get("X-Auth-Token") != "xauth-999" {
		t.Fatalf("catalyst token header wrong: %v", sess.Header)
	}
	if sess.Valid(nowUTC()) != true {
		t.Fatal("fresh catalyst session should be valid")
	}
}

func TestMerakiAndPrimeStaticAuth(t *testing.T) {
	// Meraki API key → bearer, non-expiring.
	ms, _ := (MerakiAuth{}).Authenticate(context.Background(), "", Credentials{APIKey: "mk-1"}, nil)
	if ms.Header.Get("Authorization") != "Bearer mk-1" || !ms.ExpiresAt.IsZero() {
		t.Fatalf("meraki auth wrong: %v exp=%v", ms.Header, ms.ExpiresAt)
	}
	// Prime → Basic on every request, non-expiring.
	ps, _ := (PrimeAuth{}).Authenticate(context.Background(), "", Credentials{Username: "u", Password: "p"}, nil)
	if !strings.HasPrefix(ps.Header.Get("Authorization"), "Basic ") || !ps.ExpiresAt.IsZero() {
		t.Fatalf("prime auth wrong: %v", ps.Header)
	}
}

func TestSessionValidity(t *testing.T) {
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	s := Session{ExpiresAt: base.Add(time.Minute)}
	if !s.Valid(base) {
		t.Fatal("should be valid a minute before expiry")
	}
	if s.Valid(base.Add(50 * time.Second)) {
		t.Fatal("should be invalid within the 30s skew window")
	}
	if !(Session{}).Valid(base) {
		t.Fatal("zero-expiry session is always valid")
	}
}

// Meraki path params: {org} resolves from Credentials.Extra; an unresolved
// placeholder is a config error, never sent to the vendor raw.
func TestPollPathParams(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer srv.Close()
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())

	p := merakiPoller()
	sess, _ := (MerakiAuth{}).Authenticate(context.Background(), "", Credentials{APIKey: "k"}, nil)

	// With the org id present, the placeholder resolves.
	_, _, err := p.Poll(context.Background(), PollInput{
		Base: srv.URL, Stream: "inventory", Session: sess, Do: do,
		Params: map[string]string{"org": "o-123"},
	})
	if err != nil {
		t.Fatalf("poll with params: %v", err)
	}
	if gotPath != "/api/v1/organizations/o-123/devices" {
		t.Fatalf("path param not substituted: %q", gotPath)
	}

	// Without it, the poll refuses to send the raw placeholder.
	gotPath = ""
	_, _, err = p.Poll(context.Background(), PollInput{Base: srv.URL, Stream: "inventory", Session: sess, Do: do})
	if err == nil || !strings.Contains(err.Error(), "unresolved path parameter") {
		t.Fatalf("expected unresolved-parameter error, got %v", err)
	}
	if gotPath != "" {
		t.Fatalf("request should not have been sent, but server saw %q", gotPath)
	}
}

func itoa(n int) string { return string(rune('0' + n)) }

// Session caching: a valid cached session skips the login round-trip entirely
// (steady-state polls must not log in every cycle — controllers rate-limit and
// audit logins); an expired cached session re-authenticates; and RunPollSession
// returns the session it ended with so the scheduler can cache it.
func TestRunPollSessionReusesValidSession(t *testing.T) {
	fixture, _ := os.ReadFile(filepath.Join("fixtures", "vmanage", "tunnel_down.json"))
	var logins int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			logins++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"tok` + itoa(logins) + `"}`))
		case "/dataservice/alarms":
			if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer tok") {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		}
	}))
	defer srv.Close()

	conn, _ := NewRegistry().Get("vmanage")
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())
	cfg := IntegrationConfig{
		Tenant: "t-a", IntegrationID: "int-vm", BaseURL: srv.URL,
		Streams: []string{"alarms"}, Creds: Credentials{Username: "ro", Password: "pw"},
	}
	cps, pipe := NewMemCheckpoints(), NewPipeline(1000)

	// Cycle 1: no cached session → exactly one login.
	_, sess, err := RunPollSession(context.Background(), conn, cfg, do, cps, pipe, Session{})
	if err != nil {
		t.Fatalf("cycle 1: %v", err)
	}
	if logins != 1 {
		t.Fatalf("cycle 1: want 1 login, got %d", logins)
	}
	if sess.Header == nil {
		t.Fatal("cycle 1 must return the session it authenticated")
	}

	// Cycle 2 with the cached session: NO new login.
	if _, sess, err = RunPollSession(context.Background(), conn, cfg, do, cps, pipe, sess); err != nil {
		t.Fatalf("cycle 2: %v", err)
	}
	if logins != 1 {
		t.Fatalf("cached session must skip login; got %d logins", logins)
	}

	// Cycle 3 with an EXPIRED cached session: fresh login.
	sess.ExpiresAt = time.Now().UTC().Add(-time.Minute)
	if _, sess, err = RunPollSession(context.Background(), conn, cfg, do, cps, pipe, sess); err != nil {
		t.Fatalf("cycle 3: %v", err)
	}
	if logins != 2 {
		t.Fatalf("expired session must re-login; got %d logins", logins)
	}
	if !sess.Valid(time.Now().UTC()) {
		t.Fatal("cycle 3 must return the fresh session")
	}
}

// A cached session the CONTROLLER invalidated early (server-side revocation)
// 401s mid-cycle: the run refreshes it via the existing re-auth path and
// returns the FRESH session, not the revoked one.
func TestRunPollSessionRefreshesRevokedSession(t *testing.T) {
	fixture, _ := os.ReadFile(filepath.Join("fixtures", "vmanage", "tunnel_down.json"))
	var logins int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jwt/login":
			logins++
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"tok` + itoa(logins) + `"}`))
		case "/dataservice/alarms":
			if r.Header.Get("Authorization") == "Bearer revoked" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(fixture)
		}
	}))
	defer srv.Close()

	conn, _ := NewRegistry().Get("vmanage")
	do := NewRetryDoer(srv.Client(), NewTokenBucket(0), DefaultRetry())
	cfg := IntegrationConfig{
		Tenant: "t-a", IntegrationID: "int-vm", BaseURL: srv.URL,
		Streams: []string{"alarms"}, Creds: Credentials{Username: "ro", Password: "pw"},
	}
	revoked := Session{
		Header:    http.Header{"Authorization": []string{"Bearer revoked"}},
		ExpiresAt: time.Now().UTC().Add(time.Hour), // looks valid locally
	}
	res, sess, err := RunPollSession(context.Background(), conn, cfg, do, NewMemCheckpoints(), NewPipeline(1000), revoked)
	if err != nil {
		t.Fatalf("RunPollSession: %v", err)
	}
	if logins != 1 {
		t.Fatalf("revoked session must trigger exactly one re-login, got %d", logins)
	}
	if len(res.Routed.Events) != 1 {
		t.Fatalf("expected 1 event after refresh, got %d (errs=%v)", len(res.Routed.Events), res.Errors)
	}
	if sess.Header.Get("Authorization") == "Bearer revoked" {
		t.Fatal("returned session must be the refreshed one, not the revoked one")
	}
}
