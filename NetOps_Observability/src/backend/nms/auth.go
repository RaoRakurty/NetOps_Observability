// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// auth.go — per-vendor AuthProvider implementations. Each performs the vendor's
// verified login/token flow and returns a Session (headers/cookies + expiry)
// the runtime attaches to poll requests and auto-refreshes. Flows confirmed
// against current vendor docs (2026); see specs.go.
//
// Secrets arrive already decrypted from the Vault (Credentials); providers never
// read them from anywhere else, and never log them.

func drainClose(resp *http.Response) {
	if resp != nil {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16)) // best-effort: drain for connection reuse
		_ = resp.Body.Close()                                        // best-effort: nothing actionable on close failure
	}
}

// ── Meraki: API key (static header) or OAuth bearer ──────────────────────────

type MerakiAuth struct{}

func (MerakiAuth) Authenticate(_ context.Context, _ string, creds Credentials, _ Doer) (Session, error) {
	h := http.Header{}
	switch {
	case creds.Token != "": // OAuth access token
		h.Set("Authorization", "Bearer "+creds.Token)
	case creds.APIKey != "":
		// Current Dashboard API accepts the key as a bearer; the legacy header
		// still works. Send both is wrong (bearer wins) — use bearer.
		h.Set("Authorization", "Bearer "+creds.APIKey)
	default:
		return Session{}, fmt.Errorf("meraki: api key or oauth token required")
	}
	h.Set("Accept", "application/json")
	// Static API key never expires; an OAuth token does (caller refreshes).
	return Session{Header: h}, nil
}

// ── Catalyst Center: HTTP Basic → X-Auth-Token (60 min) ──────────────────────

type CatalystAuth struct{}

func (CatalystAuth) Authenticate(ctx context.Context, base string, creds Credentials, do Doer) (Session, error) {
	if creds.Username == "" {
		return Session{}, fmt.Errorf("catalyst: username/password required")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/dna/system/api/v1/auth/token", nil)
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Authorization", "Basic "+basicCred(creds.Username, creds.Password))
	req.Header.Set("Content-Type", "application/json")
	resp, err := do.Do(req)
	if err != nil {
		return Session{}, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return Session{}, &HTTPStatusError{Op: "catalyst auth", Code: resp.StatusCode}
	}
	var body struct {
		Token string `json:"Token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		// The controller answered 200 with something we could not read (proxy
		// login page, truncated body, HTML error). That is NOT "the controller
		// returned no token" — the operator needs to know which one it was.
		return Session{}, fmt.Errorf("catalyst auth: unreadable token response: %w", err)
	}
	if body.Token == "" {
		return Session{}, fmt.Errorf("catalyst auth: no token")
	}
	h := http.Header{}
	h.Set("X-Auth-Token", body.Token)
	h.Set("Content-Type", "application/json")
	return Session{Header: h, ExpiresAt: nowUTC().Add(55 * time.Minute)}, nil
}

// ── vManage / Catalyst SD-WAN Manager: JWT, or the classic session login ──────
//
// Two login flows exist in the field (2026-10-17, lab: vManage 20.6.1):
//   - JWT: POST /jwt/login {username,password} → {"token"}; newer releases.
//   - Session: POST /j_security_check (form j_username/j_password) → a
//     JSESSIONID cookie, then GET /dataservice/client/token → the XSRF token
//     every later request carries as X-XSRF-TOKEN. All 20.x releases.
// JWT is tried first. Only a controller that does not HAVE the endpoint (404,
// 405, 501) falls back to the session flow; a 401/403 is a wrong credential
// and is reported as one — trying a second flow would only hide that.

type VManageAuth struct{}

// vmanageSessionTTL: both flows idle out at 30 min by default; refresh early.
const vmanageSessionTTL = 25 * time.Minute

func (v VManageAuth) Authenticate(ctx context.Context, base string, creds Credentials, do Doer) (Session, error) {
	if creds.Username == "" {
		return Session{}, fmt.Errorf("vmanage: username/password required")
	}
	base = strings.TrimRight(base, "/")
	s, status, err := v.jwtLogin(ctx, base, creds, do)
	if err == nil {
		return s, nil
	}
	switch status {
	case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusNotImplemented:
		return v.sessionLogin(ctx, base, creds, do)
	}
	return Session{}, err
}

// jwtLogin returns the HTTP status alongside any error so the caller can tell
// "no such endpoint" from "refused".
func (VManageAuth) jwtLogin(ctx context.Context, base string, creds Credentials, do Doer) (Session, int, error) {
	payload, _ := json.Marshal(map[string]string{"username": creds.Username, "password": creds.Password}) // discard: marshalling an in-memory value cannot fail
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/jwt/login", strings.NewReader(string(payload)))
	if err != nil {
		return Session{}, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do.Do(req)
	if err != nil {
		return Session{}, 0, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return Session{}, resp.StatusCode, &HTTPStatusError{Op: "vmanage auth", Code: resp.StatusCode}
	}
	var body struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return Session{}, resp.StatusCode, fmt.Errorf("vmanage auth: unreadable token response: %w", err)
	}
	if body.Token == "" {
		return Session{}, resp.StatusCode, fmt.Errorf("vmanage auth: no token")
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+body.Token)
	h.Set("Content-Type", "application/json")
	return Session{Header: h, ExpiresAt: nowUTC().Add(vmanageSessionTTL)}, resp.StatusCode, nil
}

// sessionLogin is the 20.x flow: form login → JSESSIONID → XSRF token.
func (VManageAuth) sessionLogin(ctx context.Context, base string, creds Credentials, do Doer) (Session, error) {
	form := url.Values{"j_username": {creds.Username}, "j_password": {creds.Password}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/j_security_check", strings.NewReader(form.Encode()))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := do.Do(req)
	if err != nil {
		return Session{}, err
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16)) // discard: a read error leaves body empty; the session-cookie check below still decides
	drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return Session{}, &HTTPStatusError{Op: "vmanage session login", Code: resp.StatusCode}
	}
	// A rejected login answers 200 with the HTML login page instead of a session.
	if strings.Contains(strings.ToLower(string(body)), "<html") {
		return Session{}, fmt.Errorf("vmanage session login: rejected — check the username and password")
	}
	var sid string
	for _, c := range resp.Cookies() {
		if c.Name == "JSESSIONID" && c.Value != "" {
			sid = c.Value
		}
	}
	if sid == "" {
		return Session{}, fmt.Errorf("vmanage session login: no session cookie returned")
	}
	treq, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/dataservice/client/token", nil)
	if err != nil {
		return Session{}, err
	}
	treq.Header.Set("Cookie", "JSESSIONID="+sid)
	tresp, err := do.Do(treq)
	if err != nil {
		return Session{}, err
	}
	tok, _ := io.ReadAll(io.LimitReader(tresp.Body, 4096)) // discard: a read error leaves the token empty, which is refused below
	drainClose(tresp)
	token := strings.TrimSpace(string(tok))
	if tresp.StatusCode != http.StatusOK || token == "" || strings.ContainsAny(token, "<> \t\r\n") {
		return Session{}, fmt.Errorf("vmanage session login: no XSRF token (status %d)", tresp.StatusCode)
	}
	h := http.Header{}
	h.Set("Cookie", "JSESSIONID="+sid)
	h.Set("X-XSRF-TOKEN", token)
	h.Set("Content-Type", "application/json")
	return Session{Header: h, ExpiresAt: nowUTC().Add(vmanageSessionTTL)}, nil
}

// ── NDFC / Nexus Dashboard: username/password/domain → JWT (20 min) ───────────

type NDFCAuth struct{}

func (NDFCAuth) Authenticate(ctx context.Context, base string, creds Credentials, do Doer) (Session, error) {
	if creds.Username == "" {
		return Session{}, fmt.Errorf("ndfc: username/password required")
	}
	domain := "local"
	if creds.Extra != nil && creds.Extra["domain"] != "" {
		domain = creds.Extra["domain"]
	}
	payload, _ := json.Marshal(map[string]string{"userName": creds.Username, "userPasswd": creds.Password, "domain": domain}) // discard: marshalling an in-memory value cannot fail
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+"/login", strings.NewReader(string(payload)))
	if err != nil {
		return Session{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := do.Do(req)
	if err != nil {
		return Session{}, err
	}
	defer drainClose(resp)
	if resp.StatusCode != http.StatusOK {
		return Session{}, &HTTPStatusError{Op: "ndfc auth", Code: resp.StatusCode}
	}
	var body struct {
		JWTToken string `json:"jwttoken"`
		Token    string `json:"token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
		return Session{}, err
	}
	tok := firstNonEmpty(body.JWTToken, body.Token)
	if tok == "" {
		return Session{}, fmt.Errorf("ndfc auth: no token")
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+tok)
	h.Set("Content-Type", "application/json")
	return Session{Header: h, ExpiresAt: nowUTC().Add(15 * time.Minute)}, nil
}

// ── Prime: HTTP Basic on every request (legacy, no session) ──────────────────

type PrimeAuth struct{}

func (PrimeAuth) Authenticate(_ context.Context, _ string, creds Credentials, _ Doer) (Session, error) {
	if creds.Username == "" {
		return Session{}, fmt.Errorf("prime: username/password required")
	}
	h := http.Header{}
	h.Set("Authorization", "Basic "+basicCred(creds.Username, creds.Password))
	h.Set("Accept", "application/json")
	return Session{Header: h}, nil // non-expiring: Basic re-sent every request
}

// ── Versa (Director/Concerto): OAuth bearer, or Basic fallback ────────────────

type VersaAuth struct {
	TokenPath string // vendor token endpoint (default "/auth/token")
}

func (a VersaAuth) Authenticate(ctx context.Context, base string, creds Credentials, do Doer) (Session, error) {
	// Prefer OAuth client-credentials when a client id/secret is present.
	if creds.ClientID != "" && creds.ClientSecret != "" {
		form := url.Values{"grant_type": {"client_credentials"}, "client_id": {creds.ClientID}, "client_secret": {creds.ClientSecret}}
		path := a.TokenPath
		if path == "" {
			path = "/auth/token"
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(base, "/")+path, strings.NewReader(form.Encode()))
		if err != nil {
			return Session{}, err
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		resp, err := do.Do(req)
		if err != nil {
			return Session{}, err
		}
		defer drainClose(resp)
		if resp.StatusCode != http.StatusOK {
			return Session{}, &HTTPStatusError{Op: "versa oauth", Code: resp.StatusCode}
		}
		var body struct {
			AccessToken string `json:"access_token"`
			ExpiresIn   int    `json:"expires_in"`
		}
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&body); err != nil {
			return Session{}, fmt.Errorf("versa oauth: unreadable token response: %w", err)
		}
		if body.AccessToken == "" {
			return Session{}, fmt.Errorf("versa oauth: no token")
		}
		h := http.Header{}
		h.Set("Authorization", "Bearer "+body.AccessToken)
		h.Set("Accept", "application/json")
		ttl := time.Duration(body.ExpiresIn) * time.Second
		if ttl <= 0 {
			ttl = 30 * time.Minute
		}
		return Session{Header: h, ExpiresAt: nowUTC().Add(ttl - 30*time.Second)}, nil
	}
	// Basic fallback (Versa Director supports it; good for testing).
	if creds.Username == "" {
		return Session{}, fmt.Errorf("versa: oauth client creds or username/password required")
	}
	h := http.Header{}
	h.Set("Authorization", "Basic "+basicCred(creds.Username, creds.Password))
	h.Set("Accept", "application/json")
	return Session{Header: h}, nil
}

// ── Generic: honor whatever the operator configured ──────────────────────────

type GenericAuth struct{}

func (GenericAuth) Authenticate(_ context.Context, _ string, creds Credentials, _ Doer) (Session, error) {
	h := http.Header{}
	switch {
	case creds.Token != "":
		h.Set("Authorization", "Bearer "+creds.Token)
	case creds.APIKey != "":
		h.Set("Authorization", "Bearer "+creds.APIKey)
	case creds.Username != "":
		h.Set("Authorization", "Basic "+basicCred(creds.Username, creds.Password))
	}
	h.Set("Accept", "application/json")
	return Session{Header: h}, nil
}

func basicCred(user, pass string) string {
	return base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
}

// nowUTC is overridable in tests.
var nowUTC = func() time.Time { return time.Now().UTC() }
