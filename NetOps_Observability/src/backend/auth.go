package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"netops/backend/internal/token"
	"netops/backend/policy"
)

// clientIP derives the caller's source IP: the first hop in X-Forwarded-For if
// present, else the host portion of RemoteAddr. Returns nil if unparseable.
func clientIP(r *http.Request) net.IP {
	if trustProxy() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first := strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
			if ip := net.ParseIP(first); ip != nil {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	return net.ParseIP(strings.TrimSpace(host))
}

// trustProxy reports whether X-Forwarded-* headers may be trusted. Default FALSE:
// behind an untrusted hop a client can spoof these to forge source IPs and dodge
// per-tenant/IP rate limits, so we only honor them when TRUST_PROXY=true.
func trustProxy() bool { return os.Getenv("TRUST_PROXY") == "true" }

// auth.go — login + middleware.
//
// Tokens are JWTs signed with HS256 using the JWT_SECRET, carrying the username
// (sub), role, issued-at and expiry. Access tokens are short-lived; clients
// trade a rotating refresh token (see refresh.go) for a fresh one at
// /api/auth/refresh. Both lifetimes are env-configurable.

// durEnv parses a Go duration from env (e.g. "15m", "12h"), falling back to def.
func durEnv(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

// Token lifetimes are env-configurable but clamped to safe, standards-aligned
// bounds — see token_policy.go.
func accessTokenTTL() time.Duration {
	// Short access token (15 min): the access JWT is a stateless authz proof; the
	// session lifecycle (idle/absolute/revocation) lives server-side and is enforced
	// at /api/auth/refresh. A short TTL makes the refresh-boundary the activity
	// signal (so idle timeout is meaningful) and tightens the revocation window.
	return boundedDurEnv("ACCESS_TOKEN_TTL", 15*time.Minute, accessTTLMin, accessTTLMax, accessTTLRecommended)
}
func refreshTokenTTL() time.Duration {
	return boundedDurEnv("REFRESH_TOKEN_TTL", 7*24*time.Hour, refreshTTLMin, refreshTTLMax, refreshTTLRecommended)
}

type ctxKey int

const userCtxKey ctxKey = 0

// ---- handlers -------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token        string     `json:"token"`
	RefreshToken string     `json:"refresh_token,omitempty"`
	ExpiresIn    int        `json:"expires_in"` // access token lifetime, seconds
	User         publicUser `json:"user"`
}

type publicUser struct {
	Username    string    `json:"username"`
	Role        string    `json:"role"`
	Email       string    `json:"email,omitempty"`
	DisplayName string    `json:"display_name,omitempty"`
	TenantID    string    `json:"tenant_id,omitempty"`
	Status      string    `json:"status,omitempty"`
	AuthSource  string    `json:"auth_source,omitempty"`
	MFAEnabled  bool      `json:"mfa_enabled"` // status only — the secret never leaves the server
	CreatedAt   time.Time `json:"created_at,omitempty"`
	LastLoginAt time.Time `json:"last_login_at,omitempty"`
}

func toPublic(u User) publicUser {
	return publicUser{
		Username:    u.Username,
		Role:        u.Role,
		Email:       u.Email,
		DisplayName: u.DisplayName,
		TenantID:    u.TenantID,
		Status:      u.Status,
		AuthSource:  u.AuthSource,
		MFAEnabled:  u.MFAEnabled,
		CreatedAt:   u.CreatedAt,
		LastLoginAt: u.LastLoginAt,
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// SR-012: login is unauthenticated — bound its body tightly (credentials are
	// tiny). Pairs with the verifyPassword length cap (SR-013).
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Account lockout (best-effort, in-memory): reject while locked, before we even
	// check the password, so a brute-forcer can't keep guessing. Per the scope's
	// Security Settings (login_attempts_allowed / unlock_time_seconds).
	if locked, d := s.loginThrottle.locked(req.Username); locked {
		w.Header().Set("Retry-After", intToString(int(d.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, errors.New("account temporarily locked due to failed sign-ins; try again later"))
		return
	}
	user, ok := s.users.Get(req.Username)
	if !ok || !verifyPassword(req.Password, user.PasswordHash) {
		// Count the failure against the lockout policy for the account's scope.
		allowed, unlock := s.lockoutPolicy(user, ok)
		// F-25: an UNCOUNTED failure is an unlimited guess. The throttle used to
		// stop counting silently once its map was full, so a username spray turned
		// brute-force lockout off platform-wide. Now it says so, and we refuse the
		// attempt rather than serving a guess we cannot count.
		if !s.loginThrottle.fail(req.Username, allowed, unlock) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests,
				errors.New("sign-in temporarily unavailable due to failed-login pressure; try again shortly"))
			return
		}
		// Generic message: don't leak whether the username exists.
		writeError(w, http.StatusUnauthorized, errors.New("invalid username or password"))
		return
	}
	s.loginThrottle.success(req.Username) // clear any prior failures on success
	// A disabled account cannot sign in — parity with the refresh / MFA / SSO /
	// LDAP / TACACS paths, which all reject status=="disabled". Checked AFTER the
	// password verifies, so an unauthenticated probe can't use it to enumerate
	// accounts (a wrong password still returns the generic error above).
	if user.Status == "disabled" {
		logWarn("auth", "login refused: account disabled", map[string]any{"user": user.Username})
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	// A SUSPENDED tenant blocks its users from signing in (deny-by-default tenant
	// lifecycle). The platform owner / global realm is never suspendable, so the
	// operator can never lock itself out.
	if user.TenantID != "" && user.TenantID != TenantGlobal && s.tenants != nil {
		if t, ok := s.tenants.Get(user.TenantID); ok && t.status() == TenantStatusSuspended {
			logWarn("auth", "login refused: tenant suspended", map[string]any{"user": user.Username, "tenant_id": t.ID})
			writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
			return
		}
	}
	// F-68: account lifecycle — expiry, inactivity, first-login reset, password
	// age. These are the Security Settings the SPA has always rendered as active
	// controls; until now nothing read them. Checked AFTER the password verifies
	// (so it cannot be used to enumerate accounts) and BEFORE any session is
	// minted. See account_policy.go.
	if s.enforceAccountPolicy(w, r, user) {
		return
	}
	// SR-029: opportunistically upgrade a hash stored at a weaker iteration count
	// to the current cost. Best-effort — never fail the login if rehash fails.
	// rehashPassword deliberately does NOT stamp PasswordChangedAt: this is the
	// same secret, re-wrapped. Treating it as a change would restart the
	// password_expire_days clock on every sign-in and make expiry unreachable.
	if passwordNeedsRehash(user.PasswordHash) {
		if err := s.users.RehashPassword(user.Username, req.Password); err != nil {
			logWarn("auth", "password rehash-on-login failed", map[string]any{"user": user.Username, "err": err.Error()})
		}
	}
	// MFA gate: an enrolled (local) user gets a short-lived challenge instead of a
	// session — they complete it at /api/auth/mfa/login with a one-time code.
	if user.MFAEnabled {
		now := time.Now()
		ch, err := token.Sign(jwtClaims{
			Sub: user.Username, Scopes: []string{mfaChallengeScope},
			Iat: now.Unix(), Exp: now.Add(mfaChallengeTTL).Unix(),
		}, jwtSecret())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logInfo("auth", "mfa challenge issued", map[string]any{"user": user.Username})
		writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": ch})
		return
	}
	s.issueSession(w, r, user)
}

// lockoutPolicy resolves the failed-login lockout thresholds for an account's
// scope (its tenant, else the provider scope). Returns allowed<=0 — lockout
// disabled — when Security Settings aren't wired (e.g. a minimal test server).
func (s *server) lockoutPolicy(user User, found bool) (allowed, unlockSeconds int) {
	if s.securitySettings == nil {
		return 0, 0
	}
	scope := "provider"
	if found && user.TenantID != "" {
		scope = user.TenantID
	}
	ss := s.securitySettings.Get(scope)
	return ss.LoginAttemptsAllowed, ss.UnlockTimeSeconds
}

// sessionPolicy resolves the session lifecycle policy for an account. The
// per-scope Security Settings (Provider / Org / Tenant) provide the baseline; the
// #24 policy engine then layers PER-ROLE refinement on top — but only an EXPLICIT
// override (not the catalog default) applies, and only if it is STRICTER (shorter
// window), so a tighter role policy can harden but never loosen the scope's. Falls
// back to standard defaults when neither store is wired (a minimal test server).
func (s *server) sessionPolicy(tenant, role string) (idle, absolute time.Duration, enforceIdle, enforceAbsolute bool) {
	idle, absolute, enforceIdle, enforceAbsolute = 30*time.Minute, 12*time.Hour, true, true
	scope := tenant
	if scope == "" {
		scope = "provider"
	}
	if s.securitySettings != nil {
		ss := s.securitySettings.Get(scope)
		if ss.IdleTimeoutMinutes > 0 {
			idle = time.Duration(ss.IdleTimeoutMinutes) * time.Minute
		}
		if ss.AbsoluteTimeoutMinutes > 0 {
			absolute = time.Duration(ss.AbsoluteTimeoutMinutes) * time.Minute
		}
		enforceIdle, enforceAbsolute = ss.EnforceIdleTimeout, ss.EnforceAbsoluteTimeout
	}
	// Per-role refinement (#24 engine, System→Tenant→Role→User). Durations are
	// stored as whole seconds. Only an explicit override applies, stricter-wins.
	if s.secPolicy != nil {
		sub := policy.Subject{Tenant: tenant, Role: role}
		if r, ok := s.secPolicy.ResolveSetting(sub, "session.idle_timeout"); ok && !r.FromDefault {
			if d := time.Duration(r.Value.Num) * time.Second; d > 0 && d < idle {
				idle = d
			}
		}
		if r, ok := s.secPolicy.ResolveSetting(sub, "session.absolute_lifetime"); ok && !r.FromDefault {
			if d := time.Duration(r.Value.Num) * time.Second; d > 0 && d < absolute {
				absolute = d
			}
		}
	}
	return idle, absolute, enforceIdle, enforceAbsolute
}

// recordSessionEvent emits a session lifecycle event to the structured log AND
// the audit trail (SOC2 / SIEM-ready). event is one of SESSION_CREATED,
// SESSION_REFRESHED, SESSION_IDLE_EXPIRED, SESSION_ABSOLUTE_EXPIRED, SESSION_REVOKED.
func (s *server) recordSessionEvent(r *http.Request, event, userID, sessionID, tenant string, extra map[string]any) {
	fields := map[string]any{"event": event, "user": userID, "session": sessionID}
	for k, v := range extra {
		fields[k] = v
	}
	logInfo("session", event, fields)
	if s.audit != nil {
		decision := "allow"
		if event == "SESSION_IDLE_EXPIRED" || event == "SESSION_ABSOLUTE_EXPIRED" || event == "SESSION_REVOKED" {
			decision = "deny"
		}
		detail := map[string]any{"event": event, "session_id": sessionID}
		for k, v := range extra {
			detail[k] = v
		}
		s.audit.Record(AuditEvent{
			Actor: userID, Tenant: tenant, Method: "SESSION", Path: "/session/" + event,
			Decision: decision, Remote: clientIP(r).String(), Detail: detail,
		})
	}
}

// mintSession opens a server-side session for user (snapshotting the scope's
// idle/absolute policy) and returns a fresh access token carrying its sid plus a
// refresh token bound to it. Shared by EVERY login path — password, MFA, LDAP,
// TACACS and SSO — so all sessions get lifecycle enforcement + observability.
func (s *server) mintSession(r *http.Request, user User) (access, refresh string, err error) {
	ttl := accessTokenTTL()
	var sid string
	if s.sessions != nil {
		idle, absolute, enforceIdle, enforceAbsolute := s.sessionPolicy(user.TenantID, user.Role)
		if !enforceIdle {
			idle = 0 // 0 = disabled at the Validate gate
		}
		if !enforceAbsolute {
			absolute = 0
		}
		sess, evicted, e := s.sessions.Create(user.Username, clientIP(r).String(), r.UserAgent(), idle, absolute)
		if e != nil {
			return "", "", e
		}
		sid = sess.ID
		s.recordSessionEvent(r, "SESSION_CREATED", user.Username, sid, user.TenantID, map[string]any{
			"idle_min": int(idle.Minutes()), "absolute_min": int(absolute.Minutes()),
		})
		for _, ev := range evicted { // concurrent-session cap evictions
			s.recordSessionEvent(r, "SESSION_REVOKED", user.Username, ev, user.TenantID, map[string]any{"reason": "max_sessions"})
		}
	}
	access, err = token.Sign(jwtClaims{
		Sub: user.Username, Role: user.Role, Tenant: user.TenantID, Sid: sid,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		return "", "", err
	}
	refresh, err = s.refresh.IssueForSession(user.Username, sid)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// issueSession mints a session and returns the standard JSON login response
// (also refreshing the console gate cookie). Shared by password login and
// MFA-challenge completion (handleMFALogin).
func (s *server) issueSession(w http.ResponseWriter, r *http.Request, user User) {
	// F-68: concurrent_login=deny — one live session per account. Revoke the
	// prior ones BEFORE minting, so the new session is never the one culled.
	// Last-login-wins (rather than refusing the new sign-in) is the deliberate
	// reading: an operator locked out by their own stale session on a closed
	// laptop is a support ticket, not a security control.
	if s.sessions != nil && concurrentLoginDenied(s.securitySettingsFor(user)) {
		n, err := s.sessions.RevokeAllForUser(user.Username)
		if err != nil {
			// The whole point of deny is that only one session lives. If the
			// revoke did not persist, minting a second session would leave two
			// usable ones — the exact state the policy forbids.
			logError("auth", "concurrent-login revoke did not persist", map[string]any{"user": user.Username, "err": err.Error()})
			writeError(w, http.StatusInternalServerError, errors.New("sign-in could not be completed; prior sessions could not be closed"))
			return
		}
		if n > 0 {
			logInfo("auth", "concurrent sessions revoked by policy", map[string]any{"user": user.Username, "count": n})
			s.recordSessionEvent(r, "SESSION_REVOKED", user.Username, "", user.TenantID,
				map[string]any{"reason": "concurrent_login_deny", "count": n})
		}
	}
	ttl := accessTokenTTL()
	tok, refresh, err := s.mintSession(r, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.users.TouchLogin(user.Username)
	setOSDCookie(w, r, tok, ttl) // /search gate cookie (enforced for platform owner only)
	logInfo("auth", "login ok", map[string]any{"user": user.Username, "role": user.Role})
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: refresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}

// handleRefresh trades a valid (rotating) refresh token for a fresh access
// token + a new refresh token. Reachable without an access token.
func (s *server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	// F-32: PRE-AUTH route — a refresh token is a few hundred bytes. Its sibling
	// /api/auth/login was correctly capped at 64 KiB; this one had no cap of its
	// own and rode only the 50 MiB global backstop, which amplifies 3-5× in the
	// struct decode and can be sent concurrently by an unauthenticated caller.
	if err := decodeJSONBody(w, r, authTokenBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Session lifecycle enforcement (idle + absolute) happens HERE, at the refresh
	// boundary — the refresh is the activity signal. Validate BEFORE rotating so an
	// idle/expired/revoked session can't mint a fresh token. Legacy/federated tokens
	// (no session id) skip this and behave as before.
	if sid, ok := s.refresh.SessionOf(req.RefreshToken); ok && sid != "" && s.sessions != nil {
		sess, verr := s.sessions.Validate(sid, true, true)
		if verr != nil {
			code := sessionErrorCode(verr)
			if code == "SESSION_IDLE_TIMEOUT" || code == "SESSION_ABSOLUTE_TIMEOUT" {
				ev := "SESSION_IDLE_EXPIRED"
				if code == "SESSION_ABSOLUTE_TIMEOUT" {
					ev = "SESSION_ABSOLUTE_EXPIRED"
				}
				s.recordSessionEvent(r, ev, sess.UserID, sid, "", nil)
			}
			// Drop the now-dead token. Best-effort: the caller is already being
			// refused, so a persist failure here must not mask that 401 — but it
			// must not vanish either (§10: no silent failures).
			if _, rerr := s.refresh.Revoke(req.RefreshToken); rerr != nil {
				logError("auth", "expired-session token revoke did not persist", map[string]any{"err": rerr.Error()})
			}
			writeJSONError(w, http.StatusUnauthorized, verr.Error(), code)
			return
		}
	}
	newRefresh, username, sid, err := s.refresh.RotateSession(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	user, ok := s.users.Get(username)
	if !ok || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
		return
	}
	if sid != "" && s.sessions != nil {
		s.sessions.Touch(sid) // record activity at the refresh boundary
		s.recordSessionEvent(r, "SESSION_REFRESHED", user.Username, sid, user.TenantID, nil)
	}
	ttl := accessTokenTTL()
	tok, err := token.Sign(jwtClaims{
		Sub: user.Username, Role: user.Role, Tenant: user.TenantID, Sid: sid,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	// Refresh the /search gate cookie too, so it tracks the rotating session and
	// covers principals that authenticated via SSO/LDAP/TACACS (they reach a fresh
	// access token through this path).
	setOSDCookie(w, r, tok, ttl)
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: newRefresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}

// handleConsoleGate (re)issues the embedded-console gate cookie for the current
// session, on demand. The embedded consoles (/netbox, /search) are loaded as raw
// browser iframes that don't pass through the SPA's Bearer/refresh path, so their
// gate cookie can go stale (short TTL) or be missing/old-path after a deploy. The
// SPA calls this (Bearer-authed) right before mounting an embedded console so the
// iframe always carries a fresh, correctly-pathed cookie. Platform-owner only.
func (s *server) handleConsoleGate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	if !isPlatformOwner(claims) { // identity check — ignore any view-as-tenant override
		writeError(w, http.StatusForbidden, errors.New("platform administrator access required"))
		return
	}
	// Re-sign a fresh session JWT for the cookie so it verifies at osd-gate
	// regardless of how the caller authenticated (session/SSO).
	ttl := accessTokenTTL()
	tok, err := token.Sign(jwtClaims{
		Sub: claims.Sub, Role: claims.Role, Tenant: claims.Tenant,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	setOSDCookie(w, r, tok, ttl)
	w.WriteHeader(http.StatusNoContent)
}

// handleLogout revokes the presented refresh token. Idempotent; reachable
// without a valid access token (the access token may already be expired).
func (s *server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	// F-32: PRE-AUTH route. An EMPTY body is tolerated by design (a browser
	// logging out with no stored token must still clear its cookie), but the
	// read is bounded and anything else is now reported.
	//
	// F-70: a field TYPO — {"refreshToken":…} instead of {"refresh_token":…} —
	// used to decode "successfully" into an empty struct, revoke nothing, and
	// return {"status":"ok"}. The caller believed it had logged out; the token
	// went on minting access tokens. Unknown fields are refused outright, the
	// same way cloud_monitors.go refuses leftover keys rather than dropping them.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, authTokenBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		logWarn("auth", "logout body rejected", map[string]any{"err": err.Error()})
		writeError(w, http.StatusBadRequest, err)
		return
	}

	// F-70: report what actually happened. `revoked` false with a token supplied
	// means the token was unknown or already dead — idempotent, still 200. A
	// PERSIST failure is different: the revoke did not stick, so saying "ok"
	// would be the same lie in a new place. That is a 500.
	revoked := false
	if req.RefreshToken != "" {
		// Revoke the server-side session too (not just the refresh token), so the
		// logout is authoritative across the session's lifecycle.
		sid, hasSession := s.refresh.SessionOf(req.RefreshToken)
		if hasSession && sid != "" && s.sessions != nil {
			killed, err := s.sessions.Revoke(sid)
			if err != nil {
				logError("auth", "logout: session revoke did not persist", map[string]any{"session": sid, "err": err.Error()})
				writeError(w, http.StatusInternalServerError, errors.New("logout could not be completed; the session is still active"))
				return
			}
			if killed {
				revoked = true
				// The audit record is written only for a revoke that actually
				// happened and actually persisted — it is a compliance artifact.
				s.recordSessionEvent(r, "SESSION_REVOKED", "", sid, "", map[string]any{"reason": "logout"})
			}
		}
		tokenKilled, err := s.refresh.Revoke(req.RefreshToken)
		if err != nil {
			logError("auth", "logout: refresh revoke did not persist", map[string]any{"err": err.Error()})
			writeError(w, http.StatusInternalServerError, errors.New("logout could not be completed; the refresh token is still valid"))
			return
		}
		if tokenKilled {
			revoked = true
		}
		if !revoked {
			logWarn("auth", "logout presented an unrecognised refresh token", nil)
		}
	}
	clearOSDCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "revoked": revoked})
}

func (s *server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	user, ok := s.users.Get(claims.Sub)
	if !ok {
		writeError(w, http.StatusUnauthorized, errors.New("user removed"))
		return
	}
	// platform_admin tells the SPA whether to surface infra-stack monitoring and
	// platform-wide administration — including the tenant "view as" switcher. This
	// is an IDENTITY question (is the caller the platform owner?), so it MUST use
	// isPlatformOwner, NOT principalTenant: the latter honors the view-as-tenant
	// override, which would flip platform_admin to false while scoped and hide the
	// very switcher needed to scope back (locking the owner into a tenant).
	owner := isPlatformOwner(claims)
	// Keep the embedded-console gate cookie fresh for the platform owner. /me is
	// hit on app load, so the bundled NetBox / Dashboards iframes always carry a
	// valid, correctly-pathed cookie without a separate round-trip (no 403 wall).
	if owner {
		if tok, err := token.Sign(jwtClaims{
			Sub: claims.Sub, Role: claims.Role, Tenant: claims.Tenant,
			Iat: time.Now().Unix(), Exp: time.Now().Add(accessTokenTTL()).Unix(),
		}, jwtSecret()); err == nil {
			setOSDCookie(w, r, tok, accessTokenTTL())
		}
	}
	// Accessible scopes (PBAC Phase B): the tenants the principal may act in and
	// the orgs it administers — feeds the L1 top-bar Org|Region|Tenant selector.
	// all_tenants=true ⇒ platform owner (reaches every tenant).
	tenants, allTenants := s.accessibleTenants(claims.Sub)
	writeJSON(w, http.StatusOK, struct {
		publicUser
		PlatformAdmin     bool     `json:"platform_admin"`
		GrafanaEnabled    bool     `json:"grafana_enabled"`
		OrgID             string   `json:"org_id"`
		AccessibleTenants []string `json:"accessible_tenants"`
		AllTenants        bool     `json:"all_tenants"`
		OrgAdminOf        []string `json:"org_admin_of"`
		DefaultLanding    string   `json:"default_landing,omitempty"`
	}{toPublic(user), owner, envOr("GRAFANA_URL", "") != "", s.principalOrg(claims), tenants, allTenants, s.orgAdminOrgs(claims.Sub), s.resolveLanding(claims)})
}

// resolveLanding returns the administratively-configured landing route for the
// caller: the caller's tenant value, else the platform default (the global tenant's
// value), else "" (the SPA then uses its built-in home). The route's existence and
// the caller's authorization to view it are validated client-side against the nav,
// so a stale or now-forbidden route degrades gracefully rather than trapping a user.
func (s *server) resolveLanding(claims jwtClaims) string {
	if tenant, _ := principalTenant(claims); tenant != "" && tenant != TenantGlobal {
		if t, ok := s.tenants.Get(tenant); ok && t.DefaultLanding != "" {
			return t.DefaultLanding
		}
	}
	if g, ok := s.tenants.Get(TenantGlobal); ok {
		return g.DefaultLanding
	}
	return ""
}

// isLocalAccount reports whether an account's password is managed locally (so it
// can be changed in-app). Federated sources (oidc/saml/ldap/tacacs) are managed
// by the IdP. An empty source means a legacy/bootstrap local account.
func isLocalAccount(authSource string) bool {
	s := strings.ToLower(strings.TrimSpace(authSource))
	return s == "" || s == "local"
}

type changePasswordRequest struct {
	// Username is used only by the unauthenticated login-window flow to name the
	// account; an authenticated caller's account comes from its token instead.
	Username        string `json:"username,omitempty"`
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

// handleChangePassword serves self-service password change in two modes:
//   - authenticated: the signed-in user changes its own password (account = token).
//   - unauthenticated: the login-window "Change password" form names the account
//     and proves ownership with the current password (this path is in publicPaths).
//
// Either way the change is server-authoritative: the current password must verify,
// the account must be local, and the new password must satisfy the Security Policy.
func (s *server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req changePasswordRequest
	// F-32: PRE-AUTH route (the login window's "Change password" names the
	// account and proves ownership with the current password).
	if err := decodeJSONBody(w, r, authCredentialBodyBytes, &req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Identify the account. An authenticated caller can only change its own.
	username := ""
	authed := false
	if claims, ok := userFrom(r.Context()); ok {
		username, authed = claims.Sub, true
	} else {
		username = strings.TrimSpace(req.Username)
	}
	if username == "" {
		writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
		return
	}
	// Generic credential error so the pre-auth path doesn't enumerate usernames;
	// the authed path keeps the clearer "current password incorrect".
	badCreds := errors.New("invalid username or password")
	if authed {
		badCreds = errors.New("current password incorrect")
	}
	user, ok := s.users.Get(username)
	if !ok {
		writeError(w, http.StatusUnauthorized, badCreds)
		return
	}
	// Only LOCAL accounts have a password we own. Federated accounts (oidc/saml/
	// ldap/tacacs) authenticate against the IdP and carry no usable local hash.
	if !isLocalAccount(user.AuthSource) {
		writeError(w, http.StatusBadRequest, errors.New("password is managed by your identity provider; change it there"))
		return
	}
	if !verifyPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, badCreds)
		return
	}
	// Enforce the account's resolved Security Policy (length + complexity) before
	// the store's own floor — zero-trust, server-authoritative (#24 wiring).
	rules := s.callerPasswordRules(jwtClaims{Sub: user.Username, Role: user.Role, Tenant: user.TenantID})
	if err := validatePasswordAgainstPolicy(req.NewPassword, rules); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// No-reuse: the new password must differ from the current one.
	if verifyPassword(req.NewPassword, user.PasswordHash) {
		writeError(w, http.StatusBadRequest, errors.New("new password must differ from the current password"))
		return
	}
	// F-68: password_history — the full check this comment used to say was left
	// undone. When the scope enables it, the candidate is verified against the
	// last passwordHistoryDepth hashes, not just the current one.
	if err := checkPasswordHistory(s.securitySettingsFor(user), user, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	if err := s.users.ChangePassword(user.Username, req.NewPassword); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Enterprise-safe: a password change revokes ALL of the user's sessions, so a
	// stolen/old session can't survive a credential reset.
	//
	// F-70: that promise was only true until the next restart, because the
	// revoke's persist error was discarded. The password is already changed by
	// this point — so the honest report is 200 with sessions_revoked:false plus
	// a loud log, NOT a 500 that would tell the caller their password change
	// failed when it did not.
	sessionsRevoked := true
	if s.sessions != nil {
		n, err := s.sessions.RevokeAllForUser(user.Username)
		if err != nil {
			sessionsRevoked = false
			logError("auth", "password change: session revoke did not persist — old sessions may survive a restart",
				map[string]any{"user": user.Username, "err": err.Error()})
		} else if n > 0 {
			s.recordSessionEvent(r, "SESSION_REVOKED", user.Username, "", user.TenantID, map[string]any{"reason": "password_change", "count": n})
		}
	}
	logInfo("auth", "password changed", map[string]any{"user": user.Username, "pre_auth": !authed})
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "sessions_revoked": sessionsRevoked})
}

// ---- middleware -----------------------------------------------------------

// Per-handler body caps for the unauthenticated auth surface (F-32). Named
// rather than inline so the five sibling routes cannot drift apart again —
// drift is exactly how /api/auth/login ended up capped and its five neighbours
// did not.
const (
	// authTokenBodyBytes bounds a body that carries only an opaque token.
	authTokenBodyBytes int64 = 16 << 10
	// authCredentialBodyBytes bounds a credential pair; matches the 64 KiB
	// already used by /api/auth/login (SR-012).
	authCredentialBodyBytes int64 = 64 << 10
)

// publicPaths can be reached without a Bearer token.
var publicPaths = []string{
	"/admin/health",
	"/admin/version",
	"/api/auth/login",
	"/api/auth/refresh",
	"/api/auth/logout",
	"/api/auth/sso/config",
	"/api/auth/sso/login",
	"/api/auth/sso/callback",
	"/api/auth/methods",
	"/api/auth/ldap/login",
	"/api/auth/tacacs/login",
	"/api/auth/change-password", // self-service from the login window; names the account + verifies the current password (local accounts only)
	"/api/auth/osd-gate",        // cookie-authenticated nginx auth_request target; does its own authz
	"/api/auth/mfa/login",       // completes the login MFA challenge; authenticates via the challenge token + code
	"/metrics",
}

func (s *server) withAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Pass through CORS preflight unchanged.
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}
		for _, p := range publicPaths {
			if r.URL.Path == p {
				next.ServeHTTP(w, r)
				return
			}
		}
		// Secure report/export links carry a signed, expiring token in the path and
		// do their own authorization in the view handler — no Bearer needed.
		if strings.HasPrefix(r.URL.Path, "/api/reports/view/") || strings.HasPrefix(r.URL.Path, "/api/exports/view/") {
			next.ServeHTTP(w, r)
			return
		}
		// ITSM inbound webhooks are called by external systems (no JWT). The
		// handler authenticates via the per-tenant path token + the provider's
		// signature (HMAC/replay) before touching any state — fail-closed.
		if strings.HasPrefix(r.URL.Path, "/api/integrations/webhook/") {
			next.ServeHTTP(w, r)
			return
		}
		// NMS controller webhooks (#95): external controllers call in with no
		// JWT; the handler authenticates via the opaque path token + the
		// connector's signature verification before touching state — fail-closed.
		if strings.HasPrefix(r.URL.Path, "/api/nms/webhook/") {
			next.ServeHTTP(w, r)
			return
		}
		// Anything outside /api/ and /admin/ (i.e. /metrics is the only
		// odd duck, already handled above) is fronted by the SPA / iframes
		// and doesn't go through this Go server.
		if !strings.HasPrefix(r.URL.Path, "/api/") && !strings.HasPrefix(r.URL.Path, "/admin/") {
			next.ServeHTTP(w, r)
			return
		}
		// /api/events is a WebSocket — the browser's WS API can't set the
		// Authorization header, so we accept ?token=<jwt> there.
		var bearer string
		// WebSocket routes accept ?token=<jwt> (browsers can't set Authorization on
		// a WS): the events hub and the device-SSH gateway (/api/devices/{id}/ssh).
		if r.URL.Path == "/api/events" ||
			(strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/ssh")) {
			bearer = r.URL.Query().Get("token")
		}
		if bearer == "" {
			auth := r.Header.Get("Authorization")
			if h := r.Header.Get("X-API-Key"); h != "" && auth == "" {
				auth = "Bearer " + h
			}
			if !strings.HasPrefix(auth, "Bearer ") {
				writeError(w, http.StatusUnauthorized, errors.New("missing bearer token"))
				return
			}
			bearer = strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		}
		// Machine clients present an API key (ntk_…). Resolve it to a synthetic
		// principal carrying the key's tenant + scopes; the RBAC role is derived
		// from the scopes (see docs/API_ACCESS.md). Scope checks gate the
		// scope-protected endpoints (e.g. write:incidents).
		if strings.HasPrefix(bearer, keyPrefix) {
			k, ok := s.apiKeys.Verify(bearer)
			if !ok {
				writeError(w, http.StatusUnauthorized, errors.New("invalid or revoked API key"))
				return
			}
			// Source-IP allow-list (NetOps extension). Reject calls from outside
			// the key's permitted CIDRs without authenticating.
			if !k.sourceAllowed(clientIP(r)) {
				writeError(w, http.StatusForbidden, errors.New("source address not permitted for this API key"))
				return
			}
			// Per-key rate limit (fixed window / minute). 429 + Retry-After when
			// the key exceeds its cap; surfaced live in Administration → API Access.
			if ok, retry := s.apiKeys.Allow(k.ID, s.apiKeys.effectiveLimit(k)); !ok {
				w.Header().Set("Retry-After", intToString(retry))
				writeError(w, http.StatusTooManyRequests, errors.New("API key rate limit exceeded"))
				return
			}
			claims := jwtClaims{
				Sub:    "apikey:" + k.ID,
				Role:   roleFromScopes(k.Scopes),
				Tenant: k.TenantID,
				Scopes: k.Scopes,
			}
			// A suspended tenant's API keys stop working too (deny-by-default).
			if s.tenantSuspended(claims) {
				writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, claims))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Our own session tokens are HS256. Try that first (the common path).
		claims, err := token.Verify(bearer, jwtSecret())
		if err == nil {
			// An MFA challenge token is NOT a session: it's the half-authenticated
			// token issued between password success and code entry. Reject it here so
			// it can only be spent at /api/auth/mfa/login, never as a Bearer.
			if claims.HasScope(mfaChallengeScope) {
				writeError(w, http.StatusUnauthorized, errors.New("MFA challenge token is not a session"))
				return
			}
			// Instant revocation: re-check the live account on EVERY request so a
			// disabled or deleted user loses access immediately — not only when the
			// stateless access token eventually expires. Cheap (in-memory map). Only
			// our own session subjects (usernames) are checked; api-key principals
			// return early above and never reach here.
			if u, ok := s.users.Get(claims.Sub); !ok || u.Status == "disabled" {
				writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
				return
			}
			// Instant tenant suspension: a suspended tenant loses access immediately,
			// not only when its access tokens expire (mirrors the disabled-user check).
			if s.tenantSuspended(claims) {
				writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
				return
			}
			// Instant session revocation: if the token carries a session id, the
			// session must still be active. Catches logout, admin kill, password-change
			// and max-session eviction immediately (idle/absolute still flip at the
			// refresh boundary). Cheap in-memory check; tokens without a sid (legacy)
			// skip it.
			if claims.Sid != "" && s.sessions != nil && !s.sessions.IsActive(claims.Sid) {
				writeJSONError(w, http.StatusUnauthorized, "session ended", "SESSION_REVOKED")
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, claims))
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Otherwise, if SSO is configured, accept a Keycloak-signed RS256 Bearer
		// (service accounts / direct API clients) verified against its JWKS.
		if op := s.oidcProvider(); op.ready() {
			if oc, verr := op.jwks.verifyRS256(bearer, op.issuer, op.clientID); verr == nil {
				ctx := context.WithValue(r.Context(), userCtxKey, s.withActingTenant(r, jwtClaims{
					Sub:    firstNonEmpty(oc.PreferredUsername, oc.Email, oc.Sub),
					Role:   op.roleFor(oc),
					Tenant: op.defaultTenant,
				}))
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		writeError(w, http.StatusUnauthorized, err)
	})
}

func userFrom(ctx context.Context) (jwtClaims, bool) {
	v := ctx.Value(userCtxKey)
	if v == nil {
		return jwtClaims{}, false
	}
	c, ok := v.(jwtClaims)
	return c, ok
}

// ---- OpenSearch Dashboards (/search) platform-owner gate (#35) -------------
//
// nginx proxies /search/ to OpenSearch Dashboards OUTSIDE this auth middleware
// (it's a browser-loaded iframe, not an XHR, so it can't carry the Bearer
// header). To keep that surface platform-owner-only — Dashboards runs with its
// security plugin off, so it has NO tenant isolation and would expose every
// tenant's logs — nginx auth_request's each /search request against
// handleOSDGate. The principal is carried in a short-lived httpOnly cookie
// scoped to Path=/search (set at login/refresh, cleared at logout), so it is
// only ever sent on /search requests and never reaches /api.
const osdCookieName = "netops_osd"

// secureCookies marks session cookies Secure (HTTPS-only) via explicit env
// override. Used as a fallback; cookieSecure also auto-detects HTTPS per request.
func secureCookies() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("SECURE_COOKIES")), "true")
}

// cookieSecure decides the Secure flag for a session cookie (SR-030). It is set
// whenever the request arrived over HTTPS (direct TLS or X-Forwarded-Proto from
// the TLS edge), OR when SECURE_COOKIES=true forces it. This auto-protects the
// JWT-bearing cookie on HTTPS deployments without breaking the plain-HTTP default
// (a Secure cookie over HTTP is silently dropped by the browser).
func cookieSecure(r *http.Request) bool {
	if secureCookies() {
		return true
	}
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
}

// consoleGatePath is the cookie path for the embedded-console gate cookie. It
// must cover every same-origin console nginx guards with the auth_request gate —
// today /search (OpenSearch Dashboards) AND /netbox/ (the bundled Source of
// Truth, embedded in-app). Path="/" so one cookie reaches them all; the cookie
// is HttpOnly + SameSite=Lax and carries only the access token the gate verifies.
const consoleGatePath = "/"

// setOSDCookie issues/refreshes the embedded-console gate cookie carrying the
// caller's access token. SameSite=Lax is sufficient (the consoles are embedded
// same-origin). Lifetime tracks the access token.
func setOSDCookie(w http.ResponseWriter, r *http.Request, token string, ttl time.Duration) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    token,
		Path:     consoleGatePath,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(ttl.Seconds()),
	})
}

// clearOSDCookie expires the gate cookie on logout (same attributes, MaxAge<0).
func clearOSDCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     osdCookieName,
		Value:    "",
		Path:     consoleGatePath,
		HttpOnly: true,
		Secure:   cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// handleOSDGate is the nginx auth_request target for the embedded consoles
// (/search, /netbox). It authenticates from the gate cookie (not a Bearer token)
// and authorizes ONLY the platform owner — a super-admin in the global tenant
// (principalTenant cross==true). 200 = allow, 401 = no/invalid session, 403 =
// authenticated but not platform owner. It is in publicPaths so the bearer-token
// middleware doesn't reject the cookie-only subrequest; the authz lives here.
//
// On allow it returns X-Netbox-User: the NetBox superuser name. nginx captures
// it (auth_request_set) and forwards it to NetBox as the REMOTE_AUTH header so
// the embedded Source of Truth auto-logs-in as that superuser — no NetBox login
// screen. Safe because the header is emitted ONLY after the platform-owner check
// passes, and nginx strips any client-supplied copy.
func (s *server) handleOSDGate(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(osdCookieName)
	if err != nil || c.Value == "" {
		writeError(w, http.StatusUnauthorized, errors.New("authentication required"))
		return
	}
	claims, err := token.Verify(c.Value, jwtSecret())
	if err != nil {
		writeError(w, http.StatusUnauthorized, errors.New("invalid or expired session"))
		return
	}
	if !isPlatformOwner(claims) { // identity check — ignore any view-as-tenant override
		writeError(w, http.StatusForbidden, errors.New("platform administrator access required"))
		return
	}
	// Compliance: the RAW OpenSearch Dashboards console (c=search) can't be
	// per-tenant filtered (its security plugin is off), so an operator could query a
	// restricted tenant's indices directly. When ANY tenant is operator-restricted we
	// deny the raw console — the operator uses the in-app Logs view, which enforces
	// the restriction. /netbox (no c=search) is unaffected.
	if r.URL.Query().Get("c") == "search" && len(s.tenants.restrictedIDs()) > 0 {
		writeError(w, http.StatusForbidden, errors.New("raw search console disabled while operator-restricted tenants exist — use the in-app Logs view"))
		return
	}
	w.Header().Set("X-Netbox-User", netboxRemoteUser())
	// Grafana auto-login: forward the authenticated principal's username so the
	// embedded Grafana (GF_AUTH_PROXY) signs the request in AS that user — no
	// "not signed in" anonymous state, no separate Grafana login. nginx captures
	// this and forwards it as X-WEBAUTH-USER on the /grafana proxy; the client's
	// own copy is never trusted (set only after this platform-owner gate passes).
	if u := sanitizeHeaderUser(claims.Sub); u != "" {
		w.Header().Set("X-Grafana-User", u)
	}
	w.WriteHeader(http.StatusOK)
}

// sanitizeHeaderUser keeps only characters valid in a username header value
// (defense-in-depth against header injection — claims.Sub is already from a
// verified JWT, but we never emit raw subject text into a response header).
func sanitizeHeaderUser(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '-' || r == '_' || r == '.' || r == '@' ||
			(r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			out = append(out, r)
		}
	}
	if len(out) > 190 {
		out = out[:190]
	}
	return string(out)
}

// netboxRemoteUser is the NetBox username the embedded console auto-logs-in as.
// It MUST match the bundled NetBox superuser (compose SUPERUSER_NAME) so NetBox's
// REMOTE_AUTH maps the request to that existing superuser rather than minting a
// permissionless auto-created user. Sourced from the same env compose feeds NetBox.
func netboxRemoteUser() string {
	if u := strings.TrimSpace(os.Getenv("NETBOX_SUPERUSER")); u != "" {
		return u
	}
	return "admin"
}

func jwtSecret() string {
	if v := os.Getenv("JWT_SECRET"); v != "" {
		return v
	}
	// Last-resort fallback so the API doesn't refuse to start without env.
	// install.py always sets JWT_SECRET; this branch only matters for
	// rogue runs (e.g. `go run main.go` directly). ensureSigningSecret() makes
	// boot fail-closed (SR-017) unless ALLOW_DEV_SECRETS=true, so reaching this
	// fallback at runtime means dev mode was explicitly opted into.
	return devFallbackSecret
}

// devFallbackSecret is the publicly-known signing secret used ONLY when no
// JWT_SECRET is configured AND dev mode was opted into (ALLOW_DEV_SECRETS=true).
const devFallbackSecret = "dev-only-do-not-use-in-production" // #nosec G101 -- intentionally public placeholder, not a real credential; ensureSigningSecret fails closed unless ALLOW_DEV_SECRETS=true

// ensureSigningSecret fails the process closed (SR-017) when no JWT_SECRET is
// set. The fallback secret is public, and it also keys report/export capability
// links (report_links.go), so running with it in any real deployment lets anyone
// forge sessions and signed links. install.py always sets JWT_SECRET; the only
// way to hit the fallback is an unconfigured run, which must be an explicit
// dev-only opt-in via ALLOW_DEV_SECRETS=true. Call this at startup.
func ensureSigningSecret() error {
	if strings.TrimSpace(os.Getenv("JWT_SECRET")) != "" {
		return nil
	}
	if os.Getenv("ALLOW_DEV_SECRETS") == "true" {
		logWarn("auth", "JWT_SECRET unset — using the publicly-known dev fallback (ALLOW_DEV_SECRETS=true). NEVER use this outside local dev: sessions and report/export links are forgeable.", nil)
		return nil
	}
	return errors.New("JWT_SECRET is not set — refusing to start with the publicly-known dev fallback secret (it also signs report/export links). Set JWT_SECRET, or set ALLOW_DEV_SECRETS=true for local development only")
}
