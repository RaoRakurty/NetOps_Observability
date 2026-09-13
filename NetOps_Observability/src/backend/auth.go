// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

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

	"netops/backend/internal/apikey"
	"netops/backend/internal/jwks"
	"netops/backend/internal/session"
	"netops/backend/internal/tenantlocator"
	"netops/backend/internal/token"
	"netops/backend/internal/users"
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

// roleFromScopes derives the RBAC role an API key principal acts under from its
// scope list. Keys are read-only by default; a write: scope grants operator-
// level write on the product modules, and admin:* grants super-admin. This keeps
// a key from ever exceeding what its scopes describe (see docs/API_ACCESS.md).
//
// EXCEPTION, tracker 254: a key whose scopes are EXCLUSIVELY `ingest:*` service
// scopes gets rbac.RoleIngest — a zero-permission grid. Such a key's authority
// comes entirely from the one gate that honours its ingest scope; everything
// else in the product refuses it.
//
// The defect this closes: the first-party RUM snippet's key is served inside a
// public web page, so it must be assumed public. Deriving RoleReadOnly for it
// made every read surface in the product — devices, flows, alerts, topology —
// readable by anyone who viewed source on the customer's own site. "Read-only"
// is not a small amount of authority when the credential is printed on a
// billboard.
func roleFromScopes(scopes []string) string {
	role := RoleReadOnly
	ingestOnly := len(scopes) > 0
	for _, s := range scopes {
		s = strings.ToLower(strings.TrimSpace(s))
		if !strings.HasPrefix(s, "ingest:") {
			ingestOnly = false
		}
		switch {
		case s == "admin:*":
			return RoleSuperAdmin
		case strings.HasPrefix(s, "write:"):
			role = RoleOperator
		}
	}
	if ingestOnly {
		return RoleIngest
	}
	return role
}

// ---- JWT / password crypto ------------------------------------------------
//
// The claims model, HS256 signer/verifier and PBKDF2 password hashing live in
// internal/token (the auth-crypto boundary). The alias keeps the 90+ in-package
// consumers source-compatible; the security property the old unexported
// actingTenant field carried (a token can never set the platform-owner
// override) is enforced by json:"-" on token.Claims.ActingTenant and pinned by
// TestCraftedTokenCannotSetActingTenant.

type jwtClaims = token.Claims

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
	// ID is the internal PRINCIPAL ID — the handle every /api/users mutation and
	// every audit actor uses (tracker 300 §4.7). The SPA keys rows and mutations
	// on it; the username is a display handle and, for a federated account, an
	// opaque string that is never shown.
	ID string `json:"id"`
	// IdentityStatus is the account's EXPLICIT migration state (owner Decision 2,
	// 2026-09-13) — a CLOSED three-value vocabulary the SPA switches on:
	//
	//	bound      — the account holds its canonical identity tuple.
	//	unresolved — it does not, and one could not be established offline. For an
	//	             oidc/saml account that is the documented waiting state (the
	//	             broker `sub` is not derivable); IdentityReason says which.
	//	ambiguous  — establishing it would have collided with another account's
	//	             identity. It was NEVER merged: a human has to decide.
	//
	// It replaces the inferred `pending` of the first cut. An admin can disable an
	// unresolved account if they do not want it bound at a later sign-in.
	IdentityStatus string `json:"identity_status,omitempty"`
	// IdentityReason is WHY, for an unresolved/ambiguous account
	// (provenance-unreconstructable | issuer-unavailable | tuple-claimed |
	// unknown-auth-source | pending-backfill). Empty for a bound account.
	IdentityReason string    `json:"identity_reason,omitempty"`
	Username       string    `json:"username"`
	Role           string    `json:"role"`
	Email          string    `json:"email,omitempty"`
	DisplayName    string    `json:"display_name,omitempty"`
	TenantID       string    `json:"tenant_id,omitempty"`
	Status         string    `json:"status,omitempty"`
	AuthSource     string    `json:"auth_source,omitempty"`
	MFAEnabled     bool      `json:"mfa_enabled"` // status only — the secret never leaves the server
	CreatedAt      time.Time `json:"created_at,omitempty"`
	LastLoginAt    time.Time `json:"last_login_at,omitempty"`
}

// identityStatusOf renders the STORED migration state (owner Decision 2). The
// store is the authority — this is a projection, not a second derivation, so the
// admin surface and the metrics can never disagree about an account.
func identityStatusOf(u User) string { return u.IdentityState() }

func toPublic(u User) publicUser {
	return publicUser{
		ID:             u.ID,
		IdentityStatus: identityStatusOf(u),
		IdentityReason: u.IdentityStateReason(),
		Username:       u.Username,
		Role:           u.Role,
		Email:          u.Email,
		DisplayName:    u.DisplayName,
		TenantID:       u.TenantID,
		Status:         u.Status,
		AuthSource:     u.AuthSource,
		MFAEnabled:     u.MFAEnabled,
		CreatedAt:      u.CreatedAt,
		LastLoginAt:    u.LastLoginAt,
	}
}

func (s *server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// SR-012: login is unauthenticated — bound its body tightly (credentials are
	// tiny). Pairs with the token.VerifyPassword length cap (SR-013).
	var req loginRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// Account lockout (best-effort, in-memory): reject while locked, before we even
	// check the password, so a brute-forcer can't keep guessing. Per the scope's
	// Security Settings (login_attempts_allowed / unlock_time_seconds).
	//
	// TWO KEYS, deliberately. The typed NAME is all that exists before the account
	// is resolved, so a spray against names that do not exist is still counted;
	// once the account IS resolved the PRINCIPAL ID is checked as well, because
	// every post-resolution stage (the MFA challenge, in particular) counts
	// against the id. Checking only the name would mean an account locked out by
	// repeated bad MFA codes still accepted password attempts — the F-25 hole
	// reopened by tracker 300's re-keying.
	if s.refuseWhileLocked(w, req.Username) {
		return
	}
	// LOCAL RESOLUTION (tracker 300 §2.5). A typed login name is NOT a principal
	// id any more: local accounts live in their own issuer namespace, keyed
	// (tenant, "local", lower(username)), so tenant A's `admin` and tenant B's
	// `admin` are two unrelated accounts.
	//
	//	per-tenant sign-in URL → LookupLocal in THAT tenant and no other
	//	generic sign-in page    → LookupLocalAny: one → proceed, none → 401,
	//	                          MANY → the same generic 401, audited
	//
	// The ambiguous case answers exactly like an unknown name, and the message
	// points at the organisation's own sign-in URL, because a reply that
	// distinguished "that name exists in several tenants" from "no such account"
	// would be a cross-tenant account-existence oracle.
	outcome := s.resolveLocalLogin(r, req.Username)
	if outcome.ambiguous > 0 {
		s.auditAmbiguousLocalLogin(r, outcome.ambiguous)
		// Counted like any other failed attempt: an attacker must not learn that
		// this name is special by watching the lockout counter stand still.
		allowed, unlock := s.lockoutPolicy(User{}, false)
		if !s.loginThrottle.Fail(req.Username, allowed, unlock) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests,
				errors.New("sign-in temporarily unavailable due to failed-login pressure; try again shortly"))
			return
		}
		writeError(w, http.StatusUnauthorized, errors.New(s.localLoginRefusal(r)))
		return
	}
	user, ok := outcome.user, outcome.found
	if ok && s.refuseWhileLocked(w, user.ID) {
		return
	}
	// throttleKey is what a failure counts against: the resolved PRINCIPAL when
	// there is one, the typed name when there is not.
	throttleKey := req.Username
	if ok {
		throttleKey = user.ID
	}
	if !ok || !token.VerifyPassword(req.Password, user.PasswordHash) {
		// Count the failure against the lockout policy for the account's scope.
		allowed, unlock := s.lockoutPolicy(user, ok)
		// F-25: an UNCOUNTED failure is an unlimited guess. The throttle used to
		// stop counting silently once its map was full, so a username spray turned
		// brute-force lockout off platform-wide. Now it says so, and we refuse the
		// attempt rather than serving a guess we cannot count.
		if !s.loginThrottle.Fail(throttleKey, allowed, unlock) {
			w.Header().Set("Retry-After", "60")
			writeError(w, http.StatusTooManyRequests,
				errors.New("sign-in temporarily unavailable due to failed-login pressure; try again shortly"))
			return
		}
		// Generic message: don't leak whether the username exists — and it is the
		// SAME sentence the ambiguous case gets, so the pair is not an oracle
		// either (localLoginRefusal).
		writeError(w, http.StatusUnauthorized, errors.New(s.localLoginRefusal(r)))
		return
	}
	// Clear BOTH counters: the proof of the password clears the account's own
	// record, and the typed name's record with it, so a mistyped tenant followed
	// by the right sign-in does not leave a half-full counter behind.
	s.loginThrottle.Success(user.ID)
	s.loginThrottle.Success(req.Username)
	// A disabled account cannot sign in — parity with the refresh / MFA / SSO /
	// LDAP / TACACS paths, which all reject status=="disabled". Checked AFTER the
	// password verifies, so an unauthenticated probe can't use it to enumerate
	// accounts (a wrong password still returns the generic error above).
	if user.Status == "disabled" {
		logWarn("auth", "login refused: account disabled", map[string]any{"user": user.ID})
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	// A SUSPENDED tenant blocks its users from signing in (deny-by-default tenant
	// lifecycle; see userTenantSuspended for the never-lock-out-the-operator rule).
	if s.userTenantSuspended(user) {
		logWarn("auth", "login refused: tenant suspended", map[string]any{"user": user.ID, "tenant_id": user.TenantID})
		writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
		return
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
	if token.PasswordNeedsRehash(user.PasswordHash) {
		if err := s.users.RehashPassword(user.ID, req.Password); err != nil {
			logWarn("auth", "password rehash-on-login failed", map[string]any{"user": user.ID, "err": err.Error()})
		}
	}
	// MFA gate: an enrolled (local) user gets a short-lived challenge instead of a
	// session — they complete it at /api/auth/mfa/login with a one-time code.
	if user.MFAEnabled {
		now := time.Now()
		ch, err := token.Sign(jwtClaims{
			Sub: user.ID, Scopes: []string{mfaChallengeScope},
			Iat: now.Unix(), Exp: now.Add(mfaChallengeTTL).Unix(),
		}, jwtSecret())
		if err != nil {
			writeError(w, http.StatusInternalServerError, err)
			return
		}
		logInfo("auth", "mfa challenge issued", map[string]any{"user": user.ID})
		writeJSON(w, http.StatusOK, map[string]any{"mfa_required": true, "mfa_token": ch})
		return
	}
	s.issueSession(w, r, user)
}

// refuseWhileLocked answers 429 when `key` is currently locked out, and reports
// whether it did. One helper so the pre- and post-resolution checks cannot drift
// on the status code, the Retry-After or the wording.
func (s *server) refuseWhileLocked(w http.ResponseWriter, key string) bool {
	if strings.TrimSpace(key) == "" {
		return false
	}
	locked, d := s.loginThrottle.Locked(key)
	if !locked {
		return false
	}
	w.Header().Set("Retry-After", intToString(int(d.Seconds())+1))
	writeError(w, http.StatusTooManyRequests, errors.New("account temporarily locked due to failed sign-ins; try again later"))
	return true
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
// #24 policy engine then layers PER-ROLE / PER-USER refinement on top — but only
// an EXPLICIT override (not the catalog default) applies, and only if it is
// STRICTER (shorter window), so a tighter policy can harden but never loosen the
// scope's. username feeds the Subject's user dimension (mirroring
// callerPasswordRules) — without it, a per-user override written via the policy
// API was silently ignored at login. Falls back to standard defaults when
// neither store is wired (a minimal test server).
func (s *server) sessionPolicy(tenant, role, username string) (idle, absolute time.Duration, enforceIdle, enforceAbsolute bool) {
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
		sub := policy.Subject{Tenant: tenant, Role: role, User: username}
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
	access, refresh, _, err = s.mintSessionWithID(r, user)
	return access, refresh, err
}

// mintSessionWithID is mintSession plus the session id it opened. Only the
// elevation SSO path needs it: that path writes one more durable artefact AFTER
// the session exists, and a failure there has to be able to close the session it
// is abandoning rather than leave an unreachable one behind (§10 — no silent
// failures, and no orphan artefacts from a sign-in the server refused).
func (s *server) mintSessionWithID(r *http.Request, user User) (access, refresh, sid string, err error) {
	ttl := accessTokenTTL()
	if s.sessions != nil {
		idle, absolute, enforceIdle, enforceAbsolute := s.sessionPolicy(user.TenantID, user.Role, user.ID)
		if !enforceIdle {
			idle = 0 // 0 = disabled at the Validate gate
		}
		if !enforceAbsolute {
			absolute = 0
		}
		sess, evicted, e := s.sessions.Create(user.ID, clientIP(r).String(), r.UserAgent(), idle, absolute)
		if e != nil {
			return "", "", "", e
		}
		sid = sess.ID
		s.recordSessionEvent(r, "SESSION_CREATED", user.ID, sid, user.TenantID, map[string]any{
			"idle_min": int(idle.Minutes()), "absolute_min": int(absolute.Minutes()),
		})
		for _, ev := range evicted { // concurrent-session cap evictions
			s.recordSessionEvent(r, "SESSION_REVOKED", user.ID, ev, user.TenantID, map[string]any{"reason": "max_sessions"})
		}
	}
	access, err = token.Sign(jwtClaims{
		Sub: user.ID, Role: user.Role, Tenant: user.TenantID, Sid: sid,
		Iat: time.Now().Unix(), Exp: time.Now().Add(ttl).Unix(),
	}, jwtSecret())
	if err != nil {
		return "", "", "", err
	}
	refresh, err = s.refresh.IssueForSession(user.ID, sid)
	if err != nil {
		return "", "", "", err
	}
	return access, refresh, sid, nil
}

// abandonSession closes a session whose tokens were never handed to the client
// because a LATER step of the same sign-in failed. Best-effort by necessity —
// the store may be the thing that is broken — but never silent: a session that
// could not be closed is logged at error, because it is a live credential the
// operator was told they did not get.
func (s *server) abandonSession(r *http.Request, user User, sid, reason string) {
	if s.sessions == nil || sid == "" {
		return
	}
	if _, err := s.sessions.Revoke(sid); err != nil {
		logError("auth", "abandoned session could not be closed", map[string]any{
			"user": user.ID, "session_id": sid, "reason": reason, "err": err.Error()})
		return
	}
	s.recordSessionEvent(r, "SESSION_REVOKED", user.ID, sid, user.TenantID,
		map[string]any{"reason": reason})
}

// issueSession mints a session and returns the standard JSON login response
// (also refreshing the console gate cookie). Shared by password login and
// MFA-challenge completion (handleMFALogin).
// enforceConcurrentLoginDeny applies F-68 concurrent_login=deny — one live
// session per account. Prior sessions are revoked BEFORE minting, so the new
// session is never the one culled. Last-login-wins (rather than refusing the
// new sign-in) is the deliberate reading: an operator locked out by their own
// stale session on a closed laptop is a support ticket, not a security
// control. Returns an error when the revoke did not persist: minting a second
// session then would leave two usable ones — the exact state the policy
// forbids. Shared by issueSession (password/MFA/LDAP/TACACS) and the SSO
// callback (#146b: SSO previously bypassed this policy entirely).
func (s *server) enforceConcurrentLoginDeny(r *http.Request, user User) error {
	if s.sessions == nil || !concurrentLoginDenied(s.securitySettingsFor(user)) {
		return nil
	}
	n, err := s.sessions.RevokeAllForUser(user.ID)
	if err != nil {
		logError("auth", "concurrent-login revoke did not persist", map[string]any{"user": user.ID, "err": err.Error()})
		return errors.New("sign-in could not be completed; prior sessions could not be closed")
	}
	if n > 0 {
		logInfo("auth", "concurrent sessions revoked by policy", map[string]any{"user": user.ID, "count": n})
		s.recordSessionEvent(r, "SESSION_REVOKED", user.ID, "", user.TenantID,
			map[string]any{"reason": "concurrent_login_deny", "count": n})
	}
	return nil
}

func (s *server) issueSession(w http.ResponseWriter, r *http.Request, user User) {
	if err := s.enforceConcurrentLoginDeny(r, user); err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	ttl := accessTokenTTL()
	tok, refresh, err := s.mintSession(r, user)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	s.users.TouchLogin(user.ID)
	setOSDCookie(w, r, tok, ttl) // /search gate cookie (enforced for platform owner only)
	logInfo("auth", "login ok", map[string]any{"user": user.ID, "role": user.Role})
	writeJSON(w, http.StatusOK, loginResponse{
		Token: tok, RefreshToken: refresh, ExpiresIn: int(ttl.Seconds()), User: toPublic(user),
	})
}

// completeFederatedLogin finishes a TACACS+/LDAP sign-in after the external
// server verified the credentials: resolve the account from the CANONICAL TUPLE
// the door verified, run the same account-state gates as handleLogin, and issue
// the session. Shared by handleTACACSLogin and handleLDAPLogin so the two JSON
// federated front doors cannot drift.
//
// It takes a users.Assertion rather than a bag of strings (tracker 300): the
// door's job is to say WHAT IT VERIFIED — which directory, and which subject in
// it — and the store's job is to resolve that to an account. A login name
// reaches the store only as a profile attribute and as the §2.6
// LegacyUsername, never as a key.
//
// THE UNBOUND FORM is used because there is exactly one platform-global LDAP and
// one platform-global TACACS+ configuration today, so one directory legitimately
// signs in users of every tenant and the account's own tenant is authoritative.
// The seam for per-tenant directories is the bound form, already implemented;
// when they arrive, the realm is threaded down here.
//
// H1: the store REFUSES (users.ErrLocalAccount) an assertion that names the
// local namespace or whose tuple points at a locally-managed account — accepting
// the IdP's verdict against a local record would bypass the local password AND
// its MFA enrollment. 403: the IdP credentials were right; this account just
// isn't federated — sign in locally instead.
func (s *server) completeFederatedLogin(w http.ResponseWriter, r *http.Request, a users.Assertion) {
	source := a.Protocol
	user, err := s.users.ResolveFederatedUnbound(a)
	if err != nil {
		status, msg, reason := identityRefusal(err)
		logWarn("auth", "federated login refused", map[string]any{"src": source, "reason": reason})
		writeError(w, status, errors.New(msg))
		return
	}
	s.logBindingSync(user, source) // PBAC Phase A: mirror the provisioned identity
	if user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account disabled"))
		return
	}
	// #146b parity: tenant suspension + hard account-lifecycle denials, same
	// as the password path (403: the credentials were right).
	if msg := s.federatedLoginBarrier(r, user); msg != "" {
		writeError(w, http.StatusForbidden, errors.New(msg))
		return
	}
	logInfo("auth", "login ok", map[string]any{"user": user.ID, "role": user.Role, "src": source})
	s.issueSession(w, r, user) // server-side session + tokens (same as password login)
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
			code := session.ErrorCode(verr)
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
	// The refresh store is keyed by the internal PRINCIPAL ID (§4.2) — legacy
	// rows carry `id == lower(username)`, so no stored token changes meaning.
	newRefresh, principalID, sid, err := s.refresh.RotateSession(req.RefreshToken)
	if err != nil {
		writeError(w, http.StatusUnauthorized, err)
		return
	}
	user, ok := s.users.Get(principalID)
	if !ok || user.Status == "disabled" {
		writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
		return
	}
	if sid != "" && s.sessions != nil {
		s.sessions.Touch(sid) // record activity at the refresh boundary
		s.recordSessionEvent(r, "SESSION_REFRESHED", user.ID, sid, user.TenantID, nil)
	}
	ttl := accessTokenTTL()
	tok, err := token.Sign(jwtClaims{
		Sub: user.ID, Role: user.Role, Tenant: user.TenantID, Sid: sid,
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
	//
	// Tracker 300: the two modes resolve DIFFERENTLY and must. An authenticated
	// caller is named by its token, whose `sub` IS the principal id. The
	// pre-auth login-window form types a LOCAL LOGIN NAME, which is only unique
	// per tenant — so it goes through the same §2.5 resolution handleLogin uses,
	// including the generic refusal for a name several tenants hold.
	var (
		user   User
		ok     bool
		authed bool
	)
	// Generic credential error so the pre-auth path doesn't enumerate usernames;
	// the authed path keeps the clearer "current password incorrect".
	badCreds := errors.New("invalid username or password")
	if claims, cok := userFrom(r.Context()); cok {
		authed = true
		badCreds = errors.New("current password incorrect")
		user, ok = s.users.Get(claims.Sub)
	} else {
		if strings.TrimSpace(req.Username) == "" {
			writeError(w, http.StatusUnauthorized, errors.New("not authenticated"))
			return
		}
		outcome := s.resolveLocalLogin(r, req.Username)
		if outcome.ambiguous > 0 {
			s.auditAmbiguousLocalLogin(r, outcome.ambiguous)
			writeError(w, http.StatusUnauthorized, errors.New(s.localLoginRefusal(r)))
			return
		}
		user, ok = outcome.user, outcome.found
	}
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
	if !token.VerifyPassword(req.CurrentPassword, user.PasswordHash) {
		writeError(w, http.StatusUnauthorized, badCreds)
		return
	}
	// Enforce the account's resolved Security Policy (length + complexity) before
	// the store's own floor — zero-trust, server-authoritative (#24 wiring).
	rules := s.callerPasswordRules(jwtClaims{Sub: user.ID, Role: user.Role, Tenant: user.TenantID})
	if err := validatePasswordAgainstPolicy(req.NewPassword, rules); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}
	// No-reuse: the new password must differ from the current one.
	if token.VerifyPassword(req.NewPassword, user.PasswordHash) {
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
	if err := s.users.ChangePassword(user.ID, req.NewPassword); err != nil {
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
		n, err := s.sessions.RevokeAllForUser(user.ID)
		if err != nil {
			sessionsRevoked = false
			logError("auth", "password change: session revoke did not persist — old sessions may survive a restart",
				map[string]any{"user": user.ID, "err": err.Error()})
		} else if n > 0 {
			s.recordSessionEvent(r, "SESSION_REVOKED", user.ID, "", user.TenantID, map[string]any{"reason": "password_change", "count": n})
		}
	}
	logInfo("auth", "password changed", map[string]any{"user": user.ID, "pre_auth": !authed})
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
	"/api/auth/locator", // resolves a per-tenant sign-in URL to a candidate realm; grants nothing
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
		// One predicate, shared with the body-limit middleware (isPublicPath), so
		// "reachable without a Bearer token" and "capped at the pre-auth size"
		// can never drift apart — and a public route added in one place is
		// public in both.
		if isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)
			return
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
		// vmalert's notifier POSTs alerts here with no JWT (it is a Go
		// evaluator, not a browser session). The handler authenticates via the
		// VMALERT_WEBHOOK_TOKEN shared secret — Bearer or Basic, constant-time
		// compared — BEFORE it parses a body or touches any state, and the
		// route is not registered at all when that secret is unset
		// (fail-closed). publicPaths cannot be used: it is an EXACT match and
		// vmalert appends /api/v2/alerts to the base url it is given.
		//
		// Body cap: a HasPrefix escape does NOT get requestBodyLimit's
		// pre-auth route-class cap (isPublicPath is exact-match too), so the
		// handler's own http.MaxBytesReader (1 MiB, alertwebhook.maxBodyBytes)
		// is the ONLY bound on this body. Do not remove it.
		if strings.HasPrefix(r.URL.Path, "/api/internal/vmalert/") {
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
		// WebSocket authentication: ONE-TIME TICKET, never a session credential.
		//
		// A browser cannot set an Authorization header on a WebSocket, so this
		// used to accept ?token=<session JWT> for /api/events and the device-SSH
		// gateway. nginx logs the request line, so every device-terminal open
		// wrote a privileged, reusable, still-valid JWT into the log pipeline
		// (stdout → Vector → OpenSearch) — turning "can read logs" into "can act
		// as that operator" for the token's remaining lifetime.
		//
		// Now the browser first POSTs /api/devices/{id}/ssh-ticket over ordinary
		// authenticated HTTPS and opens the socket with ?ticket=<opaque>. The
		// ticket is single-use, ~30s, and bound to tenant/user/device/purpose, so
		// a logged ticket is worthless. Redemption is atomic (delete-under-lock),
		// so a replayed or concurrently-raced ticket yields exactly one winner.
		//
		// /api/events no longer accepts a query credential at all: it is a
		// WebSocket hub that no shipped client opens (the SPA calls the REST
		// /api/events/feed with an Authorization header), so an unused credential
		// transport was retired rather than left standing. A future browser
		// consumer adopts the ticket flow with its own purpose.
		var bearer string
		if strings.HasPrefix(r.URL.Path, "/api/devices/") && strings.HasSuffix(r.URL.Path, "/ssh") {
			if raw := r.URL.Query().Get("ticket"); raw != "" && s.wsTickets != nil {
				if tkt, ok := s.wsTickets.Consume(raw, time.Now()); ok {
					claims := s.withActingTenant(r, jwtClaims{
						Sub: tkt.UserID, Role: tkt.Role, Tenant: tkt.TenantID,
					})
					// Ticket redemption owes the same per-request account gates as
					// the JWT path below: a ticket minted seconds before an admin
					// disabled the user (or suspended the tenant) must not open a
					// device session. The ticket carries no Sid, so session-active
					// cannot be checked here — that is a separate design item, not
					// something to fake with a lookup the ticket doesn't bind.
					if u, uok := s.users.Get(tkt.UserID); !uok || u.Status == "disabled" {
						writeError(w, http.StatusUnauthorized, errors.New("account unavailable"))
						return
					}
					if s.tenantSuspended(claims) {
						writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
						return
					}
					ctx := context.WithValue(r.Context(), wsTicketCtxKey, tkt)
					ctx = context.WithValue(ctx, userCtxKey, claims)
					next.ServeHTTP(w, r.WithContext(ctx))
					return
				}
				// Burned, expired or unknown: refuse here. Falling through to
				// another credential would defeat the single-use property.
				writeError(w, http.StatusUnauthorized, errors.New("websocket ticket invalid, expired or already used"))
				return
			}
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
		if strings.HasPrefix(bearer, apikey.KeyPrefix) {
			k, ok := s.apiKeys.Verify(bearer)
			if !ok {
				writeError(w, http.StatusUnauthorized, errors.New("invalid or revoked API key"))
				return
			}
			// Source-IP allow-list (NetOps extension). Reject calls from outside
			// the key's permitted CIDRs without authenticating.
			if !k.SourceAllowed(clientIP(r)) {
				writeError(w, http.StatusForbidden, errors.New("source address not permitted for this API key"))
				return
			}
			// Per-key rate limit (fixed window / minute). 429 + Retry-After when
			// the key exceeds its cap; surfaced live in Administration → API Access.
			if ok, retry := s.apiKeys.Allow(k.ID, s.apiKeys.EffectiveLimit(k)); !ok {
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
			// M7: re-check suspension on the EFFECTIVE tenant — withActingTenant
			// rewrites a non-owner's tenant (as_tenant / X-Acting-Tenant into a
			// reachable tenant), and a suspended tenant must stay closed through
			// the switcher, not just for principals whose TOKEN names it.
			eff := s.withActingTenant(r, claims)
			if s.tenantSuspended(eff) {
				writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, eff)
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
			// M7: the suspension check above ran on the TOKEN tenant, but
			// withActingTenant may rewrite a non-owner's tenant (the multi-tenant
			// switcher, as_tenant / X-Acting-Tenant into any reachable tenant).
			// Re-evaluate on the EFFECTIVE tenant, or an org-admin/MSP principal
			// keeps a side door into a tenant the platform just suspended. The
			// platform owner is exempt inside tenantSuspended by design (it must
			// reach a suspended tenant to reactivate it).
			eff := s.withActingTenant(r, claims)
			if s.tenantSuspended(eff) {
				writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
				return
			}
			ctx := context.WithValue(r.Context(), userCtxKey, eff)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		// Otherwise, if SSO is configured, accept a Keycloak-signed RS256 Bearer
		// (service accounts / direct API clients) verified against its JWKS. The
		// verified token proves the IDENTITY only; bearerPrincipal then applies
		// the stored-account gates (H2) so this path cannot outlive or outrank
		// what the account store says about the principal.
		if op := s.oidcProvider(); op.Ready() {
			if oc, verr := op.VerifyBearer(bearer); verr == nil {
				claims, status, berr := s.bearerPrincipal(r, op, oc)
				if berr != nil {
					writeError(w, status, berr)
					return
				}
				// M7: suspension on the EFFECTIVE tenant, same as the branches above.
				eff := s.withActingTenant(r, claims)
				if s.tenantSuspended(eff) {
					writeError(w, http.StatusForbidden, errors.New("tenant suspended"))
					return
				}
				ctx := context.WithValue(r.Context(), userCtxKey, eff)
				next.ServeHTTP(w, r.WithContext(ctx))
				return
			}
		}
		writeError(w, http.StatusUnauthorized, err)
	})
}

// bearerPrincipal resolves an IdP-verified RS256 bearer (service accounts /
// direct API clients) into request claims, applying the SAME stored-account
// gates the HS256 session branch enforces inline (H2). Before this helper the
// branch minted claims purely from the IdP token: a DISABLED account kept API
// access for the token's whole lifetime, the STORED tenant/role (an operator's
// tenant move or demotion) were ignored in favour of OIDC_DEFAULT_TENANT plus
// the raw IdP role mapping, and the federatedLoginBarrier lifecycle gates
// (tenant suspension, account validity/inactivity) never ran here at all.
//
//   - Known user → the STORED account is authoritative: disabled → 401, and the
//     stored tenant/role are what the request acts as. A LOCAL account (H1,
//     isLocalAccount — "" counts as local) is refused outright: an IdP identity
//     must never act as a colliding local account, which would bypass its
//     password and MFA enrollment.
//   - Unknown identity → JIT-provision through ResolveFederatedUnbound, exactly
//     like the interactive SSO callback (same canonical tuple, same SR-025
//     guardFederatedRole downgrade via the store's Deps.GuardRole, same JIT
//     tenant default), so a bearer token and an ID token from one broker name
//     the SAME principal.
//   - RequireMFA is honoured for USER tokens: the IdP must assert a second
//     factor (amr/acr), as the SSO callback demands. Tokens carrying an azp
//     (authorized-party/client id) claim are treated as service-account
//     (client-credentials) grants and exempted — a machine principal has no
//     interactive second factor. Deliberate trade-off, documented here: an IdP
//     that stamps azp on user tokens too (Keycloak often does) bypasses this
//     check for them; the interactive login path still enforces it, and the
//     bearer path never mints a session.
func (s *server) bearerPrincipal(r *http.Request, op *oidcProvider, oc jwks.Claims) (jwtClaims, int, error) {
	if strings.TrimSpace(oc.Sub) == "" {
		return jwtClaims{}, http.StatusUnauthorized, errors.New("bearer token carried no usable subject")
	}
	if op.RequireMFA() && oc.Azp == "" && !op.MFASatisfied(oc) {
		logWarn("auth", "bearer rejected — MFA required but not asserted by IdP", map[string]any{"sub": oc.Sub, "amr": oc.Amr, "acr": oc.Acr})
		return jwtClaims{}, http.StatusUnauthorized, errors.New("multi-factor authentication is required — token does not assert a second factor")
	}
	// THE KEY IS (tenant, iss, sub) — tracker 300. It used to be
	// firstNonEmpty(preferred_username, email, sub) used as a GLOBAL account key,
	// which is why two tokens carrying the same `preferred_username` from
	// different principals landed in one account, and why renaming a person at
	// the IdP minted a second one.
	//
	// The UNBOUND form is the right one here, and only here: this branch consults
	// `s.oidcProvider()`, the single platform relying-party connection through
	// which per-tenant IdPs are BROKERED, so one config legitimately signs in
	// users of every tenant and the account's own tenant is authoritative. It
	// resolves (issuer, subject) across tenants and REFUSES an ambiguous match
	// rather than picking one — the takeover the old global-username lookup made
	// possible is now a typed refusal instead of a successful-looking sign-in.
	//
	// H2 is unchanged: the STORED account decides tenant, role and status.
	// ResolveFederatedUnbound returns a disabled account AS IS, and the gates
	// below refuse it.
	u, err := s.users.ResolveFederatedUnbound(bearerAssertion(op, oc))
	if err != nil {
		status, msg, reason := identityRefusal(err)
		logWarn("auth", "bearer refused", map[string]any{"sub": oc.Sub, "reason": reason})
		return jwtClaims{}, status, errors.New(msg)
	}
	// A first sight provisioned an account: mirror it (PBAC Phase A). A tuple hit
	// re-mirrors too, which is harmless (the mirror is idempotent) and keeps the
	// binding in step with a role the IdP has since remapped.
	s.logBindingSync(u, "oidc")
	if u.Status == "disabled" {
		return jwtClaims{}, http.StatusUnauthorized, errors.New("account unavailable")
	}
	// #146b parity: tenant suspension + hard account-lifecycle denials, exactly
	// what the interactive federated logins run (403: the token was valid).
	if msg := s.federatedLoginBarrier(r, u); msg != "" {
		return jwtClaims{}, http.StatusForbidden, errors.New(msg)
	}
	// The JWT subject is the internal PRINCIPAL ID (§4.1), which every downstream
	// consumer — sessions, bindings, audit actor, API handles — now keys on.
	return jwtClaims{Sub: u.ID, Role: u.Role, Tenant: u.TenantID}, 0, nil
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
	if r.URL.Query().Get("c") == "search" && len(s.tenants.RestrictedIDs()) > 0 {
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

// ---------------------------------------------------------------------------
// TRACKER 300 IDENTITY NAMESPACING — see docs/design/IDENTITY_NAMESPACING_2026-09-13.md
//
// One rule, restated where it is applied: a principal is identified by
// **tenant_id + issuer + subject**, never by a username and never by an e-mail.
// Each door hands the store exactly what it VERIFIED — the issuer it checked the
// signature against and the subject that issuer asserted — and lets
// internal/users resolve it. preferred_username, e-mail and a directory login
// name travel as PROFILE attributes; the one place a username is still consulted
// is Assertion.LegacyUsername, which feeds only the bounded §2.6 lazy bind.
// ---------------------------------------------------------------------------

// bearerAssertion is the RS256 service-account / direct-API door. Same issuer
// and subject as the interactive callback — a bearer token and an ID token from
// one broker name the SAME principal, which is the point of keying on the tuple.
func bearerAssertion(op *oidcProvider, oc jwks.Claims) users.Assertion {
	return users.Assertion{
		Identity: users.Identity{
			TenantID: op.DefaultTenant(),
			Issuer:   op.Issuer(),
			Subject:  oc.Sub,
			Protocol: users.ProtocolOIDC,
		},
		Email:          oc.Email,
		DisplayName:    firstNonEmpty(oc.Name, oc.PreferredUsername, oc.Email),
		Role:           op.RoleFor(oc),
		LegacyUsername: legacyOIDCUsername(oc),
	}
}

// ---- local login resolution (§2.5) ----------------------------------------

// loginRealmTenant is the tenant a LOCAL sign-in is scoped to: the one named by
// the per-tenant entry URL the browser is on (the signed candidate cookie, which
// the server armed — never a value the browser asserted). An /org/{id} entry
// names a realm but not ONE tenant, so it resolves nothing here and the sign-in
// falls through to the cross-tenant form.
func (s *server) loginRealmTenant(r *http.Request) (string, bool) {
	c, ok := s.locatorCandidate(r)
	if !ok || c.Kind != tenantlocator.KindTenant || strings.TrimSpace(c.TenantID) == "" {
		return "", false
	}
	return c.TenantID, true
}

// localLoginOutcome is the result of resolving a typed login name to ONE local
// account. `ambiguous` means the name exists in more than one tenant and the
// per-tenant sign-in URL is the disambiguator.
type localLoginOutcome struct {
	user      User
	found     bool
	ambiguous int // how many tenants hold the name (0 unless ambiguous)
}

// resolveLocalLogin is design §2.5's local resolution, and the only place a
// typed login name becomes an account.
//
//	tenant named by the entry URL → LookupLocal, that tenant and no other
//	no tenant                     → LookupLocalAny: one → proceed; none → unknown;
//	                                MANY → ambiguous, which the caller refuses
//	                                with the SAME generic 401 an unknown name
//	                                gets. Distinguishing them would be a
//	                                cross-tenant account-existence oracle.
//
// Federated accounts are unreachable from here by construction: LookupLocal*
// resolve the `local` issuer namespace, and a federated account has no local
// login handle at all (its username IS its opaque id).
func (s *server) resolveLocalLogin(r *http.Request, name string) localLoginOutcome {
	if strings.TrimSpace(name) == "" {
		return localLoginOutcome{}
	}
	if tenant, ok := s.loginRealmTenant(r); ok {
		u, found := s.users.LookupLocal(tenant, name)
		return localLoginOutcome{user: u, found: found}
	}
	matches, ok := s.users.LookupLocalAny(name)
	switch {
	case !ok || len(matches) == 0:
		return localLoginOutcome{}
	case len(matches) == 1:
		return localLoginOutcome{user: matches[0], found: true}
	default:
		return localLoginOutcome{ambiguous: len(matches)}
	}
}

// auditAmbiguousLocalLogin records a sign-in refused because the typed name
// exists in several tenants. It records the COUNT and never the tenants or the
// name's owners: the event has to be investigable without becoming the oracle
// the generic refusal exists to prevent.
func (s *server) auditAmbiguousLocalLogin(r *http.Request, count int) {
	logWarn("auth", "login refused: local login name exists in more than one tenant — the per-tenant sign-in URL is the disambiguator",
		map[string]any{"tenants": count})
	if s.audit == nil {
		return
	}
	s.audit.Record(AuditEvent{
		Method:   "LOGIN",
		Path:     "/login.ambiguous_local_identity",
		Decision: "deny",
		Remote:   auditClientIP(r),
		Detail:   map[string]any{"action": "login.ambiguous_local_identity", "tenants": count},
	})
}

// The two refusals a LOCAL sign-in can give, and the rule that keeps them from
// becoming an oracle: EVERY 401 at this door says the same thing for a given
// REQUEST, whatever the reason. An unknown name, a wrong password and a name held
// by several tenants are indistinguishable, so none of them can be used to probe
// for accounts across the platform.
//
// The hint is attached on the GENERIC sign-in page only, where it is the actual
// remedy for the ambiguous case (design §2.5: "the per-tenant sign-in URL is the
// disambiguator") and harmless advice for the other two. It depends on the URL
// the browser is on, never on the account — which is what stops it from carrying
// information about anybody.
const (
	localLoginRefusalPlain = "invalid username or password"
	localLoginRefusalHint  = "invalid username or password — if your organisation has its own sign-in address, use that"
)

// localLoginRefusal is the ONE sentence this door answers 401 with.
func (s *server) localLoginRefusal(r *http.Request) string {
	if _, named := s.loginRealmTenant(r); named {
		return localLoginRefusalPlain
	}
	return localLoginRefusalHint
}

// ---- refusal mapping ------------------------------------------------------

// identityRefusal maps a store refusal onto (status, browser message, log
// reason). ONE mapping for every door, so the JSON doors and the redirecting SSO
// door cannot drift apart on what a refusal says.
//
// ErrForeignTenant is deliberately absent: it is answered by
// ssoRefuseForeignRealm, which says only what a mis-registered provider is told.
// Callers handle it before calling this.
func identityRefusal(err error) (int, string, string) {
	switch {
	case errors.Is(err, users.ErrLocalAccount):
		// The tuple, or the namespace it names, belongs to a LOCALLY-managed
		// account. 403: the IdP credentials were right, this account just is not
		// federated. Not split into two sentinels (store open question 4) —
		// "the assertion named the local issuer" is a door bug and "the tuple
		// points at a local record" is a corrupt index; both are the same
		// refusal and the same message, and splitting them would only add a
		// branch no door can act on differently.
		return http.StatusForbidden,
			"this account is managed locally; sign in with your local password",
			"account is managed locally"
	case errors.Is(err, users.ErrAmbiguousIdentity):
		// The same (issuer, subject) resolves to more than one reachable account.
		// Refused GENERICALLY — naming the tenants would be a cross-tenant
		// existence oracle — and never guessed (owner rule 6).
		return http.StatusForbidden,
			"your identity could not be resolved to a single account; contact your administrator",
			"identity is ambiguous across tenants"
	case errors.Is(err, users.ErrNoSuchUser):
		return http.StatusForbidden, "no account is linked to this identity", "no account for this identity"
	case errors.Is(err, users.ErrIdentityConflict):
		return http.StatusConflict, "sign-in could not be completed; please try again", "identity conflict"
	}
	return http.StatusInternalServerError, "provisioning failed", err.Error()
}

// userDisplayLabel is the SERVER-SIDE twin of the SPA's userLabel (src/frontend/
// src/lib/userLabel.ts): what to call a person on screen, never an opaque id.
//
// A federated account's username IS its `fed_<tenant>_<hash>` principal id, so
// showing it would put a meaningless hash where an operator expects a name. Any
// surface that ships a label for a user — the session list is the one today —
// goes through this, so the rule lives in one place per side of the wire.
func userDisplayLabel(u User) string {
	if d := strings.TrimSpace(u.DisplayName); d != "" {
		return d
	}
	if isLocalAccount(u.AuthSource) {
		if n := strings.TrimSpace(u.Username); n != "" {
			return n
		}
	}
	return strings.TrimSpace(u.Email)
}
