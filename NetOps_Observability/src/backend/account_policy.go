package backend

// account_policy.go — main-side wiring for the F-68 account-lifecycle gate
// (internal/secpolicy, extracted P2 RA.2). The pure chokepoint
// (secpolicy.EvaluateAccountPolicy) and the password-history rules live in the
// package; this file keeps the live-store scope resolution and the HTTP
// response shape (403 for a hard denial — the credentials were RIGHT; 200 +
// must_change_password mirroring the mfa_required shape the SPA knows).

import (
	"errors"
	"net/http"
	"time"

	"netops/backend/internal/secpolicy"
)

// Aliases keep main's historical names for the auth/users call sites.
const (
	acctPolicyExpired         = secpolicy.ReasonAccountExpired
	acctPolicyInactive        = secpolicy.ReasonAccountInactive
	acctPolicyPasswordExpired = secpolicy.ReasonPasswordExpired
	acctPolicyFirstLogin      = secpolicy.ReasonFirstLogin

	passwordHistoryDepth = secpolicy.HistoryDepth
)

func checkPasswordHistory(ss SecuritySettings, u User, candidate string) error {
	return secpolicy.CheckPasswordHistory(ss, u, candidate)
}

func applyPasswordChange(u *User, hash string, now time.Time) {
	secpolicy.ApplyPasswordChange(u, hash, now)
}

func concurrentLoginDenied(ss SecuritySettings) bool { return secpolicy.ConcurrentLoginDenied(ss) }

// securitySettingsFor resolves the Security Settings governing one account: its
// tenant's scope, else the provider scope. Mirrors lockoutPolicy/sessionPolicy,
// including their convention that an unwired store (a minimal test server)
// yields the zero value — every rule off — rather than a panic.
func (s *server) securitySettingsFor(u User) SecuritySettings {
	if s.securitySettings == nil {
		return SecuritySettings{}
	}
	scope := ScopeProvider
	if u.TenantID != "" {
		scope = u.TenantID
	}
	return s.securitySettings.Get(scope)
}

// userTenantSuspended reports whether the ACCOUNT's tenant refuses sign-ins
// (deny-by-default tenant lifecycle). The platform owner / global realm is
// never suspendable, so the operator can never lock itself out. Shared by
// every login path — password, SSO, LDAP and TACACS. Distinct from
// tenantSuspended (tenancy.go), which gates a live request's jwtClaims — this
// one runs at login time, before any token exists.
func (s *server) userTenantSuspended(u User) bool {
	if u.TenantID == "" || u.TenantID == TenantGlobal || s.tenants == nil {
		return false
	}
	t, ok := s.tenants.Get(u.TenantID)
	return ok && t.EffectiveStatus() == TenantStatusSuspended
}

// federatedLoginBarrier runs the account-state gates a FEDERATED sign-in owes
// after the IdP proved the identity: tenant suspension and the hard
// account-lifecycle denials (account_validity_days, account_inactivity_days).
// The password-lifecycle soft rules cannot fire here — secpolicy exempts
// non-local accounts from them, and the IdP owns that credential anyway.
// Returns the refusal message ("" = proceed), mirroring handleLogin's logging
// and audit trail on refusal (#146b: these gates previously ran on local
// password logins only, so an expired or tenant-suspended account could still
// sign in through SSO/LDAP/TACACS).
func (s *server) federatedLoginBarrier(r *http.Request, u User) string {
	if s.userTenantSuspended(u) {
		logWarn("auth", "login refused: tenant suspended", map[string]any{"user": u.Username, "tenant_id": u.TenantID})
		return "tenant suspended"
	}
	d := secpolicy.EvaluateAccountPolicy(s.securitySettingsFor(u), u, time.Now().UTC())
	if d.Deny {
		logWarn("auth", "sign-in blocked by account policy", map[string]any{"user": u.Username, "reason": d.Reason})
		s.recordSessionEvent(r, "LOGIN_BLOCKED", u.Username, "", u.TenantID, map[string]any{"reason": d.Reason})
		return d.Message
	}
	return ""
}

// enforceAccountPolicy runs the gate and writes the response when the sign-in
// cannot proceed. Returns true when the caller should stop.
//
// A denial is 403 (the credentials were RIGHT — saying 401 would send the user
// back to retype a password that is not the problem). A must-change is 200 with
// must_change_password, mirroring the mfa_required shape the SPA already knows:
// identity is proven, the session is withheld pending a reset.
func (s *server) enforceAccountPolicy(w http.ResponseWriter, r *http.Request, u User) bool {
	d := secpolicy.EvaluateAccountPolicy(s.securitySettingsFor(u), u, time.Now().UTC())
	if !d.Blocked() {
		return false
	}
	logWarn("auth", "sign-in blocked by account policy", map[string]any{
		"user": u.Username, "reason": d.Reason,
	})
	s.recordSessionEvent(r, "LOGIN_BLOCKED", u.Username, "", u.TenantID, map[string]any{"reason": d.Reason})
	if d.Deny {
		writeError(w, http.StatusForbidden, errors.New(d.Message))
		return true
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"must_change_password": true,
		"reason":               d.Reason,
		"message":              d.Message,
		"username":             u.Username,
	})
	return true
}
