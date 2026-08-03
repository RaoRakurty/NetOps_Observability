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
