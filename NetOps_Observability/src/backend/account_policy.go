package main

// account_policy.go — F-68: the account-lifecycle half of Security Settings.
//
// Seven settings were stored, rendered by the SPA as working controls, and read
// by NOTHING. Measured 2026-07-21, non-test read sites per field:
//
//	password_expire_enabled  0    account_validity_days    0
//	password_expire_days     0    account_inactivity_days  0
//	password_history         0    concurrent_login         0
//	reset_on_first_login     0
//
// Three siblings in the SAME struct ARE enforced — length/complexity
// (password_policy.go), lockout (auth.go lockoutPolicy), session timeouts
// (auth.go sessionPolicy). That is precisely what made the other seven
// credible: the page is right about three quarters of itself. A customer can
// answer a SOC2/PCI questionnaire "90-day expiry and inactivity lockout are
// enforced" and cite the product's own settings page as evidence. Nothing
// expired. Nothing locked.
//
// The fix is a single chokepoint rather than seven scattered checks, because
// the audit's one-line diagnosis is that this codebase fixes instances and not
// classes. evaluateAccountPolicy is pure — no clock, no IO, no store — so the
// rules are testable without a server, and account_policy_test.go exercises
// every branch. settings_reachability_test.go then fails the build if any
// SecuritySettings field ever returns to zero read sites.

import (
	"errors"
	"net/http"
	"strings"
	"time"
)

// passwordHistoryDepth bounds User.PasswordHistory. Unbounded history is the
// §9 "all queues must be bounded" violation in miniature: it rides in the user
// record, which is read on every login.
const passwordHistoryDepth = 5

// Machine-readable outcomes. The SPA branches on these; humans read Message.
const (
	acctPolicyExpired         = "account_expired"
	acctPolicyInactive        = "account_inactive"
	acctPolicyPasswordExpired = "password_expired"
	acctPolicyFirstLogin      = "password_reset_required"
)

// accountPolicyDecision is what the gate concluded. Deny and MustChange are
// distinct outcomes: Deny refuses the sign-in outright, MustChange lets the
// caller prove its identity but withholds the session until the password is
// reset. Collapsing them would either lock out every expiring user or let an
// expired account keep working.
type accountPolicyDecision struct {
	Deny       bool
	MustChange bool
	Reason     string
	Message    string
}

func (d accountPolicyDecision) blocked() bool { return d.Deny || d.MustChange }

// evaluateAccountPolicy applies the seven account-lifecycle settings to one
// account at one instant. Pure by construction: `now` is a parameter so the
// tests can age an account without sleeping, and so a clock skew cannot make
// the rules non-deterministic.
//
// Order matters. Hard denials (the account may not be used at all) are checked
// before soft ones (the account is fine, its password is not), so an expired
// account is never told to go reset a password it will not be allowed to use.
func evaluateAccountPolicy(ss SecuritySettings, u User, now time.Time) accountPolicyDecision {
	// --- hard denials -------------------------------------------------------

	// account_validity_days: the account expires N days after it was created.
	// A zero CreatedAt means an unknown age; declining to fire is the safe
	// reading (see the PasswordChangedAt note in users.go).
	if ss.AccountValidityDays > 0 && !u.CreatedAt.IsZero() {
		if expiry := u.CreatedAt.AddDate(0, 0, ss.AccountValidityDays); now.After(expiry) {
			return accountPolicyDecision{
				Deny:    true,
				Reason:  acctPolicyExpired,
				Message: "account has expired; contact an administrator to have it renewed",
			}
		}
	}

	// account_inactivity_days: an account unused for N days is locked. Gated on
	// a non-zero LastLoginAt — an account that has NEVER signed in is not
	// "inactive", it is new, and locking it on creation day would be absurd.
	// account_validity_days above is the rule that bounds a never-used account.
	if ss.AccountInactivityDays > 0 && !u.LastLoginAt.IsZero() {
		if deadline := u.LastLoginAt.AddDate(0, 0, ss.AccountInactivityDays); now.After(deadline) {
			return accountPolicyDecision{
				Deny:   true,
				Reason: acctPolicyInactive,
				Message: "account locked after " + intToString(ss.AccountInactivityDays) +
					" days of inactivity; contact an administrator",
			}
		}
	}

	// --- soft denials: identity proven, session withheld --------------------

	// Federated accounts have no local password for us to expire or reset — the
	// IdP owns that lifecycle. Applying these rules to them would produce a
	// reset prompt for a credential this platform does not hold.
	if !isLocalAccount(u.AuthSource) {
		return accountPolicyDecision{}
	}

	// An explicit flag always wins: set by reset_on_first_login at create time,
	// or by an admin. Checked before expiry so the reason stays the specific one.
	if u.MustChangePassword {
		return accountPolicyDecision{
			MustChange: true,
			Reason:     acctPolicyFirstLogin,
			Message:    "a password reset is required before you can sign in",
		}
	}

	// reset_on_first_login: no successful sign-in has ever been recorded.
	if ss.ResetOnFirstLogin && u.LastLoginAt.IsZero() {
		return accountPolicyDecision{
			MustChange: true,
			Reason:     acctPolicyFirstLogin,
			Message:    "a password reset is required before your first sign-in",
		}
	}

	// password_expire_enabled + password_expire_days.
	if ss.PasswordExpireEnabled && ss.PasswordExpireDays > 0 && !u.PasswordChangedAt.IsZero() {
		if expiry := u.PasswordChangedAt.AddDate(0, 0, ss.PasswordExpireDays); now.After(expiry) {
			return accountPolicyDecision{
				MustChange: true,
				Reason:     acctPolicyPasswordExpired,
				Message: "password expired after " + intToString(ss.PasswordExpireDays) +
					" days; set a new one to continue",
			}
		}
	}

	return accountPolicyDecision{}
}

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
	d := evaluateAccountPolicy(s.securitySettingsFor(u), u, time.Now().UTC())
	if !d.blocked() {
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

// errPasswordReused is returned when password_history rejects a new password.
var errPasswordReused = errors.New("new password matches one of your recent passwords; choose a different one")

// checkPasswordHistory enforces password_history. It is a no-op when the
// setting is off, so an operator who has not opted in keeps the current
// behaviour (the new!=current check in handleChangePassword stands either way).
//
// Hashes are salted per-entry, so this cannot be a string compare — every
// retained hash must be verified against the candidate individually. Depth is
// bounded by passwordHistoryDepth, so the cost is bounded too.
func checkPasswordHistory(ss SecuritySettings, u User, candidate string) error {
	if !ss.PasswordHistory {
		return nil
	}
	for _, h := range u.PasswordHistory {
		if h == "" {
			continue
		}
		if verifyPassword(candidate, h) {
			return errPasswordReused
		}
	}
	return nil
}

// pushPasswordHistory prepends the outgoing hash and truncates to depth.
// Returns a new slice — never mutates the caller's, which would alias the copy
// held in the store map.
func pushPasswordHistory(existing []string, outgoing string) []string {
	if outgoing == "" {
		return existing
	}
	next := make([]string, 0, passwordHistoryDepth)
	next = append(next, outgoing)
	for _, h := range existing {
		if len(next) >= passwordHistoryDepth {
			break
		}
		if h != outgoing {
			next = append(next, h)
		}
	}
	return next
}

// applyPasswordChange mutates u for a REAL password change: the outgoing hash
// joins the history, the expiry clock restarts, and any pending forced reset is
// satisfied. Shared by both store backends so the file and Postgres paths
// cannot drift — the F-63/F-50 lesson, where one backend learned a rule and its
// sibling did not.
//
// Deliberately NOT called by RehashPassword. See users.go PasswordChangedAt.
func applyPasswordChange(u *User, hash string, now time.Time) {
	u.PasswordHistory = pushPasswordHistory(u.PasswordHistory, u.PasswordHash)
	u.PasswordHash = hash
	u.PasswordChangedAt = now
	u.MustChangePassword = false
}

// concurrentLoginDenied reports whether the scope forbids a second concurrent
// session. Compared case-insensitively against "deny" and defaulting to ALLOW
// on an unrecognised value: this setting gates sign-in, and an unparseable
// value must not lock a tenant out of its own platform. The validating write
// path (handleSecuritySettings) is what keeps junk from being stored at all.
func concurrentLoginDenied(ss SecuritySettings) bool {
	return strings.EqualFold(strings.TrimSpace(ss.ConcurrentLogin), "deny")
}
