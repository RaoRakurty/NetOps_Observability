// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package secpolicy

// account.go — F-68: the account-lifecycle half of Security Settings.
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
// (password.go), lockout (auth.go lockoutPolicy), session timeouts (auth.go
// sessionPolicy). That is precisely what made the other seven credible: the
// page is right about three quarters of itself. A customer can answer a
// SOC2/PCI questionnaire "90-day expiry and inactivity lockout are enforced"
// and cite the product's own settings page as evidence. Nothing expired.
// Nothing locked.
//
// The fix is a single chokepoint rather than seven scattered checks, because
// the audit's one-line diagnosis is that this codebase fixes instances and not
// classes. EvaluateAccountPolicy is pure — no clock, no IO, no store — so the
// rules are testable without a server, and the in-package suite exercises
// every branch. main's settings_reachability_test.go then fails the build if
// any Settings field ever returns to zero read sites.

import (
	"errors"
	"strconv"
	"strings"
	"time"

	"netops/backend/internal/token"
	"netops/backend/internal/users"
)

// HistoryDepth bounds User.PasswordHistory. Unbounded history is the §9 "all
// queues must be bounded" violation in miniature: it rides in the user record,
// which is read on every login.
const HistoryDepth = 5

// Machine-readable outcomes. The SPA branches on these; humans read Message.
const (
	ReasonAccountExpired  = "account_expired"
	ReasonAccountInactive = "account_inactive"
	ReasonPasswordExpired = "password_expired"
	ReasonFirstLogin      = "password_reset_required"
)

// Decision is what the gate concluded. Deny and MustChange are distinct
// outcomes: Deny refuses the sign-in outright, MustChange lets the caller
// prove its identity but withholds the session until the password is reset.
// Collapsing them would either lock out every expiring user or let an expired
// account keep working.
type Decision struct {
	Deny       bool
	MustChange bool
	Reason     string
	Message    string
}

// Blocked reports whether the sign-in cannot proceed as-is.
func (d Decision) Blocked() bool { return d.Deny || d.MustChange }

// EvaluateAccountPolicy applies the seven account-lifecycle settings to one
// account at one instant. Pure by construction: `now` is a parameter so the
// tests can age an account without sleeping, and so a clock skew cannot make
// the rules non-deterministic.
//
// Order matters. Hard denials (the account may not be used at all) are checked
// before soft ones (the account is fine, its password is not), so an expired
// account is never told to go reset a password it will not be allowed to use.
func EvaluateAccountPolicy(ss Settings, u users.User, now time.Time) Decision {
	// --- hard denials -------------------------------------------------------

	// account_validity_days: the account expires N days after it was created.
	// A zero CreatedAt means an unknown age; declining to fire is the safe
	// reading (see the PasswordChangedAt note in users.go).
	if ss.AccountValidityDays > 0 && !u.CreatedAt.IsZero() {
		if expiry := u.CreatedAt.AddDate(0, 0, ss.AccountValidityDays); now.After(expiry) {
			return Decision{
				Deny:    true,
				Reason:  ReasonAccountExpired,
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
			return Decision{
				Deny:   true,
				Reason: ReasonAccountInactive,
				Message: "account locked after " + strconv.Itoa(ss.AccountInactivityDays) +
					" days of inactivity; contact an administrator",
			}
		}
	}

	// --- soft denials: identity proven, session withheld --------------------

	// Federated accounts have no local password for us to expire or reset — the
	// IdP owns that lifecycle. Applying these rules to them would produce a
	// reset prompt for a credential this platform does not hold.
	if !isLocalAccount(u.AuthSource) {
		return Decision{}
	}

	// An explicit flag always wins: set by reset_on_first_login at create time,
	// or by an admin. Checked before expiry so the reason stays the specific one.
	if u.MustChangePassword {
		return Decision{
			MustChange: true,
			Reason:     ReasonFirstLogin,
			Message:    "a password reset is required before you can sign in",
		}
	}

	// reset_on_first_login: no successful sign-in has ever been recorded.
	if ss.ResetOnFirstLogin && u.LastLoginAt.IsZero() {
		return Decision{
			MustChange: true,
			Reason:     ReasonFirstLogin,
			Message:    "a password reset is required before your first sign-in",
		}
	}

	// password_expire_enabled + password_expire_days.
	if ss.PasswordExpireEnabled && ss.PasswordExpireDays > 0 && !u.PasswordChangedAt.IsZero() {
		if expiry := u.PasswordChangedAt.AddDate(0, 0, ss.PasswordExpireDays); now.After(expiry) {
			return Decision{
				MustChange: true,
				Reason:     ReasonPasswordExpired,
				Message: "password expired after " + strconv.Itoa(ss.PasswordExpireDays) +
					" days; set a new one to continue",
			}
		}
	}

	return Decision{}
}

// ErrPasswordReused is returned when password_history rejects a new password.
var ErrPasswordReused = errors.New("new password matches one of your recent passwords; choose a different one")

// CheckPasswordHistory enforces password_history. It is a no-op when the
// setting is off, so an operator who has not opted in keeps the current
// behaviour (the new!=current check in handleChangePassword stands either way).
//
// Hashes are salted per-entry, so this cannot be a string compare — every
// retained hash must be verified against the candidate individually. Depth is
// bounded by HistoryDepth, so the cost is bounded too.
func CheckPasswordHistory(ss Settings, u users.User, candidate string) error {
	if !ss.PasswordHistory {
		return nil
	}
	for _, h := range u.PasswordHistory {
		if h == "" {
			continue
		}
		if token.VerifyPassword(candidate, h) {
			return ErrPasswordReused
		}
	}
	return nil
}

// PushPasswordHistory prepends the outgoing hash and truncates to depth.
// Returns a new slice — never mutates the caller's, which would alias the copy
// held in the store map.
func PushPasswordHistory(existing []string, outgoing string) []string {
	if outgoing == "" {
		return existing
	}
	next := make([]string, 0, HistoryDepth)
	next = append(next, outgoing)
	for _, h := range existing {
		if len(next) >= HistoryDepth {
			break
		}
		if h != outgoing {
			next = append(next, h)
		}
	}
	return next
}

// ApplyPasswordChange mutates u for a REAL password change: the outgoing hash
// joins the history, the expiry clock restarts, and any pending forced reset is
// satisfied. Shared by both store backends so the file and Postgres paths
// cannot drift — the F-63/F-50 lesson, where one backend learned a rule and its
// sibling did not.
//
// Deliberately NOT called by RehashPassword. See users.go PasswordChangedAt.
func ApplyPasswordChange(u *users.User, hash string, now time.Time) {
	u.PasswordHistory = PushPasswordHistory(u.PasswordHistory, u.PasswordHash)
	u.PasswordHash = hash
	u.PasswordChangedAt = now
	u.MustChangePassword = false
}

// isLocalAccount reports whether an account's password is managed locally (so
// it can be changed in-app). Federated sources (oidc/saml/ldap/tacacs) are
// managed by the IdP. An empty source means a legacy/bootstrap local account.
// (Private copy of main's auth.go helper per the no-utils rule — pinned in
// lock-step.)
func isLocalAccount(authSource string) bool {
	s := strings.ToLower(strings.TrimSpace(authSource))
	return s == "" || s == "local"
}
