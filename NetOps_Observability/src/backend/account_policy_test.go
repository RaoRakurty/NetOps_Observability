package main

import (
	"netops/backend/internal/token"
	"strings"
	"testing"
	"time"
)

// account_policy_test.go — F-68. Every branch of the seven account-lifecycle
// settings that were stored, displayed as active, and enforced by nothing.
//
// evaluateAccountPolicy is pure and takes `now` as a parameter, so an account
// can be aged 200 days without sleeping and without a fake clock.

func localUser(mod func(*User)) User {
	u := User{
		Username:   "alice",
		AuthSource: "local",
		Status:     "active",
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	if mod != nil {
		mod(&u)
	}
	return u
}

var policyNow = time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)

func TestAccountValidityDaysExpiresTheAccount(t *testing.T) {
	ss := SecuritySettings{AccountValidityDays: 30}
	// Created 2026-01-01, now 2026-07-22 — 202 days old, limit 30.
	d := evaluateAccountPolicy(ss, localUser(nil), policyNow)
	if !d.Deny {
		t.Fatalf("account 202 days old with a 30-day validity must be denied, got %+v", d)
	}
	if d.Reason != acctPolicyExpired {
		t.Errorf("reason = %q, want %q", d.Reason, acctPolicyExpired)
	}
	// Inside the window it must NOT fire.
	fresh := localUser(func(u *User) { u.CreatedAt = policyNow.AddDate(0, 0, -29) })
	if got := evaluateAccountPolicy(ss, fresh, policyNow); got.blocked() {
		t.Errorf("29-day-old account under a 30-day validity must pass, got %+v", got)
	}
}

func TestAccountValidityIsSkippedWhenUnset(t *testing.T) {
	// 0 = disabled. An ancient account must still sign in.
	ancient := localUser(func(u *User) { u.CreatedAt = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC) })
	if d := evaluateAccountPolicy(SecuritySettings{}, ancient, policyNow); d.blocked() {
		t.Fatalf("validity 0 must disable the rule, got %+v", d)
	}
}

func TestAccountInactivityLocksAfterTheWindow(t *testing.T) {
	ss := SecuritySettings{AccountInactivityDays: 90}
	stale := localUser(func(u *User) { u.LastLoginAt = policyNow.AddDate(0, 0, -91) })
	d := evaluateAccountPolicy(ss, stale, policyNow)
	if !d.Deny || d.Reason != acctPolicyInactive {
		t.Fatalf("91 days idle under a 90-day rule must lock, got %+v", d)
	}
	recent := localUser(func(u *User) { u.LastLoginAt = policyNow.AddDate(0, 0, -89) })
	if got := evaluateAccountPolicy(ss, recent, policyNow); got.blocked() {
		t.Errorf("89 days idle must pass, got %+v", got)
	}
}

// A brand-new account has never logged in. Locking it for "inactivity" on the
// day it was created is the obvious wrong reading of a zero timestamp.
func TestNeverLoggedInIsNotInactive(t *testing.T) {
	ss := SecuritySettings{AccountInactivityDays: 1}
	brandNew := localUser(func(u *User) { u.LastLoginAt = time.Time{} })
	if d := evaluateAccountPolicy(ss, brandNew, policyNow); d.Deny {
		t.Fatalf("a never-used account must not be denied as inactive, got %+v", d)
	}
}

func TestPasswordExpiryForcesAChangeNotADenial(t *testing.T) {
	ss := SecuritySettings{PasswordExpireEnabled: true, PasswordExpireDays: 90}
	old := localUser(func(u *User) { u.PasswordChangedAt = policyNow.AddDate(0, 0, -91) })
	d := evaluateAccountPolicy(ss, old, policyNow)
	if d.Deny {
		t.Fatalf("an expired PASSWORD must not deny the account outright: %+v", d)
	}
	if !d.MustChange || d.Reason != acctPolicyPasswordExpired {
		t.Fatalf("expected a forced change, got %+v", d)
	}
}

// The migration hazard: on the first boot after upgrade every existing user has
// a zero PasswordChangedAt. Falling back to CreatedAt would force a fleet-wide
// reset — including the operator's own account — the instant the stack came up.
func TestUnknownPasswordAgeDoesNotForceAFleetWideReset(t *testing.T) {
	ss := SecuritySettings{PasswordExpireEnabled: true, PasswordExpireDays: 1}
	legacy := localUser(func(u *User) {
		u.PasswordChangedAt = time.Time{}                         // never stamped
		u.CreatedAt = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC) // ancient
		u.LastLoginAt = policyNow.AddDate(0, 0, -1)               // active user
	})
	if d := evaluateAccountPolicy(ss, legacy, policyNow); d.blocked() {
		t.Fatalf("unknown password age must not block; got %+v", d)
	}
}

func TestPasswordExpiryDisabledByFlag(t *testing.T) {
	// days set but the enable flag off — the flag must win.
	ss := SecuritySettings{PasswordExpireEnabled: false, PasswordExpireDays: 1}
	old := localUser(func(u *User) { u.PasswordChangedAt = policyNow.AddDate(0, 0, -400) })
	if d := evaluateAccountPolicy(ss, old, policyNow); d.blocked() {
		t.Fatalf("password_expire_enabled=false must disable expiry, got %+v", d)
	}
}

func TestResetOnFirstLogin(t *testing.T) {
	ss := SecuritySettings{ResetOnFirstLogin: true}
	first := localUser(func(u *User) { u.LastLoginAt = time.Time{} })
	d := evaluateAccountPolicy(ss, first, policyNow)
	if !d.MustChange || d.Reason != acctPolicyFirstLogin {
		t.Fatalf("first login must force a reset, got %+v", d)
	}
	returning := localUser(func(u *User) { u.LastLoginAt = policyNow.AddDate(0, 0, -1) })
	if got := evaluateAccountPolicy(ss, returning, policyNow); got.blocked() {
		t.Errorf("a returning user must not be asked to reset, got %+v", got)
	}
}

func TestMustChangePasswordFlagIsHonoured(t *testing.T) {
	flagged := localUser(func(u *User) { u.MustChangePassword = true })
	d := evaluateAccountPolicy(SecuritySettings{}, flagged, policyNow)
	if !d.MustChange {
		t.Fatalf("an explicit MustChangePassword must force a reset, got %+v", d)
	}
}

// Federated accounts carry no local password. Telling an OIDC user to reset a
// credential this platform does not hold is a dead end.
func TestFederatedAccountsSkipPasswordRules(t *testing.T) {
	ss := SecuritySettings{
		PasswordExpireEnabled: true, PasswordExpireDays: 1,
		ResetOnFirstLogin: true,
	}
	for _, src := range []string{"oidc", "saml", "ldap", "tacacs"} {
		u := localUser(func(u *User) {
			u.AuthSource = src
			u.LastLoginAt = time.Time{}
			u.PasswordChangedAt = policyNow.AddDate(0, 0, -400)
		})
		if d := evaluateAccountPolicy(ss, u, policyNow); d.blocked() {
			t.Errorf("%s account must skip local password rules, got %+v", src, d)
		}
	}
}

// A hard denial must win over a soft one: an expired account should never be
// sent to reset a password it will not be allowed to use afterwards.
func TestHardDenialWinsOverForcedChange(t *testing.T) {
	ss := SecuritySettings{
		AccountValidityDays:   30,
		PasswordExpireEnabled: true, PasswordExpireDays: 1,
	}
	u := localUser(func(u *User) { u.PasswordChangedAt = policyNow.AddDate(0, 0, -400) })
	d := evaluateAccountPolicy(ss, u, policyNow)
	if !d.Deny || d.Reason != acctPolicyExpired {
		t.Fatalf("account expiry must take precedence, got %+v", d)
	}
}

// ---- password history ------------------------------------------------------

func TestPasswordHistoryRejectsReuseOnlyWhenEnabled(t *testing.T) {
	oldHash, err := token.HashPassword("PriorPassw0rd!")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	u := localUser(func(u *User) { u.PasswordHistory = []string{oldHash} })

	// Off by default — the operator has not opted in.
	if err := checkPasswordHistory(SecuritySettings{}, u, "PriorPassw0rd!"); err != nil {
		t.Fatalf("history disabled must permit reuse, got %v", err)
	}
	// On: the same secret must be refused even though the hash differs by salt.
	if err := checkPasswordHistory(SecuritySettings{PasswordHistory: true}, u, "PriorPassw0rd!"); err == nil {
		t.Fatal("password_history=true must reject a reused password")
	}
	// A genuinely new password passes.
	if err := checkPasswordHistory(SecuritySettings{PasswordHistory: true}, u, "BrandNewPassw0rd!"); err != nil {
		t.Fatalf("a fresh password must be accepted, got %v", err)
	}
}

func TestPasswordHistoryIsBounded(t *testing.T) {
	hist := []string{}
	for i := 0; i < 20; i++ {
		hist = pushPasswordHistory(hist, "hash-"+intToString(i))
	}
	if len(hist) != passwordHistoryDepth {
		t.Fatalf("history len = %d, want the %d cap", len(hist), passwordHistoryDepth)
	}
	if hist[0] != "hash-19" {
		t.Errorf("newest entry = %q, want hash-19 (newest first)", hist[0])
	}
}

func TestPushPasswordHistoryDoesNotAliasTheCallersSlice(t *testing.T) {
	orig := []string{"a", "b"}
	next := pushPasswordHistory(orig, "c")
	next[1] = "MUTATED"
	if orig[0] != "a" {
		t.Fatalf("caller slice was aliased and mutated: %v", orig)
	}
}

// applyPasswordChange is the shared write path; a rehash must not touch it.
func TestApplyPasswordChangeStampsAndClearsTheResetFlag(t *testing.T) {
	u := localUser(func(u *User) {
		u.PasswordHash = "old-hash"
		u.MustChangePassword = true
	})
	applyPasswordChange(&u, "new-hash", policyNow)
	if u.PasswordHash != "new-hash" {
		t.Errorf("hash not replaced: %q", u.PasswordHash)
	}
	if !u.PasswordChangedAt.Equal(policyNow) {
		t.Errorf("PasswordChangedAt = %v, want %v", u.PasswordChangedAt, policyNow)
	}
	if u.MustChangePassword {
		t.Error("a completed change must clear MustChangePassword")
	}
	if len(u.PasswordHistory) != 1 || u.PasswordHistory[0] != "old-hash" {
		t.Errorf("outgoing hash must enter history, got %v", u.PasswordHistory)
	}
}

// ---- concurrent_login ------------------------------------------------------

func TestConcurrentLoginDeniedParsing(t *testing.T) {
	cases := map[string]bool{
		"deny": true, "DENY": true, " deny ": true,
		"allow": false, "": false, "nonsense": false,
	}
	for in, want := range cases {
		if got := concurrentLoginDenied(SecuritySettings{ConcurrentLogin: in}); got != want {
			t.Errorf("concurrentLoginDenied(%q) = %v, want %v", in, got, want)
		}
	}
}

// The defaults ship expiry ON at 90 days. If a default ever changes to
// something that would block the bootstrap admin on a fresh install, this fails.
func TestDefaultSettingsDoNotBlockAFreshAdmin(t *testing.T) {
	ss := defaultSecuritySettings(ScopeProvider)
	admin := User{
		Username: "admin", AuthSource: "local", Status: "active",
		CreatedAt: policyNow, // just installed
	}
	if d := evaluateAccountPolicy(ss, admin, policyNow); d.blocked() {
		t.Fatalf("shipped defaults must let a freshly seeded admin sign in, got %+v", d)
	}
	if !strings.EqualFold(ss.ConcurrentLogin, "allow") {
		t.Errorf("default concurrent_login = %q, want allow", ss.ConcurrentLogin)
	}
}
