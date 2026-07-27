package main

// mfa_throttle_test.go — the TOTP second factor must be as brute-force-resistant
// as the first. /api/auth/mfa/login is PUBLIC and totp.Verify accepts a ±1-step
// window, so an attacker holding a stolen password could mint fresh 5-minute
// challenge tokens and grind six-digit codes forever — and because a successful
// password check CLEARS the login counter, the password throttle never sees it.
// These tests prove failed codes are counted against the same account lockout,
// and that the lockout is enforced BEFORE the code is verified.

import (
	"encoding/json"
	"net/http/httptest"
	"netops/backend/internal/totp"
	"testing"
	"time"
)

const mfaTestPassword = "Mfa-Brute-Pass!1"

// enrollMFAUser creates a local account, enrolls it in TOTP, and returns its
// username and shared secret.
func enrollMFAUser(t *testing.T, srv *httptest.Server, admin, username string) string {
	t.Helper()
	if st, b := do(t, srv, "POST", "/api/users", admin, map[string]string{
		"username": username, "password": mfaTestPassword, "role": RoleReadOnly}); st != 201 {
		t.Fatalf("create user: %d %s", st, b)
	}
	token := login(t, srv, username, mfaTestPassword).Token

	st, b := do(t, srv, "POST", "/api/auth/mfa/setup", token, map[string]string{})
	if st != 200 {
		t.Fatalf("mfa setup: %d %s", st, b)
	}
	var setup struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(b, &setup); err != nil || setup.Secret == "" {
		t.Fatalf("no secret in setup response: %s", b)
	}
	if st, b := do(t, srv, "POST", "/api/auth/mfa/activate", token,
		map[string]string{"code": totp.At(setup.Secret, time.Now())}); st != 200 {
		t.Fatalf("mfa activate: %d %s", st, b)
	}
	return setup.Secret
}

// mfaChallenge performs the password step and returns the challenge token.
func mfaChallenge(t *testing.T, srv *httptest.Server, username string) string {
	t.Helper()
	st, b := do(t, srv, "POST", "/api/auth/login", "", map[string]string{
		"username": username, "password": mfaTestPassword})
	if st != 200 {
		t.Fatalf("password step: %d %s", st, b)
	}
	var r struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	if err := json.Unmarshal(b, &r); err != nil || !r.MFARequired || r.MFAToken == "" {
		t.Fatalf("expected an MFA challenge, got: %s", b)
	}
	return r.MFAToken
}

// wrongCode returns a six-digit code guaranteed not to be the live one.
func wrongCode(secret string) string {
	if totp.At(secret, time.Now()) == "000000" {
		return "111111"
	}
	return "000000"
}

// Repeated bad TOTP codes lock the account out, and the lock is checked BEFORE
// verification — so even the CORRECT code is refused while it holds, and a fresh
// challenge token does not reset it.
func TestMFALoginLocksOutAfterRepeatedBadCodes(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	secret := enrollMFAUser(t, srv, admin, "mfa-brute")

	challenge := mfaChallenge(t, srv, "mfa-brute")
	bad := wrongCode(secret)

	// Default policy allows 3 attempts; exhaust them at the SECOND factor.
	for i := 0; i < 3; i++ {
		st, b := do(t, srv, "POST", "/api/auth/mfa/login", "", map[string]string{
			"mfa_token": challenge, "code": bad})
		if st != 401 {
			t.Fatalf("bad code %d: status %d, want 401 (%s)", i, st, b)
		}
	}

	// Now the CORRECT code is refused: the lockout is enforced before totp.Verify.
	st, b := do(t, srv, "POST", "/api/auth/mfa/login", "", map[string]string{
		"mfa_token": challenge, "code": totp.At(secret, time.Now())})
	if st != 429 {
		t.Fatalf("correct code while locked: status %d, want 429 (%s)", st, b)
	}
	// The password front door is locked too — one counter per account, so the
	// attacker cannot mint a fresh challenge and keep grinding.
	if st, b := do(t, srv, "POST", "/api/auth/login", "", map[string]string{
		"username": "mfa-brute", "password": mfaTestPassword}); st != 429 {
		t.Fatalf("password login while MFA-locked: status %d, want 429 (%s)", st, b)
	}
}

// A correct code below the threshold completes the login AND clears the counter,
// so a user who fat-fingers a code once is not penalised afterwards.
func TestMFALoginSuccessClearsFailureCounter(t *testing.T) {
	srv := newTestServer(t)
	admin := login(t, srv, "admin", "Passw0rd!2345").Token
	secret := enrollMFAUser(t, srv, admin, "mfa-butterfingers")

	challenge := mfaChallenge(t, srv, "mfa-butterfingers")
	if st, b := do(t, srv, "POST", "/api/auth/mfa/login", "", map[string]string{
		"mfa_token": challenge, "code": wrongCode(secret)}); st != 401 {
		t.Fatalf("first bad code: status %d, want 401 (%s)", st, b)
	}
	st, b := do(t, srv, "POST", "/api/auth/mfa/login", "", map[string]string{
		"mfa_token": challenge, "code": totp.At(secret, time.Now())})
	if st != 200 {
		t.Fatalf("correct code: status %d, want 200 (%s)", st, b)
	}
	var lr loginResponse
	if err := json.Unmarshal(b, &lr); err != nil || lr.Token == "" {
		t.Fatalf("no session issued: %s", b)
	}

	// Counter cleared: two more bad codes (3 total across the account's life) must
	// NOT lock the account, because the successful login reset it.
	challenge = mfaChallenge(t, srv, "mfa-butterfingers")
	for i := 0; i < 2; i++ {
		if st, b := do(t, srv, "POST", "/api/auth/mfa/login", "", map[string]string{
			"mfa_token": challenge, "code": wrongCode(secret)}); st != 401 {
			t.Fatalf("post-success bad code %d: status %d, want 401 (%s)", i, st, b)
		}
	}
}
