// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestJWTRoundtrip(t *testing.T) {
	secret := "test-secret"
	now := time.Now().Unix()
	in := Claims{Sub: "alice", Role: "admin", Iat: now, Exp: now + 3600}

	tok, err := Sign(in, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("token shape wrong: %q", tok)
	}

	out, err := Verify(tok, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Sub != "alice" || out.Role != "admin" {
		t.Fatalf("claims roundtrip wrong: %+v", out)
	}
}

func TestJWTBadSignature(t *testing.T) {
	tok, _ := Sign(Claims{Sub: "alice", Exp: time.Now().Unix() + 60}, "real")
	if _, err := Verify(tok, "different-secret"); err == nil {
		t.Fatalf("verify accepted forged signature")
	}
}

func TestJWTExpired(t *testing.T) {
	tok, _ := Sign(Claims{Sub: "alice", Exp: time.Now().Unix() - 1}, "s")
	if _, err := Verify(tok, "s"); err == nil {
		t.Fatalf("verify accepted expired token")
	}
}

func TestJWTMalformed(t *testing.T) {
	if _, err := Verify("not.a.jwt", "s"); err == nil {
		t.Fatalf("verify accepted obvious garbage")
	}
	if _, err := Verify("only-two.parts", "s"); err == nil {
		t.Fatalf("verify accepted 2-part token")
	}
	if _, err := Verify("", "s"); err == nil {
		t.Fatalf("verify accepted empty token")
	}
}

// Critical: a forged token claiming `alg: none` must not authenticate
// even if some other library tolerated it. Our implementation hard-
// codes the signing path, so this is mostly belt-and-braces.
func TestJWTAlgNoneAttack(t *testing.T) {
	// Build a token with header {"alg":"none","typ":"JWT"} and no sig.
	header := b64url([]byte(`{"alg":"none","typ":"JWT"}`))
	claims := b64url([]byte(`{"sub":"attacker","exp":99999999999}`))
	bogus := header + "." + claims + "."
	if _, err := Verify(bogus, "anything"); err == nil {
		t.Fatalf("verify accepted alg=none token")
	}
}

// SR-024: Verify enforces nbf and a future-dated iat (with small skew).
func TestJWTTimeBounds(t *testing.T) {
	secret := "test-secret"
	// A token whose nbf is far in the future must be rejected.
	future := time.Now().Add(time.Hour).Unix()
	tok, err := Sign(Claims{Sub: "u", Nbf: future, Iat: future, Exp: time.Now().Add(2 * time.Hour).Unix()}, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if _, err := Verify(tok, secret); err == nil {
		t.Error("token not-yet-valid (future nbf) must be rejected")
	}
	// A normal token (iat/nbf auto-stamped now) verifies.
	ok, err := Sign(Claims{Sub: "u", Exp: time.Now().Add(time.Hour).Unix()}, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	c, err := Verify(ok, secret)
	if err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if c.Iat == 0 || c.Nbf == 0 {
		t.Error("Sign must stamp iat and nbf")
	}
}

// signRaw HMAC-signs an arbitrary payload with the real signing path, so the
// crafted-token tests below present Verify with a VALIDLY SIGNED token — the
// signature check must not be what saves us.
func signRaw(payload, secret string) string {
	signingInput := b64url([]byte(jwtHeader)) + "." + b64url([]byte(payload))
	h := hmac.New(sha256.New, []byte(secret))
	h.Write([]byte(signingInput))
	return signingInput + "." + b64url(h.Sum(nil))
}

// SECURITY PIN for the package-decomposition change: while Claims lived in
// package main, actingTenant was unexported and therefore invisible to
// encoding/json — a token could never carry the platform-owner "view as
// tenant" override. Exporting the field for the package boundary re-creates
// that risk unless `json:"-"` excludes it. This test proves a crafted,
// correctly-signed token cannot set ActingTenant under any key spelling.
func TestCraftedTokenCannotSetActingTenant(t *testing.T) {
	secret := "test-secret"
	exp := time.Now().Add(time.Hour).Unix()
	for _, key := range []string{"actingTenant", "ActingTenant", "acting_tenant", "actingtenant"} {
		payload := `{"sub":"root","role":"super-admin","tenant":"global","` + key + `":"victim-tenant","exp":` + strconv.FormatInt(exp, 10) + `}`
		c, err := Verify(signRaw(payload, secret), secret)
		if err != nil {
			t.Fatalf("key %q: crafted token failed to verify (test is vacuous): %v", key, err)
		}
		if c.ActingTenant != "" {
			t.Errorf("key %q: crafted token populated ActingTenant=%q — the json:\"-\" control is broken", key, c.ActingTenant)
		}
		if c.Sub != "root" {
			t.Errorf("key %q: expected other claims to parse (sub=%q)", key, c.Sub)
		}
	}
}

// The marshal side of the same control: an override set server-side must never
// leak INTO a minted token (it is per-request state, not a claim).
func TestSignDoesNotEmitActingTenant(t *testing.T) {
	tok, err := Sign(Claims{Sub: "root", ActingTenant: "acme", Exp: time.Now().Add(time.Hour).Unix()}, "s")
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	payload, err := b64urlDecode(strings.Split(tok, ".")[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(strings.ToLower(string(payload)), "acting") {
		t.Errorf("minted token payload leaks the acting-tenant override: %s", payload)
	}
	// And it must not survive a roundtrip either.
	c, err := Verify(tok, "s")
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if c.ActingTenant != "" {
		t.Errorf("ActingTenant survived a sign/verify roundtrip: %q", c.ActingTenant)
	}
}
