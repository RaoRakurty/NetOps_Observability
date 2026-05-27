package main

import (
	"strings"
	"testing"
	"time"
)

func TestJWTRoundtrip(t *testing.T) {
	secret := "test-secret"
	now := time.Now().Unix()
	in := jwtClaims{Sub: "alice", Role: "admin", Iat: now, Exp: now + 3600}

	tok, err := signJWT(in, secret)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("token shape wrong: %q", tok)
	}

	out, err := verifyJWT(tok, secret)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if out.Sub != "alice" || out.Role != "admin" {
		t.Fatalf("claims roundtrip wrong: %+v", out)
	}
}

func TestJWTBadSignature(t *testing.T) {
	tok, _ := signJWT(jwtClaims{Sub: "alice", Exp: time.Now().Unix() + 60}, "real")
	if _, err := verifyJWT(tok, "different-secret"); err == nil {
		t.Fatalf("verify accepted forged signature")
	}
}

func TestJWTExpired(t *testing.T) {
	tok, _ := signJWT(jwtClaims{Sub: "alice", Exp: time.Now().Unix() - 1}, "s")
	if _, err := verifyJWT(tok, "s"); err == nil {
		t.Fatalf("verify accepted expired token")
	}
}

func TestJWTMalformed(t *testing.T) {
	if _, err := verifyJWT("not.a.jwt", "s"); err == nil {
		t.Fatalf("verify accepted obvious garbage")
	}
	if _, err := verifyJWT("only-two.parts", "s"); err == nil {
		t.Fatalf("verify accepted 2-part token")
	}
	if _, err := verifyJWT("", "s"); err == nil {
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
	if _, err := verifyJWT(bogus, "anything"); err == nil {
		t.Fatalf("verify accepted alg=none token")
	}
}
