package token

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundtrip(t *testing.T) {
	pw := "correct horse battery staple"
	hashed, err := HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if !strings.HasPrefix(hashed, "pbkdf2_sha256$") {
		t.Fatalf("encoded format unexpected: %q", hashed)
	}
	if !VerifyPassword(pw, hashed) {
		t.Fatalf("verify rejected matching password")
	}
}

func TestVerifyRejectsWrongPassword(t *testing.T) {
	hashed, err := HashPassword("hunter2")
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	if VerifyPassword("hunter3", hashed) {
		t.Fatalf("verify accepted wrong password")
	}
	if VerifyPassword("", hashed) {
		t.Fatalf("verify accepted empty password against real hash")
	}
}

func TestVerifyRejectsMalformedEncoding(t *testing.T) {
	cases := []string{
		"",
		"plaintext",
		"argon2$x$y$z",
		"pbkdf2_sha256$notanint$saltsalt$keykey",
		"pbkdf2_sha256$600000$!not-base64!$keykey",
	}
	for _, c := range cases {
		if VerifyPassword("anything", c) {
			t.Errorf("verify accepted malformed encoding: %q", c)
		}
	}
}

func TestUniqueSalts(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatalf("two hashes of the same password should differ (random salt)")
	}
}
