package main

import (
	"testing"
	"time"
)

// RFC 6238 interop: the SHA1 test vector (seed "12345678901234567890" → base32
// GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ) must yield the spec's known codes. This pins
// our implementation against any authenticator app.
func TestTOTPRFC6238Vectors(t *testing.T) {
	const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	cases := map[int64]string{
		59:         "287082",
		1111111109: "081804",
		1111111111: "050471",
		1234567890: "005924",
		2000000000: "279037",
	}
	for ts, want := range cases {
		if got := totpAt(secret, time.Unix(ts, 0)); got != want {
			t.Errorf("totpAt(%d) = %q, want %q", ts, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := newTOTPSecret()
	if err != nil {
		t.Fatalf("newTOTPSecret: %v", err)
	}
	code := totpAt(secret, time.Now())
	if !verifyTOTP(secret, code) {
		t.Error("current code must verify")
	}
	// ±1 step (clock drift) accepted; a step beyond rejected.
	if !verifyTOTP(secret, totpAt(secret, time.Now().Add(-30*time.Second))) {
		t.Error("previous-step code must verify (drift tolerance)")
	}
	if verifyTOTP(secret, totpAt(secret, time.Now().Add(-5*time.Minute))) {
		t.Error("a far-past code must NOT verify")
	}
	if verifyTOTP(secret, "000000") && totpAt(secret, time.Now()) != "000000" {
		t.Error("wrong code must not verify")
	}
	if verifyTOTP(secret, "12345") {
		t.Error("malformed (5-digit) code must not verify")
	}
}
