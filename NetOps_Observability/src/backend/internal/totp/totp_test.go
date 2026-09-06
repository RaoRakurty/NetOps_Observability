// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package totp

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
		if got := At(secret, time.Unix(ts, 0)); got != want {
			t.Errorf("At(%d) = %q, want %q", ts, got, want)
		}
	}
}

func TestVerifyTOTP(t *testing.T) {
	secret, err := NewSecret()
	if err != nil {
		t.Fatalf("NewSecret: %v", err)
	}
	code := At(secret, time.Now())
	if !Verify(secret, code) {
		t.Error("current code must verify")
	}
	// ±1 step (clock drift) accepted; a step beyond rejected.
	if !Verify(secret, At(secret, time.Now().Add(-30*time.Second))) {
		t.Error("previous-step code must verify (drift tolerance)")
	}
	if Verify(secret, At(secret, time.Now().Add(-5*time.Minute))) {
		t.Error("a far-past code must NOT verify")
	}
	if Verify(secret, "000000") && At(secret, time.Now()) != "000000" {
		t.Error("wrong code must not verify")
	}
	if Verify(secret, "12345") {
		t.Error("malformed (5-digit) code must not verify")
	}
}
