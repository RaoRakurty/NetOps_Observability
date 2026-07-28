package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// SR-024 (TestJWTTimeBounds) moved to internal/token with the signer/verifier.

// SR-029: a hash at a lower iteration count is flagged for rehash; current cost is not.
func TestPasswordNeedsRehash(t *testing.T) {
	if !passwordNeedsRehash("pbkdf2_sha256$1000$c2FsdA==$aGFzaA==") {
		t.Error("low-iteration hash should need rehash")
	}
	cur, err := hashPassword("a-fine-passphrase")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if passwordNeedsRehash(cur) {
		t.Error("current-cost hash should NOT need rehash")
	}
}

// SR-030: cookieSecure is set when the request is HTTPS (direct or via XFP) or forced.
func TestCookieSecure(t *testing.T) {
	plain := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	if cookieSecure(plain) {
		t.Error("plain HTTP request must not get a Secure cookie by default")
	}
	xfp := httptest.NewRequest(http.MethodGet, "http://x/", nil)
	xfp.Header.Set("X-Forwarded-Proto", "https")
	if !cookieSecure(xfp) {
		t.Error("X-Forwarded-Proto=https must yield a Secure cookie")
	}
}
