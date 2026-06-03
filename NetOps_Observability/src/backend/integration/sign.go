package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// sign.go — shared webhook signature primitives (§6, §9). All comparisons are
// constant-time. `timeNow` is a package var so replay-window checks are testable.

var timeNow = time.Now

// hmacSHA256Hex returns the lowercase hex HMAC-SHA256 of msg under key.
func hmacSHA256Hex(key, msg []byte) string {
	mac := hmac.New(sha256.New, key)
	mac.Write(msg)
	return hex.EncodeToString(mac.Sum(nil))
}

// constEq reports whether a == b in constant time (length-independent leak-free).
func constEq(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}

// withinSkew reports whether unix-seconds ts is within maxSkew of now. Guards
// webhook replay (an attacker can't resend a captured, validly-signed request
// outside the window).
func withinSkew(tsUnix int64, maxSkew time.Duration) bool {
	now := timeNow().Unix()
	d := now - tsUnix
	if d < 0 {
		d = -d
	}
	return time.Duration(d)*time.Second <= maxSkew
}
