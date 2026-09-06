// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package integration

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"time"
)

// sign.go — shared webhook signature primitives (§6, §9). All comparisons are
// constant-time. `timeNow` is a package var so replay-window checks are testable.

var timeNow = time.Now

// bodyReplayWindow bounds how far an inbound webhook's (HMAC-covered) event
// timestamp may lag (SR-020). Generous by default (1h) to tolerate provider
// delivery retries while still capping replay; WEBHOOK_REPLAY_WINDOW tunes it.
// Exact idempotency/stale-drop is additionally enforced by the reconcile
// ordering layer (ExternalSeq monotonicity).
func bodyReplayWindow() time.Duration {
	if v := os.Getenv("WEBHOOK_REPLAY_WINDOW"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return time.Hour
}

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
