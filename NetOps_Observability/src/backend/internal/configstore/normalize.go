package configstore

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// normalize.go — the content-addressing half of the module.
//
// Normalize is DETERMINISTIC and TOTAL: the same bytes always produce the same
// text and the same sha, and it never fails. That matters because the sha is
// the version identity, the retention key, the drift comparator and the blob
// name; a normalization that varied run to run would mint an endless stream of
// "new" versions and make every device look permanently drifted.

// Normalize renders raw captured text into the canonical form that is hashed,
// sealed and diffed:
//
//  1. CRLF and lone CR are folded to LF (a device that pages output can emit
//     either).
//  2. Every line is right-trimmed (trailing whitespace is never configuration).
//  3. Volatile lines are dropped per the documented vendor rule list
//     (dialect.go) — timestamps, size banners, free-running counters.
//  4. Trailing blank lines are dropped and the result ends in exactly one LF
//     when non-empty.
//
// Note what is NOT done: no case folding, no re-ordering, no comment stripping,
// no whitespace collapse inside a line. Each of those would let a REAL
// configuration change hash to an unchanged version — a silent miss, which is
// the one failure mode this module cannot have.
func Normalize(v Vendor, raw string) string {
	raw = strings.ReplaceAll(raw, "\r\n", "\n")
	raw = strings.ReplaceAll(raw, "\r", "\n")
	src := strings.Split(raw, "\n")
	out := make([]string, 0, len(src))
	for _, ln := range src {
		ln = strings.TrimRight(ln, " \t")
		if isVolatile(v, ln) {
			continue
		}
		out = append(out, ln)
	}
	for len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
		out = out[:len(out)-1]
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// SHA256Hex is the content address of a NORMALIZED configuration — the version
// identity. Hex, lowercase, 64 chars.
func SHA256Hex(normalized string) string {
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}

// validSHA reports whether s is a well-formed version id. Every path that takes
// a sha from a URL runs it through this BEFORE it reaches a store key or a file
// name — a version id from a request is untrusted input (§3) and is exactly the
// shape that turns into a path traversal if taken on trust.
func validSHA(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
