// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// cliRefusalPrefixes are the shapes a network CLI uses to REFUSE a command, in
// the ONE position that matters: the first line of the response.
//
// Why this guard exists. The gateway checks the exec's exit status, but several
// network operating systems answer a refused command with a diagnostic on
// stdout and exit ZERO — EOS answers a privilege-1 `show running-config` with
// "% Invalid input (privileged mode required)", SR OS and SR Linux have their
// own spellings. Without this, a capture account that lost its authorization
// stores the REFUSAL as a configuration version: the sha changes, the device
// reports drift, the diff shows the entire configuration deleted, and the
// sealed "restore from" artifact is one line of error text. That is the exact
// silent failure §10 forbids, and it is worse than no capture at all.
//
// Deliberately narrow. Only the FIRST non-blank line is examined and only these
// prefixes count, because a running-config legitimately contains `%` inside
// banners, descriptions and regexes — just never as its opening statement.
var cliRefusalPrefixes = []string{"%", "error:", "unknown command", "syntax error"}

// looksLikeCLIRefusal reports whether normalized text is a CLI's refusal of the
// capture command rather than a configuration, and returns the offending line
// so the failure record can name what the device actually said.
func looksLikeCLIRefusal(normalized string) (string, bool) {
	for _, ln := range strings.Split(normalized, "\n") {
		t := strings.TrimSpace(ln)
		if t == "" {
			continue
		}
		lower := strings.ToLower(t)
		for _, p := range cliRefusalPrefixes {
			if strings.HasPrefix(lower, p) {
				return t, true
			}
		}
		return "", false // the first real line is configuration — done
	}
	return "", false
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
