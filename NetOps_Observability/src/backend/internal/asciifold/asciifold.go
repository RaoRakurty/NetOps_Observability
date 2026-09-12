// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package asciifold finds an ASCII marker inside a string, case-insensitively,
// and returns an offset that is valid for THAT string.
//
// ── WHY THIS PACKAGE EXISTS ────────────────────────────────────────────────
//
// The idiom it replaces is
//
//	i := strings.Index(strings.ToLower(s), marker)   // then slice s[i:]
//
// and it is wrong, because strings.ToLower is NOT length-preserving:
//
//   - U+023A (Ⱥ) lowers to U+2C65 and grows from two bytes to three.
//   - U+023E (Ⱦ) lowers to U+2C66 and grows from two bytes to three.
//   - every byte of invalid UTF-8 becomes a three-byte U+FFFD.
//
// An offset measured on the lower-cased COPY therefore does not address the
// original string. It can run past the end of it, which panics the slice, or it
// can land the wrong number of bytes along, which silently returns the wrong
// substring. This repository has now been bitten by both faces of that defect:
//
//   - internal/showparse (valueAfter) panicked the API process on device output
//     that carried one of those code points.
//   - internal/pipedebug (stripBearer) sliced past the start of a bearer token,
//     so the token was written UNREDACTED into a debug session directory and
//     from there into a support bundle, which deliberately does not redact
//     again. A credential in an exported file (CLAUDE.md §8).
//
// The scan below runs over the ORIGINAL bytes and never allocates, so the
// offset it returns is always valid for the string the caller will slice. Every
// marker this repository searches for is ASCII, which is what makes a byte-wise
// fold both correct and cheaper than building a lower-cased copy.
//
// ── SCOPE ──────────────────────────────────────────────────────────────────
//
// The fold is ASCII A-Z/a-z ONLY. Bytes outside that range are compared
// verbatim, so a byte of a multi-byte rune is never rewritten and can never be
// made to match something it is not. A marker carrying non-ASCII bytes is
// matched exactly on those bytes; callers wanting Unicode case folding want
// strings.EqualFold on whole tokens, not this.
//
// This is a real capability with one job, not a "utils" drawer (CLAUDE.md §2):
// nothing else belongs in this package.
package asciifold

// lower folds one byte the ASCII way. Bytes outside A-Z are returned unchanged,
// which is exactly what a marker scan wants.
func lower(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + ('a' - 'A')
	}
	return b
}

// matchAt reports whether marker matches s at offset at. The caller guarantees
// at+len(marker) <= len(s).
func matchAt(s, marker string, at int) bool {
	for j := 0; j < len(marker); j++ {
		if lower(s[at+j]) != lower(marker[j]) {
			return false
		}
	}
	return true
}

// Index returns the byte offset in s of the FIRST ASCII case-insensitive match
// of marker, or -1 when there is none. An empty marker returns 0, matching
// strings.Index. The offset is always a valid index into s.
func Index(s, marker string) int {
	if marker == "" {
		return 0
	}
	if len(marker) > len(s) {
		return -1
	}
	for i := 0; i <= len(s)-len(marker); i++ {
		if matchAt(s, marker, i) {
			return i
		}
	}
	return -1
}

// LastIndex returns the byte offset in s of the LAST ASCII case-insensitive
// match of marker, or -1 when there is none. An empty marker returns len(s),
// matching strings.LastIndex. The offset is always a valid index into s.
func LastIndex(s, marker string) int {
	if marker == "" {
		return len(s)
	}
	if len(marker) > len(s) {
		return -1
	}
	for i := len(s) - len(marker); i >= 0; i-- {
		if matchAt(s, marker, i) {
			return i
		}
	}
	return -1
}

// Contains reports whether marker appears in s, ASCII case-insensitively. It is
// the allocation-free form of strings.Contains(strings.ToLower(s), marker),
// which is safe on its own but pointlessly copies the whole string.
func Contains(s, marker string) bool { return Index(s, marker) >= 0 }
