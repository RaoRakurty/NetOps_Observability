// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package srlpath renders a Nokia SR Linux configuration PATH as a regexp
// fragment that matches every spelling the platform legally writes.
//
// WHY THIS EXISTS. SR Linux renders its configuration as a flat list of `set`
// statements, and the SAME path reaches us in three spellings — all legal, all
// observed:
//
//	set / system aaa authentication user bob …   (bare slash, space-separated —
//	                                              the `info … flat` / commit form)
//	set /system aaa authentication user bob …    (the commit-audit line captured
//	                                              on the lab, 2026-09-03)
//	set /system/aaa/authentication/user/bob      (the gNMI-style path form)
//
// A pattern typed out against ONE of them is silently dead on the other two.
// That cost us twice: a log rule that matched only the first spelling was blind
// to two thirds of this platform's commit-audit lines (tracker D-02), and every
// SR Linux HARDENING rule anchored on `^set / system …`, so a capture in any
// other form matched nothing and the device was reported CLEAN (tracker 296) —
// a fail-open on a security control.
//
// This package is the ONE place the spellings are encoded. It is deliberately
// dialect-specific and dependency-free (stdlib only, no regexp state) so both
// the core log catalogue (internal/threatlane) and the SR Linux hardening
// dialect (enterprise/dialects) can import it without either importing the
// other — a cross-domain import the architecture rules forbid.
package srlpath

import "strings"

// Sep is the separator SR Linux writes BETWEEN configuration path elements. It
// is a character class rather than a literal precisely because of the three
// spellings above: a space, a slash, or both.
const Sep = `[\s/]+`

// Path renders a configuration path as a regexp FRAGMENT matching all three
// spellings. The leading element is `/\s*` — the slash is always present, the
// space after it optional. Segments are joined by Sep. The caller appends
// whatever boundary or suffix the rule needs, so a path fragment never asserts
// its own end.
//
// Segments are regexp SOURCE, not literals: a caller may pass a capture group
// (`(\S+?)` for a list key) or a character class as a segment. Nothing here
// quotes them.
func Path(segs ...string) string {
	return `/\s*` + strings.Join(segs, Sep)
}

// Statement renders a whole `set <path>` statement as an anchored regexp
// fragment — Path prefixed with the `set` keyword. Leading whitespace is
// tolerated so an indented capture reads the same as a flush-left one.
//
// Use it for configuration rules (`Statement("system", "ntp", "admin-state") +
// Sep + "enable"`); use Path for a fragment that appears mid-line, e.g. inside
// a log message.
func Statement(segs ...string) string {
	return `^\s*set\s+` + Path(segs...)
}

// IsStatement reports whether line parses as an SR Linux `set <path>` statement
// at all, in ANY of the three spellings — the question "is this text something
// an SR Linux rule can read", not "does it match a particular rule".
//
// It is the fail-closed test at the dialect boundary: a configuration in which
// NOT ONE line answers true is not something this platform's rule pack can
// assess, and the honest answer for it is "not evaluated", never a clean pass.
// Kept as string handling rather than a regexp so it needs no package-level
// compiled state (§5 no globals) and costs nothing per line.
func IsStatement(line string) bool {
	s := strings.TrimSpace(line)
	const kw = "set"
	if !strings.HasPrefix(s, kw) {
		return false
	}
	rest := s[len(kw):]
	trimmed := strings.TrimLeft(rest, " \t")
	if len(trimmed) == len(rest) {
		return false // `sets …` / `set=` — the keyword must be its own token
	}
	return strings.HasPrefix(trimmed, "/")
}
