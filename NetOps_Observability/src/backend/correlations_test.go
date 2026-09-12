// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"

	"netops/backend/secapi"
)

// isUUIDToken gates every value interpolated into correlations SQL / proxied
// replay URLs — shape validation, never quote-escaping (SR-011 discipline).
func TestIsUUIDToken(t *testing.T) {
	valid := []string{
		"9f0537bd-0787-547e-a6fc-6692acaec13c",
		"B8C6C907-D0FD-570C-BE97-D18E257FC61F",
	}
	for _, v := range valid {
		if !isUUIDToken(v) {
			t.Errorf("%s should be valid", v)
		}
	}
	invalid := []string{
		"",
		"9f0537bd",
		"9f0537bd-0787-547e-a6fc-6692acaec13cX", // too long
		"9f0537bd-0787-547e-a6fc-6692acaec13'",  // quote
		"9f0537bd_0787_547e_a6fc_6692acaec13c",  // wrong separators
		"zf0537bd-0787-547e-a6fc-6692acaec13c",  // non-hex
		"9f0537bd-0787-547e-a6fc-6692acaec13c; DROP ALL", // injection shape
	}
	for _, v := range invalid {
		if isUUIDToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// isDatetimeToken gates the object-window bounds before they are interpolated
// into the timeline ts filter (same SR-011 shape-validation discipline).
func TestIsDatetimeToken(t *testing.T) {
	valid := []string{
		"2026-06-14 05:11:39.836", "2026-06-14 05:11:39", "2026-01-01 00:00:00.000",
		"2026-06-14T05:11:39Z", "2026-06-14T05:11:39.836Z", // RFC 3339 wire form (chISO, S3)
	}
	for _, v := range valid {
		if !isDatetimeToken(v) {
			t.Errorf("%q should be valid", v)
		}
	}
	invalid := []string{
		"",
		"short",                      // < 10 chars
		"2026-06-14 05:11:39'; DROP", // quote + injection
		"now() - INTERVAL 1 DAY",     // function call (parens/letters)
		"2026-06-14 05:11:39.836xxxxxxxxxxxxxxxxxxxxxxxx", // too long (> 32)
	}
	for _, v := range invalid {
		if isDatetimeToken(v) {
			t.Errorf("%q should be rejected", v)
		}
	}
}

// ── Exposure Story predicate (QA 2026-09-03, D-01) ──────────────────────────
//
// The list used to join ONLY on ev.signal_id, which the engine hardcoded to the
// nil UUID on every edge-evidence row — so GET /api/security/exposure-stories
// could never return a row. The predicate is now two branches (signal join OR
// exact node-key suffix) and this pins BOTH, plus the fail-closed and window
// bounds that keep the subquery cheap and safe.
func TestSecurityExposureStoriesCondPinsBothBranches(t *testing.T) {
	const since = "created_at >= now() - INTERVAL 3600 SECOND"
	sql := securityExposureStoriesCond(since)

	mustContain := func(what, needle string) {
		t.Helper()
		if !strings.Contains(sql, needle) {
			t.Errorf("%s: missing %q in:\n%s", what, needle, sql)
		}
	}

	// branch 1 — the signal-id join, with the full vocabulary.
	mustContain("branch 1", "ev.signal_id IN (")
	mustContain("branch 1", "FROM netops.corr_signals AS sig")
	mustContain("branch 1", "sig.kind IN ('security_posture','security_exposure','security_signal')")

	// branch 2 — the EXACT node-key suffix over both halves of subject_id.
	mustContain("branch 2", "ev.subject_kind = 'edge'")
	mustContain("branch 2", "splitByString('->', ev.subject_id)")
	mustContain("branch 2", "arrayExists(n -> ")
	for _, k := range secapi.SecuritySignalKinds {
		mustContain("branch 2 kind "+k, "endsWith(n, ':"+k+"')")
	}

	// the two branches are OR'd, and the OR is parenthesised INSIDE the
	// evidence-side WHERE — never widening the window bound below.
	mustContain("branches are OR'd", "))\n\t             OR (ev.subject_kind = 'edge'")

	// both window bounds survive: the evidence side takes the caller's window,
	// the signal side its own 30-day bound. Neither may become a full scan.
	mustContain("evidence window", "WHERE ev."+since)
	mustContain("signal window", "sig.ts >= now() - INTERVAL 2592000 SECOND")
	if securityStoryWindowSeconds != 30*24*60*60 {
		t.Errorf("signal window moved: %d", securityStoryWindowSeconds)
	}

	// substring matching is forbidden: a device literally named "security"
	// must not become an exposure story.
	for _, banned := range []string{"LIKE", "like", "%security%", "position(", "match("} {
		if strings.Contains(sql, banned) {
			t.Errorf("substring/regex matching leaked into the predicate (%q):\n%s", banned, sql)
		}
	}

	// the picked set is still keyed on (correlation_id, version) — the list
	// shape correlationsListSQL expects.
	mustContain("picked-set key", "(correlation_id, version) IN (")
}

// A vocabulary that is empty — or that has been widened with something that is
// not a plain identifier — must NEVER open the list up. Fail closed.
func TestSecurityExposureStoriesCondFailsClosed(t *testing.T) {
	saved := secapi.SecuritySignalKinds
	t.Cleanup(func() { secapi.SecuritySignalKinds = saved })

	for _, tc := range []struct {
		name  string
		kinds []string
	}{
		{"empty", []string{}},
		{"nil", nil},
		{"all non-identifier", []string{"a-b", "x'; DROP TABLE netops.corr_evidence; --", "9"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secapi.SecuritySignalKinds = tc.kinds
			if got := securityExposureStoriesCond("created_at >= now()"); got != "0" {
				t.Errorf("want fail-closed %q, got:\n%s", "0", got)
			}
		})
	}

	// a PARTIALLY bad vocabulary keeps only the safe tokens, in both branches.
	secapi.SecuritySignalKinds = []string{"security_posture", "bad'token"}
	got := securityExposureStoriesCond("created_at >= now()")
	if strings.Contains(got, "bad'token") {
		t.Errorf("a non-identifier kind reached the SQL:\n%s", got)
	}
	if !strings.Contains(got, "sig.kind IN ('security_posture')") ||
		!strings.Contains(got, "endsWith(n, ':security_posture')") {
		t.Errorf("the safe kind was dropped from a branch:\n%s", got)
	}
}
