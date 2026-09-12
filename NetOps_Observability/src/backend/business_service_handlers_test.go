// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"
)

// bizSvcOwner: empty = unset (valid); non-empty follows the printable
// single-line ≤128 name rule.
func TestBizSvcOwnerBounds(t *testing.T) {
	valid := []string{"", "   ", "payments-sre", "Team Payments (EMEA)", "a.rakurty@example.com"}
	for _, s := range valid {
		if !bizSvcOwner(s) {
			t.Errorf("bizSvcOwner(%q) = false, want true", s)
		}
	}
	long := make([]byte, 129)
	for i := range long {
		long[i] = 'a'
	}
	invalid := []string{"line\nbreak", "ctrl\x01char", string(long)}
	for _, s := range invalid {
		if bizSvcOwner(s) {
			t.Errorf("bizSvcOwner(%q) = true, want false", s)
		}
	}
}

// bizSvcRunbookURL: empty = unset (valid); non-empty must be an absolute
// https:// URL a browser can safely open — never javascript:/data:/http:,
// never relative, bounded at 512 chars, no control chars.
func TestBizSvcRunbookURLBounds(t *testing.T) {
	valid := []string{
		"",
		"   ",
		"https://runbooks.example.com/payments",
		"https://wiki.corp.example/display/SRE/Payments+Runbook?version=2",
	}
	for _, s := range valid {
		if !bizSvcRunbookURL(s) {
			t.Errorf("bizSvcRunbookURL(%q) = false, want true", s)
		}
	}
	long := "https://runbooks.example.com/" + strings.Repeat("a", 512)
	invalid := []string{
		"http://runbooks.example.com/payments", // https only
		"javascript:alert(1)",
		"data:text/html,x",
		"//runbooks.example.com/payments", // scheme-relative
		"/runbooks/payments",              // relative
		"https://",                        // no host
		"not a url",
		"https://runbooks.example.com/pay\nments", // control char
		long, // > 512
	}
	for _, s := range invalid {
		if bizSvcRunbookURL(s) {
			t.Errorf("bizSvcRunbookURL(%q) = true, want false", s)
		}
	}
}
