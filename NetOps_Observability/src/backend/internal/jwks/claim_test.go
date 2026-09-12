// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package jwks

import (
	"encoding/json"
	"testing"
)

// claim_test.go — Claims.Claim, the accessor for a claim whose NAME is operator
// configuration (an elevation TTL / reason / scope claim). Two properties
// matter: it reads scalars faithfully, and it reports everything else absent
// rather than stringifying it into something a caller would act on.

func claimsFrom(t *testing.T, raw string) Claims {
	t.Helper()
	var c Claims
	if err := json.Unmarshal([]byte(raw), &c); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	c.Raw = json.RawMessage(raw)
	return c
}

func TestClaimReadsScalars(t *testing.T) {
	c := claimsFrom(t, `{"sid":"s-1","access_expires_at":1789000000,"max_session_minutes":30,"chg":" CHG-1 ","frac":1.5}`)
	if c.Sid != "s-1" {
		t.Errorf("sid %q — the IdP session id must decode into the struct", c.Sid)
	}
	for _, tc := range []struct{ name, want string }{
		{"access_expires_at", "1789000000"},
		{"max_session_minutes", "30"},
		{"chg", "CHG-1"},
		{"frac", "1.5"},
	} {
		got, ok := c.Claim(tc.name)
		if !ok || got != tc.want {
			t.Errorf("Claim(%q) = (%q, %v), want (%q, true)", tc.name, got, ok, tc.want)
		}
	}
}

func TestClaimReportsEverythingElseAbsent(t *testing.T) {
	c := claimsFrom(t, `{"obj":{"a":1},"arr":[1,2],"flag":true,"nil":null,"blank":"  "}`)
	for _, name := range []string{"obj", "arr", "flag", "nil", "blank", "missing"} {
		if got, ok := c.Claim(name); ok {
			t.Errorf("Claim(%q) = (%q, true); a non-scalar or blank claim must read as ABSENT", name, got)
		}
	}
	if _, ok := (Claims{}).Claim("anything"); ok {
		t.Error("a Claims with no verified raw body answered a claim lookup")
	}
	if _, ok := c.Claim("  "); ok {
		t.Error("a blank claim NAME resolved to something")
	}
}
