// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package elevation

import (
	"errors"
	"testing"
	"time"
)

// claimSet turns a map into the Claim accessor the package takes.
func claimSet(m map[string]string) Claim {
	return func(name string) (string, bool) {
		v, ok := m[name]
		return v, ok && v != ""
	}
}

// The one property that has to hold for every input: a claim may SHORTEN a
// grant, never lengthen it past the provider ceiling.
func TestWindowNeverExceedsTheProviderCeiling(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	pol := Policy{Provider: "elev", TTLClaim: "ttl", MaxMinutes: 30}
	ceiling := now.Add(30 * time.Minute)

	cases := []struct {
		name string
		val  string
	}{
		{"minutes far over the ceiling", "600"},
		{"epoch far over the ceiling", "1789000000"},
		{"rfc3339 far over the ceiling", "2030-01-01T00:00:00Z"},
		{"nonsense", "next tuesday"},
		{"negative", "-5"},
		{"zero", "0"},
		{"blank", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, exp, _, ok := pol.Window(now, claimSet(map[string]string{"ttl": c.val}))
			if !ok {
				t.Fatalf("window refused for %q; only an already-past instant may refuse", c.val)
			}
			if exp.After(ceiling) {
				t.Errorf("expiry %v is past the ceiling %v — a claim must never extend a grant", exp, ceiling)
			}
		})
	}
}

func TestWindowHonoursAShorterClaim(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	pol := Policy{TTLClaim: "ttl", MaxMinutes: 60}
	for _, c := range []struct {
		name, val string
		want      time.Time
	}{
		{"minutes", "15", now.Add(15 * time.Minute)},
		{"epoch seconds", itoa(now.Add(10 * time.Minute).Unix()), now.Add(10 * time.Minute)},
		{"rfc3339", now.Add(20 * time.Minute).Format(time.RFC3339), now.Add(20 * time.Minute)},
	} {
		t.Run(c.name, func(t *testing.T) {
			_, exp, src, ok := pol.Window(now, claimSet(map[string]string{"ttl": c.val}))
			if !ok {
				t.Fatal("window refused a live claim")
			}
			if !exp.Equal(c.want) {
				t.Errorf("expiry %v, want %v", exp, c.want)
			}
			if src != SourceClaim {
				t.Errorf("source %q, want %q — the claim decided this window", src, SourceClaim)
			}
		})
	}
}

func TestWindowRefusesAnAlreadyExpiredClaim(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	pol := Policy{TTLClaim: "ttl", MaxMinutes: 60}
	past := now.Add(-time.Minute).Unix()
	if _, _, _, ok := pol.Window(now, claimSet(map[string]string{"ttl": itoa(past)})); ok {
		t.Fatal("a grant the IdP says is already over was accepted")
	}
}

func TestWindowWithNoClaimUsesTheCeiling(t *testing.T) {
	now := time.Date(2026, 9, 7, 12, 0, 0, 0, time.UTC)
	nb, exp, src, ok := (Policy{MaxMinutes: 45}).Window(now, nil)
	if !ok || src != SourceProvider {
		t.Fatalf("no-claim window: ok=%v source=%q", ok, src)
	}
	if !nb.Equal(now) {
		t.Errorf("not_before %v, want now — a grant is live the moment it is made", nb)
	}
	if !exp.Equal(now.Add(45 * time.Minute)) {
		t.Errorf("expiry %v, want the 45-minute ceiling", exp)
	}
}

// A policy with no ceiling at all must not mean "forever".
func TestWindowWithNoCeilingIsStillBounded(t *testing.T) {
	now := time.Now().UTC()
	_, exp, _, ok := (Policy{}).Window(now, nil)
	if !ok || !exp.After(now) || exp.After(now.Add(2*time.Minute)) {
		t.Fatalf("a ceiling-less policy produced %v; it must fall back to the shortest window", exp)
	}
}

func TestReasonFallsBackAndIsSanitised(t *testing.T) {
	pol := Policy{ReasonClaim: "why"}
	if got := pol.Reason(claimSet(map[string]string{})); got != DefaultReason {
		t.Errorf("missing claim → %q, want %q", got, DefaultReason)
	}
	if got := (Policy{}).Reason(claimSet(map[string]string{"why": "x"})); got != DefaultReason {
		t.Errorf("unconfigured claim → %q, want %q", got, DefaultReason)
	}
	got := pol.Reason(claimSet(map[string]string{"why": "CHG-1\ninjected: line"}))
	if got != "CHG-1 injected: line" {
		t.Errorf("reason %q — control characters must not survive into an audit record", got)
	}
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	if n := len(pol.Reason(claimSet(map[string]string{"why": string(long)}))); n != MaxReasonLen {
		t.Errorf("reason length %d, want the %d cap", n, MaxReasonLen)
	}
}

func TestScopeIsAbsentOrBoundedOrRefused(t *testing.T) {
	pol := Policy{ScopeClaim: "target"}
	if v, err := pol.Scope(claimSet(map[string]string{})); v != "" || err != nil {
		t.Errorf("absent claim → (%q, %v), want the tenant-scoped default", v, err)
	}
	if v, err := pol.Scope(claimSet(map[string]string{"target": "dev-1"})); v != "dev-1" || err != nil {
		t.Errorf("plain id → (%q, %v)", v, err)
	}
	for _, bad := range []string{"../../etc/passwd", "http://evil/x", "a b", "dev\n1", "-leading"} {
		if _, err := pol.Scope(claimSet(map[string]string{"target": bad})); !errors.Is(err, ErrScopeMalformed) {
			t.Errorf("scope %q was accepted; a present-but-unusable scope must REFUSE, never widen", bad)
		}
	}
	over := make([]byte, MaxScopeLen+10)
	for i := range over {
		over[i] = 'a'
	}
	if _, err := pol.Scope(claimSet(map[string]string{"target": string(over)})); err == nil {
		t.Error("an over-long scope was accepted")
	}
}

func TestRefusalNamesEveryProvider(t *testing.T) {
	r := NewRefusal([]ProviderRef{{ID: "a", Name: "Alpha"}, {ID: "b", Name: "Beta"}})
	if r.Code != CodeRequired {
		t.Errorf("code %q", r.Code)
	}
	if want := "elevated access is required — sign in through Alpha or Beta"; r.Error != want {
		t.Errorf("message %q, want %q", r.Error, want)
	}
	none := NewRefusal(nil)
	if none.Providers == nil {
		t.Error("providers must serialise as [], never null")
	}
	if none.Error == "" || none.Code != CodeRequired {
		t.Error("a refusal with no configured door must still be a named refusal")
	}
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	if neg {
		return "-" + string(b)
	}
	return string(b)
}
