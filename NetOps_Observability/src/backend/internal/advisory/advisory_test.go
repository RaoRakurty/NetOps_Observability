// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package advisory

import (
	"context"
	"errors"
	"testing"
)

// staticConformance asserts every provider impl satisfies the seam at compile time.
var (
	_ VendorAdvisoryProvider = (*OfflineProvider)(nil)
	_ VendorAdvisoryProvider = (*MockProvider)(nil)
	_ VendorAdvisoryProvider = (*CiscoOpenVulnProvider)(nil)
)

func TestVersionConstraintMatches(t *testing.T) {
	cases := []struct {
		name string
		c    VersionConstraint
		v    string
		want bool
	}{
		{"exact hit", VersionConstraint{Exact: "17.9.4"}, "17.9.4", true},
		{"exact miss", VersionConstraint{Exact: "17.9.4"}, "17.9.5", false},
		{"range end-excl inside", VersionConstraint{EndExcl: "7.4.0"}, "7.2.8", true},
		{"range end-excl boundary", VersionConstraint{EndExcl: "7.4.0"}, "7.4.0", false},
		{"range end-incl boundary", VersionConstraint{EndIncl: "7.4.0"}, "7.4.0", true},
		{"range start-incl below", VersionConstraint{StartIncl: "7.2.0", EndExcl: "7.4.0"}, "7.0.1", false},
		{"range both inside", VersionConstraint{StartIncl: "7.2.0", EndExcl: "7.4.0"}, "7.2.5", true},
		{"unconstrained matches nothing", VersionConstraint{}, "7.2.5", false},
		{"empty version never matches", VersionConstraint{Exact: "7.2.5"}, "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.c.Matches(c.v); got != c.want {
				t.Fatalf("Matches(%q) = %v, want %v", c.v, got, c.want)
			}
		})
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"critical": "critical",
		"HIGH":     "high",
		"Medium":   "medium",
		"moderate": "medium",
		"low":      "low",
		"none":     "info",
		"":         "info",
		"bogus":    "info",
	}
	for in, want := range cases {
		if got := normalizeSeverity(in); got != want {
			t.Errorf("normalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCiscoStubNotConfigured(t *testing.T) {
	p := NewCiscoOpenVulnProvider()
	if p.Name() != SourceCiscoOpenVuln {
		t.Fatalf("Name = %q, want %q", p.Name(), SourceCiscoOpenVuln)
	}
	advs, err := p.AdvisoriesFor(context.Background(), Query{Vendor: "cisco", Platform: "IOS-XE", Version: "17.9.4a"})
	if advs != nil {
		t.Fatalf("stub returned advisories: %v", advs)
	}
	if !errors.Is(err, ErrNotConfigured) {
		t.Fatalf("err = %v, want ErrNotConfigured", err)
	}
}

func TestProviderContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	providers := []VendorAdvisoryProvider{
		NewMockProvider("mock"),
		NewCiscoOpenVulnProvider(),
		NewOfflineProvider(nil),
	}
	for _, p := range providers {
		if _, err := p.AdvisoriesFor(ctx, Query{Vendor: "cisco", Platform: "ios-xe", Version: "1"}); err == nil {
			t.Errorf("%s: expected error on cancelled context", p.Name())
		}
	}
}
