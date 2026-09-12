// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package dem

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateAcceptsEachKind(t *testing.T) {
	cases := []struct {
		name string
		in   Target
		want func(Target) error
	}{
		{"icmp host", Target{TenantID: "acme", Name: "spine1", Kind: KindICMP, Host: "10.70.245.11"}, nil},
		{"icmp name", Target{TenantID: "acme", Name: "dc", Kind: KindICMP, Host: "spine1.lab.example"}, nil},
		{"tcp host:port", Target{TenantID: "acme", Name: "tls", Kind: KindTCP, Host: "10.0.0.5:443"}, func(g Target) error {
			if g.Port != 443 || g.Host != "10.0.0.5" {
				return errf("host:port did not split: %+v", g)
			}
			return nil
		}},
		{"tcp port field", Target{TenantID: "acme", Name: "ssh", Kind: KindTCP, Host: "box", Port: 22}, nil},
		{"dns", Target{TenantID: "acme", Name: "corp", Kind: KindDNS, Host: "www.example.com."}, nil},
		{"dns with resolver", Target{TenantID: "acme", Name: "corp", Kind: KindDNS, Host: "www.example.com", Resolver: "10.0.0.53:53"}, nil},
		{"http", Target{TenantID: "acme", Name: "portal", Kind: KindHTTP, Host: "https://portal.example/health"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			if err := got.Validate(); err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if got.IntervalSec != DefaultIntervalSec {
				t.Fatalf("interval default not applied: %d", got.IntervalSec)
			}
			if c.want != nil {
				if err := c.want(got); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestValidateRefusals(t *testing.T) {
	cases := []struct {
		name string
		in   Target
		want string
	}{
		{"no tenant", Target{Name: "x", Kind: KindICMP, Host: "h"}, "concrete tenant"},
		{"wildcard tenant", Target{TenantID: "*", Name: "x", Kind: KindICMP, Host: "h"}, "concrete tenant"},
		{"no name", Target{TenantID: "acme", Kind: KindICMP, Host: "h"}, "name is required"},
		{"bad kind", Target{TenantID: "acme", Name: "x", Kind: "smtp", Host: "h"}, "kind must be one of"},
		{"reserved kind is not declarable", Target{TenantID: "acme", Name: "x", Kind: KindTunnel, Host: "h"}, "kind must be one of"},
		{"no host", Target{TenantID: "acme", Name: "x", Kind: KindICMP}, "host/url is required"},
		{"tcp without port", Target{TenantID: "acme", Name: "x", Kind: KindTCP, Host: "box"}, "needs a port"},
		{"http not a url", Target{TenantID: "acme", Name: "x", Kind: KindHTTP, Host: "ftp://box/f"}, "scheme must be"},
		{"http no host", Target{TenantID: "acme", Name: "x", Kind: KindHTTP, Host: "https:///health"}, "no host"},
		{"bad hostname", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "a b c"}, "invalid character"},
		{"interval too small", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h", IntervalSec: 1}, "interval_sec must be"},
		{"interval too large", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h", IntervalSec: 99999}, "interval_sec must be"},
		{"expect_status off http", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h", ExpectStatus: 200}, "only to an http"},
		{"expect_status invalid", Target{TenantID: "acme", Name: "x", Kind: KindHTTP, Host: "https://h/", ExpectStatus: 42}, "expect_status must be"},
		{"latency budget out of range", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h", LatencyBudgetMs: -1}, "latency_budget_ms"},
		{"availability budget out of range", Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h", AvailabilityBudgetPct: 101}, "availability_budget_pct"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := c.in
			err := got.Validate()
			if err == nil {
				t.Fatalf("expected a refusal, got none (%+v)", got)
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("refusal %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

// A site/app label becomes a metric label. Anything that could terminate a label
// set or forge a second one must not survive validation.
func TestLabelsAreSanitized(t *testing.T) {
	tgt := Target{TenantID: "acme", Name: "x", Kind: KindICMP, Host: "h",
		Site: `dc1",tenant="globex`, App: "pay{}\\ments"}
	if err := tgt.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	for _, bad := range []string{`"`, "{", "}", "\\", ","} {
		if strings.Contains(tgt.Site, bad) || strings.Contains(tgt.App, bad) {
			t.Fatalf("label kept %q: site=%q app=%q", bad, tgt.Site, tgt.App)
		}
	}
}

func TestIntervalClamps(t *testing.T) {
	if got := (Target{}).Interval(); got != DefaultIntervalSec*time.Second {
		t.Fatalf("zero interval → %v", got)
	}
	if got := (Target{IntervalSec: 1}).Interval(); got != MinIntervalSec*time.Second {
		t.Fatalf("tiny interval → %v", got)
	}
	if got := (Target{IntervalSec: 1 << 20}).Interval(); got != MaxIntervalSec*time.Second {
		t.Fatalf("huge interval → %v", got)
	}
}

func TestEffectiveAvailabilityBudgetSaysWhoDeclaredIt(t *testing.T) {
	pct, declared := (Target{}).EffectiveAvailabilityBudget()
	if declared || pct != DefaultAvailabilityBudgetPct {
		t.Fatalf("undeclared budget: %v %v", pct, declared)
	}
	pct, declared = (Target{AvailabilityBudgetPct: 99.9}).EffectiveAvailabilityBudget()
	if !declared || pct != 99.9 {
		t.Fatalf("declared budget: %v %v", pct, declared)
	}
}

// errf keeps the table's assertions readable without pulling fmt into every case.
func errf(f string, a ...any) error { return fmt.Errorf(f, a...) }
