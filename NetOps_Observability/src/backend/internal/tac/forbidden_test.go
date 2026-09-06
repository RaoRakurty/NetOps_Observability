// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package tac

// forbidden_test.go — the STRUCTURAL guards behind the owner's 2026-09-05
// output-only command policy.
//
// The policy is only worth having if it cannot be walked around, so these tests
// attack it from both sides:
//
//   - no shipped command hits it (the data is clean);
//   - the GATE refuses a forbidden command even when the closed table has been
//     TAMPERED to contain it (the enforcement does not depend on the data);
//   - matching is on tokens, so `show reload cause` and `show system processes`
//     stay allowed while `reload` and `system internal … restart` do not;
//   - a probe is admitted only inside its bounds.

import (
	"strings"
	"testing"

	"netops/backend/internal/protocoldiag"
)

func policyForTest(t *testing.T) (*Catalog, *Policy) {
	t.Helper()
	c, err := Default()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	p := c.Policy()
	if p == nil {
		t.Fatal("the loaded catalog carries no command policy")
	}
	return c, p
}

// TestPolicyLoadsWithAllThreeFamilies proves the owner's three families are
// stated in the data, in the data's own words.
func TestPolicyLoadsWithAllThreeFamilies(t *testing.T) {
	_, p := policyForTest(t)
	if len(p.Families) != 3 {
		t.Fatalf("policy declares %d families, want the owner's three", len(p.Families))
	}
	want := map[string]bool{FamilyConfig: false, FamilyRestart: false, FamilyDaemon: false}
	for _, f := range p.Families {
		if _, ok := want[f.ID]; !ok {
			t.Errorf("family %q is outside the closed set", f.ID)
		}
		want[f.ID] = true
		if strings.TrimSpace(f.Rule) == "" {
			t.Errorf("family %q states no rule", f.ID)
		}
	}
	for id, seen := range want {
		if !seen {
			t.Errorf("family %q is not declared", id)
		}
	}
	if len(p.Rules()) < 60 {
		t.Errorf("the policy carries only %d rules; the vocabulary is meant to cover every dialect", len(p.Rules()))
	}
	if p.Census.Total != p.Census.ByFamily[FamilyConfig]+p.Census.ByFamily[FamilyRestart]+p.Census.ByFamily[FamilyDaemon] {
		t.Errorf("the census does not add up: %+v", p.Census)
	}
}

// TestNoShippedCommandIsForbidden is the data guard: if a config / restart /
// daemon command ever lands in a plan, this fails before anything ships.
func TestNoShippedCommandIsForbidden(t *testing.T) {
	c, p := policyForTest(t)
	for _, d := range c.Dialects() {
		plan, ok := c.PlanFor(d)
		if !ok {
			t.Fatalf("dialect %s has no plan", d)
		}
		for intent, b := range plan.Bindings {
			if rule, hit := p.Match(d, b.Command); hit {
				t.Errorf("%s/%s: %q hits the %s rule %q", d, intent, b.Command, rule.Family, rule)
			}
			if b.Teardown == "" {
				continue
			}
			if rule, hit := p.Match(d, b.Teardown); hit {
				t.Errorf("%s/%s teardown: %q hits the %s rule %q", d, intent, b.Teardown, rule.Family, rule)
			}
		}
	}
}

// forbiddenProbes is one representative command per family per dialect. Every
// one of them must be refused by the gate, on that dialect, whatever the table
// says.
var forbiddenProbes = map[string][]string{
	"cisco-ios":         {"configure terminal", "reload in 5", "debug ip ospf adj"},
	"cisco-iosxe":       {"copy running-config startup-config", "reload", "debug ip bgp"},
	"cisco-iosxr":       {"commit replace", "reload location all", "process restart ospf"},
	"cisco-nxos":        {"write erase", "reload", "system internal ethpm restart"},
	"cisco-asa":         {"write memory", "reload", "debug crypto ikev2"},
	"arista-eos":        {"configure", "reload now", "agent Rib terminate"},
	"juniper-junos":     {"request system software add x", "request system reboot", "restart routing"},
	"nokia-sros":        {"admin save", "admin reboot now", "admin restart"},
	"nokia-srlinux":     {"tools platform linecard 1", "tools system reboot", "tools system app-management application bgp_mgr restart"},
	"huawei-vrp":        {"reset counters interface", "reboot", "pads diagnose ospf"},
	"fortinet-fortios":  {"execute factoryreset", "execute reboot", "diagnose test application miglogd 6"},
	"paloalto-panos":    {"request content upgrade install", "request restart system", "debug dnsproxyd show sys-statistics"},
	"mikrotik-routeros": {"/system reset-configuration", "/system reboot", "kill 1"},
}

// TestGateRefusesForbiddenEvenWithATamperedTable is the second layer. It builds
// a gate whose closed table DELIBERATELY contains every forbidden command — the
// exact state a hand-edited or corrupted plan file would produce — and proves
// the gate still refuses, because the policy is a separate authority from the
// table.
func TestGateRefusesForbiddenEvenWithATamperedTable(t *testing.T) {
	_, p := policyForTest(t)
	tampered := &Gate{byDialect: map[string][][]string{}, policy: p}
	for dialect, cmds := range forbiddenProbes {
		for _, cmd := range cmds {
			tampered.byDialect[dialect] = append(tampered.byDialect[dialect], strings.Fields(cmd))
		}
	}
	for dialect, cmds := range forbiddenProbes {
		for _, cmd := range cmds {
			if _, hit := p.Match(dialect, cmd); !hit {
				t.Errorf("%s: %q is not matched by any policy rule", dialect, cmd)
			}
			if tampered.AllowsDialect(dialect, cmd) {
				t.Errorf("%s: the gate allowed %q even though the policy forbids it", dialect, cmd)
			}
		}
	}
	// Sanity: the tampered table DOES contain the strings, so the refusal above
	// came from the policy and not from an empty table.
	clean := &Gate{byDialect: tampered.byDialect}
	if !clean.AllowsDialect("cisco-ios", "reload in 5") {
		t.Fatal("the tampered table does not contain the command, so the test proves nothing")
	}
}

// TestPolicyMatchesTokensNotSubstrings is the distinction the whole policy rests
// on: an OUTPUT command that merely mentions a forbidden word stays allowed.
func TestPolicyMatchesTokensNotSubstrings(t *testing.T) {
	_, p := policyForTest(t)
	allowed := []struct{ dialect, cmd string }{
		{"cisco-iosxe", "show reload"},
		{"cisco-iosxe", "show version"},
		{"cisco-nxos", "show system internal ethpm event-history"},
		{"cisco-iosxr", "show processes cpu"},
		{"cisco-iosxr", "admin show platform"},
		{"juniper-junos", "show system processes extensive"},
		{"juniper-junos", "show system commit"},
		{"nokia-sros", "show system information"},
		{"nokia-srlinux", "info from state interface ethernet-1/1"},
		{"huawei-vrp", "display cpu-usage"},
		{"fortinet-fortios", "get system status"},
		{"fortinet-fortios", "diagnose debug crashlog read"},
		{"fortinet-fortios", "execute ping 192.0.2.1"},
		{"fortinet-fortios", "execute log display"},
		{"paloalto-panos", "show system info"},
		{"paloalto-panos", "request license info"},
		{"arista-eos", "show agent Rib logs"},
	}
	for _, tc := range allowed {
		if rule, hit := p.Match(tc.dialect, tc.cmd); hit {
			t.Errorf("%s: output command %q was refused by the %s rule %q", tc.dialect, tc.cmd, rule.Family, rule)
		}
	}
	refused := []struct {
		dialect, cmd, family string
	}{
		{"cisco-iosxe", "reload", FamilyRestart},
		{"cisco-iosxe", "configure terminal", FamilyConfig},
		{"cisco-iosxe", "clear counters", FamilyConfig},
		{"cisco-iosxe", "debug ip ospf hello", FamilyDaemon},
		{"cisco-nxos", "system internal ethpm restart", FamilyDaemon},
		{"juniper-junos", "restart routing gracefully", FamilyDaemon},
		{"juniper-junos", "request system reboot", FamilyRestart},
		{"nokia-sros", "admin reboot", FamilyRestart},
		{"nokia-srlinux", "tools system app-management application bgp_mgr restart", FamilyDaemon},
		{"huawei-vrp", "reset bgp all", FamilyConfig},
		{"huawei-vrp", "pads diagnose", FamilyDaemon},
		{"fortinet-fortios", "diagnose test application miglogd 6", FamilyDaemon},
		{"fortinet-fortios", "execute reboot", FamilyRestart},
		{"fortinet-fortios", "execute tac report", FamilyConfig},
		{"paloalto-panos", "debug software restart process dnsproxy", FamilyDaemon},
	}
	for _, tc := range refused {
		rule, hit := p.Match(tc.dialect, tc.cmd)
		if !hit {
			t.Errorf("%s: %q was NOT refused", tc.dialect, tc.cmd)
			continue
		}
		if rule.Family != tc.family {
			t.Errorf("%s: %q landed in family %q, want %q (rule %q)", tc.dialect, tc.cmd, rule.Family, tc.family, rule)
		}
	}
}

// TestUnknownDialectStillGetsTheCommonRules — the policy is never narrower for a
// platform Correlix does not recognise.
func TestUnknownDialectStillGetsTheCommonRules(t *testing.T) {
	_, p := policyForTest(t)
	for _, cmd := range []string{"reload", "configure terminal", "write memory", "debug all", "kill 1"} {
		if _, hit := p.Match("some-unknown-os", cmd); !hit {
			t.Errorf("%q was allowed on an unrecognised dialect", cmd)
		}
	}
}

// TestGateBoundsProbes proves the ping/traceroute bounds are enforced at the
// GATE, on the rendered string — an in-bounds probe is allowed, and a flood, a
// sweep or an oversized repeat is not, even though the template that produced
// them is in the table.
func TestGateBoundsProbes(t *testing.T) {
	_, p := policyForTest(t)
	g := &Gate{byDialect: map[string][][]string{
		// The table is deliberately WIDE: a bare `ping`/`traceroute` template
		// with a placeholder matches any argument list, so anything refused
		// below was refused by the bounds and not by the table.
		"cisco-iosxe": {
			{"ping", "{peer}"}, {"ping", "{peer}", "{if}", "{prefix}", "{rid}", "{area}"},
			{"traceroute", "{peer}"}, {"traceroute", "{peer}", "{if}", "{prefix}"},
		},
	}, policy: p}
	for _, ok := range []string{
		"ping 192.0.2.1",
		"ping 192.0.2.1 count 5",
		"ping 192.0.2.1 size 1500 df-bit",
		"traceroute 192.0.2.1",
		"traceroute 192.0.2.1 probe 3",
	} {
		if !g.AllowsDialect("cisco-iosxe", ok) {
			t.Errorf("in-bounds probe %q was refused", ok)
		}
	}
	for _, bad := range []string{
		"ping 192.0.2.1 repeat 100000",
		"ping 192.0.2.1 count 50",
		"ping 192.0.2.1 size 18000",
		"ping 192.0.2.1 sweep 100 2000 1",
		"ping 192.0.2.1 rapid",
		"ping 192.0.2.1 pattern 0xdead",
		"traceroute 192.0.2.1 ttl 255",
		"traceroute 192.0.2.1 probe 100",
	} {
		if g.AllowsDialect("cisco-iosxe", bad) {
			t.Errorf("out-of-bounds probe %q was ALLOWED", bad)
		}
	}
}

// TestNoPolicyRuleBeginsWithAReadVerb is the invariant that keeps the policy
// from ever refusing an output — it is enforced at load, and stated here so the
// reason is recorded next to the rule set.
func TestNoPolicyRuleBeginsWithAReadVerb(t *testing.T) {
	_, p := policyForTest(t)
	for _, r := range p.Rules() {
		switch r.Tokens[0] {
		case "show", "display", "get", "info":
			t.Errorf("rule %q begins with a read verb", r)
		}
	}
}

// TestSessionScopedSettersAreDocumentedAndBounded proves the one exemption from
// the owner's rule is exactly as wide as its data says and no wider.
func TestSessionScopedSettersAreDocumentedAndBounded(t *testing.T) {
	_, p := policyForTest(t)
	scopes := p.SessionScopes()
	if len(scopes) == 0 {
		t.Fatal("no session-scoped setters are declared")
	}
	for _, s := range scopes {
		if len(s.Sources) == 0 {
			t.Errorf("session-scoped setter %q carries no citation", strings.Join(s.Tokens, " "))
		}
		if !strings.HasPrefix(s.Teardown, strings.Join(s.Tokens, " ")+" ") {
			t.Errorf("teardown %q does not belong to setter %q", s.Teardown, strings.Join(s.Tokens, " "))
		}
		if _, hit := p.Match(s.Dialect, s.Teardown); hit {
			t.Errorf("teardown %q is itself forbidden", s.Teardown)
		}
		// The setter must not be reachable on a dialect it was not declared for.
		if _, ok := p.SessionScope("cisco-iosxe", strings.Join(s.Tokens, " ")+" x"); ok && s.Dialect != "cisco-iosxe" {
			t.Errorf("setter %q leaked onto another dialect", strings.Join(s.Tokens, " "))
		}
	}
}

// TestProbeAndPolicyAgreeWithProtocoldiag keeps the two halves of the owner's
// rule in one place: what the policy refuses, the probe grammar must not admit.
func TestProbeAndPolicyAgreeWithProtocoldiag(t *testing.T) {
	_, p := policyForTest(t)
	for _, cmd := range []string{"ping 192.0.2.1", "traceroute 192.0.2.1", "execute ping 192.0.2.1"} {
		if !protocoldiag.IsProbeCommand(cmd) {
			t.Errorf("%q is not recognised as a probe", cmd)
		}
		if err := protocoldiag.ValidateBoundedProbe(cmd); err != nil {
			t.Errorf("%q is not in bounds: %v", cmd, err)
		}
		for _, dialect := range []string{"cisco-iosxe", "fortinet-fortios", "juniper-junos"} {
			if rule, hit := p.Match(dialect, cmd); hit {
				t.Errorf("%s: probe %q is refused by the %s rule %q", dialect, cmd, rule.Family, rule)
			}
		}
	}
}
