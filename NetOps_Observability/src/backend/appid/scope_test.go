// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

func TestResolveScope(t *testing.T) {
	cases := []struct {
		name string
		o    ApplicationObservation
		want ScopeMatch
	}{
		{"session", ApplicationObservation{SessionID: "s1"}, ScopeSession},
		{"flow", ApplicationObservation{FlowID: "f1"}, ScopeFlow},
		{"workload", ApplicationObservation{Workload: "billing-pod"}, ScopeWorkload},
		{"user", ApplicationObservation{User: "jdoe"}, ScopeUser},
		{"domain", ApplicationObservation{Source: SrcDNS, DstIP: "1.2.3.4"}, ScopeDomain},
		{"sni-domain", ApplicationObservation{Source: SrcSNI, DstIP: "1.2.3.4"}, ScopeDomain},
		{"dstip", ApplicationObservation{Source: SrcIPCatalog, DstIP: "1.2.3.4"}, ScopeDstIP},
		{"provider", ApplicationObservation{Source: SrcASN, DstIP: "1.2.3.4"}, ScopeProvider},
		{"port", ApplicationObservation{Source: SrcPort, DstPort: 443}, ScopePort},
	}
	for _, c := range cases {
		if got := ResolveScope(c.o).Type; got != c.want {
			t.Errorf("%s: ResolveScope=%s want %s", c.name, got, c.want)
		}
	}
}

func TestScopeStrengthOrdering(t *testing.T) {
	order := []ScopeMatch{ScopeSession, ScopeFlow, ScopeWorkload, ScopeUser, ScopeDomain, ScopeDstIP, ScopeProvider, ScopePort}
	for i := 1; i < len(order); i++ {
		if order[i-1].strength() <= order[i].strength() {
			t.Errorf("scope strength not strictly decreasing at %d: %s(%d) <= %s(%d)",
				i, order[i-1], order[i-1].strength(), order[i], order[i].strength())
		}
	}
	if !ScopeSession.exact() || !ScopeFlow.exact() {
		t.Error("session/flow must be exact")
	}
	if ScopeDomain.exact() || ScopeDstIP.exact() || ScopePort.exact() {
		t.Error("destination-scoped bindings must not be exact")
	}
}

func TestResolveScopeAmbiguityFlags(t *testing.T) {
	// destination-only bindings carry a dst_only ambiguity flag; exact ones do not.
	if r := ResolveScope(ApplicationObservation{Source: SrcDNS, DstIP: "1.2.3.4"}); len(r.Ambiguity) == 0 {
		t.Error("dst-only scope should flag ambiguity")
	}
	if r := ResolveScope(ApplicationObservation{SessionID: "s1"}); len(r.Ambiguity) != 0 {
		t.Error("exact-session scope should have no ambiguity flags")
	}
}
