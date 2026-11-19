// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"strings"
	"testing"

	"netops/backend/internal/showparse"
)

// Tracker 420 (a): the vpn area's IPsec rows reach Iris as typed lines and a
// `state:ipsec_sa` fact derived from typed fields only, worst first.
func TestAIIPsecStateAndLine(t *testing.T) {
	i64 := func(v int64) *int64 { return &v }
	port := 12346
	healthy := showparse.IPsecSA{Interface: "Tunnel1", Peer: "198.51.100.60", PeerPort: &port,
		PktsEncaps: i64(92145), PktsDecaps: i64(92144), SendErrors: i64(0), RecvErrors: i64(0),
		InboundESP: 1, OutboundESP: 1, InboundStatus: "ACTIVE(ACTIVE)", OutboundStatus: "ACTIVE(ACTIVE)"}
	line := aiIPsecLine(healthy)
	for _, want := range []string{"IPsec SA to 198.51.100.60 port 12346 on Tunnel1", "inbound ACTIVE(ACTIVE)", "92145 packets sent and 92144 received since the SA came up", "0 send / 0 receive errors"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q missing %q", line, want)
		}
	}
	cases := []struct {
		name string
		mut  func(*showparse.IPsecSA)
		want string
	}{
		{"healthy", func(*showparse.IPsecSA) {}, "active"},
		{"no inbound SA", func(s *showparse.IPsecSA) { s.InboundESP, s.InboundStatus = 0, "" }, "inactive"},
		{"outbound not active", func(s *showparse.IPsecSA) { s.OutboundStatus = "STANDBY" }, "inactive"},
		{"sent, never received", func(s *showparse.IPsecSA) { s.PktsDecaps = i64(0) }, "one_way"},
		{"received, never sent", func(s *showparse.IPsecSA) { s.PktsEncaps = i64(0) }, "one_way"},
		{"receive errors", func(s *showparse.IPsecSA) { s.RecvErrors = i64(3) }, "errors"},
		{"idle both ways is not one-way", func(s *showparse.IPsecSA) { s.PktsEncaps, s.PktsDecaps = i64(0), i64(0) }, "active"},
	}
	for _, c := range cases {
		sa := healthy
		c.mut(&sa)
		if got, _ := aiIPsecState(sa); got != c.want {
			t.Errorf("%s: state = %q, want %q", c.name, got, c.want)
		}
	}
	if !strings.Contains(aiIPsecLine(showparse.IPsecSA{Peer: "192.0.2.1"}), "inbound no SA") {
		t.Error("a direction with no SA must say so")
	}
}
