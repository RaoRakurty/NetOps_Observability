// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package iana

import "testing"

// The values flows on the lab actually carry, read from the embedded tables.
func TestDefaultNamesTheLabTraffic(t *testing.T) {
	d := Default()
	for _, c := range []struct {
		n    uint8
		want string
	}{{6, "TCP"}, {17, "UDP"}, {1, "ICMP"}, {47, "GRE"}, {50, "ESP"}} {
		if got := d.Protocol(c.n); got != c.want {
			t.Errorf("Protocol(%d) = %q, want %q", c.n, got, c.want)
		}
	}
	for _, c := range []struct {
		proto uint8
		port  uint16
		want  string
	}{
		{17, 161, "snmp"}, {17, 162, "snmptrap"}, {17, 514, "syslog"},
		{6, 443, "https"}, {6, 830, "netconf-ssh"}, {6, 22, "ssh"},
	} {
		if got := d.Service(c.proto, c.port); got != c.want {
			t.Errorf("Service(%d,%d) = %q, want %q", c.proto, c.port, got, c.want)
		}
	}
	if p, s := d.Len(); p < 140 || s < 10000 {
		t.Errorf("embedded tables too small: %d protocols, %d services", p, s)
	}
}

// A number the registry does not name stays unnamed: never a guess.
func TestUnassignedStaysEmpty(t *testing.T) {
	d := Default()
	if got := d.Protocol(200); got != "" {
		t.Errorf("Protocol(200) = %q, want unassigned", got)
	}
	// Transport matters: tcp/161 is registered too, but icmp has no ports.
	if got := d.Service(1, 161); got != "" {
		t.Errorf("Service(icmp,161) = %q, want empty", got)
	}
	var nilT *Tables
	if nilT.Protocol(6) != "" || nilT.Service(6, 443) != "" {
		t.Error("a nil table must name nothing")
	}
}

func TestParseSkipsMalformedLines(t *testing.T) {
	tb := Parse("# head\n6\tTCP\nbad\n999\tX\n17\t\n", "# h\n17\t161\tsnmp\n17\tx\ty\n6\t70000\tz\n")
	if tb.Protocol(6) != "TCP" || tb.Protocol(17) != "" {
		t.Errorf("protocols parsed wrong: %v", tb.protocols)
	}
	if tb.Service(17, 161) != "snmp" || len(tb.services) != 1 {
		t.Errorf("services parsed wrong: %v", tb.services)
	}
}
