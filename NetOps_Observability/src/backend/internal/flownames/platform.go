// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flownames

import (
	"net"
	"sort"
	"strings"
)

// platform.go: flows Correlix caused itself (tracker 387 PR 13,
// item 2). On the lab 52 % of flow rows are dst_port 161: our own SNMP
// polling, exported back to us by the routers it polls. They are real traffic
// and are never deleted, but they drown the customer's traffic in every Top N.
//
// A flow whose source or destination is one of the platform's own addresses is
// traffic_class=platform_monitoring. The addresses come from configuration,
// never from a literal here:
//   - CX_PLATFORM_ADDRESSES: comma-separated IPs or CIDRs this appliance's
//     collectors and pollers send from (the address devices see, after NAT);
//   - PATH_GRAPH_VANTAGE_ADDRESSES: the probers' declared addresses
//     ("name=addr" or "name:addr" pairs), which are platform senders too.
// The flows views exclude the class by default and say so; ?traffic=all
// includes it. Unconfigured, nothing is classified and nothing is hidden.

const (
	TrafficClassPlatform = "platform_monitoring"
	// MaxPlatformAddrs bounds the configured list (each becomes SQL).
	MaxPlatformAddrs = 64
)

// PlatformAddrs is the parsed configuration: exact addresses and networks.
type PlatformAddrs struct {
	ips  []string // canonical IP text, as flows store src_addr / dst_addr
	nets []*net.IPNet
}

func (p PlatformAddrs) Empty() bool { return len(p.ips) == 0 && len(p.nets) == 0 }

// ParsePlatformAddrs reads both variables. A value that is neither an IP nor a
// CIDR is dropped: it never reaches SQL, so a malformed entry cannot inject.
func ParsePlatformAddrs(platform, vantage string) PlatformAddrs {
	var raw []string
	raw = append(raw, strings.Split(platform, ",")...)
	for _, part := range strings.Split(vantage, ",") {
		part = strings.TrimSpace(part)
		if _, after, ok := strings.Cut(part, "="); ok {
			part = after // "name=addr", IPv6-safe
		} else if net.ParseIP(part) == nil {
			if _, after, ok := strings.Cut(part, ":"); ok {
				part = after // legacy "name:addr"
			}
		}
		raw = append(raw, part)
	}
	seen := map[string]bool{}
	var out PlatformAddrs
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || len(out.ips)+len(out.nets) >= MaxPlatformAddrs {
			continue
		}
		seen[v] = true
		if ip := net.ParseIP(v); ip != nil {
			out.ips = append(out.ips, ip.String())
			continue
		}
		if _, n, err := net.ParseCIDR(v); err == nil {
			out.nets = append(out.nets, n)
		}
	}
	sort.Strings(out.ips)
	return out
}

// Platform-address sources, as ResolvePlatformAddrs reports them.
const (
	PlatformSourceConfigured = "configured"
	PlatformSourceOutbound   = "outbound_fallback"
	PlatformSourceNone       = "none"
)

// ResolvePlatformAddrs is the configuration, or, when nothing is configured,
// the process's own outbound source address (outbound returns "" when there is
// no route). Behind Docker NAT that address is the container's, which devices
// never see: the installer writes the host's address into .env for exactly that
// reason, and the fallback only covers an install that has none.
func ResolvePlatformAddrs(platform, vantage string, outbound func() string) (PlatformAddrs, string) {
	if p := ParsePlatformAddrs(platform, vantage); !p.Empty() {
		return p, PlatformSourceConfigured
	}
	if outbound != nil {
		if p := ParsePlatformAddrs(outbound(), ""); !p.Empty() {
			return p, PlatformSourceOutbound
		}
	}
	return PlatformAddrs{}, PlatformSourceNone
}

// IPs lists the exact addresses (for the start-up log).
func (p PlatformAddrs) IPs() []string { return append([]string(nil), p.ips...) }

// contains reports whether a flow endpoint is a platform address.
func (p PlatformAddrs) Contains(addr string) bool {
	ip := net.ParseIP(strings.TrimSpace(addr))
	if ip == nil {
		return false
	}
	s := ip.String()
	for _, x := range p.ips {
		if x == s {
			return true
		}
	}
	for _, n := range p.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// sqlCond is the ClickHouse condition "this row is platform monitoring". Every
// literal is a re-rendered parsed address, never configuration text.
func (p PlatformAddrs) SQLCond() string {
	if p.Empty() {
		return ""
	}
	var parts []string
	if len(p.ips) > 0 {
		in := sqlList(p.ips)
		parts = append(parts, "src_addr IN ("+in+")", "dst_addr IN ("+in+")")
	}
	for _, n := range p.nets {
		lit := sqlLiteral(n.String())
		parts = append(parts, "isIPAddressInRange(src_addr, "+lit+")", "isIPAddressInRange(dst_addr, "+lit+")")
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// literalEscaper escapes a value for a single-quoted ClickHouse literal:
// backslash first-class, then the quote (the same rule as the api's
// chStringLiteral; ClickHouse honours backslash escapes, SR-011).
var literalEscaper = strings.NewReplacer(`\`, `\\`, `'`, `\'`)

func sqlLiteral(v string) string { return "'" + literalEscaper.Replace(v) + "'" }

func sqlList(vals []string) string {
	parts := make([]string, 0, len(vals))
	for _, v := range vals {
		parts = append(parts, sqlLiteral(v))
	}
	return strings.Join(parts, ", ")
}
