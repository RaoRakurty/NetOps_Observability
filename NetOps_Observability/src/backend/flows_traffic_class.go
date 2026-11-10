// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package backend

import (
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
)

// flows_traffic_class.go: flows Correlix caused itself (tracker 387 PR 13,
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
	trafficClassPlatform = "platform_monitoring"
	// maxPlatformAddrs bounds the configured list (each becomes SQL).
	maxPlatformAddrs = 64
)

// platformAddrSet is the parsed configuration: exact addresses and networks.
type platformAddrSet struct {
	ips  []string // canonical IP text, as flows store src_addr / dst_addr
	nets []*net.IPNet
}

func (p platformAddrSet) empty() bool { return len(p.ips) == 0 && len(p.nets) == 0 }

// parsePlatformAddrs reads both variables. A value that is neither an IP nor a
// CIDR is dropped: it never reaches SQL, so a malformed entry cannot inject.
func parsePlatformAddrs(platform, vantage string) platformAddrSet {
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
	var out platformAddrSet
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] || len(out.ips)+len(out.nets) >= maxPlatformAddrs {
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

// platformAddrsFromEnv is the live configuration.
func platformAddrsFromEnv() platformAddrSet {
	return parsePlatformAddrs(os.Getenv("CX_PLATFORM_ADDRESSES"), os.Getenv("PATH_GRAPH_VANTAGE_ADDRESSES"))
}

// contains reports whether a flow endpoint is a platform address.
func (p platformAddrSet) contains(addr string) bool {
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
func (p platformAddrSet) sqlCond() string {
	if p.empty() {
		return ""
	}
	var parts []string
	if len(p.ips) > 0 {
		in := sqlInList(p.ips)
		parts = append(parts, "src_addr IN ("+in+")", "dst_addr IN ("+in+")")
	}
	for _, n := range p.nets {
		lit := chStringLiteral(n.String())
		parts = append(parts, "isIPAddressInRange(src_addr, "+lit+")", "isIPAddressInRange(dst_addr, "+lit+")")
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// includePlatformTraffic reads the visible toggle: ?traffic=all includes it.
func includePlatformTraffic(r *http.Request) bool {
	return strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("traffic")), "all")
}

// flowTrafficClassClause is the default exclusion the flows views apply.
func flowTrafficClassClause(r *http.Request) string {
	if includePlatformTraffic(r) {
		return ""
	}
	if c := platformAddrsFromEnv().sqlCond(); c != "" {
		return " AND NOT " + c
	}
	return ""
}
