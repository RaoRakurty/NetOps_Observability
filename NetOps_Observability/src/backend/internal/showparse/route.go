// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// route.go — routing-table lookup parsers (CmdRoutePrefix).
//
// A route lookup has THREE distinguishable outcomes and this package keeps all
// three apart:
//
//	1. routes found      → Routes populated, Skipped=false
//	2. device says none  → Routes empty, Skipped=false, Reason names the
//	                       device's own negative answer ("% Network not in table")
//	3. unreadable        → Skipped=true
//
// Collapsing (2) into (3) would throw away the most decisive piece of evidence a
// BGP-peer-unreachable diagnosis has; collapsing (3) into (2) would assert a
// negative we never observed. Both are refused.

import "strings"

func registerRouteParsers(l *Library) {
	l.register(CmdRoutePrefix, parseCiscoRoute,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdRoutePrefix, parseJunosRoute, DialectJunos)
}

// routeNegative recognizes the "there is no such route" banners the
// Cisco-family CLIs print.
func routeNegative(line string) bool {
	t := strings.ToLower(trim(line))
	switch {
	case strings.HasPrefix(t, "% network not in table"),
		strings.HasPrefix(t, "%network not in table"),
		strings.HasPrefix(t, "% subnet not in table"),
		strings.HasPrefix(t, "route not found"),
		strings.HasPrefix(t, "% route not found"):
		return true
	}
	return false
}

// parseCiscoRoute parses BOTH shapes `show ip route <prefix>` can return: the
// per-prefix detail block ("Routing entry for …") and a table row
// ("O  192.0.2.0/24 [110/20] via 10.0.0.2, 00:12:34, GigabitEthernet0/0").
func parseCiscoRoute(lines []string) Result {
	var res Result
	var cur *RouteEntry
	negative := false

	flush := func() {
		if cur != nil {
			res.Routes = append(res.Routes, *cur)
			cur = nil
		}
	}
	for _, ln := range lines {
		t := trim(ln)
		if routeNegative(t) {
			negative = true
			continue
		}
		if v, ok := strings.CutPrefix(t, "Routing entry for "); ok {
			flush()
			pfx := strings.Fields(v + " x")[0]
			pfx = strings.TrimRight(pfx, ",")
			if !looksPrefix(pfx) {
				continue
			}
			cur = &RouteEntry{Prefix: pfx}
			continue
		}
		if cur != nil {
			if strings.HasPrefix(t, "Known via ") {
				ciscoKnownVia(t, cur)
				continue
			}
			// "* 10.0.0.2, from 10.0.0.2, 00:12:34 ago, via GigabitEthernet0/0"
			if body, ok := strings.CutPrefix(t, "* "); ok {
				ciscoDescriptorBlock(body, cur)
				continue
			}
			if v, ok := valueAfter(t, "Route metric is "); ok && cur.Metric == nil {
				if n, ok := atoiOK(strings.Fields(v + " x")[0]); ok {
					cur.Metric = i64Ptr(n)
				}
			}
			continue
		}
		if r, ok := ciscoRouteTableRow(t); ok {
			res.Routes = append(res.Routes, r)
		}
	}
	flush()
	if len(res.Routes) == 0 && negative {
		res.Reason = "the device reports no matching route in the routing table"
	}
	return res
}

// ciscoKnownVia reads `Known via "ospf 1", distance 110, metric 20, type intra area`.
func ciscoKnownVia(line string, r *RouteEntry) {
	for _, seg := range strings.Split(line, ",") {
		seg = trim(seg)
		if v, ok := strings.CutPrefix(seg, "Known via "); ok {
			if p := trim(strings.Trim(v, `"`)); p != "" {
				r.Protocol = strPtr(p)
			}
			continue
		}
		fs := fields(seg)
		if len(fs) != 2 {
			continue
		}
		n, ok := atoiOK(fs[1])
		if !ok {
			continue
		}
		switch strings.ToLower(fs[0]) {
		case "distance":
			r.Preference = i64Ptr(n)
		case "metric":
			r.Metric = i64Ptr(n)
		}
	}
}

// ciscoDescriptorBlock reads the "* <next-hop>, from …, <age> ago, via <iface>"
// routing-descriptor line.
func ciscoDescriptorBlock(body string, r *RouteEntry) {
	segs := strings.Split(body, ",")
	if len(segs) == 0 {
		return
	}
	if nh := trim(segs[0]); (looksIPv4(nh) || looksIPv6(nh)) && r.NextHop == nil {
		r.NextHop = strPtr(nh)
	}
	for _, seg := range segs[1:] {
		seg = trim(seg)
		if v, ok := strings.CutPrefix(seg, "via "); ok {
			if r.Iface == nil && trim(v) != "" {
				r.Iface = strPtr(trim(v))
			}
			continue
		}
		if v, ok := strings.CutSuffix(seg, " ago"); ok {
			if r.Age == nil && looksDuration(trim(v)) {
				r.Age = strPtr(trim(v))
			}
		}
	}
	r.Active = boolPtr(true) // the "*" marker is the platform's own best-path mark
}

// ciscoRouteTableRow reads a `show ip route` table row. The shape key is a
// bracketed "[distance/metric]" token followed by "via <next-hop>" — a row
// without it is not parsed.
func ciscoRouteTableRow(line string) (RouteEntry, bool) {
	fs := fields(line)
	if len(fs) < 4 {
		return RouteEntry{}, false
	}
	pfxIdx := -1
	for i, f := range fs {
		if looksPrefix(f) {
			pfxIdx = i
			break
		}
	}
	if pfxIdx < 0 || pfxIdx+1 >= len(fs) {
		return RouteEntry{}, false
	}
	admin := trim(strings.Trim(fs[pfxIdx+1], ",")) // "[110/20]"
	if !strings.HasPrefix(admin, "[") || !strings.HasSuffix(admin, "]") {
		return RouteEntry{}, false
	}
	dist, metric, ok := strings.Cut(strings.Trim(admin, "[]"), "/")
	if !ok {
		return RouteEntry{}, false
	}
	d, dOK := atoiOK(dist)
	m, mOK := atoiOK(metric)
	if !dOK || !mOK {
		return RouteEntry{}, false
	}
	r := RouteEntry{Prefix: fs[pfxIdx], Preference: i64Ptr(d), Metric: i64Ptr(m)}
	if pfxIdx > 0 {
		r.Protocol = strPtr(fs[0])
	}
	rest := strings.Split(strings.Join(fs[pfxIdx+2:], " "), ",")
	for i, seg := range rest {
		seg = trim(seg)
		if v, ok := strings.CutPrefix(seg, "via "); ok {
			v = trim(v)
			if looksIPv4(v) || looksIPv6(v) {
				r.NextHop = strPtr(v)
			}
			continue
		}
		if looksDuration(seg) && r.Age == nil {
			r.Age = strPtr(seg)
			continue
		}
		if i == len(rest)-1 && seg != "" && r.Iface == nil {
			r.Iface = strPtr(seg)
		}
	}
	return r, true
}

// parseJunosRoute parses `show route <prefix>`:
//
//	192.0.2.0/24       *[OSPF/10] 00:12:34, metric 20
//	                    > to 10.0.0.2 via ge-0/0/0.0
func parseJunosRoute(lines []string) Result {
	var res Result
	idx := -1
	for _, ln := range lines {
		t := trim(ln)
		if r, ok := junosRouteHead(t); ok {
			res.Routes = append(res.Routes, r)
			idx = len(res.Routes) - 1
			continue
		}
		if idx < 0 {
			continue
		}
		if v, ok := strings.CutPrefix(t, "> to "); ok {
			nh, iface, hasVia := strings.Cut(v, " via ")
			if looksIPv4(trim(nh)) || looksIPv6(trim(nh)) {
				res.Routes[idx].NextHop = strPtr(trim(nh))
			}
			if hasVia && trim(iface) != "" {
				res.Routes[idx].Iface = strPtr(trim(iface))
			}
		}
	}
	return res
}

// junosRouteHead reads "<prefix>  *[PROTO/pref] <age>, metric <n>". The leading
// "*" / "+" / "-" is Junos's own active-route marker and is read, not assumed.
func junosRouteHead(line string) (RouteEntry, bool) {
	fs := fields(line)
	if len(fs) < 2 || !looksPrefix(fs[0]) {
		return RouteEntry{}, false
	}
	marker := fs[1]
	active := false
	switch {
	case strings.HasPrefix(marker, "*["):
		active = true
		marker = strings.TrimPrefix(marker, "*")
	case strings.HasPrefix(marker, "+["), strings.HasPrefix(marker, "-["):
		marker = marker[1:]
	case strings.HasPrefix(marker, "["):
	default:
		return RouteEntry{}, false
	}
	inner := strings.TrimSuffix(strings.TrimPrefix(marker, "["), "]")
	proto, pref, hasPref := strings.Cut(inner, "/")
	if proto == "" {
		return RouteEntry{}, false
	}
	r := RouteEntry{Prefix: fs[0], Protocol: strPtr(proto), Active: boolPtr(active)}
	if hasPref {
		if n, ok := atoiOK(pref); ok {
			r.Preference = i64Ptr(n)
		}
	}
	if n, ok := numberAfter(fs, "metric"); ok {
		r.Metric = i64Ptr(n)
	}
	for _, f := range fs[2:] {
		f = strings.TrimRight(f, ",")
		if looksDuration(f) && r.Age == nil {
			r.Age = strPtr(f)
			break
		}
	}
	return r, true
}
