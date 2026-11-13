// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package flowquery

import (
	"errors"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// IfSentinels are the IPFIX / NetFlow "no interface" values. A record carrying
// one names no interface for that direction, so it is never a link.
const IfSentinels = "(0, 4294967295)"

// Link is one interface on one exporting device: the unit of the Flows page.
type Link struct {
	// Exporter is the exporter's address as flows carry it in sampler_address,
	// rendered from the PARSED address (never the raw parameter).
	Exporter string
	IfIndex  uint32
}

// Dir picks which of a link's two directions a statement reads.
type Dir string

const (
	DirBoth Dir = "both"
	DirIn   Dir = "in"  // flows that ENTERED the device on this interface
	DirOut  Dir = "out" // flows that LEFT the device on this interface
)

// ParseExporter validates an exporter address: one IP, no port, no zone. The
// result is the canonical text (an IPv4-mapped IPv6 address reads as IPv4),
// which is the form sampler_address carries, so it is safe to quote into SQL.
func ParseExporter(v string) (string, error) {
	v = strings.TrimSpace(v)
	a, err := netip.ParseAddr(v)
	if err != nil || a.Zone() != "" {
		return "", errors.New("device must be the exporter's IP address")
	}
	return a.Unmap().String(), nil
}

// ParseIfIndex validates an interface index: 1 to 4294967294 (the two
// sentinels are not interfaces).
func ParseIfIndex(v string) (uint32, error) {
	v = strings.TrimSpace(v)
	n, err := strconv.ParseUint(v, 10, 32)
	if err != nil || n == 0 || n == 4294967295 || !isDigits(v) {
		return 0, errors.New("if must be an interface index from 1 to 4294967294")
	}
	return uint32(n), nil
}

// ParseLink reads the required `device` and `if` parameters.
func ParseLink(q url.Values) (Link, error) {
	if strings.TrimSpace(q.Get("device")) == "" || strings.TrimSpace(q.Get("if")) == "" {
		return Link{}, errors.New("device and if are required")
	}
	exp, err := ParseExporter(q.Get("device"))
	if err != nil {
		return Link{}, err
	}
	ix, err := ParseIfIndex(q.Get("if"))
	if err != nil {
		return Link{}, err
	}
	return Link{Exporter: exp, IfIndex: ix}, nil
}

// ParseDir reads `dir`: both (default), in or out.
func ParseDir(v string) (Dir, error) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "both":
		return DirBoth, nil
	case "in":
		return DirIn, nil
	case "out":
		return DirOut, nil
	}
	return "", errors.New("dir must be both, in or out")
}

// ExporterCond restricts rows to the link's exporter.
func (l Link) ExporterCond() string { return "sampler_address = " + Quote(l.Exporter) }

// IfCond is the interface half of the link condition for one direction.
func (l Link) IfCond(d Dir) string {
	ix := strconv.FormatUint(uint64(l.IfIndex), 10)
	switch d {
	case DirIn:
		return "in_if = " + ix
	case DirOut:
		return "out_if = " + ix
	}
	return "(in_if = " + ix + " OR out_if = " + ix + ")"
}

// Cond restricts rows to the link in direction d.
func (l Link) Cond(d Dir) string { return l.ExporterCond() + " AND " + l.IfCond(d) }

// Quote renders s as a ClickHouse string literal. Both the quote and the
// backslash are escaped: ClickHouse reads backslash escapes inside literals, so
// escaping the quote alone lets a value ending in `\` escape its own closing
// quote (the same rule as the root chStringLiteral).
func Quote(s string) string {
	return "'" + strings.NewReplacer(`\`, `\\`, `'`, `\'`).Replace(s) + "'"
}

// QuoteList renders values as a comma-separated list of literals.
func QuoteList(vals []string) string {
	out := make([]string, 0, len(vals))
	for _, v := range vals {
		out = append(out, Quote(v))
	}
	return strings.Join(out, ", ")
}
