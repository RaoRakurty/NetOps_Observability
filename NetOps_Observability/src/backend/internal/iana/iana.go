// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

// Package iana names the numbers a flow record carries: the IP protocol
// (17 → UDP) and the likely service on a transport port (udp/161 → snmp).
//
// The two tables are reduced from the IANA registries at BUILD time by
// scripts/gen-iana-tables.py (sha256-pinned sources, CC0-1.0 per
// https://www.iana.org/help/licensing-terms) and embedded, so nothing is
// fetched at run time. A service name is a heuristic: a port says what is
// usually there, not what a given flow carried, and callers label it so.
package iana

import (
	_ "embed"
	"strconv"
	"strings"
	"sync"
)

//go:embed protocols.tsv
var protocolsTSV string

//go:embed services.tsv
var servicesTSV string

// Tables is the parsed registry pair. The zero value names nothing.
type Tables struct {
	protocols map[uint8]string
	services  map[uint32]string // proto<<16 | port
}

// Names is the lookup the rest of the backend depends on, so a caller can be
// tested against a fake without the embedded tables.
type Names interface {
	Protocol(n uint8) string
	Service(proto uint8, port uint16) string
}

var (
	loadOnce sync.Once
	loaded   *Tables
)

// Default returns the embedded tables, parsed once on first use.
func Default() *Tables {
	loadOnce.Do(func() { loaded = Parse(protocolsTSV, servicesTSV) })
	return loaded
}

// Parse reads the two generated TSVs. A malformed line is skipped: the
// generator's --check (tests/test_iana_tables.py) is what proves the files
// well formed, and a lookup must never fail a request.
func Parse(protocols, services string) *Tables {
	t := &Tables{protocols: map[uint8]string{}, services: map[uint32]string{}}
	for _, line := range strings.Split(protocols, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 2 {
			continue
		}
		n, err := strconv.ParseUint(cols[0], 10, 8)
		if err != nil || cols[1] == "" {
			continue
		}
		t.protocols[uint8(n)] = cols[1]
	}
	for _, line := range strings.Split(services, "\n") {
		if line == "" || line[0] == '#' {
			continue
		}
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			continue
		}
		p, err1 := strconv.ParseUint(cols[0], 10, 8)
		port, err2 := strconv.ParseUint(cols[1], 10, 16)
		if err1 != nil || err2 != nil || cols[2] == "" {
			continue
		}
		t.services[uint32(p)<<16|uint32(port)] = cols[2]
	}
	return t
}

// Protocol is the registry keyword for an IP protocol number, "" when the
// registry assigns none (callers fall back to the number).
func (t *Tables) Protocol(n uint8) string {
	if t == nil {
		return ""
	}
	return t.protocols[n]
}

// Service is the first registered service name for (proto, port), "" when the
// port is unregistered for that transport.
func (t *Tables) Service(proto uint8, port uint16) string {
	if t == nil {
		return ""
	}
	return t.services[uint32(proto)<<16|uint32(port)]
}

// Len reports the table sizes (for tests and the start-up log).
func (t *Tables) Len() (protocols, services int) {
	if t == nil {
		return 0, 0
	}
	return len(t.protocols), len(t.services)
}
