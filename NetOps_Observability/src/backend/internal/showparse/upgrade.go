// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// upgrade.go — the reads an upgrade-readiness check and a before/after change
// baseline need beyond the version: the boot variable and configuration
// register (`show bootvar`), the boot filesystem's free space (`dir
// bootflash:`), control-processor redundancy (`show redundancy`) and the
// routing table's size (`show ip route summary`).
//
// Every parser here is authored ONLY against output captured from a real device
// (Cisco IOS XE 17.3.2, a Catalyst 8000V-class SD-WAN edge, 2026-11-18) and is
// registered for IOS-XE alone. Other dialects print these reads in shapes no
// capture here proves; their commands still run and their output is honest raw
// evidence until a capture exists.

import "strings"

func registerUpgradeParsers(l *Library) {
	// The upgrade area's version read is the same `show version` the platform
	// area runs, so it shares that parser and its dialects exactly.
	l.register(CmdUpgradeVersion, parseVersionUptime,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdBootVars, parseIOSXEBootvar, DialectCiscoIOSXE)
	l.register(CmdFileSystem, parseIOSXEFileSystems, DialectCiscoIOSXE)
	l.register(CmdRedundancy, parseIOSXERedundancy, DialectCiscoIOSXE)
	l.register(CmdRouteSummary, parseIOSXERouteSummary, DialectCiscoIOSXE)
}

// maxRouteSources bounds the per-source map (§9). A real table has a handful
// of sources; a capture claiming hundreds is not a routing table.
const maxRouteSources = 32

// parseIOSXEBootvar reads `show bootvar`:
//
//	BOOT variable does not exist
//	CONFIG_FILE variable does not exist
//	BOOTLDR variable does not exist
//	Configuration register is 0x2102
//
// "does not exist" is recorded as an EMPTY BootVariable, not left nil: the
// device said there is none, which on an install-mode router is normal and is a
// different fact from a read that never mentioned it.
func parseIOSXEBootvar(lines []string) Result {
	var res Result
	uf := &UpgradeFacts{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		switch {
		case strings.HasPrefix(t, "BOOT variable does not exist"):
			uf.BootVariable = strPtr("")
			found = true
		case strings.HasPrefix(t, "BOOT variable ="):
			v := trim(strings.TrimPrefix(t, "BOOT variable ="))
			v = strings.TrimRight(v, ";")
			if v != "" {
				uf.BootVariable = strPtr(v)
				found = true
			}
		case strings.HasPrefix(t, "Configuration register is "):
			if fs := fields(strings.TrimPrefix(t, "Configuration register is ")); len(fs) > 0 && strings.HasPrefix(fs[0], "0x") {
				uf.ConfigRegister = strPtr(fs[0])
				found = true
			}
		}
	}
	if !found {
		return res
	}
	res.Upgrade = uf
	return res
}

// parseIOSXEFileSystems reads `show file systems`:
//
//	       Size(b)       Free(b)      Type  Flags  Prefixes
//	             -             -    opaque     rw   system:
//	*  10547552256    8914751488      disk     rw   bootflash: flash:
//	    2013753344    1910222848      disk     ro   webui:
//
// The device marks its DEFAULT filesystem — the one it boots from and an image
// is copied to — with a leading "*". That row is read; when no row carries the
// mark, the row whose prefixes name bootflash: is used. Rows with "-" sizes are
// network/opaque filesystems with no capacity and are never chosen.
func parseIOSXEFileSystems(lines []string) Result {
	var res Result
	inTable := false
	var pick, bootflash *UpgradeFacts
	for _, ln := range lines {
		t := trim(ln)
		if strings.HasPrefix(t, "Size(b)") {
			inTable = true
			continue
		}
		if !inTable || t == "" {
			continue
		}
		fs := fields(t)
		star := false
		if len(fs) > 0 && fs[0] == "*" {
			star = true
			fs = fs[1:]
		}
		if len(fs) < 5 {
			continue
		}
		total, ok := atoiOK(fs[0])
		free, fok := atoiOK(fs[1])
		if !ok || !fok || total <= 0 || free < 0 || free > total {
			continue
		}
		name := fs[4]
		if !strings.HasSuffix(name, ":") || len(name) > 64 {
			continue
		}
		uf := &UpgradeFacts{FileSystem: strPtr(name), FSTotalBytes: i64Ptr(total), FSFreeBytes: i64Ptr(free)}
		if star && pick == nil {
			pick = uf
		}
		for _, pfx := range fs[4:] {
			if pfx == "bootflash:" && bootflash == nil {
				bootflash = uf
			}
		}
	}
	switch {
	case pick != nil:
		res.Upgrade = pick
	case bootflash != nil:
		res.Upgrade = bootflash
	}
	return res
}

// parseIOSXERedundancy reads `show redundancy`:
//
//	                 Hardware Mode = Simplex
//	    Configured Redundancy Mode = Non-redundant
//	     Operating Redundancy Mode = Non-redundant
//	…
//	Peer (slot: 7) information is not available because it is in 'DISABLED' state
//
// The modes are taken verbatim; the peer state only from the device's own
// "because it is in '<STATE>' state" sentence. A duplex chassis prints a peer
// section this parser has not seen captured, so it reports the modes and never
// guesses a standby's readiness.
func parseIOSXERedundancy(lines []string) Result {
	var res Result
	uf := &UpgradeFacts{}
	found := false
	for _, ln := range lines {
		t := trim(ln)
		if k, v, ok := strings.Cut(t, "="); ok {
			key, val := trim(k), trim(v)
			if val == "" || len(val) > 64 {
				continue
			}
			switch key {
			case "Hardware Mode":
				uf.RedundancyHardware = strPtr(val)
				found = true
			case "Operating Redundancy Mode":
				uf.RedundancyMode = strPtr(val)
				found = true
			}
			continue
		}
		if strings.HasPrefix(t, "Peer ") {
			if _, after, ok := strings.Cut(t, "because it is in '"); ok {
				if st, _, ok := strings.Cut(after, "'"); ok && st != "" && len(st) <= 32 {
					uf.PeerState = strPtr(st)
					found = true
				}
			}
		}
	}
	if !found {
		return res
	}
	res.Upgrade = uf
	return res
}

// parseIOSXERouteSummary reads `show ip route summary`:
//
//	Route Source    Networks    Subnets     Replicates  Overhead    Memory (bytes)
//	connected       0           6           0           624         1872
//	static          1           0           0           104         312
//	bgp 64512       0           0           0           0           0
//	  External: 0 Internal: 0 Local: 0
//	internal        3                                               1856
//	Total           4           6           0           728         4040
//
// Total is networks plus subnets on the Total line. Per-source counts take the
// first two numeric columns after the source name (which can be two words —
// "bgp 64512"); the "internal" row is the router's own bookkeeping and is kept
// out of BySource, though the device counts it in its Total.
func parseIOSXERouteSummary(lines []string) Result {
	var res Result
	inTable := false
	sum := &RouteSummary{BySource: map[string]int64{}}
	gotTotal := false
	for _, ln := range lines {
		t := trim(ln)
		if strings.HasPrefix(t, "Route Source") {
			inTable = true
			continue
		}
		if !inTable || t == "" || strings.HasPrefix(t, "External:") {
			continue
		}
		fs := fields(t)
		// Find the first numeric field: everything before it is the source.
		idx := -1
		for i, f := range fs {
			if _, ok := atoiOK(f); ok {
				idx = i
				break
			}
		}
		if idx <= 0 || idx+1 >= len(fs) {
			continue
		}
		// "bgp 64512" — the AS number is the first numeric token but belongs to
		// the source name when two more numeric columns follow it.
		if idx+2 < len(fs) && strings.EqualFold(fs[0], "bgp") && idx == 1 {
			if _, ok := atoiOK(fs[idx+2]); ok {
				idx = 2
			}
		}
		src := strings.ToLower(strings.Join(fs[:idx], " "))
		nets, nok := atoiOK(fs[idx])
		subs, sok := atoiOK(fs[idx+1])
		if !nok || !sok || nets < 0 || subs < 0 {
			continue
		}
		switch src {
		case "total":
			sum.Total = nets + subs
			gotTotal = true
		case "internal":
			// The router's own bookkeeping; counted in Total by the device.
		default:
			if len(sum.BySource) < maxRouteSources {
				sum.BySource[src] = nets + subs
			}
		}
	}
	if !gotTotal {
		return res
	}
	res.RouteSummary = sum
	return res
}
