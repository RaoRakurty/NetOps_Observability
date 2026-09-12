// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// igp.go — OSPF and IS-IS adjacency-table parsers (CmdOSPFNeighbor,
// CmdISISNeighbor).
//
// The adjacency STATE is never normalized. "EXSTART/DROTHER" is the operator's
// whole tell (stuck in EXSTART, and the role that explains why) and collapsing
// it to "not full" would throw the diagnosis away. What IS normalized is the
// COLUMN SEMANTICS: Cisco's classic OSPF table shows a DEAD TIME countdown where
// NX-OS shows an UP TIME, and mapping one onto the other would invert the
// meaning of the number — so they are parsed by separate, explicitly-bound
// parsers into separate fields.

import "strings"

func registerIGPParsers(l *Library) {
	l.register(CmdOSPFNeighbor, parseCiscoOSPFNeighbor,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR)
	l.register(CmdOSPFNeighbor, parseNXOSOSPFNeighbor, DialectCiscoNXOS)
	l.register(CmdOSPFNeighbor, parseEOSOSPFNeighbor, DialectAristaEOS)
	l.register(CmdOSPFNeighbor, parseJunosOSPFNeighbor, DialectJunos)
	l.register(CmdOSPFNeighbor, parseSROSOSPFNeighbor, DialectNokiaSROS)
	l.register(CmdOSPFNeighbor, parseVRPOSPFPeer, DialectHuaweiVRP)

	l.register(CmdISISNeighbor, parseCiscoISISNeighbors,
		DialectCiscoIOS, DialectCiscoIOSXE)
	l.register(CmdISISNeighbor, parseIOSXRISISAdjacency, DialectCiscoIOSXR)
	l.register(CmdISISNeighbor, parseJunosISISAdjacency, DialectJunos)
	l.register(CmdISISNeighbor, parseSROSISISAdjacency, DialectNokiaSROS)
}

// ospfStateWord reports whether tok is an OSPF neighbour-state token. The FSM
// states are a CLOSED set, so a row whose state column is not one of them is not
// a neighbour row (fail closed rather than accept a stray line).
func ospfStateWord(tok string) bool {
	base, _, _ := strings.Cut(tok, "/")
	switch strings.ToUpper(trim(base)) {
	case "DOWN", "ATTEMPT", "INIT", "2WAY", "TWOWAY", "EXSTART", "EXCHANGE", "LOADING", "FULL":
		return true
	}
	return false
}

// ── OSPF ────────────────────────────────────────────────────────────────────

// parseCiscoOSPFNeighbor parses the IOS / IOS-XE / IOS-XR table:
//
//	Neighbor ID   Pri   State           Dead Time   Address   Interface
func parseCiscoOSPFNeighbor(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) != 6 {
			continue
		}
		if !looksIPv4(fs[0]) || !ospfStateWord(fs[2]) {
			continue
		}
		pri, priOK := atoiOK(fs[1])
		if !priOK {
			continue
		}
		n := IGPNeighbor{
			Proto:    "ospf",
			ID:       fs[0],
			State:    fs[2],
			Iface:    fs[5],
			Priority: intPtr(int(pri)),
			DeadTime: strPtr(fs[3]),
		}
		if looksIPv4(fs[4]) || looksIPv6(fs[4]) {
			n.Address = strPtr(fs[4])
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseNXOSOSPFNeighbor parses the NX-OS table, which is column-identical to the
// IOS one EXCEPT that the fourth column is Up Time, not Dead Time.
func parseNXOSOSPFNeighbor(lines []string) Result {
	res := parseCiscoOSPFNeighbor(lines)
	for i := range res.IGPNeighbors {
		res.IGPNeighbors[i].Uptime = res.IGPNeighbors[i].DeadTime
		res.IGPNeighbors[i].DeadTime = nil
	}
	return res
}

// parseEOSOSPFNeighbor parses the EOS table, which carries an extra VRF column
// on multi-VRF builds ("Neighbor ID  VRF  Pri  State  Dead Time  Address
// Interface") and the IOS six-column layout otherwise. The two are told apart by
// whether column 1 is the numeric priority. The VRF column is deliberately NOT
// carried onto the row: IGPNeighbor has no VRF field, and inventing one from a
// column this parser is only guessing at would be exactly the fabrication this
// package forbids.
func parseEOSOSPFNeighbor(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) != 6 && len(fs) != 7 {
			continue
		}
		if !looksIPv4(fs[0]) {
			continue
		}
		off := 0
		if _, numeric := atoiOK(fs[1]); !numeric {
			if len(fs) != 7 {
				continue
			}
			off = 1
		} else if len(fs) != 6 {
			continue
		}
		if !ospfStateWord(fs[2+off]) {
			continue
		}
		pri, priOK := atoiOK(fs[1+off])
		if !priOK {
			continue
		}
		n := IGPNeighbor{
			Proto:    "ospf",
			ID:       fs[0],
			State:    fs[2+off],
			Iface:    fs[5+off],
			Priority: intPtr(int(pri)),
			DeadTime: strPtr(fs[3+off]),
		}
		if looksIPv4(fs[4+off]) || looksIPv6(fs[4+off]) {
			n.Address = strPtr(fs[4+off])
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseJunosOSPFNeighbor parses the Junos table:
//
//	Address   Interface   State   ID   Pri   Dead
func parseJunosOSPFNeighbor(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) != 6 {
			continue
		}
		if !looksIPv4(fs[0]) && !looksIPv6(fs[0]) {
			continue
		}
		if !ospfStateWord(fs[2]) || !looksIPv4(fs[3]) {
			continue
		}
		pri, priOK := atoiOK(fs[4])
		if !priOK {
			continue
		}
		n := IGPNeighbor{
			Proto:    "ospf",
			ID:       fs[3],
			State:    fs[2],
			Iface:    fs[1],
			Address:  strPtr(fs[0]),
			Priority: intPtr(int(pri)),
			DeadTime: strPtr(fs[5]),
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseSROSOSPFNeighbor parses the SR OS table:
//
//	Interface-Name   Rtr Id   State   Pri   RetxQ   TTL
func parseSROSOSPFNeighbor(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		fs := fields(ln)
		if len(fs) < 4 {
			continue
		}
		if !looksIPv4(fs[1]) || !ospfStateWord(fs[2]) {
			continue
		}
		n := IGPNeighbor{Proto: "ospf", ID: fs[1], State: fs[2], Iface: fs[0]}
		if pri, ok := atoiOK(fs[3]); ok {
			n.Priority = intPtr(int(pri))
		}
		if len(fs) >= 6 {
			n.DeadTime = strPtr(fs[5])
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseVRPOSPFPeer parses the VRP `display ospf peer brief` table:
//
//	Area Id   Interface   Neighbor id   State
func parseVRPOSPFPeer(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		fs := fields(ln)
		if len(fs) != 4 {
			continue
		}
		if !looksIPv4(fs[0]) || !looksIPv4(fs[2]) || !ospfStateWord(fs[3]) {
			continue
		}
		res.IGPNeighbors = append(res.IGPNeighbors, IGPNeighbor{
			Proto: "ospf", ID: fs[2], State: fs[3], Iface: fs[1], Area: strPtr(fs[0]),
		})
	}
	return res
}

// ── IS-IS ───────────────────────────────────────────────────────────────────

// isisStateWord is the closed IS-IS adjacency-state set.
func isisStateWord(tok string) bool {
	switch strings.ToUpper(trim(tok)) {
	case "UP", "DOWN", "INIT", "INITIALIZING", "FAILED":
		return true
	}
	return false
}

// isisLevelWord is the closed IS-IS level set as the tables spell it.
func isisLevelWord(tok string) bool {
	switch strings.ToUpper(trim(tok)) {
	case "L1", "L2", "L1L2", "L1/L2":
		return true
	}
	return false
}

// parseCiscoISISNeighbors parses the IOS / IOS-XE table:
//
//	System Id   Type   Interface   IP Address   State   Holdtime   Circuit Id
func parseCiscoISISNeighbors(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 6 {
			continue
		}
		if !isisLevelWord(fs[1]) || !isisStateWord(fs[4]) {
			continue
		}
		n := IGPNeighbor{
			Proto:    "isis",
			ID:       fs[0],
			Level:    strPtr(fs[1]),
			Iface:    fs[2],
			State:    fs[4],
			Holdtime: strPtr(fs[5]),
		}
		if looksIPv4(fs[3]) || looksIPv6(fs[3]) {
			n.Address = strPtr(fs[3])
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseIOSXRISISAdjacency parses the IOS-XR table:
//
//	System Id   Interface   SNPA   State   Hold   Changed   NSF   IPv4 BFD  IPv6 BFD
//
// The level comes from the "IS-IS <tag> Level-N adjacencies:" banner above the
// table; a table with no banner yields adjacencies with Level == nil rather than
// a guessed level.
func parseIOSXRISISAdjacency(lines []string) Result {
	var res Result
	level := ""
	for _, ln := range lines {
		t := trim(ln)
		if hasFold(t, "level-1 adjacencies") {
			level = "L1"
		} else if hasFold(t, "level-2 adjacencies") {
			level = "L2"
		}
		fs := fields(t)
		if len(fs) < 5 {
			continue
		}
		if !isisStateWord(fs[3]) {
			continue
		}
		if _, ok := atoiOK(fs[4]); !ok {
			continue // the Hold column must be a number
		}
		n := IGPNeighbor{
			Proto: "isis", ID: fs[0], Iface: fs[1], State: fs[3], Holdtime: strPtr(fs[4]),
		}
		if level != "" {
			n.Level = strPtr(level)
		}
		if len(fs) >= 6 && looksDuration(fs[5]) {
			n.Uptime = strPtr(fs[5])
		}
		res.IGPNeighbors = append(res.IGPNeighbors, n)
	}
	return res
}

// parseJunosISISAdjacency parses the Junos table:
//
//	Interface   System   L   State   Hold (secs)   SNPA
func parseJunosISISAdjacency(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 5 {
			continue
		}
		lvl, lvlOK := atoiOK(fs[2])
		if !lvlOK || lvl < 1 || lvl > 3 {
			continue
		}
		if !isisStateWord(fs[3]) {
			continue
		}
		if _, ok := atoiOK(fs[4]); !ok {
			continue
		}
		levelText := "L" + fs[2]
		if lvl == 3 {
			levelText = "L1L2"
		}
		res.IGPNeighbors = append(res.IGPNeighbors, IGPNeighbor{
			Proto: "isis", ID: fs[1], Iface: fs[0], State: fs[3],
			Level: strPtr(levelText), Holdtime: strPtr(fs[4]),
		})
	}
	return res
}

// parseSROSISISAdjacency parses the SR OS table:
//
//	System ID   Usage   State   Hold   Interface
func parseSROSISISAdjacency(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		fs := fields(ln)
		if len(fs) < 5 {
			continue
		}
		if !isisLevelWord(fs[1]) || !isisStateWord(fs[2]) {
			continue
		}
		if _, ok := atoiOK(fs[3]); !ok {
			continue
		}
		res.IGPNeighbors = append(res.IGPNeighbors, IGPNeighbor{
			Proto: "isis", ID: fs[0], Level: strPtr(fs[1]), State: fs[2],
			Holdtime: strPtr(fs[3]), Iface: fs[4],
		})
	}
	return res
}
