// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// bgp.go — BGP summary parsers (CmdBGPSummary).
//
// The single most dangerous column in networking output lives here. Cisco's
// summary folds the FSM state and the prefix count into ONE column
// ("State/PfxRcd"): a number means Established-with-N-prefixes, a word means the
// session is not up. Arista splits them into TWO columns — so a generic "last
// field is a number ⇒ established" reader would call an Arista session in Idle
// with 0 prefixes "Established with 0 prefixes". That is the exact class of
// fabrication this package exists to prevent, so the two layouts get two
// explicitly-bound parsers and every state word is checked against a CLOSED set.

import "strings"

func registerBGPParsers(l *Library) {
	l.register(CmdBGPSummary, parseCiscoBGPSummary,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS)
	l.register(CmdBGPSummary, parseEOSBGPSummary, DialectAristaEOS)
	l.register(CmdBGPSummary, parseJunosBGPSummary, DialectJunos)
	l.register(CmdBGPSummary, parseSROSBGPSummary, DialectNokiaSROS)
	l.register(CmdBGPSummary, parseVRPBGPPeer, DialectHuaweiVRP)
}

// bgpStateWord normalizes a BGP state token against the CLOSED FSM set plus the
// vendor abbreviations and the non-FSM placeholders the summary column carries
// when a session is administratively or policy-suppressed. ok=false means "this
// token is not a BGP state" and the row is refused.
func bgpStateWord(tok string) (string, bool) {
	switch strings.ToLower(strings.TrimRight(trim(tok), ",")) {
	case "idle":
		return "Idle", true
	case "connect":
		return "Connect", true
	case "active":
		return "Active", true
	case "opensent", "open sent", "opensen":
		return "OpenSent", true
	case "openconfirm", "open confirm", "openconfi":
		return "OpenConfirm", true
	case "established", "estab", "establ":
		return "Established", true
	case "shut", "shutdown", "admin", "idle(admin)", "adminshut":
		return "Idle (Admin)", true
	case "nonegotiation", "noneg":
		return "NoNegotiation", true
	}
	return "", false
}

// parseCiscoBGPSummary parses the IOS / IOS-XE / IOS-XR / NX-OS summary row:
//
//	Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
//
// The shape key is columns 0-2 (a peer address, the BGP version, the remote AS).
// The final column is read as a prefix count ONLY when it is a number; a word
// there must be a member of the closed state set or the row is refused, and the
// two-token "Idle (Admin)" spelling is stitched back together.
func parseCiscoBGPSummary(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 5 {
			continue
		}
		peer, as, ok := bgpRowHead(fs)
		if !ok {
			continue
		}
		p := BGPPeer{Peer: peer, AS: i64Ptr(as)}
		last := fs[len(fs)-1]
		switch {
		case isDigits(last):
			n, _ := atoiOK(last)
			p.State = "Established"
			p.Established = true
			p.PrefixesRx = i64Ptr(n)
		case strings.HasPrefix(last, "(") && len(fs) >= 6:
			st, ok := bgpStateWord(strings.Trim(last, "()"))
			if !ok {
				continue
			}
			p.State = st
		default:
			st, ok := bgpStateWord(last)
			if !ok {
				continue
			}
			p.State = st
			p.Established = st == "Established"
		}
		// The Up/Down column is the last duration-shaped token before the state.
		for i := len(fs) - 2; i >= 3; i-- {
			if looksDuration(fs[i]) {
				p.UpDown = strPtr(fs[i])
				break
			}
		}
		if n, ok := atoiOK(fs[3]); ok && len(fs) > 4 {
			p.MsgRcvd = i64Ptr(n)
		}
		if n, ok := atoiOK(fs[4]); ok && len(fs) > 5 {
			p.MsgSent = i64Ptr(n)
		}
		res.BGPPeers = append(res.BGPPeers, p)
	}
	return res
}

// bgpRowHead validates the "<peer> <version> <as>" head every Cisco-family and
// Huawei summary row starts with.
func bgpRowHead(fs []string) (peer string, as int64, ok bool) {
	if len(fs) < 3 || !looksPeerAddress(fs[0]) {
		return "", 0, false
	}
	ver, verOK := atoiOK(fs[1])
	if !verOK || ver < 4 || ver > 6 {
		return "", 0, false
	}
	as, asOK := atoiOK(fs[2])
	if !asOK || as < 0 {
		return "", 0, false
	}
	return fs[0], as, true
}

// isDigits reports whether s is a bare decimal integer (no sign, no punctuation).
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// parseEOSBGPSummary parses the Arista layout, whose State and PfxRcd are
// SEPARATE columns:
//
//	Neighbor  V  AS  MsgRcvd  MsgSent  InQ  OutQ  Up/Down  State  PfxRcd [PfxAcc]
//
// The state column is located by scanning from the right for the first token
// that is a member of the closed state set, so an extra trailing column
// (PfxAcc, present on some releases) cannot shift the reading.
func parseEOSBGPSummary(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 9 {
			continue
		}
		peer, as, ok := bgpRowHead(fs)
		if !ok {
			continue
		}
		stIdx := -1
		var state string
		for i := len(fs) - 1; i >= 3; i-- {
			if st, ok := bgpStateWord(fs[i]); ok {
				stIdx, state = i, st
				break
			}
		}
		if stIdx < 0 {
			continue
		}
		p := BGPPeer{Peer: peer, AS: i64Ptr(as), State: state, Established: state == "Established"}
		if stIdx+1 < len(fs) && isDigits(fs[stIdx+1]) {
			n, _ := atoiOK(fs[stIdx+1])
			p.PrefixesRx = i64Ptr(n)
		}
		if stIdx-1 >= 0 && looksDuration(fs[stIdx-1]) {
			p.UpDown = strPtr(fs[stIdx-1])
		}
		if n, ok := atoiOK(fs[3]); ok {
			p.MsgRcvd = i64Ptr(n)
		}
		if n, ok := atoiOK(fs[4]); ok {
			p.MsgSent = i64Ptr(n)
		}
		res.BGPPeers = append(res.BGPPeers, p)
	}
	return res
}

// parseJunosBGPSummary parses the Junos peer table:
//
//	Peer  AS  InPkt  OutPkt  OutQ  Flaps  Last Up/Dwn  State|#Active/Received/…
//
// Junos prints the state column EITHER as a word ("Establ", "Active") or, on an
// established session, as the "active/received/accepted/damped" counts. Both are
// handled; the received count is taken from its own position and never inferred.
func parseJunosBGPSummary(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 7 {
			continue
		}
		if !looksPeerAddress(fs[0]) {
			continue
		}
		as, asOK := atoiOK(fs[1])
		if !asOK {
			continue
		}
		// Columns 2..5 (InPkt, OutPkt, OutQ, Flaps) must all be numbers.
		numeric := true
		for i := 2; i <= 5; i++ {
			if _, ok := atoiOK(fs[i]); !ok {
				numeric = false
				break
			}
		}
		if !numeric {
			continue
		}
		p := BGPPeer{Peer: fs[0], AS: i64Ptr(as)}
		if n, ok := atoiOK(fs[2]); ok {
			p.MsgRcvd = i64Ptr(n)
		}
		if n, ok := atoiOK(fs[3]); ok {
			p.MsgSent = i64Ptr(n)
		}
		last := fs[len(fs)-1]
		if counts, ok := junosPrefixCounts(last); ok {
			p.State = "Established"
			p.Established = true
			p.PrefixesRx = i64Ptr(counts)
		} else {
			st, ok := bgpStateWord(last)
			if !ok {
				continue
			}
			p.State = st
			p.Established = st == "Established"
		}
		// "Last Up/Dwn" spans one or two tokens ("2d 3:12:44"); take the last
		// duration-shaped token before the state column.
		for i := len(fs) - 2; i >= 6; i-- {
			if looksDuration(fs[i]) {
				p.UpDown = strPtr(fs[i])
				break
			}
		}
		res.BGPPeers = append(res.BGPPeers, p)
	}
	return res
}

// junosPrefixCounts reads the "active/received/accepted[/damped]" column and
// returns the RECEIVED count (the second field), which is the number the
// operator means by "prefixes received".
func junosPrefixCounts(tok string) (int64, bool) {
	parts := strings.Split(tok, "/")
	if len(parts) < 3 || len(parts) > 4 {
		return 0, false
	}
	var vals []int64
	for _, p := range parts {
		n, ok := atoiOK(p)
		if !ok {
			return 0, false
		}
		vals = append(vals, n)
	}
	return vals[1], true
}

// parseSROSBGPSummary parses the SR OS two-line neighbour record:
//
//	10.0.0.2
//	            65002     1234    0 02h31m11s 100/100/120 (IPv4)
//	                      1235    0
//
// The record is recognized ONLY as "a line that is exactly a peer address,
// immediately followed by a line whose first token is the AS number" — anything
// else is left unparsed.
func parseSROSBGPSummary(lines []string) Result {
	var res Result
	for i := 0; i+1 < len(lines); i++ {
		head := trim(lines[i])
		if !looksPeerAddress(head) {
			continue
		}
		fs := fields(lines[i+1])
		if len(fs) < 4 {
			continue
		}
		as, asOK := atoiOK(fs[0])
		if !asOK {
			continue
		}
		p := BGPPeer{Peer: head, AS: i64Ptr(as)}
		if n, ok := atoiOK(fs[1]); ok {
			p.MsgRcvd = i64Ptr(n)
		}
		for _, tok := range fs[2:] {
			if p.UpDown == nil && looksDuration(tok) {
				p.UpDown = strPtr(tok)
				continue
			}
			if p.State == "" {
				if counts, ok := srosPrefixCounts(tok); ok {
					p.State = "Established"
					p.Established = true
					p.PrefixesRx = i64Ptr(counts)
					continue
				}
				if st, ok := bgpStateWord(tok); ok {
					p.State = st
					p.Established = st == "Established"
				}
			}
		}
		if p.State == "" {
			continue
		}
		res.BGPPeers = append(res.BGPPeers, p)
		i++ // the AS line belongs to this record
	}
	return res
}

// srosPrefixCounts reads the SR OS "Rcv/Act/Sent" column and returns the
// RECEIVED count (the first field).
func srosPrefixCounts(tok string) (int64, bool) {
	parts := strings.Split(tok, "/")
	if len(parts) != 3 {
		return 0, false
	}
	var vals []int64
	for _, p := range parts {
		n, ok := atoiOK(p)
		if !ok {
			return 0, false
		}
		vals = append(vals, n)
	}
	return vals[0], true
}

// parseVRPBGPPeer parses the Huawei VRP table:
//
//	Peer  V  AS  MsgRcvd  MsgSent  OutQ  Up/Down  State  PrefRcv
//
// VRP keeps State and PrefRcv in separate columns and spells the state out in
// full, so the row is accepted only with exactly nine columns whose state token
// is in the closed set.
func parseVRPBGPPeer(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) != 9 {
			continue
		}
		peer, as, ok := bgpRowHead(fs)
		if !ok {
			continue
		}
		st, stOK := bgpStateWord(fs[7])
		if !stOK {
			continue
		}
		p := BGPPeer{Peer: peer, AS: i64Ptr(as), State: st, Established: st == "Established"}
		if n, ok := atoiOK(fs[3]); ok {
			p.MsgRcvd = i64Ptr(n)
		}
		if n, ok := atoiOK(fs[4]); ok {
			p.MsgSent = i64Ptr(n)
		}
		if looksDuration(fs[6]) {
			p.UpDown = strPtr(fs[6])
		}
		if isDigits(fs[8]) {
			n, _ := atoiOK(fs[8])
			p.PrefixesRx = i64Ptr(n)
		}
		res.BGPPeers = append(res.BGPPeers, p)
	}
	return res
}
