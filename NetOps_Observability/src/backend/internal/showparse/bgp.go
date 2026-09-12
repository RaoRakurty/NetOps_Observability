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
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoNXOS)
	// IOS-XR prints the SAME ten columns with a different second one: where IOS
	// and NX-OS print the BGP version, XR prints the SPEAKER ID. Same body, one
	// different column check — see parseIOSXRBGPSummary.
	l.register(CmdBGPSummary, parseIOSXRBGPSummary, DialectCiscoIOSXR)
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

// parseCiscoBGPSummary parses the IOS / IOS-XE / NX-OS summary row:
//
//	Neighbor  V  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  State/PfxRcd
//
// The shape key is columns 0-2 (a peer address, the BGP version, the remote AS).
// The final column is read as a prefix count ONLY when it is a number; a word
// there must be a member of the closed state set or the row is refused, and the
// two-token "Idle (Admin)" spelling is stitched back together.
func parseCiscoBGPSummary(lines []string) Result {
	return parseCiscoFamilyBGPSummary(lines, bgpVersionColumn)
}

// parseIOSXRBGPSummary parses the IOS-XR summary row:
//
//	Neighbor  Spk  AS  MsgRcvd  MsgSent  TblVer  InQ  OutQ  Up/Down  St/PfxRcd
//
// Ten columns, laid out exactly as IOS lays them out, with ONE difference: the
// second column is the BGP SPEAKER ID, not the BGP version. Requiring a version
// there refused every XR row ever handed to this library, so the typed binding
// was dead and every XR summary fell through to the regex analyzer with no sign
// that it had.
//
// The second column is discarded either way — neither the version nor the
// speaker id is a fact this package reports. It is read only to key the row
// SHAPE, which is why the two spellings can share one body.
func parseIOSXRBGPSummary(lines []string) Result {
	return parseCiscoFamilyBGPSummary(lines, bgpSpeakerColumn)
}

// parseCiscoFamilyBGPSummary is the shared body. col1 decides what the second
// column must be for the row to be recognized as a summary row at all.
func parseCiscoFamilyBGPSummary(lines []string, col1 func(int64) bool) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 5 {
			continue
		}
		peer, as, ok := bgpRowHeadCol1(fs, col1)
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

// bgpRowHead validates the "<peer> <version> <as>" head the IOS, IOS-XE, NX-OS,
// Arista and Huawei summary rows start with.
func bgpRowHead(fs []string) (peer string, as int64, ok bool) {
	return bgpRowHeadCol1(fs, bgpVersionColumn)
}

// bgpRowHeadCol1 validates a "<peer> <n> <as>" row head where col1 says what the
// middle number is allowed to be. The peer address and the AS are the same
// question on every platform; the column between them is the only one that
// differs, and it is never reported, so it is passed in rather than being a
// second copy of this function.
func bgpRowHeadCol1(fs []string, col1 func(int64) bool) (peer string, as int64, ok bool) {
	if len(fs) < 3 || !looksPeerAddress(fs[0]) {
		return "", 0, false
	}
	n, nOK := atoiOK(fs[1])
	if !nOK || !col1(n) {
		return "", 0, false
	}
	as, asOK := atoiOK(fs[2])
	if !asOK || as < 0 {
		return "", 0, false
	}
	return fs[0], as, true
}

// bgpVersionColumn accepts the BGP version column. 4 is what every deployed
// speaker prints; 5 and 6 are headroom for a version that does not exist yet,
// and the bound is what stops a line of prose with two numbers in it from being
// read as a peer.
func bgpVersionColumn(n int64) bool { return n >= 4 && n <= 6 }

// bgpSpeakerColumn accepts the IOS-XR "Spk" column. It is the BGP speaker
// process the neighbour is served by: 0 on the ordinary single-speaker router,
// and 1-15 where distributed speakers are configured. The bound plays the same
// role the version bound plays above — it keeps the row head strict enough that
// a prose line cannot become a peer — and the value itself is discarded.
func bgpSpeakerColumn(n int64) bool { return n >= 0 && n <= 15 }

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
