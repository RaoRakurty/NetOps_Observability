// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// iface.go — interface state parsers (CmdInterfaceDetail, CmdInterfaceBrief).
//
// Every parser here starts a new InterfaceState ONLY on a line it recognizes as
// that dialect's interface header. A capture whose header shape it does not
// recognize therefore produces zero rows and Parse reports the honest
// inconclusive — which is exactly what must happen when a `show interfaces`
// from an unexpected platform is handed to the wrong parser.

import "strings"

func registerInterfaceParsers(l *Library) {
	// The Cisco-family `show interfaces` block format is shared, to a
	// field-level degree, by IOS, IOS-XE, IOS-XR, NX-OS and Arista EOS. One
	// parser, five bindings — with every field taken only from a line whose
	// wording all five actually print.
	l.register(CmdInterfaceDetail, parseCiscoInterfaces,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdInterfaceDetail, parseJunosInterfaces, DialectJunos)
	l.register(CmdInterfaceDetail, parseVRPInterfaces, DialectHuaweiVRP)
	l.register(CmdInterfaceDetail, parseSROSPortDetail, DialectNokiaSROS)

	l.register(CmdInterfaceBrief, parseCiscoIPIntBrief,
		DialectCiscoIOS, DialectCiscoIOSXE, DialectCiscoIOSXR)
	l.register(CmdInterfaceBrief, parseNXOSIPIntBrief, DialectCiscoNXOS)
	l.register(CmdInterfaceBrief, parseEOSIPIntBrief, DialectAristaEOS)
	l.register(CmdInterfaceBrief, parseJunosTerse, DialectJunos)
}

// ── Cisco family: `show interfaces [name]` ──────────────────────────────────

// parseCiscoInterfaces parses the IOS/IOS-XE/IOS-XR/NX-OS/EOS interface block.
//
// The header shape it keys on is "<Name> is <admin state>[, line protocol is
// <oper>]". NX-OS omits the line-protocol clause on some interface types and
// prints "admin state is up" on its own line; both are handled, and neither is
// invented when absent.
func parseCiscoInterfaces(lines []string) Result {
	var res Result
	var cur *InterfaceState
	inputSection := false

	flush := func() {
		if cur != nil {
			res.Interfaces = append(res.Interfaces, *cur)
			cur = nil
		}
	}
	for _, ln := range lines {
		if name, admin, oper, ok := ciscoIfHeader(ln); ok {
			flush()
			cur = &InterfaceState{Name: name}
			if admin != "" {
				cur.Admin = strPtr(admin)
			}
			if oper != "" {
				cur.Oper = strPtr(oper)
			}
			inputSection = false
			continue
		}
		if _, _, ok := ciscoHeaderShape(ln); ok {
			// The line IS an interface header — unindented, one-token name,
			// "<name> is <something>" — but the state phrase is not one this
			// parser reads. Close the previous record and start no new one.
			//
			// Leaving `cur` pointing at the previous interface is what caused
			// review H5: every counter line under this header was filed against
			// the PREVIOUS port, so an operator saw a CRC storm on the wrong
			// link and troubleshot the wrong one. The record boundary must not
			// depend on the state vocabulary.
			//
			// The lines under this header are then dropped, so the drop is
			// RECORDED (§10). A silent discard of device output is itself a
			// silent failure; the gap is what makes it visible.
			flush()
			inputSection = false
			res.addGap("an interface header was not recognized, so the lines under it were left unattributed rather than filed under the previous interface: " + gapLine(ln))
			continue
		}
		if cur == nil {
			continue
		}
		fs := fields(ln)
		low := strings.ToLower(ln)
		// THE DESCRIPTION IS OPERATOR FREE TEXT, and it is the one line in the
		// record the DEVICE does not author. It is read for the description and
		// the line is then DONE: the position-independent parameter scan below
		// must never see it.
		//
		// It used to. The scan reads MTU/BW/duplex/speed/last-flapped off any
		// line that carries the token, and those fields are first-write-wins, so
		// a description reading "MTU 9000 to core, 1Gbps uplink" wrote 9000 and
		// 1000 onto the record before the device's OWN "MTU 1500 bytes, BW
		// 100000 Kbit/sec" line was reached, and that line could no longer
		// correct it. The wrong number then flowed into RCA and into LLM
		// evidence as if the device had reported it.
		//
		// The alternative — accepting these fields only from their canonical
		// POSITIONS — was rejected. One parser serves five dialects here
		// precisely because it does not depend on where in the record a line
		// falls, and pinning positions would mean enumerating each platform's
		// layout: a list that is always one platform behind (the same argument
		// ciscoStateWord makes below). Skipping the free-text line removes the
		// fabrication source and narrows nothing that is a genuine reading off a
		// device. A number an operator typed into a label is not a measurement.
		if strings.HasPrefix(trim(low), "description:") {
			if v, ok := valueAfter(ln, "escription:"); ok && v != "" {
				cur.Description = strPtr(v)
			}
			continue
		}
		switch {
		case strings.HasPrefix(trim(low), "admin state is "):
			if v, ok := valueAfter(ln, "admin state is "); ok && v != "" {
				cur.Admin = strPtr(strings.TrimRight(v, ","))
			}
		case strings.HasPrefix(trim(low), "internet address is "):
			if v, ok := valueAfter(ln, "internet address is "); ok && v != "" {
				// Same " x" sentinel as every sibling site. The `v != ""` guard
				// above already makes Fields non-empty today; the sentinel means
				// the index is safe on its own, not because of a check three
				// lines away that a later edit could drop.
				cur.IPv4 = strPtr(strings.Fields(v + " x")[0])
			}
		case strings.Contains(low, "input errors"):
			inputSection = true
			if n, ok := numberBefore(fs, "input"); ok {
				cur.InErrors = i64Ptr(n)
			}
			if n, ok := numberBefore(fs, "CRC"); ok {
				cur.CRC = i64Ptr(n)
			}
		case strings.Contains(low, "output errors"):
			inputSection = false
			if n, ok := numberBefore(fs, "output"); ok {
				cur.OutErrors = i64Ptr(n)
			}
		case strings.Contains(low, "total output drops"):
			if n, ok := numberAfter(fs, "drops"); ok {
				cur.OutDrops = i64Ptr(n)
			}
		}
		// Counter and parameter lines that are position-independent.
		if cur.MTU == nil {
			if n, ok := numberAfter(fs, "MTU"); ok && n > 0 {
				cur.MTU = intPtr(int(n))
			}
		}
		if cur.SpeedMbps == nil {
			if n, ok := numberAfter(fs, "BW"); ok {
				if mbps, ok := kbitsToMbps(n); ok {
					cur.SpeedMbps = i64Ptr(mbps)
				}
			}
		}
		if cur.SpeedMbps == nil || cur.Duplex == nil {
			ciscoDuplexSpeed(fs, cur)
		}
		if cur.LastFlap == nil && strings.Contains(low, "last flapped") {
			if v, ok := valueAfter(ln, "last flapped"); ok {
				v = trim(strings.TrimPrefix(trim(v), ":"))
				if v != "" {
					cur.LastFlap = strPtr(v)
				}
			}
		}
		if inputSection && cur.InDrops == nil {
			if n, ok := numberBefore(fs, "input"); ok && strings.Contains(low, "input packets dropped") {
				cur.InDrops = i64Ptr(n)
			}
		}
	}
	flush()
	return res
}

// ciscoHeaderShape recognizes the SHAPE of a Cisco-family interface header —
// an unindented line whose first and only head token is a name, followed by
// " is " and something.
//
// It is deliberately separate from ciscoIfHeader, and deliberately says nothing
// about the state words. This is the RECORD BOUNDARY. If the boundary depended
// on knowing the state phrase, a platform phrase we had not enumerated would be
// read as body text and its interface's counters would land on the previous
// interface (review H5). Recognizing the header and refusing its VALUES are two
// different questions and are now answered separately.
//
// It stays strict about the shape: the name must be the first token of an
// unindented line, so an indented prose line mentioning "is up" can never end a
// record.
func ciscoHeaderShape(line string) (name, rest string, ok bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return "", "", false
	}
	head, rest, found := strings.Cut(line, " is ")
	if !found {
		return "", "", false
	}
	name = trim(head)
	if name == "" || strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	if trim(rest) == "" {
		return "", "", false
	}
	return name, rest, true
}

// ciscoIfHeader recognizes "<Name> is <admin>[, line protocol is <oper>]" AND
// reads its state values. ok=false means the values are not trustworthy — the
// caller must still treat a ciscoHeaderShape line as a record boundary.
func ciscoIfHeader(line string) (name, admin, oper string, ok bool) {
	name, rest, shaped := ciscoHeaderShape(line)
	if !shaped {
		return "", "", "", false
	}
	adminPart, operPart, hasProto := strings.Cut(rest, ", line protocol is ")
	admin = trim(strings.TrimRight(adminPart, ","))
	if hasProto {
		oper = trim(strings.TrimRight(operPart, ","))
	}
	if admin == "" {
		return "", "", "", false
	}
	// Only the state words the platforms actually print start a record.
	if !ciscoStateWord(admin) {
		return "", "", "", false
	}
	if hasProto && !ciscoStateWord(oper) {
		return "", "", "", false
	}
	return name, admin, oper, true
}

// ciscoStateWord reports whether s is an admin/oper state phrase the
// Cisco-family interface header prints: one of the base words, optionally
// followed by the parenthesised reason the platform appends.
//
// The parenthesised part is matched by SHAPE rather than enumerated. The old
// closed list knew "up (connected)" and "down (notconnect)" but not Arista's
// "down (disabled)" or NX-OS's "down (Link not connected)", which is how those
// headers came to be read as body text (review H5). Enumerating every vendor's
// reason string is a list that is always one platform behind; the base word is
// the part that carries the state, and the reason is preserved VERBATIM in
// Admin/Oper either way, so nothing is guessed by accepting it.
//
// The base word set is still closed, so prose does not become a header.
func ciscoStateWord(s string) bool {
	s = trim(s)
	if open := strings.IndexByte(s, '('); open >= 0 {
		if !strings.HasSuffix(s, ")") {
			return false
		}
		s = trim(s[:open])
	}
	switch strings.ToLower(s) {
	case "up", "down", "administratively down", "reset", "deleted":
		return true
	}
	return false
}

// ciscoDuplexSpeed reads the "Full Duplex, 1000Mbps" / "Full-duplex, 1000Mb/s"
// line. Both spellings appear across the family; anything else is left absent.
func ciscoDuplexSpeed(fs []string, cur *InterfaceState) {
	for _, f := range fs {
		tok := strings.TrimRight(f, ",")
		low := strings.ToLower(tok)
		switch low {
		case "full-duplex", "half-duplex", "auto-duplex":
			if cur.Duplex == nil {
				cur.Duplex = strPtr(strings.TrimSuffix(tok, "-duplex"))
			}
		case "full", "half":
			// "Full Duplex" — only when the NEXT token is the word Duplex.
			continue
		}
		if cur.SpeedMbps == nil {
			if mbps, ok := speedTokenMbps(tok); ok {
				cur.SpeedMbps = i64Ptr(mbps)
			}
		}
	}
	for i := 0; i+1 < len(fs); i++ {
		if strings.EqualFold(strings.TrimRight(fs[i+1], ","), "duplex") {
			w := strings.TrimRight(fs[i], ",")
			if strings.EqualFold(w, "full") || strings.EqualFold(w, "half") || strings.EqualFold(w, "auto") {
				if cur.Duplex == nil {
					cur.Duplex = strPtr(w)
				}
			}
		}
	}
}

// ── Junos: `show interfaces <name> extensive` ───────────────────────────────

// parseJunosInterfaces parses the Junos physical-interface block. Junos reports
// framing errors (the FCS counter) separately from the total error count, and
// separates input from output error blocks — both distinctions are preserved
// rather than merged.
func parseJunosInterfaces(lines []string) Result {
	var res Result
	var cur *InterfaceState
	section := "" // "in" | "out" | ""

	flush := func() {
		if cur != nil {
			res.Interfaces = append(res.Interfaces, *cur)
			cur = nil
		}
	}
	for _, ln := range lines {
		t := trim(ln)
		if v, ok := strings.CutPrefix(t, "Physical interface: "); ok {
			flush()
			parts := strings.Split(v, ",")
			cur = &InterfaceState{Name: trim(parts[0])}
			for _, p := range parts[1:] {
				p = trim(p)
				switch {
				case strings.EqualFold(p, "Enabled"), strings.EqualFold(p, "Disabled"):
					cur.Admin = strPtr(p)
				default:
					if v, ok := strings.CutPrefix(p, "Physical link is "); ok {
						cur.Oper = strPtr(trim(v))
					}
				}
			}
			section = ""
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Input errors"):
			section = "in"
			continue
		case strings.HasPrefix(t, "Output errors"):
			section = "out"
			continue
		}
		if v, ok := strings.CutPrefix(t, "Description: "); ok {
			cur.Description = strPtr(trim(v))
		}
		if v, ok := valueAfter(t, "Last flapped"); ok && cur.LastFlap == nil {
			v = trim(strings.TrimPrefix(trim(v), ":"))
			if v != "" {
				cur.LastFlap = strPtr(v)
			}
		}
		// The link-level line carries MTU and Speed as comma-separated
		// "Key: value" pairs.
		for _, seg := range strings.Split(t, ",") {
			k, v, ok := kv(seg)
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "mtu":
				if n, ok := atoiOK(v); ok && n > 0 && cur.MTU == nil {
					cur.MTU = intPtr(int(n))
				}
			case "speed":
				if mbps, ok := speedTokenMbps(v); ok && cur.SpeedMbps == nil {
					cur.SpeedMbps = i64Ptr(mbps)
				}
			case "link-mode":
				if cur.Duplex == nil {
					cur.Duplex = strPtr(v)
				}
			}
		}
		// The error blocks are "Key: n, Key: n, …" on one or more lines.
		if section != "" {
			for _, seg := range strings.Split(t, ",") {
				k, v, ok := kv(seg)
				if !ok {
					continue
				}
				n, numeric := atoiOK(v)
				if !numeric {
					continue
				}
				switch strings.ToLower(k) {
				case "errors":
					if section == "in" && cur.InErrors == nil {
						cur.InErrors = i64Ptr(n)
					} else if section == "out" && cur.OutErrors == nil {
						cur.OutErrors = i64Ptr(n)
					}
				case "framing errors":
					if section == "in" && cur.CRC == nil {
						cur.CRC = i64Ptr(n)
					}
				case "drops":
					if section == "in" && cur.InDrops == nil {
						cur.InDrops = i64Ptr(n)
					} else if section == "out" && cur.OutDrops == nil {
						cur.OutDrops = i64Ptr(n)
					}
				case "carrier transitions":
					if cur.CarrierTransitions == nil {
						cur.CarrierTransitions = i64Ptr(n)
					}
				}
			}
		}
	}
	flush()
	return res
}

// ── Huawei VRP: `display interface <name>` ──────────────────────────────────

// parseVRPInterfaces parses the VRP interface block. VRP prints the admin state
// on the header line ("<name> current state : UP") and the line protocol on the
// NEXT line, and reports input and output counters under "Input:"/"Output:"
// section headers.
func parseVRPInterfaces(lines []string) Result {
	var res Result
	var cur *InterfaceState
	section := ""

	flush := func() {
		if cur != nil {
			res.Interfaces = append(res.Interfaces, *cur)
			cur = nil
		}
	}
	for _, ln := range lines {
		t := trim(ln)
		if name, state, ok := vrpIfHeader(t); ok {
			flush()
			cur = &InterfaceState{Name: name, Admin: strPtr(state)}
			section = ""
			continue
		}
		if vrpHeaderShape(t) {
			// A VRP interface header this parser could not read (a spelling the
			// exact cut does not know, a truncated capture that ends right after
			// the colon). Close the previous record and start no new one.
			//
			// Keeping `cur` here is review H5 in its VRP form: the next
			// "Line protocol current state :" line overwrote the PREVIOUS
			// interface's Oper, and the Input/Output counters that followed were
			// filed against it too. An up port then reads as down with someone
			// else's CRC count.
			//
			// The lines under this header are dropped, so the drop is RECORDED
			// (§10) rather than being a silent loss of device output.
			flush()
			section = ""
			res.addGap("an interface header was not recognized, so the lines under it were left unattributed rather than filed under the previous interface: " + gapLine(t))
			continue
		}
		if cur == nil {
			continue
		}
		if v, ok := strings.CutPrefix(t, "Line protocol current state :"); ok {
			// Same fabrication class: a capture cut off right after the colon
			// must leave Oper ABSENT. A pointer to "" is not "we did not read
			// it", it is "the device said nothing", and downstream renders it
			// as a blank state rather than as unknown.
			if o := trim(v); o != "" {
				cur.Oper = strPtr(o)
			}
			continue
		}
		switch {
		case strings.EqualFold(t, "Input:"), strings.EqualFold(t, "Input :"):
			section = "in"
			continue
		case strings.EqualFold(t, "Output:"), strings.EqualFold(t, "Output :"):
			section = "out"
			continue
		}
		if v, ok := strings.CutPrefix(t, "Description:"); ok {
			if d := trim(v); d != "" {
				cur.Description = strPtr(d)
			}
		}
		if v, ok := valueAfter(t, "The Maximum Transmit Unit is "); ok && cur.MTU == nil {
			// The " x" sentinel guarantees Fields returns at least one element:
			// a device line that ends right after the marker leaves v empty, and
			// Fields("")[0] would panic. atoiOK rejects "x", so the sentinel can
			// never become a value.
			if n, ok := atoiOK(strings.Fields(v + " x")[0]); ok && n > 0 {
				cur.MTU = intPtr(int(n))
			}
		}
		if v, ok := valueAfter(t, "Internet Address is "); ok && cur.IPv4 == nil {
			if f := strings.Fields(v); len(f) > 0 {
				cur.IPv4 = strPtr(f[0])
			}
		}
		for _, seg := range strings.Split(t, ",") {
			k, v, ok := kv(seg)
			if !ok {
				continue
			}
			switch strings.ToLower(k) {
			case "speed":
				if n, ok := atoiOK(strings.Fields(v + " x")[0]); ok && cur.SpeedMbps == nil {
					cur.SpeedMbps = i64Ptr(n)
				}
			case "duplex":
				// The `v != ""` guard is what stops the " x" sentinel from
				// BECOMING the value (tracker 282e). At the numeric sites below
				// the sentinel is harmless because atoiOK/atofOK reject the
				// token "x"; at a STRING site nothing rejects it, so a VRP line
				// reading "Duplex:" with no value used to yield Duplex = "x" —
				// a field the device never reported. The sentinel stays: it is
				// what keeps Fields(...)[0] from panicking on its own, rather
				// than because of a check somewhere else that an edit could drop.
				if v != "" && cur.Duplex == nil {
					cur.Duplex = strPtr(strings.Fields(v + " x")[0])
				}
			case "crc":
				if n, ok := atoiOK(v); ok && section == "in" && cur.CRC == nil {
					cur.CRC = i64Ptr(n)
				}
			case "total error":
				if n, ok := atoiOK(v); ok {
					switch section {
					case "in":
						if cur.InErrors == nil {
							cur.InErrors = i64Ptr(n)
						}
					case "out":
						if cur.OutErrors == nil {
							cur.OutErrors = i64Ptr(n)
						}
					}
				}
			case "drop":
				if n, ok := atoiOK(v); ok {
					switch section {
					case "in":
						if cur.InDrops == nil {
							cur.InDrops = i64Ptr(n)
						}
					case "out":
						if cur.OutDrops == nil {
							cur.OutDrops = i64Ptr(n)
						}
					}
				}
			}
		}
	}
	flush()
	return res
}

// vrpHeaderShape reports whether t is a VRP interface header LINE, whatever the
// header says. This is the RECORD BOUNDARY, and it is deliberately looser than
// vrpIfHeader: the boundary must not depend on the exact spacing around the
// colon or on the state text being present, because a header the value parser
// refuses is exactly the case that used to poison the previous interface
// (review H5).
//
// The shape is the "current state" marker followed by the colon VRP prints. The
// colon is what keeps a description or a prose line that merely contains the
// words from ending a record. The "Line protocol current state" line that
// follows every header is NOT a boundary — it belongs to the record above it.
func vrpHeaderShape(t string) bool {
	idx := asciiFoldIndex(t, vrpStateMarker)
	if idx < 0 {
		return false
	}
	rest := strings.TrimLeft(t[idx+len(vrpStateMarker):], " \t")
	if !strings.HasPrefix(rest, ":") {
		return false
	}
	return !strings.EqualFold(trim(t[:idx]), "Line protocol")
}

// vrpStateMarker is the words VRP prints between the interface name and its
// administrative state.
const vrpStateMarker = "current state"

// vrpIfHeader recognizes "<name> current state : UP" AND reads its values.
// ok=false means the values are not trustworthy — the caller must still treat a
// vrpHeaderShape line as a record boundary.
func vrpIfHeader(line string) (name, state string, ok bool) {
	head, rest, found := strings.Cut(line, " current state :")
	if !found {
		return "", "", false
	}
	name = trim(head)
	state = trim(rest)
	if name == "" || state == "" || strings.ContainsAny(name, " \t") {
		return "", "", false
	}
	if strings.EqualFold(name, "Line protocol") {
		return "", "", false
	}
	return name, state, true
}

// ── Nokia SR OS: `show port <id> detail` ────────────────────────────────────

// parseSROSPortDetail parses the SR OS port detail block, which is a two-column
// "Key : value" table (plus a transceiver sub-table carrying the DDM readings).
// Only keys SR OS actually prints are read; the parser recognizes nothing on a
// capture that is not this table, which is the intended conservative outcome.
func parseSROSPortDetail(lines []string) Result {
	var res Result
	cur := InterfaceState{}
	found := false

	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		for k, v := range kvPairs(ln) {
			switch k {
			case "interface":
				if !strings.ContainsAny(v, " ") {
					cur.Name = v
					found = true
				}
			case "description":
				cur.Description = strPtr(v)
			case "admin state":
				cur.Admin = strPtr(v)
				found = true
			case "oper state":
				cur.Oper = strPtr(v)
				found = true
			case "mtu", "configured mtu":
				if n, ok := atoiOK(v); ok && n > 0 && cur.MTU == nil {
					cur.MTU = intPtr(int(n))
				}
			case "oper speed", "configured speed":
				if mbps, ok := speedTokenMbps(strings.ReplaceAll(v, " ", "")); ok && cur.SpeedMbps == nil {
					cur.SpeedMbps = i64Ptr(mbps)
				}
			case "oper duplex", "configured duplex":
				if cur.Duplex == nil {
					cur.Duplex = strPtr(v)
				}
			case "rx optical power", "rx optical power (avg dbm)":
				if f, ok := atofOK(strings.Fields(v + " x")[0]); ok && cur.RxPowerDbm == nil {
					cur.RxPowerDbm = f64Ptr(f)
				}
			case "tx output power", "tx output power (dbm)":
				if f, ok := atofOK(strings.Fields(v + " x")[0]); ok && cur.TxPowerDbm == nil {
					cur.TxPowerDbm = f64Ptr(f)
				}
			case "temperature (c)", "temperature":
				if f, ok := atofOK(strings.Fields(v + " x")[0]); ok && cur.TempC == nil {
					cur.TempC = f64Ptr(f)
				}
			}
		}
	}
	if !found || cur.Name == "" {
		return res
	}
	res.Interfaces = append(res.Interfaces, cur)
	return res
}

// ── brief / summary tables ──────────────────────────────────────────────────

// parseCiscoIPIntBrief parses `show ip interface brief` (IOS/IOS-XE) and
// `show ipv4 interface brief` (IOS-XR). The OK?/Method columns are the shape
// key: a row without a literal YES/NO there is not this table.
func parseCiscoIPIntBrief(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 6 {
			continue
		}
		if !strings.EqualFold(fs[2], "YES") && !strings.EqualFold(fs[2], "NO") {
			continue
		}
		st := InterfaceState{Name: fs[0]}
		if !strings.EqualFold(fs[1], "unassigned") {
			st.IPv4 = strPtr(fs[1])
		}
		st.Oper = strPtr(fs[len(fs)-1])
		st.Admin = strPtr(strings.Join(fs[4:len(fs)-1], " "))
		res.Interfaces = append(res.Interfaces, st)
	}
	return res
}

// parseNXOSIPIntBrief parses the NX-OS brief table, whose status column is the
// compound "protocol-up/link-up/admin-up" token.
func parseNXOSIPIntBrief(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 3 {
			continue
		}
		if !strings.Contains(fs[2], "protocol-") {
			continue
		}
		st := InterfaceState{Name: fs[0]}
		if looksIPv4(fs[1]) || looksPrefix(fs[1]) {
			st.IPv4 = strPtr(fs[1])
		}
		for _, part := range strings.Split(fs[2], "/") {
			if v, ok := strings.CutPrefix(part, "protocol-"); ok {
				st.Oper = strPtr(v)
			}
			if v, ok := strings.CutPrefix(part, "admin-"); ok {
				st.Admin = strPtr(v)
			}
		}
		res.Interfaces = append(res.Interfaces, st)
	}
	return res
}

// parseEOSIPIntBrief parses the EOS brief table
// ("Interface  IP Address  Status  Protocol  MTU  Owner"), whose shape key is a
// pair of up/down words in columns 2 and 3.
func parseEOSIPIntBrief(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 4 {
			continue
		}
		if !eosUpDown(fs[2]) || !eosUpDown(fs[3]) {
			continue
		}
		st := InterfaceState{Name: fs[0], Admin: strPtr(fs[2]), Oper: strPtr(fs[3])}
		if looksPrefix(fs[1]) || looksIPv4(fs[1]) {
			st.IPv4 = strPtr(fs[1])
		}
		if len(fs) >= 5 {
			if n, ok := atoiOK(fs[4]); ok && n > 0 {
				st.MTU = intPtr(int(n))
			}
		}
		res.Interfaces = append(res.Interfaces, st)
	}
	return res
}

func eosUpDown(s string) bool {
	switch strings.ToLower(s) {
	case "up", "down", "admin-down", "notconnect", "errdisabled", "unknown":
		return true
	}
	return false
}

// parseJunosTerse parses `show interfaces terse`: "<name> <admin> <link>
// [proto] [local] [remote]".
func parseJunosTerse(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if ln == "" || ln[0] == ' ' {
			continue
		}
		fs := fields(ln)
		if len(fs) < 3 {
			continue
		}
		if !junosUpDown(fs[1]) || !junosUpDown(fs[2]) {
			continue
		}
		st := InterfaceState{Name: fs[0], Admin: strPtr(fs[1]), Oper: strPtr(fs[2])}
		if len(fs) >= 5 && strings.EqualFold(fs[3], "inet") && looksPrefix(fs[4]) {
			st.IPv4 = strPtr(fs[4])
		}
		res.Interfaces = append(res.Interfaces, st)
	}
	return res
}

func junosUpDown(s string) bool {
	switch strings.ToLower(s) {
	case "up", "down", "test":
		return true
	}
	return false
}
