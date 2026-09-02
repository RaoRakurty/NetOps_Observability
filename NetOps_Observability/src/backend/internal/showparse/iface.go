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
		if cur == nil {
			continue
		}
		fs := fields(ln)
		low := strings.ToLower(ln)
		switch {
		case strings.HasPrefix(trim(low), "description:"):
			if v, ok := valueAfter(ln, "escription:"); ok && v != "" {
				cur.Description = strPtr(v)
			}
		case strings.HasPrefix(trim(low), "admin state is "):
			if v, ok := valueAfter(ln, "admin state is "); ok && v != "" {
				cur.Admin = strPtr(strings.TrimRight(v, ","))
			}
		case strings.HasPrefix(trim(low), "internet address is "):
			if v, ok := valueAfter(ln, "internet address is "); ok && v != "" {
				cur.IPv4 = strPtr(strings.Fields(v)[0])
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

// ciscoIfHeader recognizes "<Name> is <admin>[, line protocol is <oper>]".
// It is deliberately strict: the name must be the FIRST token of an unindented
// line, so an indented prose line mentioning "is up" can never start a record.
func ciscoIfHeader(line string) (name, admin, oper string, ok bool) {
	if line == "" || line[0] == ' ' || line[0] == '\t' {
		return "", "", "", false
	}
	head, rest, found := strings.Cut(line, " is ")
	if !found {
		return "", "", "", false
	}
	name = trim(head)
	if name == "" || strings.ContainsAny(name, " \t") {
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

// ciscoStateWord is the closed set of admin/oper state phrases the Cisco-family
// interface header prints. Anything else is not a header (fail closed).
func ciscoStateWord(s string) bool {
	switch strings.ToLower(trim(s)) {
	case "up", "down", "administratively down", "up (connected)", "down (notconnect)",
		"up (disabled)", "down (errdisabled)", "down (inactive)", "reset",
		"deleted", "up (not connect)":
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
		if cur == nil {
			continue
		}
		if v, ok := strings.CutPrefix(t, "Line protocol current state :"); ok {
			cur.Oper = strPtr(trim(v))
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
			if n, ok := atoiOK(strings.Fields(v)[0]); ok && n > 0 {
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
				if cur.Duplex == nil {
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

// vrpIfHeader recognizes "<name> current state : UP".
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
