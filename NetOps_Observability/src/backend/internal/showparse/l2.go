package showparse

// l2.go — ARP / neighbour-cache and MAC forwarding-table parsers (CmdARP,
// CmdMAC).
//
// The AGE column is the trap here: IOS reports it in MINUTES, NX-OS and EOS as a
// hh:mm:ss elapsed time, SR OS as an EXPIRY countdown ("00h58m32s" until the
// entry dies — the opposite direction). Converting any of them to a duration
// would silently invent a common unit that does not exist, so Age is carried as
// the device's own text and the caller is told, by the dialect, what it means.

import "strings"

func registerL2Parsers(l *Library) {
	l.register(CmdARP, parseCiscoARP, DialectCiscoIOS, DialectCiscoIOSXE)
	l.register(CmdARP, parseTabularARP, DialectCiscoNXOS, DialectAristaEOS)
	l.register(CmdARP, parseSROSARP, DialectNokiaSROS)

	l.register(CmdMAC, parseCiscoMAC, DialectCiscoIOS, DialectCiscoIOSXE, DialectAristaEOS)
	l.register(CmdMAC, parseNXOSMAC, DialectCiscoNXOS)
	l.register(CmdMAC, parseVRPMAC, DialectHuaweiVRP)
}

// parseCiscoARP parses the IOS / IOS-XE table:
//
//	Protocol  Address  Age (min)  Hardware Addr  Type  Interface
//
// The literal "Internet" protocol column is the shape key.
func parseCiscoARP(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 5 || !strings.EqualFold(fs[0], "Internet") {
			continue
		}
		if !looksIPv4(fs[1]) || !looksMAC(fs[3]) {
			continue
		}
		e := ARPEntry{Address: fs[1], MAC: strPtr(fs[3]), Age: strPtr(fs[2]), Type: strPtr(fs[4])}
		if len(fs) >= 6 {
			e.Iface = strPtr(fs[len(fs)-1])
		}
		res.ARP = append(res.ARP, e)
	}
	return res
}

// parseTabularARP parses the NX-OS / EOS table, which is
// "<address> <age> <mac> <interface>" with no protocol column.
func parseTabularARP(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 4 {
			continue
		}
		if !looksIPv4(fs[0]) || !looksMAC(fs[2]) {
			continue
		}
		res.ARP = append(res.ARP, ARPEntry{
			Address: fs[0], Age: strPtr(fs[1]), MAC: strPtr(fs[2]), Iface: strPtr(fs[3]),
		})
	}
	return res
}

// parseSROSARP parses the SR OS table:
//
//	IP Address  MAC Address  Expiry  Type  Interface
func parseSROSARP(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		fs := fields(ln)
		if len(fs) < 5 {
			continue
		}
		if !looksIPv4(fs[0]) || !looksMAC(fs[1]) {
			continue
		}
		res.ARP = append(res.ARP, ARPEntry{
			Address: fs[0], MAC: strPtr(fs[1]), Age: strPtr(fs[2]),
			Type: strPtr(fs[3]), Iface: strPtr(fs[4]),
		})
	}
	return res
}

// macTypeWord is the closed set of forwarding-entry types the tables print.
func macTypeWord(tok string) bool {
	switch strings.ToLower(trim(tok)) {
	case "dynamic", "static", "secure", "sticky", "system", "self", "igmp", "router":
		return true
	}
	return false
}

// parseCiscoMAC parses the IOS / IOS-XE / EOS table:
//
//	Vlan  Mac Address  Type  Ports
func parseCiscoMAC(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 4 {
			continue
		}
		vlan, vlanOK := atoiOK(fs[0])
		if !vlanOK || !looksMAC(fs[1]) || !macTypeWord(fs[2]) {
			continue
		}
		res.MAC = append(res.MAC, MACEntry{
			MAC: fs[1], VLAN: intPtr(int(vlan)), Type: strPtr(fs[2]), Iface: strPtr(fs[3]),
		})
	}
	return res
}

// parseNXOSMAC parses the NX-OS table, whose rows carry a leading flag glyph
// ("*", "+", "G", "C") ahead of the VLAN column.
func parseNXOSMAC(lines []string) Result {
	var res Result
	for _, ln := range lines {
		fs := fields(ln)
		if len(fs) < 4 {
			continue
		}
		if len(fs[0]) == 1 && !isDigits(fs[0]) {
			fs = fs[1:]
		}
		if len(fs) < 4 {
			continue
		}
		vlan, vlanOK := atoiOK(fs[0])
		if !vlanOK || !looksMAC(fs[1]) || !macTypeWord(fs[2]) {
			continue
		}
		res.MAC = append(res.MAC, MACEntry{
			MAC: fs[1], VLAN: intPtr(int(vlan)), Type: strPtr(fs[2]),
			Iface: strPtr(fs[len(fs)-1]),
		})
	}
	return res
}

// parseVRPMAC parses the Huawei VRP table:
//
//	MAC Address  VLAN/VSI/BD  Learned-From  Type
//
// The VLAN column is the compound "10/-/-" token; only its VLAN component is
// read, and only when it is a number ("-/-/bd10" leaves VLAN nil).
func parseVRPMAC(lines []string) Result {
	var res Result
	for _, ln := range lines {
		if isSeparator(ln) {
			continue
		}
		fs := fields(ln)
		if len(fs) < 4 || !looksMAC(fs[0]) || !macTypeWord(fs[3]) {
			continue
		}
		e := MACEntry{MAC: fs[0], Type: strPtr(fs[3]), Iface: strPtr(fs[2])}
		if vlan, ok := atoiOK(strings.Split(fs[1], "/")[0]); ok {
			e.VLAN = intPtr(int(vlan))
		}
		res.MAC = append(res.MAC, e)
	}
	return res
}
