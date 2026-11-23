// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package wan

import (
	"sort"
	"strconv"
	"strings"
)

// facts.go — assembles one device's per-interface WAN facts from what the api
// read (pure; the api does the IO).

// IfRow is one controller-reported interface (the interface bridge's NMS row:
// VPN, closed-set port role and kind, description, addresses).
type IfRow struct {
	Name, VRF, Role, Kind, Alias string
	Addrs                        []string
}

// DeviceInputs is what the api has for one device.
type DeviceInputs struct {
	DeviceID, Name string
	// Candidate: the device name matches the policy pattern, or the device is an
	// SD-WAN edge (see DeviceFacts.Candidate).
	Candidate bool
	// AddrIf is the merged bridge's interface address → ifName for this device.
	AddrIf map[string]string
	// Rows are the controller's rows for this device (nil when none).
	Rows []IfRow
	// TLOCIfaces / TLOCAddrs are the SD-WAN overlay facts' transport locators:
	// TLOC interface names, and the device's own BFD source addresses.
	TLOCIfaces []string
	TLOCAddrs  []string
	// NextHops is the policy's next-hop map (keys device/ifName or device).
	NextHops map[string]string
	// Marks are the operator's marks, ifName → MarkWAN / MarkNotWAN.
	Marks map[string]string
	// Linked: ifName → the WAN-candidate device it is directly connected to.
	Linked map[string]string
	// SNMP is the device's own IF-MIB facts per ifName (the merged bridge's
	// spelling). They fill only interfaces the bridge already knows.
	SNMP map[string]SNMPIf
	// ExternalBGP is ExternalBGPPeers over the device's BGP4-MIB sessions,
	// keyed by local address.
	ExternalBGP map[string]ExternalPeer
}

// BuildFacts folds one device's inputs into the classifier's facts. canon is
// the canonical port key ("Gi1" ≡ "GigabitEthernet1"); the merged bridge's
// spelling is the one shown (it is what the device_if_* series carry).
func BuildFacts(in DeviceInputs, canon func(string) string) DeviceFacts {
	if canon == nil {
		canon = func(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
	}
	type acc struct {
		f     IfFacts
		addrs map[string]bool
	}
	ifs := map[string]*acc{}
	get := func(name string) *acc {
		k := canon(name)
		if k == "" {
			return nil
		}
		a := ifs[k]
		if a == nil {
			a = &acc{f: IfFacts{Name: strings.TrimSpace(name)}, addrs: map[string]bool{}}
			ifs[k] = a
		}
		return a
	}
	sdwan := len(in.TLOCIfaces) > 0 || len(in.TLOCAddrs) > 0
	for _, r := range in.Rows {
		a := get(r.Name)
		if a == nil {
			continue
		}
		if a.f.VRF == "" {
			a.f.VRF = r.VRF
		}
		if a.f.Role == "" {
			a.f.Role = r.Role
		}
		if a.f.Kind == "" {
			a.f.Kind = r.Kind
		}
		if a.f.Alias == "" {
			a.f.Alias = r.Alias
		}
		for _, ip := range r.Addrs {
			a.addrs[ip] = true
		}
		if _, err := strconv.Atoi(strings.TrimSpace(r.VRF)); err == nil || r.Role != "" {
			sdwan = true
		}
	}
	for ip, ifn := range in.AddrIf {
		a := get(ifn)
		if a == nil {
			continue
		}
		a.f.Name = strings.TrimSpace(ifn) // the merged bridge's spelling
		a.addrs[ip] = true
	}

	// The device's own IF-MIB ifType: fills the kind the controller did not
	// state, on interfaces the bridge already knows (never invents one).
	for n, si := range in.SNMP {
		a := ifs[canon(n)]
		if a == nil {
			continue
		}
		if a.f.Kind == "" {
			a.f.Kind = si.Kind
		}
		if a.f.Kind == KindWANMedia && a.f.IfType == "" {
			a.f.IfType = si.Type
		}
	}

	// cEdge: Tunnel1 carries the same VPN 0 address as GigabitEthernet1.
	tunnelByAddr := map[string]string{}
	for _, a := range ifs {
		if IsTunnelInterface(a.f.Name, a.f.Kind) && strings.TrimSpace(a.f.VRF) == "0" {
			for ip := range a.addrs {
				if cur, ok := tunnelByAddr[ip]; !ok || a.f.Name < cur {
					tunnelByAddr[ip] = a.f.Name
				}
			}
		}
	}
	tlocIf := map[string]bool{}
	for _, n := range in.TLOCIfaces {
		if k := canon(n); k != "" {
			tlocIf[k] = true
		}
	}
	tlocAddr := map[string]bool{}
	for _, ip := range in.TLOCAddrs {
		tlocAddr[strings.TrimSpace(ip)] = true
	}
	marks := map[string]string{}
	for n, m := range in.Marks {
		if m == MarkWAN || m == MarkNotWAN {
			marks[canon(n)] = m
		}
	}
	linked := map[string]string{}
	for n, peer := range in.Linked {
		linked[canon(n)] = peer
	}

	keys := make([]string, 0, len(ifs))
	for k := range ifs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := DeviceFacts{Candidate: in.Candidate, SDWAN: sdwan}
	for _, k := range keys {
		a := ifs[k]
		f := a.f
		for ip := range a.addrs {
			f.Addrs = append(f.Addrs, ip)
		}
		sort.Strings(f.Addrs)
		tunnel := IsTunnelInterface(f.Name, f.Kind)
		f.InTLOC = tlocIf[k]
		if !tunnel {
			for _, ip := range f.Addrs {
				if tlocAddr[ip] {
					f.InTLOC = true
				}
				if t := tunnelByAddr[ip]; t != "" && strings.TrimSpace(f.VRF) == "0" {
					f.TunnelOver = t
				}
			}
		}
		f.NextHop = nextHopFor(in, f.Name)
		f.ExternalBGP = externalFor(f.Addrs, in.ExternalBGP)
		f.Mark = marks[k]
		f.Linked = linked[k]
		out.Ifaces = append(out.Ifaces, f)
	}
	return out
}

// nextHopFor is the next-hop declared for exactly this port, keyed by the
// device id or its name (the policy editor asks for the device by name).
func nextHopFor(in DeviceInputs, ifn string) string {
	if in.NextHops == nil {
		return ""
	}
	for _, dev := range []string{in.DeviceID, in.Name} {
		if dev == "" {
			continue
		}
		if t := strings.TrimSpace(in.NextHops[dev+"/"+ifn]); t != "" {
			return t
		}
	}
	return ""
}
