// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package showparse

// ipsec_test.go — the IOS-XE IPsec SA parser against `show crypto ipsec sa`
// CAPTURED on a real Cisco IOS XE 17.3.2 SD-WAN edge (lab, 2026-11-19). Only
// identities changed: every address is mapped to an RFC 5737 documentation
// address (consistently, so endpoints still pair up). Every other byte —
// spacing, counters, SPIs, the empty AH/PCP lists — is what the device printed.

import (
	"strings"
	"testing"
)

const capturedIOSXEIPsecSA = `



interface: Tunnel1
    Crypto map tag: Tunnel1-vesen-head-0, local addr 192.0.2.80

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (198.51.100.60/255.255.255.255/0/12346)
   current_peer 198.51.100.60 port 12346
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 92145, #pkts encrypt: 92145, #pkts digest: 92145
    #pkts decaps: 92144, #pkts decrypt: 92144, #pkts verify: 92144
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 198.51.100.60
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x102(258)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2011, flow_id: CSR:11, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2012, flow_id: CSR:12, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (198.51.100.40/255.255.255.255/0/12346)
   current_peer 198.51.100.40 port 12346
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 241461, #pkts encrypt: 241461, #pkts digest: 241461
    #pkts decaps: 92511, #pkts decrypt: 92511, #pkts verify: 92511
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 198.51.100.40
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x102(258)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2009, flow_id: CSR:9, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2010, flow_id: CSR:10, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (198.51.100.100/255.255.255.255/0/12366)
   current_peer 198.51.100.100 port 12366
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 87773, #pkts encrypt: 87773, #pkts digest: 87773
    #pkts decaps: 87774, #pkts decrypt: 87774, #pkts verify: 87774
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 198.51.100.100
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x103(259)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2007, flow_id: CSR:7, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x103(259)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2008, flow_id: CSR:8, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (198.51.100.51/255.255.255.255/0/12346)
   current_peer 198.51.100.51 port 12346
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 87760, #pkts encrypt: 87760, #pkts digest: 87760
    #pkts decaps: 87755, #pkts decrypt: 87755, #pkts verify: 87755
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 198.51.100.51
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x102(258)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2001, flow_id: CSR:1, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2002, flow_id: CSR:2, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (203.0.113.20/255.255.255.255/0/12346)
   current_peer 203.0.113.20 port 12346
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 237603, #pkts encrypt: 237603, #pkts digest: 237603
    #pkts decaps: 385289, #pkts decrypt: 385289, #pkts verify: 385289
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 203.0.113.20
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x102(258)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2003, flow_id: CSR:3, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2004, flow_id: CSR:4, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:

   protected vrf: (none)
   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)
   remote ident (addr/mask/prot/port): (203.0.113.52/255.255.255.255/0/12346)
   current_peer 203.0.113.52 port 12346
     PERMIT, flags={origin_is_acl,}
    #pkts encaps: 87786, #pkts encrypt: 87786, #pkts digest: 87786
    #pkts decaps: 87783, #pkts decrypt: 87783, #pkts verify: 87783
    #pkts compressed: 0, #pkts decompressed: 0
    #pkts not compressed: 0, #pkts compr. failed: 0
    #pkts not decompressed: 0, #pkts decompress failed: 0
    #send errors 0, #recv errors 0

     local crypto endpt.: 192.0.2.80, remote crypto endpt.: 203.0.113.52
     plaintext mtu 1438, path mtu 1480, ip mtu 1480, ip mtu idb Tunnel1
     current outbound spi: 0x102(258)
     PFS (Y/N): N, DH group: none

     inbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2005, flow_id: CSR:5, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     inbound ah sas:

     inbound pcp sas:

     outbound esp sas:
      spi: 0x102(258)
        transform: esp-gcm 256 ,
        in use settings ={Transport UDP-Encaps, esn}
        conn id: 2006, flow_id: CSR:6, sibling_flags FFFFFFFF80000008, crypto map: Tunnel1-vesen-head-0
        sa timing: remaining key lifetime is not applicable
        Kilobyte Volume Rekey has been disabled
        IV size: 8 bytes
        replay detection support: Y
        Status: ACTIVE(ACTIVE)

     outbound ah sas:

     outbound pcp sas:
`

func TestParseIOSXEIPsecSA_Captured(t *testing.T) {
	res, err := NewLibrary().Parse(CmdIPsecSA, DialectCiscoIOSXE, capturedIOSXEIPsecSA)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped || len(res.IPsecSAs) != 6 {
		t.Fatalf("want 6 SAs from the capture, got %d (skipped=%v %s)", len(res.IPsecSAs), res.Skipped, res.Reason)
	}
	first := res.IPsecSAs[0]
	if first.Interface != "Tunnel1" || first.Peer != "198.51.100.60" || first.PeerPort == nil || *first.PeerPort != 12346 {
		t.Errorf("first SA identity = %+v", first)
	}
	if first.LocalEndpoint != "192.0.2.80" || first.RemoteEndpoint != "198.51.100.60" {
		t.Errorf("endpoints = %q / %q", first.LocalEndpoint, first.RemoteEndpoint)
	}
	if first.PktsEncaps == nil || *first.PktsEncaps != 92145 || first.PktsDecaps == nil || *first.PktsDecaps != 92144 {
		t.Errorf("counters = %v / %v", first.PktsEncaps, first.PktsDecaps)
	}
	if first.SendErrors == nil || *first.SendErrors != 0 || first.RecvErrors == nil || *first.RecvErrors != 0 {
		t.Errorf("errors = %v / %v", first.SendErrors, first.RecvErrors)
	}
	if first.InboundESP != 1 || first.OutboundESP != 1 || first.InboundStatus != "ACTIVE(ACTIVE)" || first.OutboundStatus != "ACTIVE(ACTIVE)" {
		t.Errorf("ESP SAs = %d/%d %q/%q", first.InboundESP, first.OutboundESP, first.InboundStatus, first.OutboundStatus)
	}
	// The fifth flow received more than it sent — counters are per flow, never
	// carried over from the previous block.
	if sa := res.IPsecSAs[4]; sa.Peer != "203.0.113.20" || sa.PktsEncaps == nil || *sa.PktsEncaps != 237603 || *sa.PktsDecaps != 385289 {
		t.Errorf("fifth SA = %+v", sa)
	}
	if p := res.IPsecSAs[2].PeerPort; p == nil || *p != 12366 {
		t.Errorf("third SA port = %v, want 12366", p)
	}
}

// Shapes derived from the capture (labelled as derived, not captured): a flow
// whose inbound list is empty and one that never received a packet.
func TestParseIOSXEIPsecSA_DerivedShapes(t *testing.T) {
	block := capturedIOSXEIPsecSA[:strings.Index(capturedIOSXEIPsecSA, "   protected vrf: (none)\n   local  ident (addr/mask/prot/port): (192.0.2.80/255.255.255.255/0/12346)\n   remote ident (addr/mask/prot/port): (198.51.100.40")]
	noInbound := strings.Replace(block, "     inbound esp sas:\n      spi: 0x102(258)", "     inbound esp sas:\n", 1)
	noInbound = strings.Replace(noInbound, "        Status: ACTIVE(ACTIVE)", "", 1)
	res, _ := NewLibrary().Parse(CmdIPsecSA, DialectCiscoIOSXE, noInbound)
	if len(res.IPsecSAs) != 1 || res.IPsecSAs[0].InboundESP != 0 || res.IPsecSAs[0].InboundStatus != "" || res.IPsecSAs[0].OutboundESP != 1 {
		t.Fatalf("no inbound ESP SA: %+v", res.IPsecSAs)
	}
	oneWay := strings.Replace(block, "#pkts decaps: 92144", "#pkts decaps: 0", 1)
	res, _ = NewLibrary().Parse(CmdIPsecSA, DialectCiscoIOSXE, oneWay)
	if len(res.IPsecSAs) != 1 || res.IPsecSAs[0].PktsDecaps == nil || *res.IPsecSAs[0].PktsDecaps != 0 {
		t.Fatalf("one-way flow: %+v", res.IPsecSAs)
	}
}

// Output that is not the authored shape yields no rows: an error banner, a
// counter line with no current_peer, a current_peer that is not an address.
func TestParseIOSXEIPsecSA_NeverGuesses(t *testing.T) {
	for _, raw := range []string{
		"% Invalid input detected at '^' marker.",
		"    #pkts encaps: 10, #pkts encrypt: 10",
		"interface: Tunnel1\n   current_peer not-an-address port 500\n    #pkts encaps: 5,",
	} {
		res, err := NewLibrary().Parse(CmdIPsecSA, DialectCiscoIOSXE, raw)
		if err != nil {
			t.Fatal(err)
		}
		if len(res.IPsecSAs) != 0 || !res.Skipped {
			t.Errorf("%q produced rows: %+v", raw, res.IPsecSAs)
		}
	}
}
