package collectors

import "testing"

// Real-world sysDescr shapes, one per vendor family the parser covers.
func TestParseOS(t *testing.T) {
	cases := []struct {
		name, vendor, descr string
		product, version    string
	}{
		{
			"cisco ios classic", "cisco",
			"Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)E10, RELEASE SOFTWARE (fc4)",
			"ios", "15.2(4)E10",
		},
		{
			"cisco ios xe", "cisco",
			"Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE — Cisco IOS-XE Software",
			"ios_xe", "17.9.4a",
		},
		{
			"cisco nx-os", "cisco",
			"Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(10), RELEASE SOFTWARE",
			"nx-os", "9.3(10)",
		},
		{
			"cisco ios xr", "cisco",
			"Cisco IOS XR Software (NCS-5500), Version 7.5.2 Copyright (c) 2013-2022 by Cisco Systems, Inc.",
			"ios_xr", "7.5.2",
		},
		{
			"cisco asa", "cisco",
			"Cisco Adaptive Security Appliance Version 9.16(4)",
			"asa", "9.16(4)",
		},
		{
			"juniper junos", "juniper",
			"Juniper Networks, Inc. mx240 internet router, kernel JUNOS 21.4R3-S4.9, Build date: 2023-06-15",
			"junos", "21.4R3-S4.9",
		},
		{
			"arista eos", "arista",
			"Arista Networks EOS version 4.33.1F running on an Arista cEOSLab",
			"eos", "4.33.1F",
		},
		{
			"fortinet fortios", "fortinet",
			"FortiGate-60F v7.2.8,build1639,240228 (GA.M)",
			"fortios", "7.2.8",
		},
		{
			"paloalto pan-os", "paloalto",
			"Palo Alto Networks PA-3220 series firewall, PAN-OS 10.2.4-h2",
			"pan-os", "10.2.4-h2",
		},
		{
			"paloalto no version", "paloalto",
			"Palo Alto Networks PA-220 series firewall",
			"pan-os", "",
		},
		{
			"nokia sros", "nokia",
			"TiMOS-B-21.10.R6 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2021 Nokia.",
			"sros", "21.10.R6",
		},
		{
			"huawei vrp", "huawei",
			"Huawei Versatile Routing Platform Software VRP (R) software, Version 8.180 (CE12800 V200R005C10SPC800)",
			"vrp", "8.180",
		},
		{
			"mikrotik routeros", "mikrotik",
			"RouterOS 7.14.2 (stable) on RB4011iGS+",
			"routeros", "7.14.2",
		},
		{
			"linux kernel", "linux",
			"Linux leaf1 5.15.0-179-generic #199-Ubuntu SMP x86_64",
			"linux_kernel", "5.15.0-179-generic",
		},
		{"unknown vendor", "acme", "AcmeOS 1.2.3", "", ""},
		{"empty descr", "cisco", "", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ParseOS(c.vendor, c.descr)
			if got.Product != c.product || got.Version != c.version {
				t.Fatalf("ParseOS(%q, %q) = {%q %q}, want {%q %q}",
					c.vendor, c.descr, got.Product, got.Version, c.product, c.version)
			}
		})
	}
}
