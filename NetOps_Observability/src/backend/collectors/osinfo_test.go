// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

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

// srlDescription is the description leaf lab spine1/spine2 (Nokia SR Linux
// 7220 IXR-D3L) actually serve — read over gNMI /system/information on
// 2026-09-03 and byte-identical on both, and the same string SR Linux answers
// sysDescr.0 with. It is the fixture because tracker 231 is about THESE
// devices: nothing about this parse is hypothetical.
const srlDescription = "SRLinux-v26.3.2-426-g2b38957bbca 7220 IXR-D3L Copyright (c) 2000-2026 Nokia. " +
	"Kernel 5.15.0-186-generic #196-Ubuntu SMP Thu Aug 7 16:07:34 UTC 2026"

// TestResolveDeviceOSReadsTheVersionOffTheRowWhenSysDescrHasNone is tracker
// 231. The lab spines are MANUAL rows: `vendor: nokia`, `os: "SR Linux"`, no
// sysDescr (the platform's ACL refuses the collector host). That label resolves
// the product and no version, so /api/vulns and the security lane reported both
// devices UNASSESSED forever — correctly, but permanently.
func TestResolveDeviceOSReadsTheVersionOffTheRowWhenSysDescrHasNone(t *testing.T) {
	for _, tc := range []struct {
		name             string
		os, osVersion    string
		product, version string
	}{
		{
			name: "sysDescr alone still resolves both halves",
			os:   srlDescription,
			// The capture stops at the first hyphen, so the build suffix never
			// reaches a CVE range comparison.
			product: "srlinux", version: "26.3.2",
		},
		{
			name: "the lab spines as they are today: a product label and nothing else",
			os:   "SR Linux",
			// UNASSESSED is the honest answer, and it names the product it
			// could not assess rather than saying nothing at all.
			product: "srlinux", version: "",
		},
		{
			name: "the row carries the device-reported version beside the label",
			os:   "SR Linux", osVersion: "SRLinux-v26.3.2-426-g2b38957bbca",
			product: "srlinux", version: "26.3.2",
		},
		{
			name: "a source that wrote the WHOLE description leaf into os_version",
			os:   "SR Linux", osVersion: srlDescription,
			product: "srlinux", version: "26.3.2",
		},
		{
			name: "a live sysDescr WINS over a stale row leaf",
			os:   srlDescription, osVersion: "SRLinux-v25.10.1-1-gdeadbeef",
			product: "srlinux", version: "26.3.2",
		},
		{
			name: "a bare number nobody read off a device invents nothing",
			os:   "SR Linux", osVersion: "26.3.2",
			product: "srlinux", version: "",
		},
		{
			name: "an empty leaf changes nothing",
			os:   "SR Linux", osVersion: "   ",
			product: "srlinux", version: "",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ResolveDeviceOS("nokia", tc.os, tc.osVersion)
			if got.Product != tc.product || got.Version != tc.version {
				t.Errorf("ResolveDeviceOS = %+v, want product=%q version=%q", got, tc.product, tc.version)
			}
		})
	}
}

// TestResolveDeviceOSNeverInventsAcrossVendors — the version leaf is parsed by
// the SAME vendor-gated pattern as a sysDescr, so one vendor's version text can
// never be read under another vendor's profile.
func TestResolveDeviceOSNeverInventsAcrossVendors(t *testing.T) {
	if got := ResolveDeviceOS("arista", "SR Linux", srlDescription); got.Version != "" {
		t.Errorf("an SR Linux description resolved a version under the arista profile: %+v", got)
	}
	if got := ResolveDeviceOS("", "SR Linux", srlDescription); got.Version != "" || got.Product != "" {
		t.Errorf("an unknown vendor resolved something: %+v", got)
	}
}
