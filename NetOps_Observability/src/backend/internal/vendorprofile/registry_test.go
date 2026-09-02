package vendorprofile

import (
	"errors"
	"testing"
)

func TestLookupByIDAndAlias(t *testing.T) {
	reg := Default()
	for _, id := range []string{
		"cisco/ios", "cisco/ios_xe", "cisco/ios_xr", "cisco/nx-os", "cisco/asa",
		"juniper/junos", "arista/eos", "nokia/srlinux", "nokia/sros",
	} {
		p, ok := reg.Lookup(id)
		if !ok {
			t.Fatalf("profile %q missing from the registry", id)
		}
		if p.ID != id {
			t.Errorf("Lookup(%q).ID = %q", id, p.ID)
		}
	}
	// The telemetry catalog names Arista's lab platform "ceos"; it must resolve
	// to the SAME profile, not a second product.
	p, ok := reg.Lookup("arista/ceos")
	if !ok || p.ID != "arista/eos" {
		t.Fatalf("arista/ceos alias did not resolve to arista/eos: %+v ok=%v", p.ID, ok)
	}
	if _, ok := reg.Lookup("acme/widgetos"); ok {
		t.Fatal("an unknown id must NOT resolve — there is no default profile")
	}
}

func TestVendorForSysObjectID(t *testing.T) {
	reg := Default()
	cases := map[string]string{
		"1.3.6.1.4.1.9.1.1745":     "cisco",
		"1.3.6.1.4.1.2636.1.1.1.2": "juniper",
		"1.3.6.1.4.1.30065.1.3011": "arista",
		"1.3.6.1.4.1.6527.1.3.23":  "nokia",
		"1.3.6.1.4.1.8072.3.2.10":  "net-snmp",
		"1.3.6.1.4.1.9789.1":       "sophos", // legacy Astaro enterprise
	}
	for oid, want := range cases {
		got, ok := reg.VendorForSysObjectID(oid)
		if !ok || got != want {
			t.Errorf("VendorForSysObjectID(%q) = %q,%v want %q", oid, got, ok, want)
		}
	}
	for _, oid := range []string{"1.3.6.1.2.1.1.2.0", "1.3.6.1.4.1.424242", "", "garbage"} {
		if v, ok := reg.VendorForSysObjectID(oid); ok {
			t.Errorf("VendorForSysObjectID(%q) resolved to %q — unknown must stay unknown", oid, v)
		}
	}
}

// TestSysDescrRankOrderIsLoadBearing pins the ordering invariant the text
// backstop depends on: a BIG-IP sysDescr embeds "Linux" and must resolve to f5.
func TestSysDescrRankOrderIsLoadBearing(t *testing.T) {
	reg := Default()
	got, ok := reg.VendorForSysDescr("BIG-IP 15.1.10 : Linux 3.10.0-862.14.4.el7.ve.x86_64")
	if !ok || got != "f5" {
		t.Fatalf("BIG-IP sysDescr resolved to %q (ok=%v), want f5", got, ok)
	}
	if got, ok := reg.VendorForSysDescr("Linux leaf1 5.15.0-179-generic"); !ok || got != "linux" {
		t.Fatalf("plain Linux sysDescr resolved to %q (ok=%v), want linux", got, ok)
	}
	if v, ok := reg.VendorForSysDescr("AcmeOS 1.2.3"); ok {
		t.Fatalf("unknown sysDescr resolved to %q — must stay unknown", v)
	}
}

// TestResolveOSOverCollectorFixtures drives the registry with the same real
// sysDescr shapes collectors/osinfo_test.go uses — the "lookup by detected OS
// string" contract, at the registry level.
func TestResolveOSOverCollectorFixtures(t *testing.T) {
	reg := Default()
	cases := []struct{ vendor, descr, product, version string }{
		{"cisco", "Cisco IOS Software, C2960 Software (C2960-LANBASEK9-M), Version 15.2(4)E10, RELEASE SOFTWARE (fc4)", "ios", "15.2(4)E10"},
		{"cisco", "Cisco IOS Software [Cupertino], Catalyst L3 Switch Software (CAT9K_IOSXE), Version 17.9.4a, RELEASE SOFTWARE — Cisco IOS-XE Software", "ios_xe", "17.9.4a"},
		{"cisco", "Cisco NX-OS(tm) n9000, Software (n9000-dk9), Version 9.3(10), RELEASE SOFTWARE", "nx-os", "9.3(10)"},
		{"cisco", "Cisco IOS XR Software (NCS-5500), Version 7.5.2 Copyright (c) 2013-2022 by Cisco Systems, Inc.", "ios_xr", "7.5.2"},
		{"cisco", "Cisco Adaptive Security Appliance Version 9.16(4)", "asa", "9.16(4)"},
		{"juniper", "Juniper Networks, Inc. mx240 internet router, kernel JUNOS 21.4R3-S4.9, Build date: 2023-06-15", "junos", "21.4R3-S4.9"},
		{"arista", "Arista Networks EOS version 4.33.1F running on an Arista cEOSLab", "eos", "4.33.1F"},
		{"nokia", "TiMOS-B-21.10.R6 both/x86_64 Nokia 7750 SR Copyright (c) 2000-2021 Nokia.", "sros", "21.10.R6"},
		{"fortinet", "FortiGate-60F v7.2.8,build1639,240228 (GA.M)", "fortios", "7.2.8"},
		{"paloalto", "Palo Alto Networks PA-220 series firewall", "pan-os", ""},
		{"huawei", "Huawei Versatile Routing Platform Software VRP (R) software, Version 8.180 (CE12800 V200R005C10SPC800)", "vrp", "8.180"},
		{"mikrotik", "RouterOS 7.14.2 (stable) on RB4011iGS+", "routeros", "7.14.2"},
		{"linux", "Linux leaf1 5.15.0-179-generic #199-Ubuntu SMP x86_64", "linux_kernel", "5.15.0-179-generic"},
		{"net-snmp", "Linux leaf1 5.15.0-179-generic #199-Ubuntu SMP x86_64", "linux_kernel", "5.15.0-179-generic"},
	}
	for _, c := range cases {
		got, ok := reg.ResolveOS(c.vendor, c.descr)
		if !ok {
			t.Errorf("ResolveOS(%q, …) not resolved", c.vendor)
			continue
		}
		if got.Product != c.product || got.Version != c.version {
			t.Errorf("ResolveOS(%q, %q) = {%q %q}, want {%q %q}", c.vendor, c.descr, got.Product, got.Version, c.product, c.version)
		}
	}
	// A Cisco sysDescr naming no family: the version is still read, the product
	// is honestly blank — never guessed at "ios".
	got, ok := reg.ResolveOS("cisco", "Cisco Systems appliance, Version 1.2")
	if !ok || got.Product != "" || got.Version != "1.2" {
		t.Errorf("family-less Cisco sysDescr = %+v ok=%v, want {\"\" \"1.2\"}", got, ok)
	}
}

// TestUnknownVendorIsHonest — the load-bearing honesty rule. An unknown vendor
// must resolve to NOTHING at every entry point: no default profile, no
// nearest-neighbour vendor, no partially filled OSIdentity.
func TestUnknownVendorIsHonest(t *testing.T) {
	reg := Default()
	for _, vendor := range []string{"acme", "", "Cisco", "CISCO", "  cisco  ", "sonicwall"} {
		if id, ok := reg.ResolveOS(vendor, "AcmeOS Version 1.2.3"); ok {
			t.Errorf("ResolveOS(%q) resolved to %+v — unknown/unnormalized vendors must not resolve", vendor, id)
		}
		if p, ok := reg.ProfileForOS(vendor, "AcmeOS Version 1.2.3"); ok {
			t.Errorf("ProfileForOS(%q) resolved to %q", vendor, p.ID)
		}
	}
	// A vendor we DO know but with no matching platform: still no profile.
	if p, ok := reg.ProfileForOS("cisco", "Cisco Systems appliance, Version 1.2"); ok {
		t.Errorf("ProfileForOS resolved a family-less Cisco sysDescr to %q", p.ID)
	}
	// Detection-only vendors claim identity and nothing else.
	if _, ok := reg.ResolveOS("extreme", "Extreme Networks EXOS version 31.7"); ok {
		t.Error("a detection-only vendor must not resolve an OS product")
	}
	if _, err := reg.AdvisoryFor("acme", "widgetos"); !errors.Is(err, ErrNotFound) {
		t.Errorf("AdvisoryFor(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := reg.ThreatFor("acme", "widgetos"); !errors.Is(err, ErrNotFound) {
		t.Errorf("ThreatFor(unknown) = %v, want ErrNotFound", err)
	}
	if _, err := reg.CaptureFor("acme/widgetos"); !errors.Is(err, ErrNotFound) {
		t.Errorf("CaptureFor(unknown) = %v, want ErrNotFound", err)
	}
	if _, ok := reg.HardeningBindingForPlatform("Acme WidgetOS"); ok {
		t.Error("an unknown platform must not bind a hardening dialect")
	}
	if _, ok := reg.VRFDisplayTerm("acme"); ok {
		t.Error("an unknown vendor must not claim a dialect")
	}
}

func TestProfileForOSAndPlatformText(t *testing.T) {
	reg := Default()
	p, ok := reg.ProfileForOS("cisco", "Cisco IOS XR Software (NCS-5500), Version 7.5.2")
	if !ok || p.ID != "cisco/ios_xr" {
		t.Fatalf("ProfileForOS = %q ok=%v, want cisco/ios_xr", p.ID, ok)
	}
	p, ok = reg.ProfileForPlatformText("Nokia SR Linux")
	if !ok || p.Vendor != "nokia" {
		t.Fatalf("ProfileForPlatformText(Nokia SR Linux) = %q ok=%v", p.ID, ok)
	}
	if _, ok := reg.ProfileForPlatformText(""); ok {
		t.Error("empty platform text must not resolve")
	}
}

func TestConsumerBindings(t *testing.T) {
	reg := Default()
	// hardening
	if b, ok := reg.HardeningBindingForPlatform("Cisco IOS-XE 17.9"); !ok || b != "cisco-iosxe" {
		t.Errorf("hardening binding = %q ok=%v", b, ok)
	}
	if d, ok := reg.HardeningDisplay("nokia"); !ok || d != "Nokia SR OS" {
		t.Errorf("hardening display = %q ok=%v", d, ok)
	}
	// Arista has no hardening bindings in the catalog: the profile must say so
	// rather than borrow Cisco's dialect.
	if b, ok := reg.HardeningBindingForPlatform("Arista EOS 4.33"); ok {
		t.Errorf("Arista bound to hardening dialect %q — the catalog ships no Arista bindings", b)
	}
	// advisory
	ab, err := reg.AdvisoryFor("cisco", "ios_xe")
	if err != nil {
		t.Fatalf("AdvisoryFor: %v", err)
	}
	if ab.Provider == "" || len(ab.ProductIDs) == 0 {
		t.Errorf("advisory binding incomplete: %+v", ab)
	}
	// threat
	tb, err := reg.ThreatFor("cisco", "ios")
	if err != nil {
		t.Fatalf("ThreatFor: %v", err)
	}
	if len(tb.LogRuleIDs) == 0 {
		t.Error("cisco/ios declares no assessed log rules")
	}
	if tb, err := reg.ThreatFor("juniper", "junos"); err != nil || len(tb.LogRuleIDs) != 0 {
		t.Errorf("juniper/junos threat coverage = %+v err=%v, want an empty (unassessed) claim", tb, err)
	}
	// capture
	cap, err := reg.CaptureFor("cisco/ios_xe")
	if err != nil {
		t.Fatalf("CaptureFor: %v", err)
	}
	if cap.RunningConfigCmd != "show running-config" || cap.ShowVersionCmd != "show version" ||
		len(cap.PagerOffCmds) == 0 || cap.PromptRegex == "" {
		t.Errorf("cisco/ios_xe capture incomplete: %+v", cap)
	}
	// A platform whose capture commands are not established says so with empty
	// fields rather than a guessed command.
	srl, err := reg.CaptureFor("nokia/srlinux")
	if err != nil {
		t.Fatalf("CaptureFor srlinux: %v", err)
	}
	if srl.RunningConfigCmd != "info from running" || len(srl.PagerOffCmds) != 0 {
		t.Errorf("nokia/srlinux capture = %+v", srl)
	}
}

// TestAccessorsReturnCopies — the registry is shared, immutable reference data;
// a caller must not be able to mutate it through a returned slice.
func TestAccessorsReturnCopies(t *testing.T) {
	reg := Default()
	ids := reg.IDs()
	if len(ids) == 0 {
		t.Fatal("no ids")
	}
	ids[0] = "MUTATED"
	if reg.IDs()[0] == "MUTATED" {
		t.Fatal("IDs() must return a copy")
	}
	p, _ := reg.Lookup("cisco/ios_xe")
	if len(p.Detection.PlatformContains) > 0 {
		p.Detection.PlatformContains[0] = "MUTATED"
		q, _ := reg.Lookup("cisco/ios_xe")
		if q.Detection.PlatformContains[0] == "MUTATED" {
			t.Fatal("Lookup must not hand out mutable internal slices")
		}
	}
}
