package hardening

import "testing"

func TestVendorFromPlatform(t *testing.T) {
	cases := map[string]Vendor{
		"Cisco IOS-XE 17.9": VendorCiscoIOSXE,
		"cisco ios-xr 7.x":  VendorCiscoIOSXE,
		"Catalyst NX-OS":    VendorCiscoIOSXE,
		"Juniper JunOS 21":  VendorJuniper,
		"junos":             VendorJuniper,
		"Nokia SR OS 22":    VendorNokia,
		// SR Linux is its OWN dialect: it shares Nokia's name with SR OS and
		// none of its configuration grammar (dialect_fabric.go).
		"Nokia SR Linux":  VendorSRLinux,
		"TiMOS-B":         VendorNokia,
		"Arista EOS 4.36": VendorArista,
		"Acme WidgetOS":   VendorUnknown,
		"":                VendorUnknown,
	}
	for platform, want := range cases {
		if got := VendorFromPlatform(platform); got != want {
			t.Errorf("VendorFromPlatform(%q) = %q, want %q", platform, got, want)
		}
	}
}

func TestIOSStanzaParsing(t *testing.T) {
	cfg := NewConfig(VendorCiscoIOSXE, `hostname r1
line vty 0 4
 transport input ssh
 access-class MGMT-IN in
line con 0
 exec-timeout 5 0
interface Gi0/0
 ip address 10.0.0.1 255.255.255.0
`)
	sts := cfg.iosStanzas(reIOSVTYHeader)
	if len(sts) != 1 {
		t.Fatalf("expected 1 vty stanza, got %d", len(sts))
	}
	if !sts[0].childHas(reIOSAccessClassIn) {
		t.Error("vty stanza should have an inbound access-class child")
	}
	if !sts[0].childHas(reIOSTransIn) {
		t.Error("vty stanza should have a transport input child")
	}
	// A stanza's children must stop at the next column-0 line (no bleed into
	// `line con 0` / `interface`).
	for _, ch := range sts[0].children {
		if ch == "exec-timeout 5 0" || ch == "ip address 10.0.0.1 255.255.255.0" {
			t.Errorf("stanza child bled past its block: %q", ch)
		}
	}
}

func TestConfigLinesAreCopied(t *testing.T) {
	cfg := NewConfig(VendorCiscoIOSXE, "a\nb\n")
	ls := cfg.Lines()
	ls[0] = "MUTATED"
	if cfg.Lines()[0] == "MUTATED" {
		t.Fatal("Config.Lines must return a copy — internal state was mutated")
	}
}
