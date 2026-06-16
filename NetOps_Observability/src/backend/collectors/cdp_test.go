package collectors

import "testing"

// cdpCacheTable is indexed by "ifIndex.deviceIndex"; the LOCAL port comes from the
// FIRST arc (vs LLDP's middle arc). Getting it wrong mislabels every local port.
func TestCDPLocalIfIndex(t *testing.T) {
	cases := map[string]string{
		"10.1": "10",
		"3.2":  "3",
		"7":    "", // malformed: only one arc
		"":     "",
	}
	for suffix, want := range cases {
		if got := cdpLocalIfIndex(suffix); got != want {
			t.Errorf("cdpLocalIfIndex(%q) = %q, want %q", suffix, got, want)
		}
	}
}

// cdpCacheAddress is usually a 4-octet IPv4 (addressType ip = 1).
func TestCDPAddr(t *testing.T) {
	ip := berVal{raw: []byte{10, 0, 0, 5}}
	if got := cdpAddr(ip, berVal{raw: []byte{1}}); got != "10.0.0.5" {
		t.Errorf("ip addr = %q, want 10.0.0.5", got)
	}
	// type unset but 4 octets → still IPv4 (lenient)
	if got := cdpAddr(ip, berVal{}); got != "10.0.0.5" {
		t.Errorf("untyped 4-octet addr = %q, want 10.0.0.5", got)
	}
	if got := cdpAddr(berVal{}, berVal{raw: []byte{1}}); got != "" {
		t.Errorf("empty addr = %q, want empty", got)
	}
}

// CDP often appends the DNS domain to the device-id; we trim it to match
// inventory hostnames, but never truncate an IP-like first label.
func TestCDPTrimDomain(t *testing.T) {
	cases := map[string]string{
		"spine1.lab.example.com": "spine1",
		"wan-r2":                 "wan-r2",
		"10.0.0.1":               "10.0.0.1", // IP-like → untouched
		"leaf1.local":            "leaf1",
	}
	for in, want := range cases {
		if got := cdpTrimDomain(in); got != want {
			t.Errorf("cdpTrimDomain(%q) = %q, want %q", in, got, want)
		}
	}
}
