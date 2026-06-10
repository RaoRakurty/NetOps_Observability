package main

import "testing"

func TestNetboxDirectionNormalize(t *testing.T) {
	cases := map[string]string{
		"":      "write", // default: devices → NetBox only
		"write": "write",
		"WRITE": "write",
		" read": "read",
		"Read":  "read",
		"both":  "both",
		"junk":  "write", // unknown falls back to the safe default
	}
	for in, want := range cases {
		if got := netboxDirection(netboxConfig{Direction: in}); got != want {
			t.Errorf("netboxDirection(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetboxDirectionGates(t *testing.T) {
	// write (default): writes up, never reads back.
	w := netboxConfig{}
	if !netboxWritesDevices(w) || netboxReadsDevices(w) {
		t.Errorf("write mode: want writes=true reads=false, got writes=%v reads=%v", netboxWritesDevices(w), netboxReadsDevices(w))
	}
	// read: reads only.
	r := netboxConfig{Direction: "read"}
	if netboxWritesDevices(r) || !netboxReadsDevices(r) {
		t.Errorf("read mode gates wrong")
	}
	// both: reads and writes.
	b := netboxConfig{Direction: "both"}
	if !netboxWritesDevices(b) || !netboxReadsDevices(b) {
		t.Errorf("both mode gates wrong")
	}
}
