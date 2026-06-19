package main

import "testing"

func TestNetboxDirectionNormalize(t *testing.T) {
	cases := map[string]string{
		"":      "none", // default: automatic sync OFF until opted in
		"none":  "none",
		"off":   "none", // alias
		"NONE":  "none",
		"write": "write",
		"WRITE": "write",
		" read": "read",
		"Read":  "read",
		"both":  "both",
		"junk":  "none", // unknown falls back to the safe default
	}
	for in, want := range cases {
		if got := netboxDirection(netboxConfig{Direction: in}); got != want {
			t.Errorf("netboxDirection(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetboxDirectionGates(t *testing.T) {
	// default (empty → none): no sync in either direction.
	def := netboxConfig{}
	if netboxWritesDevices(def) || netboxReadsDevices(def) {
		t.Errorf("default mode: want writes=false reads=false, got writes=%v reads=%v", netboxWritesDevices(def), netboxReadsDevices(def))
	}
	// write: writes up, never reads back.
	w := netboxConfig{Direction: "write"}
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
	// none: automatic sync off — neither reads nor writes.
	n := netboxConfig{Direction: "none"}
	if netboxWritesDevices(n) || netboxReadsDevices(n) {
		t.Errorf("none mode: want writes=false reads=false, got writes=%v reads=%v", netboxWritesDevices(n), netboxReadsDevices(n))
	}
}
