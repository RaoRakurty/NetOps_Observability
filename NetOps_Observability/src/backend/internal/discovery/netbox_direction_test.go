package discovery

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
		if got := NetboxDirection(NetboxConfig{Direction: in}); got != want {
			t.Errorf("NetboxDirection(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNetboxDirectionGates(t *testing.T) {
	// default (empty → none): no sync in either direction.
	def := NetboxConfig{}
	if NetboxWritesDevices(def) || NetboxReadsDevices(def) {
		t.Errorf("default mode: want writes=false reads=false, got writes=%v reads=%v", NetboxWritesDevices(def), NetboxReadsDevices(def))
	}
	// write: writes up, never reads back.
	w := NetboxConfig{Direction: "write"}
	if !NetboxWritesDevices(w) || NetboxReadsDevices(w) {
		t.Errorf("write mode: want writes=true reads=false, got writes=%v reads=%v", NetboxWritesDevices(w), NetboxReadsDevices(w))
	}
	// read: reads only.
	r := NetboxConfig{Direction: "read"}
	if NetboxWritesDevices(r) || !NetboxReadsDevices(r) {
		t.Errorf("read mode gates wrong")
	}
	// both: reads and writes.
	b := NetboxConfig{Direction: "both"}
	if !NetboxWritesDevices(b) || !NetboxReadsDevices(b) {
		t.Errorf("both mode gates wrong")
	}
	// none: automatic sync off — neither reads nor writes.
	n := NetboxConfig{Direction: "none"}
	if NetboxWritesDevices(n) || NetboxReadsDevices(n) {
		t.Errorf("none mode: want writes=false reads=false, got writes=%v reads=%v", NetboxWritesDevices(n), NetboxReadsDevices(n))
	}
}
