package rca

import (
	"testing"
	"time"
)

// The wire-format contract (docs/design/ch-time-wire-format.md): parseChTS
// accepts BOTH the RFC 3339 form chISO emits and the legacy zone-less
// ClickHouse rendering, so mixed fleets during rollout stay readable. The
// integrator's parseCHTime carries the same contract in ch_time_wire_test.go.
func TestParseChTSAcceptsBothWireFormats(t *testing.T) {
	want := time.Date(2026, 7, 16, 21, 56, 3, 562_000_000, time.UTC)
	for _, s := range []string{
		"2026-07-16T21:56:03.562Z", // new wire format (chISO)
		"2026-07-16 21:56:03.562",  // legacy toString(DateTime64), UTC by contract
	} {
		if got, ok := parseChTS(s); !ok || !got.Equal(want) {
			t.Errorf("parseChTS(%q) = %v ok=%v, want %v", s, got, ok, want)
		}
	}
	wantSec := want.Truncate(time.Second)
	for _, s := range []string{"2026-07-16T21:56:03Z", "2026-07-16 21:56:03"} {
		if got, ok := parseChTS(s); !ok || !got.Equal(wantSec) {
			t.Errorf("parseChTS(%q) = %v ok=%v, want %v", s, got, ok, wantSec)
		}
	}
	if _, ok := parseChTS("not a time"); ok {
		t.Error("garbage must not parse")
	}
}
