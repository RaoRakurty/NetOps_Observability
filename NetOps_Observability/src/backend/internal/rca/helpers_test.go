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

// ParseFmtUTC must be the exact inverse of FmtUTC: the deterministic document
// reuse path turns a recorded GeneratedAt stamp back into the build clock, and
// any loss in the round-trip re-renders different bytes than the revision it
// claims to reproduce. FmtUTC is second-granular, so the contract holds for
// second-truncated clocks (which reportNow guarantees).
func TestParseFmtUTCRoundTripsFmtUTC(t *testing.T) {
	for _, want := range []time.Time{
		time.Date(2026, 7, 12, 20, 0, 0, 0, time.UTC),
		time.Date(2026, 12, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
	} {
		got, err := ParseFmtUTC(FmtUTC(want))
		if err != nil || !got.Equal(want) {
			t.Errorf("ParseFmtUTC(FmtUTC(%v)) = %v err=%v, want lossless round-trip", want, got, err)
		}
		if got.Location() != time.UTC {
			t.Errorf("parsed instant must be UTC, got %v", got.Location())
		}
	}
	for _, bad := range []string{"", "2026-07-12 20:00:00", "2026-07-12T20:00:00Z", "garbage UTC"} {
		if _, err := ParseFmtUTC(bad); err == nil {
			t.Errorf("ParseFmtUTC(%q) must refuse a non-FmtUTC stamp", bad)
		}
	}
}
