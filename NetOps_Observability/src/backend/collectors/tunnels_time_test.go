package collectors

import (
	"encoding/json"
	"math"
	"testing"
	"time"
)

// Every tunnel row must carry the poll instant as fractional epoch seconds —
// the timezone-unambiguous wire form ClickHouse accepts for DateTime64(3).
// Before this field existed, rows were stamped by the ClickHouse server's
// insert clock (DEFAULT now64(3)) and the real measurement time was lost.
func TestEpochSeconds(t *testing.T) {
	cases := []struct {
		name string
		in   time.Time
		want float64
	}{
		{"utc instant", time.Date(2026, 7, 17, 6, 30, 0, 250e6, time.UTC), 1784269800.250},
		// A non-UTC wall clock must produce the SAME epoch value — the
		// epoch is zone-independent by definition.
		{"IST wall clock, same instant", time.Date(2026, 7, 17, 12, 0, 0, 250e6, time.FixedZone("IST", 5*3600+1800)), 1784269800.250},
		{"Nepal +05:45, same instant", time.Date(2026, 7, 17, 12, 15, 0, 250e6, time.FixedZone("NPT", 5*3600+2700)), 1784269800.250},
		// Dec 31 → Jan 1 UTC rollover: a device at UTC-6 still in Dec 31
		// local time maps to Jan 1 UTC. Round-trip must not lose the year.
		{"year rollover at UTC-6", time.Date(2026, 12, 31, 23, 30, 0, 0, time.FixedZone("CST", -6*3600)), 1798781400.000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := epochSeconds(c.in)
			if math.Abs(got-c.want) > 0.0005 {
				t.Fatalf("epochSeconds(%v) = %.3f, want %.3f", c.in, got, c.want)
			}
		})
	}
}

func TestTunnelRowCarriesTs(t *testing.T) {
	at := time.Date(2026, 7, 17, 6, 30, 0, 0, time.UTC)
	row := tunnelRow{Ts: epochSeconds(at), ID: "r1/Tunnel0", Type: "gre", Status: "up"}
	j, err := json.Marshal(row)
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(j, &back); err != nil {
		t.Fatal(err)
	}
	ts, ok := back["ts"].(float64)
	if !ok {
		t.Fatalf("marshaled row missing numeric ts: %s", j)
	}
	if math.Abs(ts-1784269800) > 0.0005 {
		t.Fatalf("ts = %.3f, want 1784269800.000", ts)
	}
}
