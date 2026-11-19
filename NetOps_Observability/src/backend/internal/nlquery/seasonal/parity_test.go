// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package seasonal

// parity_test.go — the Go half of the seasonal-baseline parity (tracker 337
// N-H6 step 4). The correlation engine's shadow seasonal score
// (src/correlation/seasonal_shadow.py) is a twin of this package; both test
// suites reproduce every case of testdata/parity.json exactly, so Iris's
// seasonal answers and the engine's shadow can never disagree about a tier,
// a centre, a scale or a z.

import (
	"encoding/json"
	"math"
	"os"
	"testing"
	"time"
)

type parityRef struct {
	OffsetHours int     `json:"offset_hours"`
	Value       float64 `json:"value"`
	Present     bool    `json:"present"`
	Excluded    bool    `json:"excluded"`
}

type parityCase struct {
	Name   string      `json:"name"`
	Unit   string      `json:"unit"`
	Floor  float64     `json:"floor"`
	X      float64     `json:"x"`
	Weekly []parityRef `json:"weekly"`
	Daily  []parityRef `json:"daily"`
	Want   struct {
		Tier        string   `json:"tier"`
		Centre      float64  `json:"centre"`
		Scale       float64  `json:"scale"`
		Used        int      `json:"used"`
		Considered  int      `json:"considered"`
		Excluded    int      `json:"excluded"`
		HistoryDays int      `json:"history_days"`
		Z           *float64 `json:"z"`
	} `json:"want"`
}

func TestParityWithTheEngineShadow(t *testing.T) {
	raw, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fx struct {
		Now   string       `json:"now"`
		Cases []parityCase `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fx); err != nil {
		t.Fatal(err)
	}
	now, err := time.Parse(time.RFC3339, fx.Now)
	if err != nil {
		t.Fatal(err)
	}
	if len(fx.Cases) < 5 {
		t.Fatalf("parity fixture has %d cases — it rotted", len(fx.Cases))
	}
	refs := func(rs []parityRef) []Ref {
		out := make([]Ref, len(rs))
		for i, r := range rs {
			out[i] = Ref{At: now.Add(-time.Duration(r.OffsetHours) * time.Hour), Value: r.Value, Present: r.Present, Excluded: r.Excluded}
		}
		return out
	}
	near := func(a, b float64) bool { return math.Abs(a-b) < 1e-9 }
	for _, c := range fx.Cases {
		if got := UnitFloor(c.Unit); !near(got, c.Floor) {
			t.Errorf("%s: UnitFloor(%q) = %v, fixture %v", c.Name, c.Unit, got, c.Floor)
		}
		p := Fit(now, refs(c.Weekly), refs(c.Daily), c.Floor)
		w := c.Want
		if string(p.Tier) != w.Tier || !near(p.Centre, w.Centre) || !near(p.Scale, w.Scale) ||
			p.Used != w.Used || p.Considered != w.Considered || p.Excluded != w.Excluded || p.HistoryDays != w.HistoryDays {
			t.Errorf("%s: Go fit %+v, fixture %+v", c.Name, p, w)
		}
		z, ok := p.Z(c.X)
		switch {
		case w.Z == nil && ok:
			t.Errorf("%s: Go gives z=%v, fixture says no z", c.Name, z)
		case w.Z != nil && (!ok || !near(z, *w.Z)):
			t.Errorf("%s: Go z=%v ok=%v, fixture %v", c.Name, z, ok, *w.Z)
		}
	}
}
