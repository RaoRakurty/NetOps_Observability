// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package appid

import "testing"

func TestScoringPolicyBaseWeights(t *testing.T) {
	p := DefaultScoringPolicy()
	cases := map[Source]int{
		SrcOperator: 100, SrcSoT: 100, SrcCloudTag: 100,
		SrcNGFWAppID: 95, SrcIPFIXAppID: 90, SrcWorkload: 80,
		SrcCloudGraph: 75, SrcDNS: 65, SrcSNI: 65,
		SrcIPCatalog: 45, SrcASN: 25, SrcPort: 10,
	}
	for s, want := range cases {
		if got := p.base(s); got != want {
			t.Errorf("base(%s)=%d want %d", s, got, want)
		}
	}
	if p.base(Source("nonexistent")) != 0 {
		t.Error("unknown source must score 0")
	}
	if p.Version == "" {
		t.Error("scoring policy must be versioned (replay)")
	}
}

func TestBandForScoreBoundaries(t *testing.T) {
	cases := []struct {
		score int
		band  ConfidenceBand
	}{
		{100, BandAuthoritative}, {95, BandAuthoritative}, {94, BandHigh}, {75, BandHigh},
		{74, BandMedium}, {50, BandMedium}, {49, BandLow}, {20, BandLow}, {19, BandUnresolved}, {0, BandUnresolved},
	}
	for _, c := range cases {
		if got := BandForScore(c.score); got != c.band {
			t.Errorf("BandForScore(%d)=%s want %s", c.score, got, c.band)
		}
	}
}

func TestClampAndBandCap(t *testing.T) {
	if clampScore(150) != 100 || clampScore(-5) != 0 || clampScore(42) != 42 {
		t.Error("clampScore wrong")
	}
	if bandCap(BandLow) != 49 || bandCap(BandMedium) != 74 || bandCap(BandHigh) != 94 || bandCap(BandAuthoritative) != 100 {
		t.Error("bandCap wrong")
	}
}
