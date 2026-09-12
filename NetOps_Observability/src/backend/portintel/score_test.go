// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package portintel

import "testing"

func TestScoreCleanPort(t *testing.T) {
	r := Score(PortEvidence{RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if r.Score != 100 || r.State != "ok" || r.DominantIssue != "" {
		t.Fatalf("clean port must score 100/ok: %+v", r)
	}
}

func TestScoreOperDownIsLinkDebit(t *testing.T) {
	r := Score(PortEvidence{OperDown: true, RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if r.Contributions["link_flap"] != wLinkFlap || r.DominantIssue != "link_flap" {
		t.Fatalf("oper-down should take the full link debit: %+v", r)
	}
	if r.Score != 100-wLinkFlap {
		t.Fatalf("score should be 100-15=85, got %d", r.Score)
	}
}

func TestScoreFECBERDominates(t *testing.T) {
	// Uncorrectable words = critical FEC = the heaviest single debit.
	r := Score(PortEvidence{UCWordsPerMin: 5, RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if r.Contributions["fec_ber"] != wFECBER || r.DominantIssue != "fec_ber" {
		t.Fatalf("uncorrectable words should max FEC/BER: %+v", r)
	}
}

func TestScoreDeterministicAndReplayStable(t *testing.T) {
	ev := PortEvidence{PreFECBER: 2e-4, RxMarginDB: 1, PCSDeskewFault: true, TempMarginC: 10, TxMarginDB: 5}
	a := Score(ev, DefaultPolicy())
	b := Score(ev, DefaultPolicy())
	if a.Score != b.Score || a.DominantIssue != b.DominantIssue {
		t.Fatalf("scorer must be deterministic: %+v vs %+v", a, b)
	}
}

func TestScoreLaneDivergence(t *testing.T) {
	// One lane far below the others → divergence debit.
	r := Score(PortEvidence{LaneRxDBM: []float64{-3, -3.2, -3.1, -15}, RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if r.Contributions["lane_divergence"] == 0 {
		t.Fatalf("a lane 12 dB below its peers must debit divergence: %+v", r)
	}
	// Tight lanes → no divergence debit.
	ok := Score(PortEvidence{LaneRxDBM: []float64{-3, -3.1, -3.05, -3.2}, RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if ok.Contributions["lane_divergence"] != 0 {
		t.Fatalf("tight lanes must not debit: %+v", ok)
	}
}

func TestScoreStatesAndFloor(t *testing.T) {
	// Pile on every dimension → floors at 0/critical, never negative.
	worst := PortEvidence{
		OperDown: true, RxPowerAlarm: true, TxPowerAlarm: true, RxMarginDB: -1, TxMarginDB: -1,
		PostFECBER: 1e-6, UCWordsPerMin: 10, PCSDeskewFault: true, LocalFault: true,
		Unsupported: true, CRCErrRate: 5, FiberPathConflict: true, TempMarginC: -1, VoltageOutOfBand: true,
		LaneRxDBM: []float64{-3, -20},
	}
	r := Score(worst, DefaultPolicy())
	if r.Score != 0 || r.State != "critical" {
		t.Fatalf("maximally broken port must floor at 0/critical: %+v", r)
	}
	// A single mid debit lands in watch.
	w := Score(PortEvidence{FlapsPerHour: 5, RxMarginDB: 5, TxMarginDB: 5, TempMarginC: 10}, DefaultPolicy())
	if w.State != "watch" && w.State != "ok" {
		t.Fatalf("moderate flap should be ok/watch, got %s (%d)", w.State, w.Score)
	}
}
