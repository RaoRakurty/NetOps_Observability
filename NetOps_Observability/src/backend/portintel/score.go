package portintel

import "sort"

// score.go — the deterministic port-health scorer (#94 P4, owner weights). It
// starts every port at 100 and DEBITS each dimension by how far its evidence
// crosses the threshold policy, tracking which dimension took the biggest bite
// (the dominant issue). Pure + deterministic + fully unit-tested: the same
// PortEvidence always yields the same score, so it is replay-stable and the UI
// can explain "72 because FEC/BER debited 18 and DOM debited 6".
//
// Weights are the maximum debit a dimension can take (owner spec):
//   FEC/BER 18 · link-state/flap 15 · DOM absolute 12 · DOM margin 10 ·
//   lane symmetry/divergence 8 · PCS/deskew/fault 10 · inventory/config 8 ·
//   MAC/PHY corruption 8 · fiber-path consistency 6 · thermal/power 5.
// (Sum = 100: a maximally-broken port floors at 0.)

const (
	wFECBER    = 18
	wLinkFlap  = 15
	wDOMAbs    = 12
	wDOMMargin = 10
	wPCS       = 10
	wLane      = 8
	wInventory = 8
	wMACPHY    = 8
	wFiberPath = 6
	wThermal   = 5
)

// PortEvidence is the normalized input the scorer reasons over — the latest
// snapshot for one port. Zero values mean "no evidence" (no debit), so a port
// with only link state scores near 100.
type PortEvidence struct {
	// Link/flap
	OperDown     bool
	FlapsPerHour float64
	// DOM absolute alarms (already-crossed hard thresholds)
	RxPowerAlarm   bool
	TxPowerAlarm   bool
	// DOM margins (dB / units of headroom; <=0 means past the warn boundary)
	RxMarginDB float64
	TxMarginDB float64
	// FEC/BER
	PreFECBER  float64
	PostFECBER float64
	UCWordsPerMin float64
	FECCorrectedVsBaseline float64 // multiple of baseline (0 = unknown)
	// Lanes
	LaneRxDBM []float64 // per-lane RX; divergence computed from the spread
	// PCS/faults
	PCSDeskewFault bool
	LocalFault     bool
	RemoteFault    bool
	// Inventory/config
	Unsupported bool
	// MAC/PHY corruption
	CRCErrRate float64 // errors/sec (>0 debits)
	// Fiber path
	FiberPathConflict bool
	// Thermal/power
	TempMarginC   float64 // C of headroom below high-warn (<=0 debits)
	VoltageOutOfBand bool
}

// HealthResult is the scorer's output → port_health_current.
type HealthResult struct {
	Score          int            // 0-100
	State          string         // ok | watch | degraded | critical
	DominantIssue  string         // the dimension that took the biggest debit
	Contributions  map[string]int // dimension → debit (for "why 72")
}

// Score computes the deterministic port health. clampDebit keeps each dimension
// within its weight; the dominant issue is the single largest debit.
func Score(ev PortEvidence, pol ThresholdPolicy) HealthResult {
	contrib := map[string]int{}
	debit := func(dim string, amount, weight int) {
		if amount <= 0 {
			return
		}
		if amount > weight {
			amount = weight
		}
		contrib[dim] = amount
	}

	// FEC/BER (heaviest, 18): critical pre/post-FEC or uncorrectable words → full.
	fec := 0
	switch {
	case ev.PostFECBER >= pol.PostFECBERCritical && ev.PostFECBER > 0,
		ev.PreFECBER >= pol.PAM4PreFECBERCritical && ev.PreFECBER > 0,
		ev.UCWordsPerMin >= pol.UCWordsPolicyPerMin && ev.UCWordsPerMin > 0:
		fec = wFECBER
	case ev.PostFECBER >= pol.PostFECBERDegraded && ev.PostFECBER > 0,
		ev.PreFECBER >= pol.PAM4PreFECBERDegraded && ev.PreFECBER > 0,
		ev.FECCorrectedVsBaseline >= pol.CorrectedFECRateVsBaseline && ev.FECCorrectedVsBaseline > 0:
		fec = wFECBER * 2 / 3
	case ev.PreFECBER >= pol.PAM4PreFECBERWatch && ev.PreFECBER > 0,
		ev.PostFECBER >= pol.PostFECBERWatch && ev.PostFECBER > 0:
		fec = wFECBER / 3
	}
	debit("fec_ber", fec, wFECBER)

	// Link state / flap (15): oper-down is the full debit; flapping scales.
	link := 0
	if ev.OperDown {
		link = wLinkFlap
	} else if pol.FlapRatePerHour > 0 && ev.FlapsPerHour >= pol.FlapRatePerHour {
		link = wLinkFlap * 2 / 3
	} else if ev.FlapsPerHour > 0 {
		link = wLinkFlap / 3
	}
	debit("link_flap", link, wLinkFlap)

	// DOM absolute alarms (12).
	domAbs := 0
	if ev.RxPowerAlarm {
		domAbs += wDOMAbs
	}
	if ev.TxPowerAlarm {
		domAbs += wDOMAbs / 2
	}
	debit("dom_absolute", domAbs, wDOMAbs)

	// DOM margin (10): negative/low RX or TX headroom.
	domMargin := 0
	if ev.RxMarginDB <= 0 {
		domMargin += wDOMMargin
	} else if ev.RxMarginDB < pol.RxMarginLowWarnDB {
		domMargin += wDOMMargin / 2
	}
	if ev.TxMarginDB <= 0 {
		domMargin += wDOMMargin / 2
	}
	debit("dom_margin", domMargin, wDOMMargin)

	// PCS/deskew/fault (10).
	pcs := 0
	if ev.PCSDeskewFault {
		pcs += wPCS
	}
	if ev.LocalFault || ev.RemoteFault {
		pcs += wPCS / 2
	}
	debit("pcs_fault", pcs, wPCS)

	// Lane symmetry/divergence (8): worst-lane vs median RX spread.
	debit("lane_divergence", laneDivergenceDebit(ev.LaneRxDBM, pol.LaneDivergenceRatio), wLane)

	// Inventory/config (8): unsupported transceiver.
	if ev.Unsupported {
		debit("inventory", wInventory, wInventory)
	}

	// MAC/PHY corruption (8): CRC error rate.
	if ev.CRCErrRate > 0 {
		amt := wMACPHY / 2
		if ev.CRCErrRate >= 1.0 {
			amt = wMACPHY
		}
		debit("mac_phy", amt, wMACPHY)
	}

	// Fiber-path consistency (6).
	if ev.FiberPathConflict {
		debit("fiber_path", wFiberPath, wFiberPath)
	}

	// Thermal/power (5).
	thermal := 0
	if ev.TempMarginC <= 0 {
		thermal += wThermal
	} else if ev.TempMarginC < pol.TemperatureMarginHighWarnC {
		thermal += wThermal / 2
	}
	if ev.VoltageOutOfBand {
		thermal += wThermal / 2
	}
	debit("thermal_power", thermal, wThermal)

	// Aggregate.
	total := 0
	dominant, dominantAmt := "", 0
	for dim, amt := range contrib {
		total += amt
		if amt > dominantAmt || (amt == dominantAmt && dim < dominant) {
			dominant, dominantAmt = dim, amt
		}
	}
	score := 100 - total
	if score < 0 {
		score = 0
	}
	return HealthResult{
		Score: score, State: stateFor(score), DominantIssue: dominant, Contributions: contrib,
	}
}

// laneDivergenceDebit debits when the worst lane's RX diverges from the median
// by more than the policy ratio (in dB terms). Needs >=2 lanes.
func laneDivergenceDebit(laneRx []float64, ratio float64) int {
	if len(laneRx) < 2 || ratio <= 0 {
		return 0
	}
	sorted := append([]float64(nil), laneRx...)
	sort.Float64s(sorted)
	median := sorted[len(sorted)/2]
	worst := sorted[0] // lowest RX = worst
	// dB spread from median to worst; a wide spread = divergence.
	spread := median - worst
	switch {
	case spread >= 3.0*ratio:
		return wLane
	case spread >= ratio:
		return wLane / 2
	}
	return 0
}

func stateFor(score int) string {
	switch {
	case score >= 90:
		return "ok"
	case score >= 70:
		return "watch"
	case score >= 40:
		return "degraded"
	default:
		return "critical"
	}
}
