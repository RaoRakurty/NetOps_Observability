package portintel

// threshold.go — vendor-aware threshold policy with fallback heuristics (#94 P4,
// owner spec). A ThresholdPolicy carries the warn/alarm boundaries the scorer
// debits against. DefaultPolicy() is the vendor-neutral fallback; a vendor
// adapter (P3b(2)) can supply module-specific values (e.g. a coherent optic's
// min-rx-OSNR from its mode descriptor) that override the defaults per port.

// ThresholdPolicy is the full set of boundaries (owner field list). All margins
// are "headroom before trouble" in the field's unit; a negative margin means the
// reading is already past the boundary.
type ThresholdPolicy struct {
	RxMarginLowWarnDB        float64 // dB of RX headroom below which we warn
	TxMarginLowWarnDB        float64
	TemperatureMarginHighWarnC float64 // C below the high-warn threshold
	VoltageMarginThresholdV  float64
	BiasGrowthRatio          float64 // TX bias / baseline that flags aging
	PAM4PreFECBERWatch       float64
	PAM4PreFECBERDegraded    float64
	PAM4PreFECBERCritical    float64
	PostFECBERWatch          float64
	PostFECBERDegraded       float64
	PostFECBERCritical       float64
	CorrectedFECRateVsBaseline float64 // multiple of baseline that flags masking
	UCWordsPolicyPerMin      float64 // uncorrectable words/min tolerated (>0 = degraded)
	LaneDivergenceRatio      float64 // worst-lane / median that flags divergence
	FlapRatePerHour          float64 // link flaps/hour that flags instability
	CoherentOSNRMarginDB     float64 // dB above min-rx-OSNR required
	CoherentInputPowerMarginDB float64
	FiberPathBudgetHeadroomDB float64
}

// DefaultPolicy is the vendor-neutral fallback (values chosen from common
// SFF-8472 / OpenZR+ operating margins; a vendor adapter refines per module).
func DefaultPolicy() ThresholdPolicy {
	return ThresholdPolicy{
		RxMarginLowWarnDB:          3.0,
		TxMarginLowWarnDB:          3.0,
		TemperatureMarginHighWarnC: 5.0,
		VoltageMarginThresholdV:    0.15,
		BiasGrowthRatio:            1.5,
		PAM4PreFECBERWatch:         1e-5,
		PAM4PreFECBERDegraded:      1e-4,
		PAM4PreFECBERCritical:      2.4e-4, // ~KP4 FEC limit
		PostFECBERWatch:            1e-15,
		PostFECBERDegraded:         1e-12,
		PostFECBERCritical:         1e-9,
		CorrectedFECRateVsBaseline: 10.0,
		UCWordsPolicyPerMin:        1.0,
		LaneDivergenceRatio:        3.0,
		FlapRatePerHour:            3.0,
		CoherentOSNRMarginDB:       2.0,
		CoherentInputPowerMarginDB: 2.0,
		FiberPathBudgetHeadroomDB:  1.0,
	}
}
