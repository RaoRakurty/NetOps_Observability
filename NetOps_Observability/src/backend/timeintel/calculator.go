package timeintel

import (
	"strings"
	"time"
)

// metricDef declares a phase as a (start,end) pair of lifecycle events. impactFallback
// metrics may fall back to first_signal for a missing impact_started — an INFERENCE,
// flagged is_inferred (the earliest customer-impacting signal stands in for the
// unobservable true impact onset).
type metricDef struct {
	name           MetricName
	start, end     EventType
	impactFallback bool // start defaults to first_signal (inferred) when impact_started is absent
}

// metricDefs encodes the canonical formulas (owner spec). Note the deliberate
// distinctions the tests guard: TTA is ticket_created→acknowledged (NOT impact→ack);
// TTC is first_signal→correlation_completed; TTI is first_signal→root_domain_identified;
// recovery (→recovered) and resolution (→closed) are SEPARATE metrics.
var metricDefs = []metricDef{
	{MetricTTD, EvImpactStarted, EvDetected, true},
	{MetricTTC, EvFirstSignal, EvCorrelationCompleted, false},
	{MetricTTI, EvFirstSignal, EvRootDomainIdentified, false},
	{MetricTTE, EvFirstSignal, EvEvidenceReady, false},
	{MetricTTA, EvTicketCreated, EvAcknowledged, false},
	{MetricTTM, EvDetected, EvMitigated, false},
	{MetricTTRRecovery, EvImpactStarted, EvRecovered, true},
	{MetricTTRResolution, EvImpactStarted, EvClosed, true},
}

// ComputeTimeMetrics decomposes one incident's lifecycle into phase metrics. It is
// pure and idempotent: same lifecycle + version → identical output (CalculatedAt is
// the only time-varying field, taken from `now`). A missing start/end yields an
// INCOMPLETE metric naming the missing event — never a bogus zero. is_inferred and
// the minimum constituent confidence propagate from the constituent stamps.
func ComputeTimeMetrics(lc Lifecycle, version string, now time.Time) []TimeMetric {
	out := make([]TimeMetric, 0, len(metricDefs))
	for _, d := range metricDefs {
		m := TimeMetric{
			Name: d.name, StartEvent: d.start, EndEvent: d.end,
			Confidence: 1, CalculatedAt: now, CalculationVersion: version,
		}

		start, hasStart := lc[d.start]
		// impact_started inference: stand in the earliest customer-impacting signal,
		// flagged inferred. The metric's start_event stays impact_started (what it MEANS).
		if !hasStart && d.impactFallback {
			if fs, ok := lc[EvFirstSignal]; ok {
				start = EventStamp{At: fs.At, Source: SrcInferred, Confidence: fs.Confidence}
				hasStart = true
			}
		}
		end, hasEnd := lc[d.end]

		if !hasStart {
			m.MissingEvent = string(d.start)
			m.BlockedBy = "missing " + string(d.start)
			out = append(out, m)
			continue
		}
		if !hasEnd {
			m.MissingEvent = string(d.end)
			m.BlockedBy = "missing " + string(d.end)
			s := start.At
			m.StartedAt = &s
			out = append(out, m)
			continue
		}

		s, e := start.At, end.At
		m.Complete = true
		m.StartedAt = &s
		m.EndedAt = &e
		// Clamp negatives to 0: clock skew / out-of-order stamps must not produce a
		// negative "duration" (which would read as nonsense), but we keep the metric
		// complete and let confidence/source carry the uncertainty.
		dur := e.Sub(s)
		if dur < 0 {
			dur = 0
		}
		m.DurationMs = dur.Milliseconds()
		m.IsInferred = start.Source == SrcInferred || end.Source == SrcInferred
		m.Confidence = minConf(start.Confidence, end.Confidence)
		out = append(out, m)
	}
	return out
}

// DriverContext carries the RCA facts the time-loss driver needs beyond raw stamps:
// whether evidence is still gated, and who owns the implicated seam.
type DriverContext struct {
	EvidenceMissing bool   // RCA evidence policy unsatisfied (evidence_missing non-empty)
	Owner           string // customer | isp | cloud_provider | saas | carrier | sdwan_vendor | unknown | ...
}

// providerOwners are seam owners outside the customer's repair control — once the
// owner is identified as one of these and the service has not recovered, the
// remaining time is provider repair, not Correlix or operator delay.
func isProviderOwner(owner string) bool {
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case "isp", "carrier", "cloud_provider", "saas", "sdwan_vendor", "colo_provider", "wan_provider", "provider":
		return true
	}
	return false
}

// DeriveTimeLossDriver answers "where did the time go" for one incident, with two
// honest overrides ahead of the largest-segment rule:
//
//   - evidence_missing: if the RCA still lacks required cross-plane evidence, the
//     readiness delay dominates the narrative regardless of raw segment sizes.
//   - provider_repair: once the owner is a provider AND we are past owner_identified
//     but not yet recovered, the open time is provider repair (outside our control) —
//     only in that window, per the spec.
//
// Otherwise it picks the longest completed segment among the operator-controllable
// phases. Returns the driver and a precise, non-marketing explanation.
func DeriveTimeLossDriver(lc Lifecycle, ctx DriverContext) (TimeLossDriver, string) {
	_, recovered := lc[EvRecovered]
	_, ownerID := lc[EvOwnerIdentified]

	// Override 1: provider repair pending (owner identified, not recovered). Checked
	// before evidence so a confirmed provider-owned, evidence-complete incident reads
	// correctly; if evidence is ALSO missing the evidence gate wins (below) only when
	// the owner is not yet a provider.
	if ownerID && !recovered && isProviderOwner(ctx.Owner) {
		return DriverProviderRepair, "owner identified as " + strings.ToLower(ctx.Owner) + "; provider repair pending"
	}
	// Override 2: evidence readiness gated.
	if ctx.EvidenceMissing {
		return DriverEvidenceMissing, "evidence readiness delayed — required cross-plane telemetry missing"
	}

	// Largest controllable segment. Segments are incremental (not cumulative) so they
	// partition the elapsed time without double-counting.
	type seg struct {
		driver     TimeLossDriver
		start, end EventType
		label      string
	}
	segs := []seg{
		{DriverDetection, EvImpactStarted, EvDetected, "detection"},
		{DriverCorrelation, EvFirstSignal, EvRootDomainIdentified, "correlation & isolation"},
		{DriverOwnership, EvRootDomainIdentified, EvOwnerIdentified, "owner identification"},
		{DriverAcknowledgement, EvTicketCreated, EvAcknowledged, "acknowledgement"},
		{DriverMitigation, EvMitigationStarted, EvMitigated, "mitigation"},
	}
	best := DriverUnknown
	bestLabel := ""
	var bestDur time.Duration = -1
	for _, sg := range segs {
		st, ok1 := segStart(lc, sg.start)
		en, ok2 := lc[sg.end]
		if !ok1 || !ok2 {
			continue
		}
		d := en.At.Sub(st.At)
		if d < 0 {
			d = 0
		}
		if d > bestDur {
			bestDur = d
			best = sg.driver
			bestLabel = sg.label
		}
	}
	if best == DriverUnknown {
		return DriverUnknown, "insufficient lifecycle timestamps to attribute time"
	}
	return best, "most time was spent in " + bestLabel
}

// segStart resolves a segment start, applying the same impact_started→first_signal
// inference the metrics use so the detection segment is computable on inferred impact.
func segStart(lc Lifecycle, t EventType) (EventStamp, bool) {
	if s, ok := lc[t]; ok {
		return s, true
	}
	if t == EvImpactStarted {
		if fs, ok := lc[EvFirstSignal]; ok {
			return EventStamp{At: fs.At, Source: SrcInferred, Confidence: fs.Confidence}, true
		}
	}
	return EventStamp{}, false
}

func minConf(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
