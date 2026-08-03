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
		m.Confidence = min(start.Confidence, end.Confidence)
		out = append(out, m)
	}
	return out
}

// DriverContext carries the RCA facts the bottleneck walk needs beyond raw stamps:
// whether evidence is still gated, who owns the implicated seam, and whether an ITSM
// workflow is connected (so we can say "workflow required" instead of inventing a
// ticket phase that can't progress).
type DriverContext struct {
	EvidenceMissing   bool   // RCA evidence policy unsatisfied (evidence_missing non-empty)
	Owner             string // customer | isp | cloud_provider | saas | carrier | sdwan_vendor | unknown | ...
	WorkflowConnected bool   // an ITSM workflow is linked (false today — #78 not wired)
}

// ownerLabel renders a seam owner for operator-facing copy (never lowercase raw).
func ownerLabel(owner string) string {
	switch strings.ToLower(strings.TrimSpace(owner)) {
	case "isp", "carrier", "wan_provider", "provider":
		return "ISP"
	case "sdwan_vendor":
		return "SD-WAN provider"
	case "cloud_provider":
		return "Cloud provider"
	case "saas":
		return "SaaS provider"
	case "app_team":
		return "Application team"
	case "netops", "network_ops", "colo_provider":
		return "Network"
	case "", "unknown":
		return "Owner"
	default:
		words := strings.Fields(strings.ReplaceAll(strings.ToLower(owner), "_", " "))
		for i, w := range words {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
		return strings.Join(words, " ")
	}
}

// DeriveCurrentBottleneck walks the incident lifecycle in order and returns the
// EARLIEST incomplete phase as the current bottleneck, with operator-facing copy.
// This is phase-consistent: provider_repair is reported ONLY once the seam is
// isolated, evidence is ready, the ticket is created AND acknowledged — never before
// (the contradiction the old largest-segment/override logic produced).
func DeriveCurrentBottleneck(lc Lifecycle, ctx DriverContext) (TimeLossDriver, string) {
	has := func(ev EventType) bool { _, ok := lc[ev]; return ok }
	provider := isProviderOwner(ctx.Owner)
	who := ownerLabel(ctx.Owner)

	if has(EvClosed) {
		return DriverResolved, "Incident resolved and closed."
	}
	if !has(EvFirstSignal) {
		return DriverUnknown, "Insufficient lifecycle data to locate the bottleneck."
	}
	if !has(EvRootDomainIdentified) {
		return DriverRootIsolation, "Root domain isolation pending — correlating evidence to localise the fault."
	}
	if !has(EvOwnerIdentified) {
		return DriverOwnerAssignment, "Root domain isolated; owner assignment pending."
	}
	if ctx.EvidenceMissing || !has(EvEvidenceReady) {
		if provider {
			return DriverEvidence, who + "-owned seam isolated; provider escalation is waiting on evidence readiness."
		}
		return DriverEvidence, "Root domain isolated; evidence bundle pending."
	}
	// Evidence is ready. Everything past here is ITSM/workflow — if no workflow is
	// connected, say so honestly rather than invent a ticket phase that can't move.
	if !has(EvTicketCreated) {
		if !ctx.WorkflowConnected {
			return DriverWorkflow, "Evidence bundle ready; ticket, recovery and closure require ServiceNow, Jira, PagerDuty or operator workflow evidence."
		}
		if provider {
			return DriverTicketCreation, "Evidence bundle is ready; waiting for provider ticket creation."
		}
		return DriverTicketCreation, "Evidence bundle is ready; waiting for ticket creation."
	}
	if !has(EvAcknowledged) {
		if provider {
			return DriverAcknowledgement, "Provider ticket created; waiting for carrier acknowledgement."
		}
		return DriverAcknowledgement, "Ticket created; waiting for owner acknowledgement."
	}
	if !has(EvMitigated) && !has(EvRecovered) {
		if provider {
			return DriverProviderRepair, who + "-owned seam isolated; the provider repair clock is now the limiting phase."
		}
		return DriverMitigation, "Acknowledged; mitigation in progress."
	}
	if !has(EvRecovered) {
		if !ctx.WorkflowConnected {
			return DriverWorkflow, "Mitigation recorded; a service recovery signal is required to confirm recovery."
		}
		return DriverRecovery, "Mitigated; awaiting a service recovery signal."
	}
	if !has(EvClosed) {
		return DriverClosure, "Service recovered; waiting for ticket closure."
	}
	return DriverResolved, "Incident resolved and closed."
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

// DeriveTimeLossDriver is the phase-consistent bottleneck (kept name for callers).
// It is exactly DeriveCurrentBottleneck — the per-incident current bottleneck, which
// the fleet rollup also aggregates as its "top time-loss phase".
func DeriveTimeLossDriver(lc Lifecycle, ctx DriverContext) (TimeLossDriver, string) {
	return DeriveCurrentBottleneck(lc, ctx)
}

