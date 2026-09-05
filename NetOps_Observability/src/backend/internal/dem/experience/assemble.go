package experience

// assemble.go — the ADAPTERS: turning what Correlix actually measures today
// into the evidence this package reasons over.
//
// This is the only file that knows where evidence comes from. Everything else
// works on already-normalized [EvidenceItem]s, which is why the reasoning is
// testable without a metrics backend and why a new producer (RUM, flow ART,
// SD-WAN SLA) is a new function here and nothing else.
//
// Today's producers, honestly stated:
//   synthetic  — internal/dem's prober: availability against the error budget,
//                p95 against the DECLARED latency budget, path stability.
//   pathgraph  — path fingerprint changes under a reachable target.
//   changes    — the normalized change feed (config, cloud, BGP, deploys).
// Everything else in [SourceLadder] is declared and reports as NOT CONFIGURED,
// which is what makes "we cannot confirm, because we have only one kind of
// instrument" a visible fact rather than a silent ceiling.

import (
	"fmt"
	"time"

	"netops/backend/internal/dem"
)

// AssembleInput is what the API layer collects before reasoning starts.
type AssembleInput struct {
	TenantID string
	Window   string
	// WindowDuration is the requested window's length; Now is the clock. Both
	// are arguments so the whole assembly is deterministic under test.
	WindowDuration time.Duration
	Now            time.Time

	// FeatureEnabled reports whether experience collection is switched on. With
	// it off, every surface says so rather than rendering an empty table.
	FeatureEnabled bool
	// MetricsAvailable reports whether the time-series backend answered. False
	// is NOT "everything is fine"; it is ReasonQueryFailed everywhere.
	MetricsAvailable bool
	QueryError       error

	Targets  []dem.Target
	Results  []dem.Result
	Stats    map[string]dem.WindowStats
	Journeys []JourneyDefinition
	Changes  []ChangeEvent
}

// Assembly is everything the API's surfaces render.
type Assembly struct {
	Window string
	Bundle Bundle
	// Targets / Results are the measurement inputs, carried through so the
	// coverage surface can join a journey step to the check that protects it
	// without re-querying the catalogue.
	Targets       []dem.Target
	Results       []dem.Result
	JourneyHealth []JourneyHealth
	DataHealth    DataHealth
	Score         ExperienceScore
	Incidents     []ExperienceIncident
	// Measured / Reason / Detail are the whole-view honesty flags, mirroring
	// internal/dem's ExperienceResponse so both surfaces agree on the sentence.
	Measured bool
	Reason   string
	Detail   string
}

// Assemble builds the whole experience view. PURE given its input.
func Assemble(in AssembleInput, policy ScorePolicy) Assembly {
	win := NewWindow(in.Now.Add(-in.WindowDuration).UTC(), in.Now.UTC())
	a := Assembly{Window: in.Window, Targets: in.Targets, Results: in.Results}

	resultByID := map[string]dem.Result{}
	for _, r := range in.Results {
		resultByID[r.Subject] = r
	}
	targetByID := map[string]dem.Target{}
	for _, t := range in.Targets {
		targetByID[t.ID] = t
	}

	evidence := syntheticEvidence(in, targetByID, resultByID)
	health := assembleDataHealth(in, evidence)
	a.DataHealth = health

	measurements := map[string]map[string]StepMeasurement{}
	for _, j := range in.Journeys {
		m := map[string]StepMeasurement{}
		for _, s := range j.Steps {
			if s.TargetID == "" {
				continue
			}
			m[s.ID] = stepMeasurement(resultByID[s.TargetID], in.Stats[s.TargetID])
		}
		measurements[j.ID] = m
		h := ComputeJourneyHealth(j, in.Window, m)
		a.JourneyHealth = append(a.JourneyHealth, h)
	}
	SortJourneyHealth(a.JourneyHealth)

	// Journey-scoped evidence: a failing step's measurement is evidence about
	// the JOURNEY, not only about the target, and the incident detector needs
	// it stamped that way to scope an incident to one journey.
	evidence = append(evidence, journeyEvidence(in, a.JourneyHealth, targetByID)...)

	a.Bundle = Bundle{
		TenantID: in.TenantID, Window: win, Now: in.Now.UTC(),
		Journeys: in.Journeys, JourneyHealth: a.JourneyHealth,
		Evidence: evidence, Missing: health.MissingFrom(), Changes: in.Changes,
		Reliability: map[string]SyntheticReliability{},
	}
	a.Incidents = Detect(a.Bundle)
	a.Score = tenantScore(in, policy, a.JourneyHealth, resultByID)

	switch {
	case !in.FeatureEnabled:
		a.Reason = dem.ReasonFeatureOff
		a.Detail = "Digital experience collection is off. Nothing on this screen was measured; an empty table here does not mean everything is well."
	case len(in.Targets) == 0 && len(in.Journeys) == 0:
		a.Reason = dem.ReasonNoTargets
		a.Detail = "No experience target and no journey is declared for this tenant, so nothing is being measured."
	case !in.MetricsAvailable:
		a.Reason = dem.ReasonQueryFailed
		a.Detail = "The metrics store did not answer, so no experience score is shown. This is not a healthy result."
	case a.Score.Measured || len(a.JourneyHealth) > 0:
		a.Measured = a.Score.Measured
		if !a.Measured {
			a.Reason, a.Detail = a.Score.Reason, a.Score.Detail
		}
	default:
		a.Reason = dem.ReasonNoSamples
		a.Detail = "No measurement reached this window."
	}
	return a
}

// stepMeasurement projects one target's verdict onto a journey step.
func stepMeasurement(r dem.Result, st dem.WindowStats) StepMeasurement {
	if !r.Measured {
		return StepMeasurement{Reason: orReason(r.Reason), Detail: r.Detail}
	}
	m := StepMeasurement{Measured: true, Samples: st.Samples, P95Ms: st.LatencyP95Ms}
	if st.Samples > 0 {
		m.SuccessPct = float64(st.Successes) / float64(st.Samples) * 100
	}
	return m
}

func orReason(r string) string {
	if r == "" {
		return dem.ReasonNoSamples
	}
	return r
}

// syntheticEvidence turns each measured target into evidence.
//
// A HEALTHY target produces CONTRADICTING evidence for the causes it would have
// shown — that is negative evidence as a first-class citizen: "the DNS check
// from the same vantage succeeded throughout" is exactly what rules a resolver
// out, and dropping it because it is boring is how a wrong hypothesis survives.
func syntheticEvidence(in AssembleInput, targets map[string]dem.Target, results map[string]dem.Result) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(in.Results)*2)
	for _, t := range in.Targets {
		r, ok := results[t.ID]
		if !ok || !r.Measured {
			continue
		}
		observer := "prober"
		if t.Site != "" {
			observer = "prober@" + t.Site
		}
		prov := Provenance{
			Source: SourceSynthetic, SourceObject: t.ID, Producer: observer,
			EventAt: lastProbe(r, in.Now), Observation: ObservationObserved,
			DataClass: DataClassCustomerMetadata,
		}
		avail := r.Availability
		switch {
		case avail.Measured && !avail.Met:
			v, b := avail.Value, avail.Budget
			it := EvidenceItem{
				ID: "syn-avail-" + t.ID, TenantID: t.TenantID, Kind: KindSyntheticResult,
				Entity: t.ID, EntityKind: "target",
				Summary: fmt.Sprintf("%s was reachable on %.2f%% of checks against a %.2f%% budget, measured from %s",
					t.Name, v, b, observer),
				Value: &v, Baseline: &b, Unit: "%",
				Stance: StanceSupports, IndependenceGroup: ModalityActiveProbe, Observer: observer,
				Reliability: DefaultReliability(SourceSynthetic), ExpectedIntervalSec: t.IntervalSec,
				App: t.App, Site: t.Site, Cohort: Cohort{Site: t.Site},
				CauseClass: causeForKind(t.Kind), CauseEntity: causeEntityForKind(t),
				Provenance: prov,
			}
			out = append(out, it)
		case avail.Measured && avail.Met:
			v := avail.Value
			out = append(out, EvidenceItem{
				ID: "syn-avail-ok-" + t.ID, TenantID: t.TenantID, Kind: KindSyntheticResult,
				Entity: t.ID, EntityKind: "target",
				Summary: fmt.Sprintf("%s stayed reachable on %.2f%% of checks from %s throughout the window", t.Name, v, observer),
				Value:   &v, Unit: "%",
				Stance: StanceContradicts, IndependenceGroup: ModalityActiveProbe, Observer: observer,
				Reliability: DefaultReliability(SourceSynthetic), ExpectedIntervalSec: t.IntervalSec,
				App: t.App, Site: t.Site, Cohort: Cohort{Site: t.Site},
				ContradictsCauses: contradictedByHealthyCheck(t.Kind),
				Provenance:        prov,
			})
		}
		if lat := r.Latency; lat.Measured && !lat.Met && lat.BudgetDeclared {
			v, b := lat.Value, lat.Budget
			out = append(out, EvidenceItem{
				ID: "syn-lat-" + t.ID, TenantID: t.TenantID, Kind: KindSyntheticResult,
				Entity: t.ID, EntityKind: "target",
				Summary: fmt.Sprintf("%s answered in %.0f ms at p95 against a declared %.0f ms budget, measured from %s",
					t.Name, v, b, observer),
				Value: &v, Baseline: &b, Unit: "ms",
				Stance: StanceSupports, IndependenceGroup: ModalityActiveProbe, Observer: observer,
				Reliability: DefaultReliability(SourceSynthetic), ExpectedIntervalSec: t.IntervalSec,
				App: t.App, Site: t.Site, Cohort: Cohort{Site: t.Site},
				Provenance: prov,
			})
		}
		if ps := r.PathStability; ps.Measured && !ps.Met {
			v := ps.Value
			out = append(out, EvidenceItem{
				ID: "path-" + t.ID, TenantID: t.TenantID, Kind: KindPathDegradation,
				Entity: t.ID, EntityKind: "target",
				Summary: fmt.Sprintf("the measured forward path to %s changed on %.0f%% of observations", t.Name, v),
				Value:   &v, Unit: "%",
				Stance: StanceSupports, IndependenceGroup: ModalityActiveProbe, Observer: observer,
				Reliability: DefaultReliability(SourcePathGraph),
				App:         t.App, Site: t.Site, Cohort: Cohort{Site: t.Site},
				CauseClass: CauseRoutingChange, CauseEntity: "path to " + t.Name,
				Provenance: Provenance{
					Source: SourcePathGraph, SourceObject: t.ID, Producer: observer,
					EventAt: prov.EventAt, Observation: ObservationObserved,
					DataClass: DataClassCustomerMetadata,
				},
			})
		}
	}
	return out
}

// journeyEvidence stamps a failing journey's step onto the journey, so an
// incident can be scoped to the workflow rather than only to the check.
func journeyEvidence(in AssembleInput, health []JourneyHealth, targets map[string]dem.Target) []EvidenceItem {
	out := make([]EvidenceItem, 0, len(health))
	for _, h := range health {
		if !h.Measured || h.MeetsSLO || h.FailingStepID == "" {
			continue
		}
		for _, s := range h.Steps {
			if s.StepID != h.FailingStepID {
				continue
			}
			t := targets[s.TargetID]
			v := s.SuccessPct
			b := s.SLOSuccess
			observer := "prober"
			if t.Site != "" {
				observer = "prober@" + t.Site
			}
			out = append(out, EvidenceItem{
				ID: "jny-" + h.JourneyID + "-" + s.StepID, TenantID: in.TenantID,
				Kind: KindJourneyOutcome, Entity: h.JourneyID + "/" + s.StepID, EntityKind: "journey_step",
				Summary: fmt.Sprintf("the %q step of the %s journey succeeded on %.2f%% of attempts against a %.2f%% objective",
					s.Label, h.Name, v, b),
				Value: &v, Baseline: &b, Unit: "%",
				Stance: StanceSupports, IndependenceGroup: ModalityActiveProbe, Observer: observer,
				Reliability: DefaultReliability(SourceSynthetic),
				App:         h.App, Site: t.Site, JourneyID: h.JourneyID, StepID: s.StepID,
				Cohort: Cohort{Site: t.Site},
				Provenance: Provenance{
					Source: SourceSynthetic, SourceObject: s.TargetID, Producer: observer,
					EventAt: in.Now.UTC(), Observation: ObservationObserved,
					DataClass: DataClassCustomerMetadata,
				},
			})
		}
	}
	return out
}

// causeForKind maps a synthetic check kind onto the cause a FAILURE of it
// implicates. Only DNS is specific enough to name a cause on its own; an HTTP,
// TCP or ICMP failure implicates "something between here and there", and
// inventing a cause for it would be exactly the confident guess this product
// exists to replace. Those return "", and the item then supports whichever
// hypothesis other evidence raised.
func causeForKind(kind string) string {
	if kind == dem.KindDNS {
		return CauseDNSResolution
	}
	return ""
}

func causeEntityForKind(t dem.Target) string {
	if t.Kind == dem.KindDNS {
		if t.Resolver != "" {
			return t.Resolver
		}
		return "the prober's resolver"
	}
	return ""
}

// contradictedByHealthyCheck lists the causes a SUCCEEDING check rules out. A
// healthy DNS check from the same vantage is real evidence against a resolver
// hypothesis; a healthy HTTP check is evidence against the application tier.
func contradictedByHealthyCheck(kind string) []string {
	switch kind {
	case dem.KindDNS:
		return []string{CauseDNSResolution}
	case dem.KindHTTP:
		return []string{CauseApplicationRegress, CauseDependencyFailure}
	default:
		return nil
	}
}

func lastProbe(r dem.Result, fallback time.Time) time.Time {
	if r.LastProbe != nil && !r.LastProbe.IsZero() {
		return r.LastProbe.UTC()
	}
	return fallback.UTC()
}

// SourceLadder is the declared set of experience-evidence sources, in the order
// the design of record builds them (§M.5). Every one of them appears on the
// Data Health surface, including the ones with no producer — a source that is
// absent from the list is a source nobody notices is missing.
var SourceLadder = []string{
	SourceSynthetic, SourcePathGraph, SourceConfigDrift, SourceCloud, SourceBGP,
	SourceFlow, SourceSDWAN, SourceWireless, SourceRUM, SourceAgent,
}

// assembleDataHealth reports each source's real state.
func assembleDataHealth(in AssembleInput, evidence []EvidenceItem) DataHealth {
	seen := map[string]int{}
	last := map[string]time.Time{}
	for _, e := range evidence {
		seen[e.Source]++
		if e.ObservedAt.After(last[e.Source]) {
			last[e.Source] = e.ObservedAt
		}
	}
	for _, c := range in.Changes {
		seen[c.Source]++
		if c.ObservedAt.After(last[c.Source]) {
			last[c.Source] = c.ObservedAt
		}
	}

	scored := 0
	for _, r := range in.Results {
		if r.Measured {
			scored++
		}
	}

	out := make([]SourceHealth, 0, len(SourceLadder))
	for _, src := range SourceLadder {
		h := SourceHealth{Source: src, EventsInWindow: seen[src]}
		if ts, ok := last[src]; ok && !ts.IsZero() {
			t := ts
			h.LastSeen = &t
		}
		switch src {
		case SourceSynthetic:
			h.Configured = len(in.Targets) > 0
			h.CoverageTotal, h.CoverageCovered = len(in.Targets), scored
			switch {
			case !in.FeatureEnabled:
				h.State, h.Detail = StateOff, "experience collection is switched off"
			case !h.Configured:
				h.State, h.Detail = StateOff, "no experience target is declared"
			case !in.MetricsAvailable:
				h.State, h.Detail = StateMisconfigured, "the metrics store did not answer, so we cannot say whether the prober is reporting"
			case scored == 0:
				h.State, h.Detail = StateNoData, "targets are declared but no probe result reached this window"
			default:
				h.State = StateFlowing
			}
		case SourcePathGraph:
			h.Configured = true
			pathSamples := 0
			for _, st := range in.Stats {
				pathSamples += st.PathSamples
			}
			switch {
			case !in.MetricsAvailable:
				h.State, h.Detail = StateMisconfigured, "the metrics store did not answer"
			case pathSamples == 0:
				h.State, h.Detail = StateNoData, "no forward path was observed under these targets in this window, so path stability is not measured — it is not 'stable'"
			default:
				h.State = StateFlowing
			}
		case SourceConfigDrift, SourceCloud, SourceBGP:
			h.Configured = seen[src] > 0
			if seen[src] > 0 {
				h.State = StateFlowing
			} else {
				h.State, h.Detail = StateNoData, "no change of this kind was recorded in the window (which may be correct — a quiet estate reports nothing)"
			}
		default:
			h.State = StateOff
			h.Detail = "no producer for this source is deployed yet"
		}
		out = append(out, h)
	}
	return BuildDataHealth(in.Window, out, in.Now)
}

// tenantScore composes the tenant-level published score from the dimensions
// Correlix can actually measure today. A dimension with no producer is ABSENT
// with its reason, its weight is redistributed, and below the evidence minimum
// no score is published at all.
func tenantScore(in AssembleInput, policy ScorePolicy, health []JourneyHealth, results map[string]dem.Result) ExperienceScore {
	dims := map[string]DimensionInput{}

	measuredJourneys, journeySum := 0, 0.0
	for _, h := range health {
		if h.Measured {
			measuredJourneys++
			journeySum += h.SuccessPct
		}
	}
	if measuredJourneys > 0 {
		dims[DimJourneySuccess] = DimensionInput{
			Measured: true, Points: journeySum / float64(measuredJourneys), Samples: measuredJourneys,
			Detail: plural(measuredJourneys, "declared journey is", "declared journeys are") + " measured in this window",
		}
	} else {
		dims[DimJourneySuccess] = DimensionInput{Reason: ReasonJourneyNotMeasured,
			Detail: "no declared journey has a measured required step, so journey success has no value"}
	}

	availSum, availN := 0.0, 0
	latSum, latN := 0.0, 0
	pathSum, pathN := 0.0, 0
	for _, r := range results {
		if !r.Measured {
			continue
		}
		if r.Availability.Measured {
			availSum += r.Availability.Points
			availN++
		}
		if r.Latency.Measured {
			latSum += r.Latency.Points
			latN++
		}
		if r.PathStability.Measured {
			pathSum += r.PathStability.Points
			pathN++
		}
	}
	dims[DimAvailability] = dimFrom(availSum, availN, dem.ReasonNoSamples,
		"no target produced a scorable availability measurement in this window")
	dims[DimResponsiveness] = dimFrom(latSum, latN, dem.ReasonNoSamples,
		"no target declared a latency budget, so responsiveness has no threshold to be scored against")
	dims[DimNetworkQuality] = dimFrom(pathSum, pathN, dem.ReasonNoSamples,
		"no forward path was observed, so network quality is not measured — it is not 'good'")

	dims[DimErrorFreeInteraction] = DimensionInput{Reason: MissingNotConfigured,
		Detail: "error-free interaction is measured from first-party real-user telemetry, which is not collected yet"}
	dims[DimUserFriction] = DimensionInput{Reason: MissingNotConfigured,
		Detail: "user friction (retries, re-authentication, roaming, abandonment) needs real-user or endpoint telemetry, which is not collected yet"}

	return ComputeScore(in.TenantID, "tenant", in.Window, AggWorstOf, policy, DefaultAppClass, dims, nil)
}

func dimFrom(sum float64, n int, reason, detail string) DimensionInput {
	if n == 0 {
		return DimensionInput{Reason: reason, Detail: detail}
	}
	return DimensionInput{Measured: true, Points: sum / float64(n), Samples: n}
}
