package main

// rca_report_wording.go — the derivation + wording half of the RCA report
// builder (rca_report.go). Every sentence here follows the directive's honesty
// rules: evidence-specific, telemetry-qualified, never circular ("evidence
// changed", "matches this issue type" and bare "no impact" are banned), and a
// suspect is named by its POSSIBLE PROBLEM, never by a generic "network change".

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// sigProblemStatement — per-signature "possible problem → suspect" line (§9/§16).
// The signature TITLE says what was observed; this says what the problem would
// be if the hypothesis is right. Falls back to a domain-derived sentence.
var sigProblemStatement = map[string]string{
	"sig.ent.cloud.ipsec-tunnel-down":          "The IPsec tunnel's IKE/DPD keepalives failed, so every application behind the tunnel lost its private path.",
	"sig.ent.cloud.private-connectivity-down":  "A cloud routing or connectivity change removed the private path to the applications behind it.",
	"sig.ent.cloud.app-dependency-down":        "An in-cloud dependency (database, cache, queue, or policy) stopped answering, degrading the applications that rely on it.",
	"sig.ent.cloud.region-degradation":         "The cloud provider's region or a regional service is impaired.",
	"sig.ent.cloud.region-impairment":          "The cloud provider's region or a regional service is impaired.",
	"sig.ent.wan-edge.bgp-peer-flap":           "A WAN routing session is flapping, repeatedly withdrawing and re-learning routes.",
	"sig.ent.wan-edge.bgp-peer-down":           "A WAN routing session went down, removing routes through that peer.",
	"sig.ent.wan-edge.routing-instability":     "Routing at the WAN edge is unstable, shifting traffic between paths.",
	"sig.ent.wan-edge.congestion":              "The WAN edge link is congested and dropping or delaying traffic.",
	"sig.ent.wan-edge.tunnel-mtu-blackhole":    "Packets above a size threshold are silently dropped on the tunnel path (MTU blackhole).",
	"sig.ent.middle-mile.dia-egress-latency":   "The ISP / DIA egress path is adding latency.",
	"sig.ent.middle-mile.dia-egress-loss":      "The ISP / DIA egress path is dropping packets.",
	"sig.ent.middle-mile.physical-degradation": "A circuit or optical segment on the provider path is degrading.",
	"sig.ent.access.local-link-fault":          "A local access link is faulty or flapping.",
	"sig.ent.access.uplink-down":               "An access uplink is down, isolating the devices behind it.",
	"sig.ent.internet.dns-impairment":          "DNS resolution is failing or slow, so services cannot be reached by name.",
	"sig.ent.lan.link-flap":                    "A LAN link is flapping.",
	"sig.ent.lan.stp-topology-change":          "The LAN spanning-tree topology changed, briefly interrupting forwarding.",
	"sig.ent.sdwan.tunnel-flap":                "An SD-WAN overlay tunnel is flapping between states.",
	"sig.ent.sdwan.brownout":                   "An SD-WAN path is in brownout — up, but lossy or slow.",
	"sig.ent.dc.fabric-link-down":              "A data-center fabric link is down, reducing east-west capacity.",
	"sig.ent.app.saas-experience-degraded":     "The application's user experience degraded (failed or slow checks) while no network-path fault has been demonstrated — the suspect is the application/SaaS service itself, its load balancer, or its DNS/TLS front door.",
	"sig.ent.app.lb-target-health-failure":     "The load balancer is marking backend targets unhealthy, so requests fail or drain away.",
	"sig.ent.app.tls-cert-expired":             "The service's TLS certificate expired, so clients refuse the connection.",
	"sig.ent.app.dns-failover-wrong-target":    "DNS failover moved the service name to a wrong or unhealthy target.",
}

// rcaProblemFor returns the possible-problem sentence for a signature id.
// No filler: a signature without a curated statement renders no problem line
// (the title + evidence still carry the hypothesis) rather than a circular one.
func rcaProblemFor(sigID, _ string) string {
	return sigProblemStatement[sigID]
}

// countNoun renders "One automated check" / "3 automated checks" — the report
// never prints "N thing(s)" (§2 pluralization rule).
func countNoun(n int, noun string) string {
	switch n {
	case 1:
		return "One " + noun
	default:
		return fmt.Sprintf("%d %ss", n, noun)
	}
}

// ---- scope ---------------------------------------------------------------------

func buildRcaScope(meta map[string]any, anomalous []map[string]any, hb rcaHypBlob) rcaReportScope {
	var sc rcaReportScope
	seen := map[string]map[string]bool{}
	add := func(bucket string, v string, out *[]string) {
		v = strings.TrimSpace(v)
		if v == "" || v == "<nil>" {
			return
		}
		if seen[bucket] == nil {
			seen[bucket] = map[string]bool{}
		}
		if !seen[bucket][v] {
			seen[bucket][v] = true
			*out = append(*out, v)
		}
	}
	// affected buckets (engine-owned projection)
	if a, ok := meta["affected"].(string); ok && a != "" {
		var af struct {
			Devices  []string `json:"devices"`
			Sites    []string `json:"sites"`
			Services []string `json:"services"`
			Apps     []string `json:"apps"`
			Paths    []string `json:"paths"`
		}
		if json.Unmarshal([]byte(a), &af) == nil {
			for _, d := range af.Devices {
				add("dev", d, &sc.Devices)
			}
			for _, s := range af.Sites {
				add("site", s, &sc.Sites)
			}
			for _, s := range af.Services {
				add("svc", s, &sc.Services)
			}
			for _, s := range af.Apps {
				add("svc", s, &sc.Services)
			}
			sc.PathsCount = len(af.Paths)
		}
	}
	// named app impact (fusion layer)
	if ai, ok := meta["app_impact"].(string); ok && ai != "" {
		var parsed struct {
			Apps []struct {
				App string `json:"app"`
			} `json:"apps"`
		}
		if json.Unmarshal([]byte(ai), &parsed) == nil {
			for _, a := range parsed.Apps {
				add("svc", a.App, &sc.Services)
			}
		}
	}
	// vantages / targets / regions from the anomalous evidence itself
	for _, sig := range anomalous {
		if fmt.Sprintf("%v", sig["modality_class"]) == "active_probe" {
			add("van", fmt.Sprintf("%v", sig["observer_id"]), &sc.Vantages)
			eid := fmt.Sprintf("%v", sig["entity_id"])
			if _, dst, ok := strings.Cut(eid, "->"); ok {
				add("tgt", strings.TrimSpace(dst), &sc.Targets)
			} else if fmt.Sprintf("%v", sig["entity_type"]) == "service" {
				add("tgt", eid, &sc.Targets)
			}
		}
		if a, ok := sig["attrs"].(string); ok && a != "" {
			var at struct {
				Region  string `json:"region"`
				Account string `json:"account"`
			}
			if json.Unmarshal([]byte(a), &at) == nil {
				add("reg", at.Region, &sc.Regions)
				add("acct", at.Account, &sc.Accounts)
			}
		}
	}
	for _, s := range hb.GroundingContext.Seams {
		add("seam", s.SeamID+" ("+s.SeamType+")", &sc.Seams)
	}
	return sc
}

// latestProbeTransaction extracts the most recent FAILED synthetic check's
// per-phase results from signal attrs — the actual transaction outcome the
// prober measured (owner feedback: show full HTTP/TCP/DNS results).
func latestProbeTransaction(all []map[string]any) *rcaProbeTransaction {
	var best *rcaProbeTransaction
	var bestTS time.Time
	for _, sig := range all {
		kind := fmt.Sprintf("%v", sig["kind"])
		if !strings.HasPrefix(kind, "synthetic_") || strings.HasSuffix(kind, "_clear") {
			continue
		}
		a, _ := sig["attrs"].(string)
		if a == "" {
			continue
		}
		var at struct {
			Target     string   `json:"target"`
			Method     string   `json:"method"`
			StatusCode int      `json:"status_code"`
			FailClass  string   `json:"fail_class"`
			DNSMs      *float64 `json:"dns_ms"`
			TCPMs      *float64 `json:"tcp_connect_ms"`
			TLSMs      *float64 `json:"tls_ms"`
			TTFBMs     *float64 `json:"ttfb_ms"`
			TotalMs    *float64 `json:"total_ms"`
		}
		if json.Unmarshal([]byte(a), &at) != nil {
			continue
		}
		if at.StatusCode == 0 && at.FailClass == "" && at.TotalMs == nil {
			continue // no transaction detail on this signal
		}
		ts, ok := parseChTS(fmt.Sprintf("%v", sig["ts"]))
		if !ok || ts.Before(bestTS) {
			continue
		}
		bestTS = ts
		best = &rcaProbeTransaction{
			Target: at.Target, Method: at.Method, StatusCode: at.StatusCode,
			FailClass: at.FailClass, DNSMs: at.DNSMs, TCPMs: at.TCPMs,
			TLSMs: at.TLSMs, TTFBMs: at.TTFBMs, TotalMs: at.TotalMs, At: fmtUTC(ts),
		}
	}
	return best
}

// ---- signal summary --------------------------------------------------------------

func buildSignalSummary(all, anomalous, clears []map[string]any, observers map[string]bool, peakSev string, hb rcaHypBlob) rcaSignalSummary {
	out := rcaSignalSummary{
		Total: len(all), Anomalous: len(anomalous), Clears: len(clears),
		UniqueObservers: len(observers), PeakSeverity: peakSev,
	}
	// P1.7: dedupe derived signals into evidence groups — one (observer, entity)
	// measurement source is ONE group however many kinds it emitted.
	groups := map[string]bool{}
	for _, sig := range anomalous {
		groups[fmt.Sprintf("%v|%v", sig["observer_id"], sig["entity_id"])] = true
	}
	out.EvidenceGroups = len(groups)
	for _, sig := range all {
		if b, _ := sig["attached"].(bool); b {
			out.Attached++
		}
	}
	// probe detail — measured values only; absent means unknown, never zero (§6/§20)
	var (
		probeObs, probeFailed      int
		vantages                   = map[string]bool{}
		stages                     = map[string]bool{}
		peakLoss, baseRtt, peakRtt *float64
		firstFailed, lastFailed    time.Time
	)
	for _, sig := range all {
		if fmt.Sprintf("%v", sig["modality_class"]) != "active_probe" {
			continue
		}
		kind := fmt.Sprintf("%v", sig["kind"])
		if strings.HasSuffix(kind, "_clear") {
			continue
		}
		probeObs++
		attached, _ := sig["attached"].(bool)
		failedKind := strings.Contains(kind, "loss") || strings.Contains(kind, "fail") ||
			strings.Contains(kind, "timeout") || strings.Contains(kind, "5xx")
		if attached || failedKind {
			probeFailed++
			vantages[fmt.Sprintf("%v", sig["observer_id"])] = true
			if st := rcaFailureStage(kind); st != "" {
				stages[st] = true
			}
			if ts, ok := parseChTS(fmt.Sprintf("%v", sig["ts"])); ok {
				if firstFailed.IsZero() || ts.Before(firstFailed) {
					firstFailed = ts
				}
				if ts.After(lastFailed) {
					lastFailed = ts
				}
			}
			v := asFloat(sig["value"])
			b := asFloat(sig["baseline"])
			metric := fmt.Sprintf("%v", sig["metric_name"])
			switch {
			case strings.Contains(metric, "loss") || strings.Contains(kind, "loss"):
				if v > 0 && (peakLoss == nil || v > *peakLoss) {
					vv := v
					peakLoss = &vv
				}
			case strings.Contains(metric, "rtt") || strings.Contains(kind, "rtt") || strings.Contains(metric, "latency"):
				if v > 0 && (peakRtt == nil || v > *peakRtt) {
					vv := v
					peakRtt = &vv
				}
				if b > 0 && baseRtt == nil {
					bb := b
					baseRtt = &bb
				}
			}
		}
	}
	if probeObs > 0 {
		p := &rcaProbeSummary{
			Observations: probeObs, Failed: probeFailed,
			PeakLossPct: peakLoss, BaselineRttMs: baseRtt, PeakRttMs: peakRtt,
		}
		for v := range vantages {
			p.AffectedVantages = append(p.AffectedVantages, v)
		}
		sort.Strings(p.AffectedVantages)
		for s := range stages {
			p.FailureStages = append(p.FailureStages, s)
		}
		sort.Strings(p.FailureStages)
		if !firstFailed.IsZero() {
			p.FirstFailed = fmtUTC(firstFailed)
		}
		if !lastFailed.IsZero() {
			p.LastFailed = fmtUTC(lastFailed)
		}
		p.LastTransaction = latestProbeTransaction(all)
		// Independence is a verdict-gate fact, not an assumption (§20 rule 6).
		if len(hb.Ranking.Hypotheses) > 0 && len(hb.Ranking.Hypotheses[0].Verdict.IndependentPair) == 2 {
			// §3: name the ACTUAL confirming observers, never just assert a pair.
			pair := hb.Ranking.Hypotheses[0].Verdict.IndependentPair
			p.IndependenceNote = fmt.Sprintf(
				"independent confirming pair established by the verdict gate: %s × %s",
				strings.ReplaceAll(pair[0], "_", " "), strings.ReplaceAll(pair[1], "_", " "))
		} else if len(p.AffectedVantages) > 1 {
			p.IndependenceNote = "multiple vantages reported failures, but path/vantage independence has not been established"
		}
		out.Probe = p
	}
	return out
}

// ---- evidence coverage --------------------------------------------------------------

func buildEvidenceCoverage(total, anomalous map[string]int, laneMin, laneMax map[string]time.Time, hb rcaHypBlob, firstObs, lastObs time.Time) []rcaEvidenceLane {
	trusted := map[string]bool{}
	if len(hb.Ranking.Hypotheses) > 0 {
		v := hb.Ranking.Hypotheses[0].Verdict
		for _, m := range v.TrustedModalities {
			trusted[m] = true
		}
		if len(trusted) == 0 {
			for _, m := range v.ModalityCoverage {
				trusted[m] = true
			}
		}
	}
	var out []rcaEvidenceLane
	for _, lane := range rcaLaneOrder {
		n, an := total[lane], anomalous[lane]
		if n == 0 && lane == "management_plane" {
			continue // controller lane omitted entirely when absent, not "no data"
		}
		l := rcaEvidenceLane{
			Class: lane, Label: rcaLaneLabel[lane],
			Observations: n, Anomalous: an,
			CountsTowardConfidence: an > 0 && trusted[lane],
		}
		if t := laneMin[lane]; !t.IsZero() {
			l.From = fmtUTC(t)
		}
		if t := laneMax[lane]; !t.IsZero() {
			l.To = fmtUTC(t)
		}
		switch {
		case an > 0:
			l.Availability, l.State, l.Coverage = "available", "anomalous", "full"
			l.Finding = fmt.Sprintf("%d of %d observations in this window are anomalous and tied to this case.", an, n)
		case n > 0:
			// P1 coverage quality: "no anomaly" is a claim about the window — it is
			// only clean when the lane actually SPANNED the incident window. A lane
			// that stopped before the last anomaly (or started after the first) has
			// PARTIAL coverage and is inconclusive, never a green Normal.
			full, missing := rcaLaneWindowCoverage(laneMin[lane], laneMax[lane], firstObs, lastObs)
			l.Availability = "available"
			if full {
				l.State, l.Coverage = "normal", "full"
				l.Finding = fmt.Sprintf("%d observations spanning the incident window; none tied to this case as anomalous.", n)
			} else {
				l.State, l.Coverage = "inconclusive", "partial"
				l.MissingInterval = missing
				l.Finding = fmt.Sprintf("%d observations, but coverage did not span the full incident window — no anomaly observed during available coverage. Missing interval: %s. Insufficient to confirm or exclude impact for the full incident.", n, orDefault(missing, "unknown"))
			}
		default:
			// §7: "No data" is coverage ABSENCE. It is never healthy evidence and
			// we do not claim to know whether the lane is unconfigured or broken.
			l.Availability, l.State, l.Coverage = "no_data", "no_data", "none"
			l.Finding = "No telemetry from this evidence class reached the platform in this window — unavailable or not configured. This absence is not evidence of health."
		}
		out = append(out, l)
	}
	return out
}

// rcaLaneWindowCoverage reports whether a lane's observation span [laneMin,
// laneMax] covered the incident window [firstObs, lastObs], and (when partial)
// the missing interval. A small slack (the greater of 2 min or a fifth of the
// window) absorbs sampling jitter — the same tolerance the impact-axis coverage
// check uses. When the incident window is a single instant, any observation
// counts as full coverage (there is no interval to miss).
func rcaLaneWindowCoverage(laneMin, laneMax, firstObs, lastObs time.Time) (bool, string) {
	if firstObs.IsZero() || lastObs.IsZero() || laneMin.IsZero() || laneMax.IsZero() {
		return true, "" // insufficient timing to make a partial-coverage claim
	}
	if !lastObs.After(firstObs) {
		return true, ""
	}
	slack := lastObs.Sub(firstObs) / 5
	if slack < 2*time.Minute {
		slack = 2 * time.Minute
	}
	lateStart := laneMin.After(firstObs.Add(slack))
	earlyEnd := laneMax.Before(lastObs.Add(-slack))
	if !lateStart && !earlyEnd {
		return true, ""
	}
	switch {
	case lateStart && earlyEnd:
		return false, fmt.Sprintf("%s–%s and %s–%s", fmtUTC(firstObs), fmtUTC(laneMin), fmtUTC(laneMax), fmtUTC(lastObs))
	case lateStart:
		return false, fmt.Sprintf("%s–%s", fmtUTC(firstObs), fmtUTC(laneMin))
	default:
		return false, fmt.Sprintf("%s–%s", fmtUTC(laneMax), fmtUTC(lastObs))
	}
}

// ---- hypotheses view -------------------------------------------------------------------

// humanizeClause turns an engine clause expression ("probe_loss|synthetic_icmp_loss")
// into operator language ("Packet loss or Icmp loss check") — no raw kind token
// ever reaches the report (customer-facing language rule). Dedupes alternatives
// that humanize identically.
func humanizeClause(clause string) string {
	seen := map[string]bool{}
	var parts []string
	for _, alt := range strings.Split(clause, "|") {
		l := kindNoc(strings.TrimSpace(alt))
		if l != "" && !seen[l] {
			seen[l] = true
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, " or ")
}

func humanizeClauses(clauses []string) []string {
	var out []string
	for _, c := range clauses {
		if h := humanizeClause(c); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// clauseCaseEvidence renders a satisfied clause as the ACTUAL case evidence
// that matched it (§15: matching rules are not evidence): the observed kinds
// among the clause's alternatives, with signal + observer counts. Falls back
// to the humanized clause only if no observed kind matches (defensive).
func clauseCaseEvidence(clause string, kindCounts map[string]int, kindObservers map[string]map[string]bool) string {
	var parts []string
	for _, alt := range strings.Split(clause, "|") {
		k := strings.TrimSpace(alt)
		n := kindCounts[k]
		if n == 0 {
			continue
		}
		obs := len(kindObservers[k])
		label := kindNoc(k)
		if obs > 1 {
			parts = append(parts, fmt.Sprintf("%s (%d signals from %d observers)", label, n, obs))
		} else {
			parts = append(parts, fmt.Sprintf("%s (%s)", label, strings.ToLower(countNoun(n, "signal"))))
		}
	}
	if len(parts) == 0 {
		return "" // display only MATCHED evidence — never the matching rule text
	}
	return strings.Join(parts, "; ")
}

func supportingCaseEvidence(satisfied []string, kindCounts map[string]int, kindObservers map[string]map[string]bool) []string {
	var out []string
	for _, c := range satisfied {
		if e := clauseCaseEvidence(c, kindCounts, kindObservers); e != "" {
			out = append(out, e)
		}
	}
	return out
}

func buildHypothesesView(hb rcaHypBlob, kindCounts map[string]int, kindObservers map[string]map[string]bool) []rcaHypothesis {
	var out []rcaHypothesis
	for i, h := range hb.Ranking.Hypotheses {
		// no filler (§9): a hypothesis earns a row by evidence or by having been
		// explicitly ruled out (contradicted rows explain the reasoning).
		if h.Confidence <= 0 && len(h.Satisfied) == 0 && !h.Contradicted {
			continue
		}
		title := signatureNocTitle(h.ID)
		if title == "" || title == h.ID {
			title = h.Title
		}
		hy := rcaHypothesis{
			Type: rcaHypothesisType(h.ID),
			Rank: i + 1, ID: h.ID, Title: title,
			Problem:    rcaProblemFor(h.ID, h.Title),
			Confidence: h.Confidence, Label: h.ConfidenceLabel,
			Supporting:    supportingCaseEvidence(h.Satisfied, kindCounts, kindObservers),
			Contradicted:  h.Contradicted,
			Contradicting: aiHumanizeMissing(humanizeClauses(h.Contradictions)),
			Missing:       humanizeClauses(h.Missing),
			Owner:         rcaOwnerTeam[h.Verdict.Owner],
		}
		// P1.9 taxonomy: observation and causal role are independent axes.
		// "Condition observed: yes / origin: ruled out" is expressible; a single
		// blended "Confirmed / Ruled out" field is not renderable.
		hy.ObservationState = "not_observed"
		if len(hy.Supporting) > 0 {
			hy.ObservationState = "observed"
			// P1 issue-family confirmation gate: a hypothesis cannot be CONFIRMED
			// while its own required confirmation evidence is still missing (the
			// "underlay confirmed while missing = observe underlay status" defect).
			// Confirmation requires a confirmed verdict AND no outstanding required
			// evidence — otherwise it stays observed/suspected.
			if strings.ToLower(h.Verdict.Tier) == "confirmed" && !h.Contradicted && len(h.Missing) == 0 {
				hy.ObservationState = "confirmed"
			}
		}
		switch {
		case h.Contradicted:
			hy.CausalRole, hy.CandidacyState = "ruled_out_as_origin", "ruled_out"
			// a ruled-out row never renders a live confidence label (audit D7)
			hy.Label = ""
		case hy.Type == "symptom classification":
			// a symptom names what was observed — it is never ranked as a cause
			hy.CausalRole, hy.CandidacyState = "symptom", "not_ranked_as_cause"
		case strings.ToLower(h.ConfidenceLabel) == "likely" || strings.ToLower(h.ConfidenceLabel) == "confirmed":
			hy.CausalRole, hy.CandidacyState = "probable_origin", "active"
		default:
			hy.CausalRole, hy.CandidacyState = "possible_origin", "active"
		}
		for _, m := range humanizeClauses(h.Missing) {
			hy.ConfirmWhen = append(hy.ConfirmWhen, "observe "+m)
		}
		out = append(out, hy)
		if len(out) >= 5 {
			break
		}
	}
	return out
}

// ---- ownership ----------------------------------------------------------------------------

// rcaExternalOwnerTeams — owner teams that are OUTSIDE this organization.
// Accountability never lands on an external provider without demarcation
// evidence (P1.10); until then they are candidates and the internal network
// team owns the technical investigation.
var rcaExternalOwnerTeams = map[string]bool{
	"ISP / carrier": true, "Carrier": true, "Cloud provider": true,
	"Colo provider": true, "SD-WAN vendor": true,
}

func buildOwnership(analysis string, faultLocalized bool, serviceClassification string, hb rcaHypBlob, sig rcaSignalSummary, kindCounts map[string]int) rcaOwnership {
	own := rcaOwnership{
		TriageOwner:      "NOC",
		TriageReason:     "Default triage owner until the failure stage and fault domain are identified.",
		SuspectedDomain:  "Undetermined",
		EscalationOwner:  "Pending",
		EscalationReason: "Escalation owner is assigned when the analysis reaches probable/confirmed with a supported fault domain.",
	}
	seen := map[string]bool{}
	for _, h := range hb.Ranking.Hypotheses {
		if h.Contradicted || (h.Confidence <= 0 && len(h.Satisfied) == 0) {
			continue
		}
		team := rcaOwnerTeam[h.Verdict.Owner]
		if team == "" || seen[team] {
			continue
		}
		seen[team] = true
		own.Candidates = append(own.Candidates, rcaOwnerCandidate{
			Team:   team,
			Reason: fmt.Sprintf("named by the %q hypothesis (%s)", signatureNocTitle(h.ID), strings.ToLower(orDefault(h.ConfidenceLabel, "candidate"))),
		})
	}
	if len(hb.Ranking.Hypotheses) > 0 && (analysis == "confirmed" || analysis == "probable") {
		top := hb.Ranking.Hypotheses[0]
		team := rcaOwnerTeam[top.Verdict.Owner]
		if team != "" {
			own.SuspectedDomain = orDefault(top.Verdict.Layer, team)
			switch {
			case analysis == "confirmed" && rcaExternalOwnerTeams[team]:
				// P1.10: an external provider/carrier is never handed
				// accountability from a hypothesis token. The internal network
				// team owns the investigation; the provider is a CANDIDATE
				// until the demarcation evidence contract is satisfied
				// (provider-side alarm + independent-vantage evidence beyond
				// the customer boundary — assessDemarcation).
				own.TechnicalOwner = "NetOps"
				own.ExternalCandidate = team
				own.Demarcation, own.DemarcationBasis = assessDemarcation(team, kindCounts)
				if own.Demarcation == "provider_boundary_confirmed" {
					own.EscalationOwner = team
					own.EscalationReason = fmt.Sprintf("demarcation is confirmed — a provider-side alarm and independent-vantage evidence localize the fault beyond the customer boundary, so %s escalation is warranted", strings.ToLower(team))
				} else {
					own.EscalationOwner = "NetOps"
					own.EscalationReason = fmt.Sprintf("the fault localizes toward the %s domain; %s escalation is pending provider-demarcation confirmation", strings.ToLower(team), strings.ToLower(team))
				}
			case analysis == "confirmed" && faultLocalized && team == "Application team" &&
				serviceClassification == "external / third-party service":
				// §12: the internal Application team does not own a third-party
				// service — vendor escalation does, once the fault localizes there.
				own.TechnicalOwner = team
				own.EscalationOwner = "SaaS vendor escalation (via vendor management)"
				own.EscalationReason = fmt.Sprintf("the fault localizes to %s — an external service this platform does not operate", signatureNocTitle(top.ID))
			case analysis == "confirmed" && faultLocalized:
				own.TechnicalOwner = team
				own.EscalationOwner = team
				own.EscalationReason = fmt.Sprintf("the confirmed leading hypothesis (%s) places the fault in this team's domain", signatureNocTitle(top.ID))
			case analysis == "confirmed":
				// §20 restraint: a confirmed CONDITION whose fault has not been
				// localized to an object does not hand a team the pager — the
				// hypothesis names a candidate domain, not a proven owner.
				own.EscalationOwner = "Pending localization"
				own.EscalationReason = fmt.Sprintf("%s is the leading candidate domain; the fault is not yet localized to a specific component", team)
			default:
				own.EscalationOwner = "Pending confirmation"
				own.EscalationReason = fmt.Sprintf("%s is the leading candidate, pending independent confirmation", team)
			}
		}
	}
	// an evidence-free owner guess is banned (§11) — nothing more to do: the
	// triage owner stays NOC and the domain stays Undetermined by default.
	_ = sig
	return own
}

// ---- decision --------------------------------------------------------------------------------

func buildDecision(analysis, incident, recoveryState, impact, monitoring string, generatedAt string, pol incidentPolicy, configured bool, monitorWindow time.Duration) rcaDecision {
	polName := pol.Name
	if !configured {
		polName = pol.Name + " (platform default — no tenant policy configured)"
	}
	d := rcaDecision{
		PolicyID: pol.ID, PolicyName: polName,
		OpenThreshold: fmt.Sprintf("verdict ≥ %s%s%s", pol.MinVerdict,
			map[bool]string{true: ", customer-facing evidence required", false: ""}[pol.RequireCustomerFacing],
			map[bool]string{true: ", suspected additionally requires critical severity", false: ""}[pol.SuspectedRequiresCritical]),
		MonitoringWindow: fmtDur(monitorWindow) + " after recovery",
		AutoCloseWhen:    "no recurrence and no NEW customer-impact evidence arising within the monitoring window (impact already recorded for this incident stays recorded and does not block a clean close)",
		ReopenWhen:       fmt.Sprintf("the same condition recurs within %s (flap suppression)", fmtDur(monitorWindow)),
		EscalationState:  "armed",
		EscalateWhen:     "customer impact is confirmed, or a second independent evidence class corroborates the fault",
	}
	// The escalation conditions are EVALUATED at report time — conditions that
	// already hold render as an executed trigger, never as a future promise.
	if impact == "confirmed" || analysis == "confirmed" {
		d.EscalationState = "triggered"
		d.EscalationAt = generatedAt
	}
	d.AutoCloseEligible = monitoring == "completed_no_recurrence"
	if pol.RequirePersistenceSeconds > 0 {
		d.OpenThreshold += fmt.Sprintf(", condition persisting ≥ %s", fmtDur(time.Duration(pol.RequirePersistenceSeconds)*time.Second))
	}
	switch {
	case analysis == "confirmed" && incident == "active":
		d.Decision = "Open incident"
		d.Reason = "Customer impact and fault are confirmed by independent evidence; restoration workflow should begin."
	case incident == "recovered" || incident == "closed" || incident == "no_longer_observed":
		// Monitoring copy is RECOVERY-STATE-AWARE (P1.5/P1.6 residue): "has
		// recovered" may only ever render on observed recovery evidence. A
		// window that merely quiesced is "no longer observed" — never recovered.
		d.Decision = "Monitor"
		switch recoveryState {
		case "explicitly_confirmed":
			d.Reason = "The condition has recovered. The case is held in a monitoring window; it reopens on recurrence and closes clean otherwise."
		case "not_applicable":
			d.Reason = "This case was merged into another; lifecycle and monitoring continue on the surviving case."
		case "component_only", "failed_validation":
			d.Reason = "The condition is no longer observed, but recovery is not confirmed end-to-end — recovery evidence did not cover every participating scope. The case reopens on recurrence."
		default: // inferred | not_observed — no recovery evidence: never claim recovery
			d.Reason = "The condition is no longer observed; no recovery evidence was captured. The case reopens on recurrence."
		}
	case analysis == "probable" || (analysis == "suspected" && impact == "detected"):
		d.Decision = "Investigate"
		d.Reason = "Evidence is aligned but not independently confirmed. Validate the missing evidence before opening a customer incident."
	default:
		d.Decision = "Hold"
		d.Reason = "The evidence does not meet the ticket-open policy. Auto-ticketing holds until the policy threshold is met."
	}
	return d
}

// rcaSeverityIncidentBasis renders the INCIDENT severity's reasoning from policy
// inputs — environment, current end-to-end impact, corroboration, analysis
// maturity and recovery/residual state — never the circular "peak of the
// attached evidence". Generic across issue families.
func rcaSeverityIncidentBasis(sevIncident string, validation bool, impactSyn, impactRU, analysis string, observers, anomLanes int, ra rcaRecoveryAssessment) string {
	if validation {
		return "Validation scenario — production severity not applicable; simulated severity reflects the injected condition only."
	}
	var parts []string
	if impactSyn == "confirmed" {
		parts = append(parts, "complete synthetic path loss")
	}
	switch impactRU {
	case "confirmed":
		parts = append(parts, "confirmed real-user impact")
	case "detected", "indicator_detected":
		parts = append(parts, "real-traffic impact indicators")
	}
	switch analysis {
	case "confirmed":
		parts = append(parts, "confirmed fault condition")
	case "probable":
		parts = append(parts, "probable fault, not yet independently confirmed")
	}
	if anomLanes >= 2 && observers >= 2 {
		parts = append(parts, fmt.Sprintf("corroborated across %d evidence classes and %d observers", anomLanes, observers))
	} else {
		parts = append(parts, "single uncorroborated evidence stream (severity capped)")
	}
	if ra.Service.State == "failed_validation" {
		parts = append(parts, "service recovery failed validation")
	}
	if ra.ResidualAfterComponent {
		parts = append(parts, "residual degradation persisted after component recovery")
	}
	if len(parts) == 0 {
		parts = append(parts, "no corroborated impact or fault evidence")
	}
	return strings.ToUpper(sevIncident) + " — " + strings.Join(parts, "; ") + "."
}

// ---- titles -----------------------------------------------------------------------------------

// buildRcaTitle: evidence-based, deterministic, service-name-first (§2).
// Returns (title, subtitle, problemNoun) — problemNoun feeds the management
// summary ("temporary connectivity degradation to X").
func buildRcaTitle(topHyp, analysis, incident string, scope rcaReportScope, laneAnomalous map[string]int, changes []rcaCloudChange) (string, string, string) {
	service := ""
	if len(scope.Services) > 0 {
		service = scope.Services[0]
	} else if len(scope.Targets) > 0 {
		service = aiEntityLabel(scope.Targets[0])
	}
	suffix := ""
	switch incident {
	case "recovered":
		suffix = " — recovered"
	case "no_longer_observed":
		// The window quiesced without recovery evidence — never claim recovery.
		suffix = " — no longer observed"
	}

	// A matched signature names the condition (factual, not verdict-bearing).
	if topHyp != "" && topHyp != "undetermined" && strings.HasPrefix(topHyp, "sig.") {
		t := signatureNocTitle(topHyp)
		noun := strings.ToLower(t)
		if service != "" {
			return t + " — " + service + suffix, "Leading hypothesis; see analysis state for certainty", noun
		}
		return t + suffix, "Leading hypothesis; see analysis state for certainty", noun
	}

	// No signature: describe the dominant anomalous evidence class factually.
	// "Network change" is permitted ONLY when an actual change event exists (§2).
	dominant, best := "", 0
	for lane, n := range laneAnomalous {
		if n > best {
			best, dominant = n, lane
		}
	}
	noun := map[string]string{
		"active_probe":     "active-check degradation",
		"passive_flow":     "traffic-flow anomaly",
		"control_plane":    "routing/link event cluster",
		"device_telemetry": "device-health anomaly",
		"management_plane": "controller-reported anomaly",
	}[dominant]
	if noun == "" {
		noun = "telemetry anomaly"
	}
	hasChange := false
	for _, c := range changes {
		if c.Attached {
			hasChange = true
			break
		}
	}
	adj := ""
	if incident == "recovered" {
		adj = "Transient "
	}
	title := adj + noun
	title = strings.ToUpper(title[:1]) + title[1:]
	if service != "" {
		title += " — " + service
	}
	if hasChange {
		title += " (cloud change in window)"
	}
	return title + suffix, "No fault signature matched — cause undetermined", noun
}

// ---- why / confirmation wording (§16) ------------------------------------------------------------

func buildWhyWording(analysis string, hb rcaHypBlob, sig rcaSignalSummary, laneAnomalous map[string]int) (whySusp string, whyNot []string, required string) {
	var lanes []string
	for _, l := range rcaLaneOrder {
		if laneAnomalous[l] > 0 {
			lanes = append(lanes, strings.ToLower(rcaLaneLabel[l]))
		}
	}
	switch {
	case len(lanes) == 1 && lanes[0] == "active checks" && sig.Probe != nil:
		whySusp = countNoun(len(sig.Probe.AffectedVantages), "active-check source") + " reported degradation to the same target during an overlapping time window."
	case len(lanes) > 1:
		whySusp = fmt.Sprintf("Anomalies in %s align in the same time window and scope.", strings.Join(lanes, ", "))
	case len(lanes) == 1:
		whySusp = fmt.Sprintf("Anomalous %s evidence was observed in this window; no other evidence class corroborates yet.", lanes[0])
	default:
		whySusp = "No anomalous evidence is currently tied to this case."
	}
	if analysis != "confirmed" && len(hb.Ranking.Hypotheses) > 0 {
		whyNot = friendlyReasons(hb.Ranking.Hypotheses[0].Verdict.Reasons)
	}
	if analysis != "confirmed" {
		if sig.Probe != nil && len(lanes) == 1 && lanes[0] == "active checks" {
			required = "Identify whether the checks failed during DNS, TCP, TLS, or HTTP; validate vantage independence; and compare the incident window against real-user traffic, load-balancer health, application errors, and network telemetry."
		} else {
			required = "Obtain an independent observation of the same fault from a second evidence class (routing/link state, traffic flow, device health, or an active check from an independent vantage)."
		}
	}
	return whySusp, whyNot, required
}

// ---- management summary (§3) -----------------------------------------------------------------------

// rcaMgmtWordCap is the management summary's word ceiling (130–160-word
// target). Over the cap, whole LOWER-PRIORITY sentences drop — never a
// mid-sentence truncation, never the what-happened / is-it-still-happening /
// impact sentences.
const rcaMgmtWordCap = 160

// rcaSummarySentence is one management-summary sentence with its trim priority.
type rcaSummarySentence struct {
	text      string
	protected bool // never dropped
	dropRank  int  // among unprotected sentences, HIGHER rank drops first
}

// rcaComposeSummary joins the sentences, enforcing the word cap by dropping
// unprotected sentences in deterministic priority order (highest dropRank
// first; ties drop the later sentence first). Returns the text and whether
// trimming occurred.
func rcaComposeSummary(sents []rcaSummarySentence, capWords int) (string, bool) {
	words := func() int {
		n := 0
		for _, s := range sents {
			if s.text != "" {
				n += len(strings.Fields(s.text))
			}
		}
		return n
	}
	trimmed := false
	for words() > capWords {
		drop := -1
		for i, s := range sents {
			if s.protected || s.text == "" {
				continue
			}
			if drop == -1 || s.dropRank >= sents[drop].dropRank {
				drop = i
			}
		}
		if drop == -1 {
			break // only protected sentences remain — never truncate mid-sentence
		}
		sents[drop].text = ""
		trimmed = true
	}
	var parts []string
	for _, s := range sents {
		if s.text != "" {
			parts = append(parts, s.text)
		}
	}
	return strings.Join(parts, " "), trimmed
}

func buildManagementSummary(problemNoun string, scope rcaReportScope, times rcaReportTimes, incident, analysis, impact, impactSyn, impactRealUser, monitoring string, decision rcaDecision, sig rcaSignalSummary, monitorWindow time.Duration, ra rcaRecoveryAssessment, merge *rcaIncidentMerge) (string, bool) {
	subject := "the monitored service"
	if len(scope.Services) > 0 {
		subject = scope.Services[0]
	} else if len(scope.Targets) > 0 {
		subject = aiEntityLabel(scope.Targets[0])
	}
	// Sentences are collected with their trim priority (length discipline):
	// what-happened / still-happening / impact are PROTECTED; the monitoring
	// tail drops first (rank 3), then cause status (2), then the decision (1).
	var sents []rcaSummarySentence
	addP := func(text string) {
		sents = append(sents, rcaSummarySentence{text: strings.TrimSpace(text), protected: true})
	}
	add := func(rank int, text string) {
		sents = append(sents, rcaSummarySentence{text: strings.TrimSpace(text), dropRank: rank})
	}
	// what happened + when
	when := times.FirstObserved
	if when == "" {
		when = times.WindowStart + " UTC"
	}
	src := "automated telemetry"
	if sig.Probe != nil && sig.Probe.Failed > 0 {
		src = countNoun(len(sig.Probe.AffectedVantages), "automated check")
		if len(sig.Probe.AffectedVantages) == 0 {
			src = "automated checks"
		}
	}
	addP(fmt.Sprintf("At %s, %s detected a condition of “%s” affecting %s.", when, src, orDefault(problemNoun, "telemetry anomaly"), subject))
	// still happening / duration. Component vs service recovery are stated
	// SEPARATELY (P1.2): a conflicting timeline is explained, never averaged.
	switch {
	case ra.ResidualAfterComponent && times.ComponentRecoveredAt != "" && !times.RecoveredCaptured:
		addP(fmt.Sprintf("A component recovered at %s, but end-to-end service checks continued failing through %s — the incident entered residual degradation rather than full recovery, and service recovery is not confirmed.",
			times.ComponentRecoveredAt, orDefault(times.LastAnomalous, "the end of the window")))
		if incident == "active" && times.DurationBasis == "elapsed_still_active" && times.DurationMS > 0 {
			addP(fmt.Sprintf("The condition is ongoing (%s elapsed).", fmtDur(time.Duration(times.DurationMS)*time.Millisecond)))
		}
	case times.RecoveredCaptured && times.DurationMS > 0:
		addP(fmt.Sprintf("The condition recovered after %s.", fmtDur(time.Duration(times.DurationMS)*time.Millisecond)))
	case incident == "no_longer_observed":
		last := times.LastAnomalous
		if last == "" {
			last = times.WindowEnd + " UTC"
		}
		addP(fmt.Sprintf("Anomalous signals were last observed at %s; no recovery evidence was captured, so recovery is NOT confirmed.", last))
	case incident == "recovered" || incident == "closed":
		addP("The condition is no longer observed; the exact recovery time was not captured.")
	case times.DurationBasis == "elapsed_still_active" && times.DurationMS > 0:
		addP(fmt.Sprintf("The condition is ongoing (%s elapsed).", fmtDur(time.Duration(times.DurationMS)*time.Millisecond)))
	default:
		addP("The condition is under observation.")
	}
	// merged source (P1): the merge and the surviving incident's ownership are
	// PROTECTED — a merged case's most load-bearing fact is that it no longer owns
	// its own lifecycle.
	if merge != nil {
		addP(merge.Statement)
	}
	// impact — ALWAYS telemetry-qualified (§3/§12); axes never conflated (P1.5)
	switch impact {
	case "confirmed":
		addP("Customer impact is confirmed by independent evidence, including real user traffic.")
	case "detected":
		if impactRealUser == "confirmed" || impactRealUser == "detected" {
			addP("Customer-impact indicators were detected but are not independently confirmed.")
		} else {
			// §5: synthetic checks model a representative transaction — they do
			// not prove real users failed the same one.
			addP("Synthetic path impact is confirmed; actual real-user impact was not confirmed because relevant real-traffic telemetry was insufficient.")
		}
	case "indicator_detected":
		addP("A real-traffic indicator was detected — traffic behaviour deviated from baseline — but actual customer impact is unconfirmed.")
	case "none_detected":
		addP("No customer impact was detected within available telemetry coverage.")
	case "not_observable":
		addP("Customer impact could not be assessed — impact telemetry coverage was unavailable or insufficient for this window.")
	default:
		if impactSyn == "none_detected" || impactRealUser == "none_detected" {
			// Partial coverage (P1.6): one axis observed cleanly, the other did
			// not cover the window — the covered axis is reported honestly, the
			// overall no-impact CLAIM is not made.
			addP("No impact signature appeared in the covered evidence, but impact-relevant coverage was incomplete for this window, so absence of customer impact is not established.")
		} else {
			addP("Customer impact is unknown.")
		}
	}
	// cause status — a confirmed FAULT is never called a confirmed ROOT CAUSE (P1.3)
	switch analysis {
	case "confirmed":
		add(2, "The fault condition is confirmed and the affected domain has been localized; the underlying root cause remains under investigation.")
	case "probable":
		add(2, "A probable fault domain is identified, pending independent confirmation.")
	case "inconclusive":
		add(2, "The leading explanation was ruled out by contradicting evidence; the cause is currently inconclusive.")
	default:
		add(2, "The cause remains unconfirmed because independent evidence classes did not corroborate the observations.")
	}
	// decision + next. A merged source's decision IS the merge statement (already
	// added, protected) — avoid repeating it; state where work continues instead.
	if merge != nil {
		add(1, "Restoration, monitoring and ticketing continue on the surviving incident.")
		return rcaComposeSummary(sents, rcaMgmtWordCap)
	}
	add(1, fmt.Sprintf("Decision: %s — %s", decision.Decision, decision.Reason))
	switch {
	case monitoring == "active":
		add(3, fmt.Sprintf("Monitoring is active until %s, with automatic escalation if the condition recurs or customer-impact evidence appears.", times.MonitoringUntil))
	case monitoring == "completed":
		add(3, "The post-recovery monitoring window has completed without recurrence.")
	case incident == "recovered" || incident == "recovering":
		add(3, fmt.Sprintf("A %s monitoring window follows recovery, with automatic escalation if the condition recurs or customer-impact evidence appears.", fmtDur(monitorWindow)))
	default:
		add(3, "Escalation follows the policy thresholds stated in the decision section.")
	}
	return rcaComposeSummary(sents, rcaMgmtWordCap)
}

// ---- NOC quick-read (§4) ----------------------------------------------------------------------------------

func buildNocQuickRead(incident, recovery, analysis, impact, impactSyn, impactRU, ticket, monitoring string, times rcaReportTimes, scope rcaReportScope, sig rcaSignalSummary, coverage []rcaEvidenceLane, own rcaOwnership, actions []rcaAction, ra rcaRecoveryAssessment, merge *rcaIncidentMerge) []rcaKV {
	var kv []rcaKV
	// A merged source's quick-read leads with the merge: source-case lifecycle,
	// the surviving incident, and where operational ownership now lives (P1).
	if merge != nil {
		survivor := "unresolved"
		if merge.SurvivorResolved {
			survivor = merge.SurvivingDisplayID
		}
		kv = append(kv,
			rcaKV{K: "Incident state", V: "Merged into " + survivor},
			rcaKV{K: "Surviving incident", V: survivor},
			rcaKV{K: "Operational ownership", V: "Surviving incident owns lifecycle, monitoring, ticketing and restoration"},
		)
	} else {
		kv = append(kv, rcaKV{K: "Incident", V: strings.ReplaceAll(incident, "_", " ")})
	}
	kv = append(kv, rcaKV{K: "Recovery", V: strings.ReplaceAll(recovery, "_", " ")})
	// Recovery BY SCOPE (P1.1) — the NOC sees component vs service recovery as
	// separate rows, never one blended state.
	if ra.Component.State != "not_applicable" {
		v := strings.ReplaceAll(ra.Component.State, "_", " ")
		if ra.Component.At != "" {
			v += " at " + ra.Component.At
		}
		kv = append(kv, rcaKV{K: "Component recovery", V: v})
	}
	if ra.Service.State != "not_applicable" {
		v := strings.ReplaceAll(ra.Service.State, "_", " ")
		if ra.Service.At != "" {
			v += " at " + ra.Service.At
		}
		kv = append(kv, rcaKV{K: "Service recovery", V: v})
	}
	ticketV := strings.ReplaceAll(ticket, "_", " ")
	if merge != nil {
		if merge.SurvivorResolved {
			ticketV = "Managed by surviving incident " + merge.SurvivingDisplayID
		} else {
			ticketV = "Transferred — surviving incident unresolved"
		}
	}
	kv = append(kv,
		rcaKV{K: "Analysis", V: analysis},
		rcaKV{K: "Impact", V: strings.ReplaceAll(impact, "_", " ")},
		rcaKV{K: "Synthetic impact", V: strings.ReplaceAll(impactSyn, "_", " ")},
		rcaKV{K: "Real-user impact", V: strings.ReplaceAll(impactRU, "_", " ")},
		rcaKV{K: "Ticket", V: ticketV},
	)
	if times.FirstObserved != "" {
		kv = append(kv, rcaKV{K: "First observed", V: times.FirstObserved})
	}
	if times.LastAnomalous != "" {
		kv = append(kv, rcaKV{K: "Last anomalous", V: times.LastAnomalous})
	}
	if times.RecoveredCaptured {
		kv = append(kv, rcaKV{K: "Recovered at", V: times.RecoveredAt})
	} else if incident == "no_longer_observed" {
		kv = append(kv, rcaKV{K: "Recovered at", V: "Not confirmed — signals stopped; no recovery evidence"})
	} else if incident == "recovered" || incident == "closed" {
		kv = append(kv, rcaKV{K: "Recovered at", V: "Not captured"})
	}
	if times.DurationBasis == "single_observation" {
		kv = append(kv, rcaKV{K: "Duration", V: "Single failed observation — exact duration unknown"})
	}
	if times.DurationMS > 0 {
		basis := map[string]string{
			"to_recovery": "", "elapsed_still_active": " (elapsed, still active)",
			"to_last_observation": " (to last observation)",
		}[times.DurationBasis]
		kv = append(kv, rcaKV{K: "Duration", V: fmtDur(time.Duration(times.DurationMS)*time.Millisecond) + basis})
	}
	if times.MonitoringUntil != "" {
		label := times.MonitoringUntil
		if monitoring == "completed" {
			label += " (completed, no recurrence)"
		}
		kv = append(kv, rcaKV{K: "Monitoring until", V: label})
	}
	if len(scope.Services) > 0 {
		kv = append(kv, rcaKV{K: "Service / application", V: strings.Join(scope.Services, ", ")})
	}
	if scope.ServiceClassification != "" {
		kv = append(kv, rcaKV{K: "Service classification", V: scope.ServiceClassification})
	}
	if len(scope.Targets) > 0 {
		kv = append(kv, rcaKV{K: "Affected targets", V: strings.Join(firstN(scope.Targets, 4), ", ")})
	}
	if len(scope.Regions) > 0 {
		kv = append(kv, rcaKV{K: "Regions", V: strings.Join(scope.Regions, ", ")})
	}
	if sig.Probe != nil {
		kv = append(kv, rcaKV{K: "Checks failing", V: fmt.Sprintf("%d of %d observations", sig.Probe.Failed, sig.Probe.Observations)})
		if len(sig.Probe.AffectedVantages) > 0 {
			kv = append(kv, rcaKV{K: "Affected vantages", V: strings.Join(sig.Probe.AffectedVantages, ", ")})
		}
		if len(sig.Probe.FailureStages) > 0 {
			// §7: packet loss / latency are SYMPTOMS, never protocol stages.
			var stages, symptoms []string
			for _, v := range sig.Probe.FailureStages {
				switch strings.ToLower(v) {
				case "packet loss", "latency high", "timeout", "response-time change":
					symptoms = append(symptoms, v)
				default:
					stages = append(stages, v)
				}
			}
			if len(stages) > 0 {
				kv = append(kv, rcaKV{K: "Failure stages", V: strings.Join(stages, ", ")})
			}
			if len(symptoms) > 0 {
				kv = append(kv, rcaKV{K: "Failure symptoms", V: strings.Join(symptoms, ", ")})
			}
			_ = []string{}
		}
	}
	kv = append(kv, rcaKV{K: "Peak severity", V: sig.PeakSeverity})
	var present, absent []string
	for _, l := range coverage {
		switch {
		case l.Availability == "available" && l.Coverage == "partial":
			present = append(present, l.Label+" (partial)")
		case l.Availability == "available":
			present = append(present, l.Label)
		default:
			absent = append(absent, l.Label)
		}
	}
	if len(present) > 0 {
		kv = append(kv, rcaKV{K: "Evidence present", V: strings.Join(present, ", ")})
	}
	if len(absent) > 0 {
		kv = append(kv, rcaKV{K: "Evidence missing", V: strings.Join(absent, ", ")})
	}
	kv = append(kv, rcaKV{K: "Triage owner", V: own.TriageOwner})
	if own.TechnicalOwner != "" {
		kv = append(kv, rcaKV{K: "Technical owner", V: own.TechnicalOwner})
	}
	if own.ExternalCandidate != "" {
		kv = append(kv, rcaKV{K: "External provider", V: own.ExternalCandidate + " (candidate — " + strings.ReplaceAll(own.Demarcation, "_", " ") + ")"})
	}
	if len(actions) > 0 {
		v := actions[0].Action
		if actions[0].OperationalPriority != "" {
			v = "[" + actions[0].OperationalPriority + "] " + v
		}
		kv = append(kv, rcaKV{K: "Next action", V: v})
	}
	return kv
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
