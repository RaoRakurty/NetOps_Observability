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

// ---- signal summary --------------------------------------------------------------

func buildSignalSummary(all, anomalous, clears []map[string]any, observers map[string]bool, peakSev string, hb rcaHypBlob) rcaSignalSummary {
	out := rcaSignalSummary{
		Total: len(all), Anomalous: len(anomalous), Clears: len(clears),
		UniqueObservers: len(observers), PeakSeverity: peakSev,
	}
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
		// Independence is a verdict-gate fact, not an assumption (§20 rule 6).
		if len(hb.Ranking.Hypotheses) > 0 && len(hb.Ranking.Hypotheses[0].Verdict.IndependentPair) == 2 {
			p.IndependenceNote = "an independent confirming pair was established by the verdict gate"
		} else if len(p.AffectedVantages) > 1 {
			p.IndependenceNote = "multiple vantages reported failures, but path/vantage independence has not been established"
		}
		out.Probe = p
	}
	return out
}

// ---- evidence coverage --------------------------------------------------------------

func buildEvidenceCoverage(total, anomalous map[string]int, laneMin, laneMax map[string]time.Time, hb rcaHypBlob) []rcaEvidenceLane {
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
			l.Availability, l.State = "available", "anomalous"
			l.Finding = fmt.Sprintf("%d of %d observations in this window are anomalous and tied to this case.", an, n)
		case n > 0:
			l.Availability, l.State = "available", "normal"
			l.Finding = fmt.Sprintf("%d observations in this window; none tied to this case as anomalous.", n)
		default:
			// §7: "No data" is coverage ABSENCE. It is never healthy evidence and
			// we do not claim to know whether the lane is unconfigured or broken.
			l.Availability, l.State = "no_data", "no_data"
			l.Finding = "No telemetry from this evidence class reached the platform in this window — unavailable or not configured. This absence is not evidence of health."
		}
		out = append(out, l)
	}
	return out
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

func buildHypothesesView(hb rcaHypBlob) []rcaHypothesis {
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
			Rank: i + 1, ID: h.ID, Title: title,
			Problem:    rcaProblemFor(h.ID, h.Title),
			Confidence: h.Confidence, Label: h.ConfidenceLabel,
			Supporting:    humanizeClauses(h.Satisfied),
			Contradicted:  h.Contradicted,
			Contradicting: aiHumanizeMissing(humanizeClauses(h.Contradictions)),
			Missing:       humanizeClauses(h.Missing),
			Owner:         rcaOwnerTeam[h.Verdict.Owner],
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

func buildOwnership(analysis string, hb rcaHypBlob, sig rcaSignalSummary) rcaOwnership {
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
			if analysis == "confirmed" {
				own.EscalationOwner = team
				own.EscalationReason = fmt.Sprintf("the confirmed leading hypothesis (%s) places the fault in this team's domain", signatureNocTitle(top.ID))
			} else {
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

func buildDecision(analysis, incident, impact string, pol incidentPolicy, configured bool, monitorWindow time.Duration) rcaDecision {
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
		EscalateWhen:     "customer impact is confirmed, or a second independent evidence class corroborates the fault",
	}
	if pol.RequirePersistenceSeconds > 0 {
		d.OpenThreshold += fmt.Sprintf(", condition persisting ≥ %s", fmtDur(time.Duration(pol.RequirePersistenceSeconds)*time.Second))
	}
	switch {
	case analysis == "confirmed" && incident == "active":
		d.Decision = "Open incident"
		d.Reason = "Customer impact and fault are confirmed by independent evidence; restoration workflow should begin."
	case incident == "recovered" || incident == "closed":
		d.Decision = "Monitor"
		d.Reason = "The condition has recovered. The case is held in a monitoring window; it reopens on recurrence and closes clean otherwise."
	case analysis == "probable" || (analysis == "suspected" && impact == "detected"):
		d.Decision = "Investigate"
		d.Reason = "Evidence is aligned but not independently confirmed. Validate the missing evidence before opening a customer incident."
	default:
		d.Decision = "Hold"
		d.Reason = "The evidence does not meet the ticket-open policy. Auto-ticketing holds until the policy threshold is met."
	}
	return d
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
	case "recovered", "closed":
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
	if incident == "recovered" || incident == "closed" {
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

func buildManagementSummary(problemNoun string, scope rcaReportScope, times rcaReportTimes, incident, analysis, impact, monitoring string, decision rcaDecision, sig rcaSignalSummary, monitorWindow time.Duration) string {
	var b strings.Builder
	subject := "the monitored service"
	if len(scope.Services) > 0 {
		subject = scope.Services[0]
	} else if len(scope.Targets) > 0 {
		subject = aiEntityLabel(scope.Targets[0])
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
	fmt.Fprintf(&b, "At %s, %s detected a condition of “%s” affecting %s. ", when, src, orDefault(problemNoun, "telemetry anomaly"), subject)
	// still happening / duration
	switch {
	case times.RecoveredCaptured && times.DurationMS > 0:
		fmt.Fprintf(&b, "The condition recovered after %s. ", fmtDur(time.Duration(times.DurationMS)*time.Millisecond))
	case incident == "no_longer_observed":
		last := times.LastAnomalous
		if last == "" {
			last = times.WindowEnd + " UTC"
		}
		fmt.Fprintf(&b, "Anomalous signals were last observed at %s; no recovery evidence was captured, so recovery is NOT confirmed. ", last)
	case incident == "recovered" || incident == "closed":
		b.WriteString("The condition is no longer observed; the exact recovery time was not captured. ")
	case times.DurationBasis == "elapsed_still_active" && times.DurationMS > 0:
		fmt.Fprintf(&b, "The condition is ongoing (%s elapsed). ", fmtDur(time.Duration(times.DurationMS)*time.Millisecond))
	default:
		b.WriteString("The condition is under observation. ")
	}
	// impact — ALWAYS telemetry-qualified (§3/§12)
	switch impact {
	case "confirmed":
		b.WriteString("Customer impact is confirmed by independent evidence. ")
	case "detected":
		b.WriteString("Customer-impact indicators were detected but are not independently confirmed. ")
	case "none_detected":
		b.WriteString("No customer impact was detected within available telemetry coverage. ")
	case "not_observable":
		b.WriteString("Customer impact could not be assessed — impact telemetry was unavailable for this window. ")
	default:
		b.WriteString("Customer impact is unknown. ")
	}
	// cause status
	switch analysis {
	case "confirmed":
		b.WriteString("The root cause is confirmed. ")
	case "probable":
		b.WriteString("A probable cause is identified, pending independent confirmation. ")
	case "inconclusive":
		b.WriteString("The leading cause was ruled out by contradicting evidence; the cause is currently inconclusive. ")
	default:
		b.WriteString("The cause remains unconfirmed because independent evidence classes did not corroborate the observations. ")
	}
	// decision + next
	fmt.Fprintf(&b, "Decision: %s — %s ", decision.Decision, decision.Reason)
	switch {
	case monitoring == "active":
		fmt.Fprintf(&b, "Monitoring is active until %s, with automatic escalation if the condition recurs or customer-impact evidence appears.", times.MonitoringUntil)
	case monitoring == "completed":
		b.WriteString("The post-recovery monitoring window has completed without recurrence.")
	case incident == "recovered" || incident == "recovering":
		fmt.Fprintf(&b, "A %s monitoring window follows recovery, with automatic escalation if the condition recurs or customer-impact evidence appears.", fmtDur(monitorWindow))
	default:
		b.WriteString("Escalation follows the policy thresholds stated in the decision section.")
	}
	return b.String()
}

// ---- next actions (§14) --------------------------------------------------------------------------------

func buildActions(analysis string, hb rcaHypBlob, sig rcaSignalSummary, decision rcaDecision, own rcaOwnership) []rcaAction {
	var out []rcaAction
	add := func(a rcaAction) {
		a.Priority = len(out) + 1
		out = append(out, a)
	}
	// engine runbook first (fault-class-specific first steps)
	if len(hb.Ranking.Hypotheses) > 0 {
		for _, step := range hb.Ranking.Hypotheses[0].Verdict.FirstSteps {
			if len(out) >= 3 {
				break
			}
			add(rcaAction{Action: step, Owner: own.TriageOwner, ExpectedResult: "confirm or rule out the leading hypothesis"})
		}
	}
	// probe forensics when the evidence is active-check-shaped
	if sig.Probe != nil && sig.Probe.Failed > 0 {
		add(rcaAction{
			Action:         "Inspect the most recent failed check transaction",
			Owner:          "NOC",
			ExpectedResult: "DNS result, resolved IP, TCP status, TLS status, HTTP status, response time, and the failure stage",
		})
		if sig.Probe.IndependenceNote != "" && !strings.Contains(sig.Probe.IndependenceNote, "established by the verdict gate") {
			add(rcaAction{
				Action:         "Validate vantage independence for the reporting checks",
				Owner:          "Platform operations",
				ExpectedResult: "agent host, site, DNS resolver, upstream provider, and path overlap for each vantage",
			})
		}
		add(rcaAction{
			Action:         "Compare real traffic and application health during the incident window",
			Owner:          "NOC",
			ExpectedResult: "request volume, completion rate, load-balancer target health, application error rate",
			EscalateWhen:   "real-user impact, flow loss, or application errors corroborate the checks",
		})
	}
	if analysis != "confirmed" {
		add(rcaAction{
			Action:         "Continue monitoring under the active policy",
			Owner:          "NOC",
			ExpectedResult: "auto-close after the stability window, reopen on recurrence",
			EscalateWhen:   decision.EscalateWhen,
		})
	}
	return out
}

// ---- NOC quick-read (§4) ----------------------------------------------------------------------------------

func buildNocQuickRead(incident, recovery, analysis, impact, ticket, monitoring string, times rcaReportTimes, scope rcaReportScope, sig rcaSignalSummary, coverage []rcaEvidenceLane, own rcaOwnership, actions []rcaAction) []rcaKV {
	kv := []rcaKV{
		{K: "Incident", V: strings.ReplaceAll(incident, "_", " ")},
		{K: "Recovery", V: strings.ReplaceAll(recovery, "_", " ")},
		{K: "Analysis", V: analysis},
		{K: "Impact", V: impact},
		{K: "Ticket", V: ticket},
	}
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
			kv = append(kv, rcaKV{K: "Failure stages", V: strings.Join(sig.Probe.FailureStages, ", ")})
		}
	}
	kv = append(kv, rcaKV{K: "Peak severity", V: sig.PeakSeverity})
	var present, absent []string
	for _, l := range coverage {
		if l.State == "anomalous" || l.State == "normal" {
			present = append(present, l.Label)
		} else {
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
	if len(actions) > 0 {
		kv = append(kv, rcaKV{K: "Next action", V: actions[0].Action})
	}
	return kv
}

func firstN(s []string, n int) []string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
