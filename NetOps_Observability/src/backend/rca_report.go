package main

// rca_report.go — the canonical, server-side RCA report view model (owner
// directive 2026-07-12; design: docs/design/rca-report-overhaul.md).
//
// The report is a PURE derivation over the same tenant-scoped slice the
// timeline and rca-path-view read (loadCorrSlice + mergeTimelineEvidence) plus
// the ticket link — no engine re-decision, no stored prose. Honesty rules are
// enforced HERE, in the builder, not in the template:
//
//   unknown is not zero · missing is not healthy · correlated is not caused ·
//   a recovered signal is not a resolved root cause · one evidence class never
//   confirms · a recovery time that was not captured is said so, never invented.
//
// Four INDEPENDENT state dimensions replace the old single "RCA state" badge:
// incident (lifecycle), analysis (evidence maturity), impact (customer effect,
// telemetry-qualified), ticket (workflow). "Recovered" applies to the incident,
// never to the analysis.

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ---- typed view model --------------------------------------------------------

type rcaReport struct {
	ReportID      string `json:"report_id"`
	CorrelationID string `json:"correlation_id"`
	DisplayID     string `json:"display_id"` // P-XXXXXX (problemDisplayID)
	Version       int    `json:"version"`
	ReportType    string `json:"report_type"` // see reportTypeFor
	Title         string `json:"title"`
	Subtitle      string `json:"subtitle,omitempty"`
	GeneratedAt   string `json:"generated_at"` // UTC, canonical

	States   rcaReportStates    `json:"states"`
	Times    rcaReportTimes     `json:"times"`
	Scope    rcaReportScope     `json:"scope"`
	Summary  rcaReportSummaries `json:"summary"`
	Signals  rcaSignalSummary   `json:"signal_summary"`
	Coverage []rcaEvidenceLane  `json:"evidence_coverage"`
	// Cloud change events observed in/near the window. Empty = none observed
	// (the section is omitted, not rendered as healthy).
	CloudChanges []rcaCloudChange `json:"cloud_changes,omitempty"`
	Hypotheses   []rcaHypothesis  `json:"hypotheses"`
	// SingleHypothesis: render "Current hypothesis", not "Hypothesis ranking".
	SingleHypothesis bool           `json:"single_hypothesis"`
	RootCause        rcaRootCause   `json:"root_cause"`
	Ownership        rcaOwnership   `json:"ownership"`
	Decision         rcaDecision    `json:"decision"`
	Actions          []rcaAction    `json:"next_actions"`
	Ticket           map[string]any `json:"ticket,omitempty"` // ticketStatusView passthrough
	// The §7 ordered spine block (rcaPathBlock passthrough) — the topology
	// section renders ONLY measured/declared structure, never invented paths.
	Path any `json:"path,omitempty"`
	// Topology is the report-facing projection of the measured spine (§15):
	// service/vantage names primary, addresses secondary, seam + state per hop.
	// Available=false renders as an honest absence, never an invented diagram.
	Topology rcaTopologyView `json:"topology"`
}

type rcaSpineHopView struct {
	Index    int    `json:"index"`
	Label    string `json:"label"`
	Address  string `json:"address,omitempty"`
	Kind     string `json:"kind"`
	Boundary string `json:"boundary,omitempty"`
	State    string `json:"state"`
	SeamID   string `json:"seam_id,omitempty"`
}

type rcaTopologyView struct {
	Available  bool              `json:"available"`
	Reason     string            `json:"reason,omitempty"`
	VantageID  string            `json:"vantage_id,omitempty"`
	ObservedAt string            `json:"observed_at,omitempty"`
	Stale      bool              `json:"stale"`
	Hops       []rcaSpineHopView `json:"hops,omitempty"`
}

type rcaReportStates struct {
	// Incident lifecycle is separate from recovery assessment (§1/§17 of the
	// truthfulness spec): signals aging out of the window is NOT recovery.
	Incident string `json:"incident"` // active | recovering | recovered | no_longer_observed | closed
	// Recovery is asserted ONLY from observed recovery evidence.
	Recovery      string `json:"recovery"`       // explicitly_confirmed | not_observed
	RecoveryBasis string `json:"recovery_basis"` // human sentence: what (if anything) proved recovery
	Analysis      string `json:"analysis"`       // observed | suspected | probable | confirmed | inconclusive
	Impact        string `json:"impact"`         // confirmed | detected | none_detected | not_observable | unknown
	// §5 impact axes: a failed synthetic proves the SYNTHETIC transaction failed;
	// real-user impact needs real-traffic evidence (flow collapse, LB/app errors).
	ImpactSynthetic string `json:"impact_synthetic"` // confirmed | none_detected | not_observable
	ImpactRealUser  string `json:"impact_real_user"` // confirmed | detected | none_detected | not_observable
	Ticket        string `json:"ticket"`         // not_opened | held | opened | resolved | failed
	Severity      string `json:"severity"`       // peak attached severity: info|warn|high|crit|unknown
	// Monitoring is evaluated against report-generation time — never described
	// as running past its own end.
	Monitoring string `json:"monitoring"` // not_started | active | completed
	// Confidence carries its basis so "Medium" is never a bare adjective.
	Confidence      string `json:"confidence"` // High | Medium | Low
	ConfidenceBasis string `json:"confidence_basis"`
}

type rcaReportTimes struct {
	FirstObserved string `json:"first_observed,omitempty"` // earliest anomalous evidence
	LastAnomalous string `json:"last_anomalous,omitempty"` // latest anomalous evidence
	// RecoveredAt is set ONLY from observed clear evidence (clear_ts / clear
	// signal timestamps). Never inferred from report-generation or close time.
	RecoveredAt       string `json:"recovered_at,omitempty"`
	RecoveredCaptured bool   `json:"recovered_captured"`
	DurationMS        int64  `json:"duration_ms,omitempty"`
	// DurationBasis states what the duration measures:
	// to_recovery | to_last_observation | elapsed_still_active | unknown
	DurationBasis   string `json:"duration_basis"`
	MonitoringUntil string `json:"monitoring_until,omitempty"`
	WindowStart     string `json:"window_start"`
	WindowEnd       string `json:"window_end"`
}

type rcaReportScope struct {
	Services   []string `json:"services,omitempty"` // named apps/services (operator identifiers)
	Targets    []string `json:"targets,omitempty"`  // probe/impact targets (service name first, IP secondary)
	Devices    []string `json:"devices,omitempty"`
	Sites      []string `json:"sites,omitempty"`
	Regions    []string `json:"regions,omitempty"`
	Accounts   []string `json:"accounts,omitempty"`
	Vantages   []string `json:"vantages,omitempty"` // observing vantages that saw anomalies
	Seams      []string `json:"seams,omitempty"`    // provider boundaries in the grounding context
	PathsCount int      `json:"paths_count,omitempty"`
}

type rcaReportSummaries struct {
	// Management: what happened / still happening / duration / impact
	// (telemetry-qualified) / cause status / decision / next. ~100-140 words.
	Management string `json:"management"`
	// NOC quick-read: structured fields, 30-second scan.
	Noc []rcaKV `json:"noc"`
	// WhySuspected / WhyNotConfirmed: evidence-specific, never circular.
	WhySuspected    string   `json:"why_suspected,omitempty"`
	WhyNotConfirmed []string `json:"why_not_confirmed,omitempty"`
	RequiredConfirm string   `json:"required_confirmation,omitempty"`
}

type rcaKV struct {
	K string `json:"k"`
	V string `json:"v"`
}

type rcaSignalSummary struct {
	Total           int    `json:"total"`
	Attached        int    `json:"attached"`
	Anomalous       int    `json:"anomalous"` // attached, non-clear
	Clears          int    `json:"clears"`
	UniqueObservers int    `json:"unique_observers"`
	PeakSeverity    string `json:"peak_severity"`
	// Probe detail — present only when active-probe evidence exists. Values are
	// included only when actually measured; absent means unknown, not zero.
	Probe *rcaProbeSummary `json:"probe,omitempty"`
}

type rcaProbeSummary struct {
	Observations     int      `json:"observations"`
	Failed           int      `json:"failed"`
	AffectedVantages []string `json:"affected_vantages,omitempty"`
	FailureStages    []string `json:"failure_stages,omitempty"`
	PeakLossPct      *float64 `json:"peak_loss_pct,omitempty"`
	BaselineRttMs    *float64 `json:"baseline_rtt_ms,omitempty"`
	PeakRttMs        *float64 `json:"peak_rtt_ms,omitempty"`
	FirstFailed      string   `json:"first_failed,omitempty"`
	LastFailed       string   `json:"last_failed,omitempty"`
	// Independence is stated only when known (verdict gate); never assumed.
	IndependenceNote string `json:"independence_note,omitempty"`
}

type rcaEvidenceLane struct {
	Class string `json:"class"` // engine modality key
	Label string `json:"label"` // NOC label
	// Availability: available | no_data. State: anomalous | normal | no_data |
	// not_applicable. "No data" is coverage ABSENCE — it never reads as healthy
	// and never contributes to confidence.
	Availability string `json:"availability"`
	State        string `json:"state"`
	Observations int    `json:"observations"`
	Anomalous    int    `json:"anomalous"`
	Finding      string `json:"finding"`
	From         string `json:"from,omitempty"`
	To           string `json:"to,omitempty"`
	// CountsTowardConfidence: this lane is among the verdict gate's trusted /
	// covering modalities for the top hypothesis.
	CountsTowardConfidence bool `json:"counts_toward_confidence"`
}

type rcaCloudChange struct {
	Kind        string `json:"kind"` // cloud_change | cloud_audit | security_policy_change
	Provider    string `json:"provider,omitempty"`
	EventSource string `json:"event_source,omitempty"`
	RequestID   string `json:"request_id,omitempty"` // provider event key
	Account     string `json:"account,omitempty"`
	Region      string `json:"region,omitempty"`
	Resource    string `json:"resource,omitempty"`
	Actor       string `json:"actor,omitempty"`
	At          string `json:"at"`
	// DeltaSeconds: change time minus first anomalous observation (negative =
	// change preceded the symptom). Present only when both times are known.
	DeltaSeconds *int64 `json:"delta_seconds,omitempty"`
	// Relationship: same_resource | same_service | same_account_region |
	// temporal_only. Never a causal claim.
	Relationship string `json:"relationship"`
	Attached     bool   `json:"attached"`
	Explanation  string `json:"explanation"`
}

type rcaHypothesis struct {
	Rank          int      `json:"rank"`
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Problem       string   `json:"problem"` // what the possible problem is → the suspect
	Domain        string   `json:"domain,omitempty"`
	Confidence    float64  `json:"confidence"`
	Label         string   `json:"label"` // engine confidence_label
	Supporting    []string `json:"supporting,omitempty"`
	Contradicted  bool     `json:"contradicted"`
	Contradicting []string `json:"contradicting,omitempty"`
	Missing       []string `json:"missing,omitempty"`
	ConfirmWhen   []string `json:"confirm_when,omitempty"`
	Owner         string   `json:"owner,omitempty"`
}

type rcaRootCause struct {
	Identified bool     `json:"identified"`
	Statement  string   `json:"statement"` // "Root cause has not been identified." when false
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Owner      string   `json:"owner,omitempty"`
	Evidence   []string `json:"evidence,omitempty"`
}

type rcaOwnerCandidate struct {
	Team   string `json:"team"`
	Reason string `json:"reason"`
}

type rcaOwnership struct {
	TriageOwner      string              `json:"triage_owner"` // NOC unless evidence says otherwise
	TriageReason     string              `json:"triage_reason"`
	SuspectedDomain  string              `json:"suspected_domain"` // Undetermined until evidence
	Candidates       []rcaOwnerCandidate `json:"candidates,omitempty"`
	EscalationOwner  string              `json:"escalation_owner"`
	EscalationReason string              `json:"escalation_reason"`
}

type rcaDecision struct {
	Decision   string `json:"decision"` // Open incident | Investigate | Monitor | Hold
	Reason     string `json:"reason"`
	PolicyID   string `json:"policy_id"`
	PolicyName string `json:"policy_name"`
	// Explicit, policy-driven mechanics — never vague prose.
	OpenThreshold    string `json:"open_threshold"`
	MonitoringWindow string `json:"monitoring_window"`
	AutoCloseWhen    string `json:"auto_close_when"`
	ReopenWhen       string `json:"reopen_when"`
	EscalateWhen     string `json:"escalate_when"`
}

type rcaAction struct {
	Priority       int    `json:"priority"`
	Action         string `json:"action"`
	Owner          string `json:"owner"`
	ExpectedResult string `json:"expected_result,omitempty"`
	EscalateWhen   string `json:"escalate_when,omitempty"`
}

// ---- vocabulary --------------------------------------------------------------

// Lane labels — the Go mirror of frontend MODALITY_META (labels.ts). When a
// mapping is added on one side, add it on the other.
var rcaLaneLabel = map[string]string{
	"device_telemetry": "Device health",
	"control_plane":    "Routing & link events",
	"passive_flow":     "Traffic flow",
	"active_probe":     "Active checks",
	"management_plane": "Controller / management plane",
}

var rcaLaneOrder = []string{"device_telemetry", "control_plane", "passive_flow", "active_probe", "management_plane"}

// Owner tokens (catalog verdict.owner) → team language. Mirror of OWNER_LABEL
// in labels.ts.
var rcaOwnerTeam = map[string]string{
	"netops": "NetOps", "network_ops": "NetOps", "isp": "ISP / carrier",
	"carrier": "Carrier", "cloud_provider": "Cloud provider", "app_team": "Application team",
	"colo_provider": "Colo provider", "sdwan_vendor": "SD-WAN vendor", "platform": "Platform operations",
}

// Failure stage from probe/synthetic signal kinds — the NOC's "where in the
// transaction did it die" axis. Derived, since no stage column exists.
func rcaFailureStage(kind string) string {
	switch {
	case strings.Contains(kind, "dns"):
		return "DNS"
	case strings.Contains(kind, "tcp"):
		return "TCP connect"
	case strings.Contains(kind, "tls"), strings.Contains(kind, "cert"):
		return "TLS"
	case strings.Contains(kind, "http"):
		return "HTTP"
	case strings.Contains(kind, "timeout"):
		return "Timeout"
	case strings.Contains(kind, "icmp"), kind == "probe_loss":
		return "Packet loss"
	case strings.Contains(kind, "rtt"), strings.Contains(kind, "latency"):
		return "Latency"
	default:
		return ""
	}
}

// App-impact / customer-facing evidence kinds (mirror of the confirmability
// audit's APP_GROUNDABLE set, display side).
// rcaStateUp buffers a semantic up-state event until firstObs is known.
type rcaStateUp struct {
	sig map[string]any
	ts  time.Time
}

// rcaIsRecoveryStateSignal reports whether a signal is semantic recovery
// evidence (§17): a *_status kind asserting the resource came back
// (state up/established/…, severity info) — e.g. ipsec_tunnel_status up.
// Status lanes signal recovery this way rather than with *_clear kinds.
func rcaIsRecoveryStateSignal(sig map[string]any) bool {
	kind := fmt.Sprintf("%v", sig["kind"])
	if !strings.HasSuffix(kind, "_status") {
		return false
	}
	if strings.ToLower(fmt.Sprintf("%v", sig["severity"])) != "info" {
		return false
	}
	a, _ := sig["attrs"].(string)
	if a == "" {
		return false
	}
	var at struct {
		State string `json:"state"`
	}
	if json.Unmarshal([]byte(a), &at) != nil {
		return false
	}
	switch strings.ToLower(at.State) {
	case "up", "established", "reachable", "healthy", "ok":
		return true
	}
	return false
}

func rcaIsImpactKind(kind, entityType, probeScope string) bool {
	return rcaIsRealUserImpactKind(kind, entityType) || rcaIsSyntheticImpactKind(kind, probeScope)
}

// rcaIsRealUserImpactKind: evidence produced by REAL traffic or the serving
// infrastructure itself (§5) — the only kinds that may support a real-user
// impact claim. A failed synthetic check is never in this set.
func rcaIsRealUserImpactKind(kind, entityType string) bool {
	switch kind {
	case "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high",
		"flow_volume_anomaly":
		return true
	case "cloud_health":
		return entityType == "app"
	}
	return false
}

// rcaIsSyntheticImpactKind: a customer-path synthetic/probe failure — proves
// the configured transaction failed from that vantage, nothing more (§5).
func rcaIsSyntheticImpactKind(kind, probeScope string) bool {
	if strings.HasPrefix(kind, "synthetic_") || strings.HasPrefix(kind, "probe_") {
		return probeScope == "customer_path"
	}
	return false
}

var rcaCloudChangeKinds = map[string]bool{
	"cloud_change": true, "cloud_audit": true, "security_policy_change": true,
}

// parseChTS parses ClickHouse toString() datetimes ("2026-07-12 19:50:45[.123]").
func parseChTS(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05.000", "2006-01-02 15:04:05", time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func fmtUTC(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }

// fmtDur renders a duration for operators ("3m 15s", "1h 04m").
func fmtDur(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	switch {
	case h > 0:
		return fmt.Sprintf("%dh %02dm", h, m)
	case m > 0:
		return fmt.Sprintf("%dm %02ds", m, s)
	default:
		return fmt.Sprintf("%ds", s)
	}
}

// ---- hypotheses blob decoding --------------------------------------------------

type rcaHypBlob struct {
	Ranking struct {
		Hypotheses []struct {
			ID              string   `json:"id"`
			Title           string   `json:"title"`
			Confidence      float64  `json:"confidence"`
			ConfidenceLabel string   `json:"confidence_label"`
			Contradicted    bool     `json:"contradicted"`
			Contradictions  []string `json:"contradictions"`
			Satisfied       []string `json:"satisfied"`
			Missing         []string `json:"missing"`
			BlastRadius     string   `json:"blast_radius"`
			Verdict         struct {
				Tier              string   `json:"verdict_tier"`
				Owner             string   `json:"owner"`
				Layer             string   `json:"layer"`
				Reasons           []string `json:"reasons"`
				FirstSteps        []string `json:"first_steps"`
				IndependentPair   []string `json:"independent_pair"`
				ModalityCoverage  []string `json:"modality_coverage"`
				ObserverCoverage  []string `json:"observer_coverage"`
				TrustedModalities []string `json:"trusted_modalities"`
			} `json:"verdict"`
		} `json:"hypotheses"`
	} `json:"ranking"`
	GroundingContext struct {
		Seams []struct {
			SeamID   string `json:"seam_id"`
			SeamType string `json:"seam_type"`
		} `json:"seams"`
	} `json:"grounding_context"`
}

func decodeHypotheses(meta map[string]any) rcaHypBlob {
	var hb rcaHypBlob
	if h, ok := meta["hypotheses"].(string); ok && h != "" {
		// best-effort: absent/malformed blob → empty ranking (renders honestly)
		_ = json.Unmarshal([]byte(h), &hb)
	}
	return hb
}

// ---- the builder ---------------------------------------------------------------

type rcaReportInput struct {
	ID      string
	Meta    map[string]any
	Signals []map[string]any // AFTER mergeTimelineEvidence (attached/link_status stamped)
	Edges   []map[string]any
	Ticket  map[string]any // ticketStatusView output ("state": …)
	Policy  incidentPolicy
	// PolicyConfigured: false → Policy is the platform default, and the report
	// says so instead of implying tenant intent.
	PolicyConfigured bool
	Path             any // rcaPathBlock output (may be nil)
	Now              time.Time
}

func buildRcaReport(in rcaReportInput) rcaReport {
	meta := in.Meta
	hb := decodeHypotheses(meta)
	verdict := strings.ToLower(fmt.Sprintf("%v", meta["verdict_tier"]))
	state := strings.ToLower(fmt.Sprintf("%v", meta["state"]))
	// The ranking blob is the live analysis; the scalar column can lag it
	// (Phase 0 finding D1b: report title disagreed with the workspace on the
	// same case). Prefer the ranking's leader whenever it is present.
	topHyp := fmt.Sprintf("%v", meta["top_hypothesis"])
	if len(hb.Ranking.Hypotheses) > 0 && hb.Ranking.Hypotheses[0].ID != "" {
		topHyp = hb.Ranking.Hypotheses[0].ID
	}
	version := int(asFloat(meta["version"]))

	// ---- classify the slice ----------------------------------------------------
	var (
		anomalous, clears            []map[string]any
		observers                    = map[string]bool{}
		laneTotal, laneAnomalous     = map[string]int{}, map[string]int{}
		laneMin, laneMax             = map[string]time.Time{}, map[string]time.Time{}
		firstObs, lastObs, recovered time.Time
		peakSevRank                  int
		peakSev                      = "unknown"
		impactAnomalies              int
		impactSynthetic              int
		impactRealUser               int
		realUserLanesPresent         bool
		impactLanesPresent           bool
		changes                      []rcaCloudChange
		stateUps                     []rcaStateUp
	)
	sevRank := map[string]int{"info": 1, "warn": 2, "high": 3, "crit": 4}
	for _, sig := range in.Signals {
		kind := fmt.Sprintf("%v", sig["kind"])
		lane := fmt.Sprintf("%v", sig["modality_class"])
		attached, _ := sig["attached"].(bool)
		ts, tsOK := parseChTS(fmt.Sprintf("%v", sig["ts"]))
		if tsOK {
			if laneMin[lane].IsZero() || ts.Before(laneMin[lane]) {
				laneMin[lane] = ts
			}
			if ts.After(laneMax[lane]) {
				laneMax[lane] = ts
			}
		}
		laneTotal[lane]++
		// Semantic recovery evidence (§17): status lanes signal recovery as
		// state=up/established events, not *_clear kinds. Buffer them — only
		// an up observed AFTER the first anomaly is recovery (a healthy
		// assertion from before the fault proves nothing about it).
		if rcaIsRecoveryStateSignal(sig) {
			if tsOK {
				stateUps = append(stateUps, rcaStateUp{sig: sig, ts: ts})
			}
			continue
		}
		isClear := strings.HasSuffix(kind, "_clear")
		if isClear {
			clears = append(clears, sig)
			// recovery time = observed clear evidence only (clear_ts wins over ts)
			ct, ok := parseChTS(fmt.Sprintf("%v", sig["clear_ts"]))
			if !ok {
				ct, ok = ts, tsOK
			}
			if ok && ct.After(recovered) {
				recovered = ct
			}
			continue
		}
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			observers[o] = true
		}
		if !attached {
			continue
		}
		anomalous = append(anomalous, sig)
		laneAnomalous[lane]++
		if tsOK {
			if firstObs.IsZero() || ts.Before(firstObs) {
				firstObs = ts
			}
			if ts.After(lastObs) {
				lastObs = ts
			}
		}
		sev := strings.ToLower(fmt.Sprintf("%v", sig["severity"]))
		if sevRank[sev] > peakSevRank {
			peakSevRank, peakSev = sevRank[sev], sev
		}
		entityType := fmt.Sprintf("%v", sig["entity_type"])
		probeScope := fmt.Sprintf("%v", sig["probe_scope"])
		if rcaIsRealUserImpactKind(kind, entityType) {
			impactAnomalies++
			impactRealUser++
		} else if rcaIsSyntheticImpactKind(kind, probeScope) {
			impactAnomalies++
			impactSynthetic++
		}
		if rcaCloudChangeKinds[kind] {
			changes = append(changes, decodeCloudChange(sig, true))
		}
	}
	// unattached cloud changes in the window still matter (§8) — temporal context
	for _, sig := range in.Signals {
		kind := fmt.Sprintf("%v", sig["kind"])
		attached, _ := sig["attached"].(bool)
		if rcaCloudChangeKinds[kind] && !attached && !strings.HasSuffix(kind, "_clear") {
			changes = append(changes, decodeCloudChange(sig, false))
		}
	}
	// any lane that could carry customer impact present at all?
	for _, lane := range []string{"active_probe", "passive_flow"} {
		if laneTotal[lane] > 0 {
			impactLanesPresent = true
		}
	}
	// real-user impact is observable only where real-traffic telemetry exists:
	// the passive-flow lane, or LB/app-edge kinds (they ride device_telemetry).
	realUserLanesPresent = laneTotal["passive_flow"] > 0 || impactRealUser > 0
	for _, sig := range in.Signals {
		switch fmt.Sprintf("%v", sig["kind"]) {
		case "lb_5xx", "lb_target_unhealthy", "app_error_rate_high", "app_latency_high", "lb_4xx_high":
			realUserLanesPresent = true
		}
	}

	// ---- states -------------------------------------------------------------------
	// Recovery is an ASSESSMENT, not a synonym for "the window closed": an
	// object that quiesced because its signals aged out has merely stopped
	// being observed (§17 — "no additional data" is not "successful recovery").
	// Merge buffered semantic up-events: only those after the first anomaly
	// are recovery evidence for THIS fault.
	for _, su := range stateUps {
		if !firstObs.IsZero() && su.ts.After(firstObs) {
			clears = append(clears, su.sig)
			if su.ts.After(recovered) {
				recovered = su.ts
			}
		}
	}
	recoveryState, recoveryBasis := "not_observed", "No recovery evidence was captured."
	if !recovered.IsZero() {
		recoveryState = "explicitly_confirmed"
		recoveryBasis = fmt.Sprintf("%s; last clear observed %s.", countNoun(len(clears), "recovery signal"), fmtUTC(recovered))
	}
	incident := "active"
	switch {
	case state == "merged":
		incident = "closed"
	case state == "closed" && recoveryState == "explicitly_confirmed":
		incident = "recovered"
	case state == "closed":
		incident = "no_longer_observed"
	case len(clears) > 0:
		incident = "recovering"
	}

	analysis := "observed"
	label := ""
	contradictedTop := false
	if len(hb.Ranking.Hypotheses) > 0 {
		h0 := hb.Ranking.Hypotheses[0]
		label = strings.ToLower(h0.ConfidenceLabel)
		contradictedTop = h0.Contradicted
	}
	switch {
	case verdict == "confirmed":
		analysis = "confirmed"
	case label == "likely":
		analysis = "probable"
	case verdict == "suspected":
		analysis = "suspected"
	}
	if contradictedTop && analysis != "confirmed" {
		// leading cause ruled out and nothing confirmed → the analysis is honest
		// about being inconclusive, not "suspected" of a dead hypothesis.
		alive := false
		for _, h := range hb.Ranking.Hypotheses {
			if !h.Contradicted && (h.Confidence > 0 || len(h.Satisfied) > 0) {
				alive = true
				break
			}
		}
		if !alive {
			analysis = "inconclusive"
		}
	}

	impact := "unknown"
	switch {
	case analysis == "confirmed" && impactAnomalies > 0:
		impact = "confirmed"
	case impactAnomalies > 0:
		impact = "detected"
	case impactLanesPresent:
		impact = "none_detected"
	default:
		impact = "not_observable"
	}
	// §5 axes. A failed configured check IS the synthetic-transaction impact —
	// a fact, not a hypothesis. Real-user impact needs real-traffic evidence.
	impactSyn := "not_observable"
	switch {
	case impactSynthetic > 0:
		impactSyn = "confirmed"
	case laneTotal["active_probe"] > 0:
		impactSyn = "none_detected"
	}
	impactRU := "not_observable"
	switch {
	case impactRealUser > 0 && analysis == "confirmed":
		impactRU = "confirmed"
	case impactRealUser > 0:
		impactRU = "detected"
	case realUserLanesPresent:
		impactRU = "none_detected"
	}

	ticketState := "not_opened"
	if in.Ticket != nil {
		switch fmt.Sprintf("%v", in.Ticket["state"]) {
		case "open", "updated", "pending":
			ticketState = "opened"
		case "resolved":
			ticketState = "resolved"
		case "failed":
			ticketState = "failed"
		default:
			ticketState = "not_opened"
		}
	}
	if ticketState == "not_opened" && analysis != "confirmed" && len(anomalous) > 0 {
		ticketState = "held" // policy hold, stated with its policy below
	}

	// ---- confidence (engine-derived, basis stated) -------------------------------
	confidence, basis := "Low", "single evidence class; no independent corroboration"
	if len(hb.Ranking.Hypotheses) > 0 {
		v := hb.Ranking.Hypotheses[0].Verdict
		nMod, nObs := len(v.ModalityCoverage), len(v.ObserverCoverage)
		switch {
		case analysis == "confirmed":
			confidence = "High"
			basis = fmt.Sprintf("independent confirmation across %d evidence classes and %d observers", nMod, nObs)
		case nMod >= 2 && nObs >= 2:
			confidence = "Medium"
			basis = fmt.Sprintf("%d evidence classes from %d observers align, but no fully independent confirming pair", nMod, nObs)
		default:
			basis = fmt.Sprintf("evidence rests on %s from %s", countNoun(maxInt(nMod, 1), "evidence class"), strings.ToLower(countNoun(maxInt(nObs, 1), "observer")))
		}
	}

	// ---- times -------------------------------------------------------------------
	times := rcaReportTimes{
		WindowStart:   fmt.Sprintf("%v", meta["window_start"]),
		WindowEnd:     fmt.Sprintf("%v", meta["window_end"]),
		DurationBasis: "unknown",
	}
	if !firstObs.IsZero() {
		times.FirstObserved = fmtUTC(firstObs)
	}
	if !lastObs.IsZero() {
		times.LastAnomalous = fmtUTC(lastObs)
	}
	if !recovered.IsZero() && (incident == "recovered" || incident == "recovering" || incident == "closed") {
		times.RecoveredAt = fmtUTC(recovered)
		times.RecoveredCaptured = true
	}
	switch {
	case times.RecoveredCaptured && !firstObs.IsZero():
		times.DurationMS = recovered.Sub(firstObs).Milliseconds()
		times.DurationBasis = "to_recovery"
	case incident == "active" && !firstObs.IsZero():
		times.DurationMS = in.Now.Sub(firstObs).Milliseconds()
		times.DurationBasis = "elapsed_still_active"
	case !firstObs.IsZero() && !lastObs.IsZero():
		times.DurationMS = lastObs.Sub(firstObs).Milliseconds()
		times.DurationBasis = "to_last_observation"
	}
	monitorWindow := time.Duration(in.Policy.SuppressFlappingSeconds) * time.Second
	if monitorWindow <= 0 {
		monitorWindow = 30 * time.Minute
	}
	// Monitoring state is evaluated against report-generation time (§17): a
	// window that ended before this report was generated is COMPLETED, never
	// described as still running.
	monitoring := "not_started"
	if times.RecoveredCaptured {
		until := recovered.Add(monitorWindow)
		times.MonitoringUntil = fmtUTC(until)
		if in.Now.Before(until) {
			monitoring = "active"
		} else {
			monitoring = "completed"
		}
	}

	// ---- scope -------------------------------------------------------------------
	scope := buildRcaScope(meta, anomalous, hb)

	// ---- signal summary ------------------------------------------------------------
	sigSummary := buildSignalSummary(in.Signals, anomalous, clears, observers, peakSev, hb)

	// ---- evidence coverage ----------------------------------------------------------
	coverage := buildEvidenceCoverage(laneTotal, laneAnomalous, laneMin, laneMax, hb)

	// ---- cloud change correlation -----------------------------------------------------
	for i := range changes {
		classifyCloudChange(&changes[i], firstObs, scope)
	}
	sort.SliceStable(changes, func(i, j int) bool { return changes[i].At < changes[j].At })

	// ---- hypotheses --------------------------------------------------------------------
	hyps := buildHypothesesView(hb)

	// ---- root cause ----------------------------------------------------------------------
	root := rcaRootCause{Identified: false, Statement: "Root cause has not been identified."}
	if analysis == "confirmed" {
		locus := groundedLocus(in.Edges)
		if locus != "" {
			root = rcaRootCause{
				Identified: true,
				Statement:  fmt.Sprintf("Fault localized to %s by independent evidence.", aiEntityLabel(locus)),
				Object:     locus,
				ObjectType: "grounded entity",
			}
			if len(hb.Ranking.Hypotheses) > 0 {
				root.Owner = rcaOwnerTeam[hb.Ranking.Hypotheses[0].Verdict.Owner]
				root.Evidence = aiHumanizeMissing(hb.Ranking.Hypotheses[0].Satisfied)
			}
		} else {
			root.Statement = "The fault condition is confirmed, but the evidence does not converge on a single root-cause object."
		}
	}

	// ---- ownership ---------------------------------------------------------------------------
	ownership := buildOwnership(analysis, hb, sigSummary)

	// ---- decision (policy-driven) ---------------------------------------------------------------
	decision := buildDecision(analysis, incident, impact, in.Policy, in.PolicyConfigured, monitorWindow)

	// ---- wording ----------------------------------------------------------------------------------
	title, subtitle, problemNoun := buildRcaTitle(topHyp, analysis, incident, scope, laneAnomalous, changes)
	whySusp, whyNot, required := buildWhyWording(analysis, hb, sigSummary, laneAnomalous)

	mgmt := buildManagementSummary(problemNoun, scope, times, incident, analysis, impact, impactRU, monitoring, decision, sigSummary, monitorWindow)

	// ---- actions -----------------------------------------------------------------------------------
	actions := buildActions(analysis, hb, sigSummary, decision, ownership)

	// ---- NOC quick-read -------------------------------------------------------------------------------
	noc := buildNocQuickRead(incident, recoveryState, analysis, impact, impactSyn, impactRU, ticketState, monitoring, times, scope, sigSummary, coverage, ownership, actions)

	rep := rcaReport{
		ReportID:      "rr-" + strings.ReplaceAll(in.ID, "-", "")[:12] + fmt.Sprintf("-v%d", version),
		CorrelationID: in.ID,
		DisplayID:     problemDisplayID(in.ID),
		Version:       version,
		ReportType:    reportTypeFor(analysis),
		Title:         title,
		Subtitle:      subtitle,
		GeneratedAt:   fmtUTC(in.Now),
		States: rcaReportStates{
			Incident: incident, Recovery: recoveryState, RecoveryBasis: recoveryBasis,
			Analysis: analysis, Impact: impact,
			ImpactSynthetic: impactSyn, ImpactRealUser: impactRU,
			Ticket: ticketState,
			Severity: peakSev, Monitoring: monitoring,
			Confidence: confidence, ConfidenceBasis: basis,
		},
		Times:            times,
		Scope:            scope,
		Summary:          rcaReportSummaries{Management: mgmt, Noc: noc, WhySuspected: whySusp, WhyNotConfirmed: whyNot, RequiredConfirm: required},
		Signals:          sigSummary,
		Coverage:         coverage,
		CloudChanges:     changes,
		Hypotheses:       hyps,
		SingleHypothesis: len(hyps) <= 1,
		RootCause:        root,
		Ownership:        ownership,
		Decision:         decision,
		Actions:          actions,
		Ticket:           in.Ticket,
		Path:             in.Path,
	}
	return rep
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// reportTypeFor — the document may only call itself an RCA when a root cause
// analysis actually concluded (§2 of the directive).
func reportTypeFor(analysis string) string {
	switch analysis {
	case "confirmed":
		return "Root Cause Analysis"
	case "probable":
		return "Preliminary Root Cause Analysis"
	case "inconclusive":
		return "Incident Analysis — Cause Inconclusive"
	default:
		return "Incident Assessment"
	}
}

// groundedLocus — the entity the grounded topo edges converge on (same rule the
// rca-path-view uses; duplicated intentionally small to stay pure/local).
func groundedLocus(edges []map[string]any) string {
	shareCount := map[string]int{}
	for _, e := range edges {
		if fmt.Sprintf("%v", e["grounding_kind"]) == "topo" {
			if ref := fmt.Sprintf("%v", e["grounding_ref"]); strings.HasPrefix(ref, "shared:") {
				shareCount[strings.TrimPrefix(ref, "shared:")]++
			}
		}
	}
	locus, best := "", 0
	for k, n := range shareCount {
		if n > best || (n == best && (locus == "" || k < locus)) {
			best, locus = n, k
		}
	}
	return locus
}

func decodeCloudChange(sig map[string]any, attached bool) rcaCloudChange {
	attrs := map[string]any{}
	if a, ok := sig["attrs"].(string); ok && a != "" {
		_ = json.Unmarshal([]byte(a), &attrs)
	}
	str := func(k string) string {
		if v, ok := attrs[k]; ok && v != nil {
			return fmt.Sprintf("%v", v)
		}
		return ""
	}
	provider := str("provider")
	if provider == "" {
		src := str("event_source")
		switch {
		case strings.Contains(src, "amazonaws"), strings.Contains(src, "aws"):
			provider = "AWS"
		case strings.Contains(src, "azure"), strings.Contains(src, "microsoft"):
			provider = "Azure"
		case strings.Contains(src, "google"), strings.Contains(src, "gcp"):
			provider = "GCP"
		}
	}
	at := ""
	if t, ok := parseChTS(fmt.Sprintf("%v", sig["ts"])); ok {
		at = fmtUTC(t)
	}
	res := str("resource_id")
	if res == "" {
		res = fmt.Sprintf("%v", sig["entity_id"])
	}
	return rcaCloudChange{
		Kind: fmt.Sprintf("%v", sig["kind"]), Provider: provider,
		EventSource: str("event_source"), RequestID: str("request_id"),
		Account: str("account"), Region: str("region"),
		Resource: res, Actor: str("actor"), At: at, Attached: attached,
	}
}

func classifyCloudChange(c *rcaCloudChange, firstObs time.Time, scope rcaReportScope) {
	if t, ok := parseChTS(strings.TrimSuffix(c.At, " UTC")); ok && !firstObs.IsZero() {
		d := int64(t.Sub(firstObs).Seconds())
		c.DeltaSeconds = &d
	}
	inScope := func(list []string, v string) bool {
		for _, s := range list {
			if v != "" && (s == v || strings.Contains(s, v) || strings.Contains(v, s)) {
				return true
			}
		}
		return false
	}
	switch {
	case inScope(scope.Services, c.Resource) || inScope(scope.Targets, c.Resource):
		c.Relationship = "same_resource"
	case c.Attached:
		c.Relationship = "same_service"
	case inScope(scope.Regions, c.Region) || inScope(scope.Accounts, c.Account):
		c.Relationship = "same_account_region"
	default:
		c.Relationship = "temporal_only"
	}
	// Honest, non-causal explanation (§8: temporal proximity never confirms).
	when := "in the incident window"
	if c.DeltaSeconds != nil {
		d := *c.DeltaSeconds
		if d <= 0 {
			when = fmt.Sprintf("%s before the first anomalous observation", fmtDur(time.Duration(-d)*time.Second))
		} else {
			when = fmt.Sprintf("%s after the first anomalous observation", fmtDur(time.Duration(d)*time.Second))
		}
	}
	switch c.Relationship {
	case "same_resource":
		c.Explanation = fmt.Sprintf("A %s change occurred %s and touched a resource mapped to the affected service. The timing and resource relationship support investigation, but causation is not confirmed.", orDefault(c.Provider, "cloud"), when)
	case "same_service":
		c.Explanation = fmt.Sprintf("A %s change occurred %s and is correlated into this case as evidence. Causation is not confirmed.", orDefault(c.Provider, "cloud"), when)
	case "same_account_region":
		c.Explanation = fmt.Sprintf("A %s change occurred %s in the same account/region. No direct resource relationship to the affected service was demonstrated.", orDefault(c.Provider, "cloud"), when)
	default:
		c.Explanation = fmt.Sprintf("A %s change occurred %s. Only temporal proximity relates it to this incident — no resource or service relationship was demonstrated.", orDefault(c.Provider, "cloud"), when)
	}
}
