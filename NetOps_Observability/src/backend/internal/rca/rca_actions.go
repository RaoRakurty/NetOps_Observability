// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_actions.go — the contextual ActionPlanner (P1.13, audit D5).
//
// Actions are selected from the PARTICIPATING EVIDENCE and the current
// analytical state, never from the report title alone. Before an action
// renders, the planner validates that the evidence family the action
// interrogates actually took part in this incident: an IKE/child-SA step never
// appears on a flow-only SaaS case, and a Direct Connect/BGP step never
// appears when the only evidence is a cloud-flow anomaly.
//
// Expected outputs are matched by whole-word protocol tokens — never by raw
// substring (the old code matched "sa" inside "SaaS" and emitted IKE/child-SA
// output on application cases).
//
// Operational priority (owner's priority model): P1 = immediate restoration /
// containment, worked now; P2 = diagnostic confirmation, validation, coverage
// or prevention work that can follow stabilization. It is labelled separately
// from incident severity by design.

import (
	"fmt"
	"strings"
)

// ---- evidence families -----------------------------------------------------------

// rcaActionFamily is one protocol/evidence family an action can interrogate.
type rcaActionFamily struct {
	Name string
	// StepTokens: whole-word tokens in an action's text that place it in this
	// family (lower-case; matched against tokenized words, never substrings).
	StepTokens []string
	// EvidenceKinds: participating signal-kind prefixes/tokens that prove this
	// family's evidence took part in the incident.
	EvidenceKinds []string
	// Lanes: participating anomalous lanes that also satisfy the family.
	Lanes []string
	// ExpectedOutput: the concrete observable a step in this family yields.
	ExpectedOutput string
}

// The family table is data — extending a playbook means adding a row, never a
// case-specific conditional.
var rcaActionFamilies = []rcaActionFamily{
	{
		Name:           "ipsec",
		StepTokens:     []string{"ike", "ipsec", "dpd", "rekey", "sa", "selector"},
		EvidenceKinds:  []string{"ipsec", "tunnel"},
		ExpectedOutput: "IKE/child-SA state, last DPD result, and rekey timestamps from the gateway",
	},
	{
		Name:           "bgp",
		StepTokens:     []string{"bgp", "prefix", "prefixes", "adjacency", "neighbor", "neighbour"},
		EvidenceKinds:  []string{"bgp", "route", "routing"},
		ExpectedOutput: "session state, last reset reason, and prefix counts for the affected peer/session",
	},
	{
		Name:           "dns",
		StepTokens:     []string{"dns", "resolver", "resolution"},
		EvidenceKinds:  []string{"dns"},
		ExpectedOutput: "the DNS response code, answer set and resolved addresses from the configured resolver, plus an alternate-resolver comparison",
	},
	{
		Name:           "tls",
		StepTokens:     []string{"tls", "cert", "certificate", "handshake", "sni"},
		EvidenceKinds:  []string{"tls", "cert"},
		ExpectedOutput: "the TLS handshake result, certificate validity window, issuer and negotiated protocol version",
	},
	{
		Name:           "http",
		StepTokens:     []string{"http", "5xx", "url", "status"},
		EvidenceKinds:  []string{"http", "5xx"},
		ExpectedOutput: "the HTTP status code, response time, and a multi-vantage comparison of the same request",
	},
	{
		Name:           "lb",
		StepTokens:     []string{"balancer", "lb", "backend", "target"},
		EvidenceKinds:  []string{"lb_"},
		ExpectedOutput: "target-health states and backend error rates on the load balancer",
	},
	{
		Name:           "flow",
		StepTokens:     []string{"flow", "flows", "netflow", "traffic", "sampling", "collector"},
		EvidenceKinds:  []string{"flow"},
		Lanes:          []string{"passive_flow"},
		ExpectedOutput: "source/destination/application breakdown, observed volume versus baseline, sampling rate, and collector health for the affected flows",
	},
	{
		Name:           "interface",
		StepTokens:     []string{"interface", "link", "port", "errors", "optic"},
		EvidenceKinds:  []string{"interface", "link", "port"},
		Lanes:          []string{"control_plane", "device_telemetry"},
		ExpectedOutput: "interface admin/oper state, error and discard counters, and the active route toward the target",
	},
	{
		Name:           "device",
		StepTokens:     []string{"cpu", "memory", "device", "reboot", "process"},
		EvidenceKinds:  []string{"cpu", "memory", "device"},
		Lanes:          []string{"device_telemetry"},
		ExpectedOutput: "device reachability, CPU/memory utilisation versus baseline, and recent restart/process events",
	},
	{
		Name:           "path",
		StepTokens:     []string{"trace", "traceroute", "hop", "vantage", "ping", "reachability", "synthetic", "probe"},
		EvidenceKinds:  []string{"probe", "synthetic", "path"},
		Lanes:          []string{"active_probe"},
		ExpectedOutput: "the last responding hop and the first non-responding boundary (address, TTL, loss percentage per hop)",
	},
	{
		Name:           "cloud_route",
		StepTokens:     []string{"vpc", "vnet", "transit", "propagated", "blackhole"},
		EvidenceKinds:  []string{"cloud", "route"},
		ExpectedOutput: "the route-table entries for the affected prefix, next-hop/attachment state, and any recent route changes",
	},
}

// rcaTokenize splits an action step into lower-case word tokens (letters and
// digits only) so family matching is whole-word: "SaaS" ≠ "sa".
func rcaTokenize(s string) map[string]bool {
	out := map[string]bool{}
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out[b.String()] = true
			b.Reset()
		}
	}
	for _, r := range strings.ToLower(s) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			flush()
		}
	}
	flush()
	return out
}

// rcaStepFamilies returns the families a step's own wording places it in.
func rcaStepFamilies(step string) []rcaActionFamily {
	tokens := rcaTokenize(step)
	var out []rcaActionFamily
	for _, f := range rcaActionFamilies {
		for _, t := range f.StepTokens {
			if tokens[t] {
				out = append(out, f)
				break
			}
		}
	}
	return out
}

// rcaFamilyEvidencePresent reports whether the family's evidence participated.
func rcaFamilyEvidencePresent(f rcaActionFamily, kindCounts map[string]int, laneAnomalous map[string]int) bool {
	for kind := range kindCounts {
		for _, tok := range f.EvidenceKinds {
			if strings.Contains(kind, tok) {
				return true
			}
		}
	}
	for _, lane := range f.Lanes {
		if laneAnomalous[lane] > 0 {
			return true
		}
	}
	return false
}

// ---- the planner ------------------------------------------------------------------

type rcaActionInput struct {
	Analysis      string // observed | suspected | probable | confirmed | inconclusive
	Incident      string // active | recovering | recovered | no_longer_observed | closed
	Hyp           rcaHypBlob
	Signals       rcaSignalSummary
	Decision      rcaDecision
	Ownership     Ownership
	Ctx           rcaIssueContext // resolved issue context (applicable families)
	LaneAnomalous map[string]int
	KindCounts    map[string]int
	Residual      bool // anomalies continued after a component recovery
	Validation    bool
	// Merge: set on a merged/superseded source case. A merged source must NOT
	// continue issuing restoration actions — they belong to the surviving
	// incident (P1 merge ownership of side effects).
	Merge *rcaIncidentMerge
}

// planActions builds the ordered action list. Every emitted action passed the
// evidence-applicability gate; expected outputs are family-derived.
func planActions(in rcaActionInput) []rcaAction {
	// A merged source case issues no independent restoration/diagnostic work —
	// the surviving incident owns every action. The only action is coordination:
	// track the incident on the survivor (P1 merge ownership of side effects).
	if in.Merge != nil {
		survivor := "the surviving incident"
		if in.Merge.SurvivorResolved {
			survivor = "surviving incident " + in.Merge.SurvivingDisplayID
		}
		return []rcaAction{{
			Priority: 1, Action: "Track restoration, monitoring and ticketing on " + survivor,
			Owner: "NOC (incident coordination)", OperationalPriority: "P2", Purpose: "monitoring",
			ExpectedResult: "the surviving incident carries the transferred evidence, current phase, service-recovery state and ticket/escalation ownership from this merge forward",
		}}
	}
	stillFailing := in.Incident == "active" || in.Residual
	// P1 only for restoration work on a live, evidence-backed fault.
	runbookPriority := "P2"
	runbookPurpose := "discrimination"
	if stillFailing && (in.Analysis == "confirmed" || in.Analysis == "probable") {
		runbookPriority, runbookPurpose = "P1", "restoration"
	}

	var out []rcaAction
	add := func(a rcaAction) {
		a.Priority = len(out) + 1
		if a.OperationalPriority == "" {
			a.OperationalPriority = "P2"
		}
		out = append(out, a)
	}

	// (a) engine runbook first-steps — evidence-gated (P1.13 rule 1-3):
	// a step whose wording interrogates a protocol family requires that
	// family's evidence to have participated in THIS incident.
	if len(in.Hyp.Ranking.Hypotheses) > 0 {
		for _, step := range in.Hyp.Ranking.Hypotheses[0].Verdict.FirstSteps {
			if len(out) >= 3 {
				break
			}
			// Strict gate: EVERY family the step's wording interrogates must
			// have participating evidence. A step that mixes a present family
			// with an absent one (e.g. "examine the flow … verify IKE output")
			// is cross-issue contamination and is dropped whole.
			fams := rcaStepFamilies(step)
			applicable := true
			expected := ""
			for _, f := range fams {
				// the resolved issue context is the single applicability
				// authority (IssueContextResolver.applicable_actions)
				if !in.Ctx.familyApplicable(f.Name) {
					applicable = false
					break
				}
				if expected == "" {
					expected = f.ExpectedOutput
				}
			}
			if !applicable {
				continue // evidence for this step's family did not participate
			}
			if expected == "" {
				expected = "the specific observation that isolates the fault to, or clears, this step's domain"
			}
			add(rcaAction{
				Action: step, Owner: in.Ownership.TriageOwner,
				OperationalPriority: runbookPriority, Purpose: runbookPurpose,
				ExpectedResult: expected,
			})
		}
	}

	// (b) flow-anomaly validation playbook — when passive-flow evidence
	// participated and no active-check evidence corroborates, the FIRST work is
	// validating the observation itself (playbook G): scope, baseline,
	// collection health, then independent corroboration.
	flowOnly := in.LaneAnomalous["passive_flow"] > 0 && in.LaneAnomalous["active_probe"] == 0 &&
		in.LaneAnomalous["control_plane"] == 0 && in.LaneAnomalous["device_telemetry"] == 0
	if flowOnly {
		add(rcaAction{
			Action:              "Identify the source, destination, application, protocol/port and direction of the anomalous flows",
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "validation",
			ExpectedResult: "the affected traffic scope: source/destination pairs, application or service mapping, and flow direction",
		})
		add(rcaAction{
			Action:              "Compare the observed flow volume against the expected baseline for this scope and time of day",
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "validation",
			ExpectedResult: "observed versus baseline volume and whether the deviation reflects demand, path loss, a routing change, or collection loss",
		})
		add(rcaAction{
			Action:              "Validate flow-collector health and sampling for the reporting exporter",
			Owner:               "Platform operations",
			OperationalPriority: "P2", Purpose: "validation",
			ExpectedResult: "collector reachability, export continuity, and the configured sampling rate during the window",
		})
		add(rcaAction{
			Action:              "Obtain independent corroboration from an active check or application-health telemetry for the affected service",
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "discrimination",
			ExpectedResult: "an active-check or application-health observation that confirms or clears real session failures",
			EscalateWhen:   "an independent evidence class corroborates the traffic anomaly",
		})
	}

	// (c) probe forensics when the evidence is active-check-shaped
	if in.Signals.Probe != nil && in.Signals.Probe.Failed > 0 {
		add(rcaAction{
			Action:              "Inspect the most recent failed check transaction",
			Owner:               "NOC",
			OperationalPriority: map[bool]string{true: "P1", false: "P2"}[stillFailing],
			Purpose:             "discrimination",
			ExpectedResult:      "DNS result, resolved IP, TCP status, TLS status, HTTP status, response time, and the failure stage",
		})
		if in.Signals.Probe.IndependenceNote != "" && !strings.Contains(in.Signals.Probe.IndependenceNote, "established by the verdict gate") {
			add(rcaAction{
				Action:              "Validate vantage independence for the reporting checks",
				Owner:               "Platform operations",
				OperationalPriority: "P2", Purpose: "validation",
				ExpectedResult: "agent host, site, DNS resolver, upstream provider, and path overlap for each vantage",
			})
		}
		add(rcaAction{
			Action:              "Compare real traffic, load-balancer target health and application errors during the incident window",
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "discrimination",
			ExpectedResult: "request volume, completion rate, load-balancer target health, application error rate",
			EscalateWhen:   "real-user impact, flow loss, or application errors corroborate the checks",
		})
	}

	// (d) residual-degradation gate: while end-to-end checks still fail after a
	// component recovery, closing/monitoring is blocked by a P1 validation task.
	if in.Residual && stillFailing {
		add(rcaAction{
			Action:              "Validate end-to-end service recovery — component status recovered while service checks continued failing",
			Owner:               in.Ownership.TriageOwner,
			OperationalPriority: "P1", Purpose: "restoration",
			ExpectedResult: "passing end-to-end checks across every affected path, or the residual failing segment isolated",
			EscalateWhen:   "service checks are still failing after component recovery",
		})
	}

	if in.Analysis != "confirmed" {
		add(rcaAction{
			Action:              "Continue monitoring under the active policy",
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "monitoring",
			ExpectedResult: "auto-close after the stability window, reopen on recurrence",
			EscalateWhen:   in.Decision.EscalateWhen,
		})
	}

	// (e) differential control (§13): a single-vantage failure needs an
	// independent vantage before any target-side conclusion firms up.
	if in.Signals.Probe != nil && len(in.Signals.Probe.AffectedVantages) == 1 {
		add(rcaAction{
			Action:              fmt.Sprintf("Run the same check from an independent vantage (only %s has reported this)", in.Signals.Probe.AffectedVantages[0]),
			Owner:               "NOC",
			OperationalPriority: "P2", Purpose: "discrimination",
			ExpectedResult: "the same target's result from a second vantage — fails there too (target side) or only here (local side)",
		})
	}
	return out
}
