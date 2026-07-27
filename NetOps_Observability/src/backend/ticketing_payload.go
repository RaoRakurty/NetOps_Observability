package main

import (
	"encoding/json"
	"fmt"
	"netops/backend/internal/rca"
	"netops/backend/internal/ticketing"
	"sort"
	"strings"
	"time"
)

// ticketing_payload.go — pure assembly of the RCA correlation object into the
// facts the incident policy decides on, and the provider-agnostic ticket body.
//
// Single source of truth: buildRcaPathView already maps (meta, signals, edges)
// into the operator-facing RCA diagnosis (verdict, confidence, internal, title,
// summary, action, evidence, missing evidence, affected path, impacted apps).
// We REUSE that view rather than re-deriving any RCA decision here (no second
// brain that can drift). The functions below are deterministic and I/O-free, so
// they are unit-tested in isolation.

var corrSevRank = map[string]int{"info": 0, "warn": 1, "high": 2, "crit": 3}

// buildCorrTicketFacts projects the RCA object into policy-relevant facts. It
// takes the already-built rcaPathView (the RCA decision) plus the raw meta/
// signals it was built from (for severity, authority and window, which the view
// doesn't surface). No RCA re-decision — verdict/confidence/internal come
// straight from the view.
func buildCorrTicketFacts(meta map[string]any, sigRows []map[string]any, view rcaPathView) ticketing.CorrFacts {
	f := ticketing.CorrFacts{
		Verdict:    view.Verdict,
		Confidence: view.Confidence,
		Internal:   view.Internal,
		Validation: view.Validation,
		Signature:  strings.TrimSpace(fmt.Sprintf("%v", meta["top_hypothesis"])),
	}
	if f.Signature == "<nil>" {
		f.Signature = ""
	}

	// attached, non-clear signals = the evidence the engine actually used (same
	// filter buildRcaPathView applies).
	attached := attachedTicketSignals(sigRows)
	probes, others, authority := 0, 0, false
	peak := -1
	lanes, observers := map[string]bool{}, map[string]bool{}
	for _, sig := range attached {
		if r, ok := corrSevRank[strings.ToLower(fmt.Sprintf("%v", sig["severity"]))]; ok && r > peak {
			peak = r
		}
		lanes[fmt.Sprintf("%v", sig["modality_class"])] = true
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" && o != "<nil>" {
			observers[o] = true
		}
		if fmt.Sprintf("%v", sig["modality_class"]) == "active_probe" {
			probes++
			if a := strings.ToLower(fmt.Sprintf("%v", sig["probe_authority"])); a != "" && a != "none" && a != "low" && a != "<nil>" {
				authority = true
			}
		} else {
			others++
		}
	}
	// P1.11 severity discipline on the ticketing path too: a single
	// uncorroborated evidence stream (one modality class, one observer) never
	// carries CRIT into the ticket policy for an unconfirmed verdict — the same
	// generic cap the report's incident-severity model applies.
	if peak == corrSevRank["crit"] && f.Verdict != "confirmed" && len(lanes) <= 1 && len(observers) <= 1 {
		peak = corrSevRank["high"]
	}
	for sev, r := range corrSevRank {
		if r == peak {
			f.PeakSeverity = sev
		}
	}
	f.ProbeOnly = probes > 0 && others == 0
	f.LowAuthorityProbe = f.ProbeOnly && !authority

	// affected scope/entities come from the object's authoritative `affected`
	// projection (the engine's blast radius) plus the impacted apps the view
	// already named. Path src→dst is the most operator-legible scope.
	devices, paths, ifaces := parseAffectedScope(meta)
	f.AffectedEntities = dedupeNonEmpty(append(append(append([]string{}, devices...), ifaces...), paths...))
	f.ImpactedApps = append(f.ImpactedApps, view.AppImpact.apps()...)
	switch {
	case view.Path.Source != "" && view.Path.Destination != "":
		f.AffectedScope = view.Path.Source + " → " + view.Path.Destination
	case len(ifaces) > 0:
		f.AffectedScope = ifaces[0]
	case len(devices) > 0:
		f.AffectedScope = devices[0]
	case len(paths) > 0:
		f.AffectedScope = paths[0]
	case len(f.ImpactedApps) > 0:
		f.AffectedScope = f.ImpactedApps[0]
	}
	f.HasAffectedEntity = len(f.AffectedEntities) > 0 || len(f.ImpactedApps) > 0 ||
		(view.Path.Source != "" || view.Path.Destination != "")

	// observed window → persistence.
	f.WindowStart = parseCorrTime(meta["window_start"])
	f.WindowEnd = parseCorrTime(meta["window_end"])

	// Emitter-side consistency gate (audit D11 follow-through): the same facts
	// every destination system's message is built from are validated once, here,
	// so the sweeper/notify emitters can hold contradictory state with a reason.
	f.ConsistencyIssues = rca.TicketFactConsistencyIssues(
		strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", meta["state"]))), sigRows)
	return f
}

// buildTicketPayload assembles the provider-agnostic ticket body from the RCA
// view + facts + the deciding policy. Title is the RCA narration's title
// (already "Suspected|Confirmed <fault> on <entity>"); the body carries the
// diagnosis and a deep link, never raw alert text.
func buildTicketPayload(view rcaPathView, facts ticketing.CorrFacts, policy ticketing.IncidentPolicy, rcaBaseURL string) ticketing.Payload {
	p := ticketing.Payload{
		CorrObjectID:      view.CorrObjectID,
		ExternalSystem:    policy.ExternalSystem,
		Title:             view.Title,
		Verdict:           view.Verdict,
		Confidence:        view.Confidence,
		Signature:         facts.Signature,
		Summary:           view.Summary,
		RecommendedAction: view.RecommendedAction,
		Owner:             ownerOf(view.Annotations),
		AffectedScope:     facts.AffectedScope,
		AffectedEntities:  facts.AffectedEntities,
		MissingEvidence:   view.MissingEvidenceSummary,
		ImpactedApps:      facts.ImpactedApps,
		RCAURL:            rcaDeepLink(rcaBaseURL, view.CorrObjectID),
		AssignmentGroup:   policy.AssignmentGroup,
	}
	p.Impact, p.Urgency = ticketImpactUrgency(policy, view.Verdict, facts.PeakSeverity)
	p.EvidenceUsed = evidenceUsedLines(view.EvidenceSummary)
	if p.Title == "" {
		// Defensive: never ship a blank short description.
		verb := "Suspected"
		if view.Verdict == "confirmed" {
			verb = "Confirmed"
		}
		subj := facts.AffectedScope
		if subj == "" {
			subj = "network path"
		}
		p.Title = verb + " network fault on " + subj
	}
	return p
}

// ── helpers (pure) ───────────────────────────────────────────────────────────

// ticketImpactUrgency derives the ServiceNow impact/urgency from the RCA
// verdict + peak severity. The policy's per-verdict mapping wins when set
// (the customer decides, including demoting); an unset (0) slot falls back to
// the built-in escalation, which uses the policy defaults as the BASELINE and
// only ever makes a ticket MORE severe (numerically lower). ServiceNow computes
// Priority from its Impact×Urgency matrix, so with the 2/2 defaults:
//
//	confirmed + critical → 1/1 → P1 Critical
//	confirmed (other)    → 2/1 → P2 High
//	suspected            → policy defaults (2/2 → P3 Moderate)
//
// A confirmed root cause filing at the same P3 as a tentative suspicion was the
// 2026-07-11 operator complaint — the verdict was never consulted.
func ticketImpactUrgency(p ticketing.IncidentPolicy, verdict, peakSeverity string) (int, int) {
	if verdict != "confirmed" {
		return p.DefaultImpact, p.DefaultUrgency
	}
	if peakSeverity == "crit" {
		return orInt(p.ImpactConfirmedCritical, moreSevere(p.DefaultImpact, 1)),
			orInt(p.UrgencyConfirmedCritical, moreSevere(p.DefaultUrgency, 1))
	}
	// A confirmed root cause is always urgent — the RCA engine has already done
	// the triage a human would do before raising urgency.
	return orInt(p.ImpactConfirmed, p.DefaultImpact),
		orInt(p.UrgencyConfirmed, moreSevere(p.DefaultUrgency, 1))
}

// orInt returns v when set (>0), else the fallback.
func orInt(v, fallback int) int {
	if v > 0 {
		return v
	}
	return fallback
}

// moreSevere picks the more severe of two ServiceNow impact/urgency values
// (lower = more severe; 0 means "unset" and never wins).
func moreSevere(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 || a <= b {
		return a
	}
	return b
}

// attachedTicketSignals mirrors buildRcaPathView's attached filter: signals the
// engine attached, excluding *_clear recoveries.
func attachedTicketSignals(sigRows []map[string]any) []map[string]any {
	var out []map[string]any
	for _, sig := range sigRows {
		if b, _ := sig["attached"].(bool); !b {
			continue
		}
		if strings.HasSuffix(fmt.Sprintf("%v", sig["kind"]), "_clear") {
			continue
		}
		out = append(out, sig)
	}
	return out
}

// parseAffectedScope reads the object's `affected` JSON projection.
func parseAffectedScope(meta map[string]any) (devices, paths, ifaces []string) {
	s, _ := meta["affected"].(string)
	if s == "" || s == "{}" {
		return nil, nil, nil
	}
	var af struct {
		Devices    []string `json:"devices"`
		Paths      []string `json:"paths"`
		Interfaces []string `json:"interfaces"`
	}
	if json.Unmarshal([]byte(s), &af) != nil {
		return nil, nil, nil
	}
	return af.Devices, af.Paths, af.Interfaces
}

// apps returns the named impacted application labels (nil-safe).
func (ai *rcaAppImpact) apps() []string {
	if ai == nil {
		return nil
	}
	out := make([]string, 0, len(ai.Apps))
	for _, a := range ai.Apps {
		if a.App != "" {
			out = append(out, a.App)
		}
	}
	return out
}

// evidenceUsedLines surfaces the human-legible evidence the engine actually used
// (verdict reason + the independent confirming pair + decisive modalities),
// pulled from the RCA view's evidence_summary. Order is stable for hashing.
func evidenceUsedLines(summary map[string]any) []string {
	if summary == nil {
		return nil
	}
	var out []string
	if r, ok := summary["verdict_reason"].(string); ok && r != "" {
		out = append(out, r)
	}
	if pair, ok := summary["confirming_pair"].([]string); ok && len(pair) == 2 {
		out = append(out, "confirmed by "+pair[0]+" ⟂ "+pair[1])
	}
	if mods, ok := summary["decisive_modalities"].([]string); ok && len(mods) > 0 {
		out = append(out, "decisive: "+strings.Join(mods, ", "))
	}
	return out
}

func rcaDeepLink(base, id string) string {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	if base == "" {
		base = "/app"
	}
	return base + "/correlations/" + id
}

func parseCorrTime(v any) time.Time {
	s := strings.TrimSpace(fmt.Sprintf("%v", v))
	if s == "" || s == "<nil>" {
		return time.Time{}
	}
	for _, layout := range []string{"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

func dedupeNonEmpty(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
