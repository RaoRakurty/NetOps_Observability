// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

import (
	"regexp"
	"sort"
	"strings"
)

// quality.go — the reusable AI Response Quality Layer. It turns the engine's raw
// verdicts, evidence keys, owners and signals into NOC-friendly, deduplicated,
// action-oriented language used by EVERY answer mode — not one-off RCA
// formatting. Everything here is pure + deterministic (no LLM, no store), so it
// runs identically in the model-grounded path and the evidence-only fallback,
// and is unit-testable. See docs/design/ai-response-quality.md.

// ---- status / RCA maturity (spec §8) ----------------------------------------

// StatusLabel maps an engine verdict to a NOC-facing status word.
func StatusLabel(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return "Confirmed"
	case "suspected":
		return "Suspected"
	case "candidate":
		return "Candidate"
	case "undetermined", "":
		return "Undetermined"
	default:
		return capitalize(verdict)
	}
}

// MaturitySentence is the one-line "what this verdict means" in plain language,
// honest about evidence (never overclaims a confirmed RCA — spec §20).
func MaturitySentence(verdict string, signals, nodes int) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return "Correlix confirmed this fault domain — the supporting evidence aligned across independent signals."
	case "suspected":
		return "Correlix suspects this fault domain based on multiple supporting signals; final validation is not complete."
	case "candidate":
		return "Correlix identified this as a candidate fault domain, but the evidence is still weak."
	default:
		if signals <= 1 && nodes <= 1 {
			return "Correlix does not have enough evidence yet to determine a root cause — only one signal was observed on one device."
		}
		return "Correlix does not have enough evidence yet to determine a root cause; the available signals are thin or conflicting."
	}
}

// ---- confidence (spec §10, §19) ---------------------------------------------

// ConfidenceLabel renders confidence for a NOC reader. An undetermined verdict
// or a zero score reads as "Not established" — never a bare "0%" headline.
func ConfidenceLabel(conf float64, verdict string) string {
	v := strings.ToLower(strings.TrimSpace(verdict))
	if v == "undetermined" || v == "" || conf <= 0 {
		return "Not established"
	}
	switch {
	case conf >= 0.85:
		return "High"
	case conf >= 0.6:
		return "Moderate"
	case conf >= 0.35:
		return "Low"
	default:
		return "Very low"
	}
}

// ---- evidence keys (spec §11) -----------------------------------------------

// evidenceKeyLabel maps a raw engine evidence/signal key to operational language.
var evidenceKeyLabel = map[string]string{
	"ospf_adjacency_change":        "OSPF adjacency-change signal",
	"isis_adjacency_change":        "IS-IS adjacency-change signal",
	"bgp_adjacency_change":         "BGP adjacency-change signal",
	"bgp_state_anomaly":            "BGP state-change signal",
	"link_state_change":            "Link up/down signal",
	"probe_loss":                   "Probe packet-loss evidence",
	"probe_rtt_anomaly":            "Probe latency anomaly",
	"if_metric_anomaly":            "Interface metric anomaly",
	"if_errors":                    "Interface error counters",
	"if_util_high":                 "High interface utilization",
	"device_resource_anomaly":      "Device CPU/memory anomaly",
	"firewall_deny":                "Firewall deny event",
	"firewall_session_utilization": "Firewall session-utilization signal",
	"flow_retries":                 "Flow retry/retransmission evidence",
	"flow_volume_anomaly":          "Traffic-volume anomaly",
	"app_latency":                  "Application latency evidence",
	"db_latency":                   "Database latency evidence",
	"query_latency":                "Database query-latency evidence",
	"cloud_app_health":             "Cloud/SaaS application-health signal",
	"saas_anomaly":                 "SaaS anomaly",
	"tunnel_flap":                  "Tunnel flap signal",
	"tunnel_degraded":              "Tunnel-degradation signal",
}

var reEvidenceKey = regexp.MustCompile(`[a-z][a-z0-9]+(?:_[a-z0-9]+)+`)

// evidenceKeyToLabel renders one raw key; unknown keys are cleaned (underscores →
// spaces, title-ish) so nothing reads like a debug token, but stay recognizable.
func evidenceKeyToLabel(key string) string {
	key = strings.ToLower(strings.TrimSpace(key))
	if l, ok := evidenceKeyLabel[key]; ok {
		return l
	}
	return capitalize(strings.ReplaceAll(key, "_", " ")) + " signal"
}

// FormatMissingEvidence turns the engine's raw missing-evidence lines (which
// embed keys like "needs ospf_adjacency_change") into clean operational bullets:
// "OSPF adjacency-change signal was not found." Deduplicated, order-stable.
func FormatMissingEvidence(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		// Prefer the key after "needs <key>"; else the first snake_case token.
		key := ""
		if i := strings.LastIndex(strings.ToLower(l), "needs "); i >= 0 {
			key = strings.TrimSpace(l[i+6:])
			key = strings.Fields(key + " ")[0]
		}
		if !reEvidenceKey.MatchString(key) {
			if m := reEvidenceKey.FindString(strings.ToLower(l)); m != "" {
				key = m
			}
		}
		var bullet string
		if reEvidenceKey.MatchString(key) {
			bullet = evidenceKeyToLabel(key) + " was not found"
		} else {
			// No machine key — fall back to the (already-humanized) line, trimmed.
			bullet = strings.TrimRight(strings.TrimSpace(l), ".")
		}
		if bullet == "" || seen[bullet] {
			continue
		}
		seen[bullet] = true
		out = append(out, bullet)
	}
	return out
}

// ---- recommended owner inference (spec §13) ---------------------------------

// ownerRule maps a domain token (found in signals/missing-evidence/title) to a team.
type ownerRule struct {
	re   *regexp.Regexp
	team string
}

var ownerRules = []ownerRule{
	{regexp.MustCompile(`ospf|isis|bgp|adjacency|routing|route`), "Network / Routing team"},
	{regexp.MustCompile(`firewall|security|deny|session_util|policy`), "Network / Security team"},
	{regexp.MustCompile(`db_latency|query_latency|database`), "Database team"},
	{regexp.MustCompile(`flow_retr|app_to_db|retransmission`), "Network / Application team (DB secondary)"},
	{regexp.MustCompile(`probe_loss|probe_rtt|dia|provider|isp|middle-mile`), "Network / Provider team"},
	{regexp.MustCompile(`if_error|link_down|link_state|interface|uplink`), "Network team"},
	{regexp.MustCompile(`cloud|saas|app_health`), "Cloud / Application team"},
	{regexp.MustCompile(`sdwan|tunnel|overlay|ipsec`), "Network / SD-WAN team"},
	{regexp.MustCompile(`servicenow|webhook|sync|integration`), "Platform / Integration owner"},
	{regexp.MustCompile(`app_identification|low_confidence|vendor`), "Network Observability / App-Mapping owner"},
	{regexp.MustCompile(`cpu|memory|resource|hardware|fabric|device`), "Network / Compute team"},
}

// InferOwner returns the explicit owner if present, else a provisional team
// inferred from the incident's domain tokens, else "Needs triage" — never a bare
// "unassigned" when a domain can be inferred (spec §13).
func InferOwner(explicit string, hints ...string) string {
	e := strings.TrimSpace(explicit)
	if e != "" && !strings.EqualFold(e, "unassigned") && !strings.EqualFold(e, "none") {
		return e
	}
	hay := strings.ToLower(strings.Join(hints, " "))
	for _, r := range ownerRules {
		if r.re.MatchString(hay) {
			return r.team + ", pending confirmation"
		}
	}
	return "Needs triage"
}

// ---- next actions (spec §14) ------------------------------------------------

// NextActionsRCA generates concrete next steps for an RCA answer, tuned to the
// verdict + what evidence is missing.
func NextActionsRCA(verdict string, devices []string, missingRaw []string) []string {
	dev := "the affected device"
	if len(devices) == 1 {
		dev = devices[0]
	} else if len(devices) > 1 {
		dev = devices[0] + " and peers"
	}
	hay := strings.ToLower(strings.Join(missingRaw, " "))
	var acts []string
	switch {
	case strings.Contains(hay, "ospf") || strings.Contains(hay, "isis") || strings.Contains(hay, "bgp") || strings.Contains(hay, "adjacency"):
		acts = append(acts,
			"Check OSPF/IS-IS/BGP neighbor state on "+dev+".",
			"Review "+dev+" syslog and routing events during the incident window.",
			"Confirm routing-adjacency telemetry is enabled and being ingested.")
	case strings.Contains(hay, "probe") || strings.Contains(hay, "loss") || strings.Contains(hay, "rtt"):
		acts = append(acts, "Check probe loss/latency on the affected path and compare vantage points.")
	case strings.Contains(hay, "firewall") || strings.Contains(hay, "deny"):
		acts = append(acts, "Review firewall deny events and session utilization for the affected policy.")
	}
	if strings.EqualFold(strings.TrimSpace(verdict), "undetermined") {
		acts = append(acts,
			"Compare "+dev+" against peer devices for similar signals.",
			"Keep RCA status as undetermined until additional evidence confirms the fault domain.")
	} else {
		acts = append(acts, "Validate the suspected fault domain and collect the missing evidence.")
	}
	return dedupeLines(acts)
}

// ---- priority ranking (spec §16 + current-state issue) ----------------------

// IsClassified reports whether a problem has a real signature pattern (vs a
// low-evidence / unclassified placeholder title), used by the priority score and
// the "why this is first" wording.
func IsClassified(title string) bool {
	t := strings.ToLower(title)
	return t != "" && !strings.Contains(t, "low-evidence") && !strings.Contains(t, "unclassified") && !strings.HasPrefix(t, "correlation ")
}

// PriorityScore ranks an active incident by OPERATIONAL priority, never recency:
// confirmed > suspected > candidate > undetermined; classified > unclassified;
// multi-signal/multi-node and higher confidence/blast-radius score higher. A
// low-evidence single-node undetermined item scores near zero, so it can't out-
// rank a suspected classified incident (the bug the operator flagged).
func PriorityScore(pr Problem) float64 {
	s := 0.0
	switch strings.ToLower(strings.TrimSpace(pr.Verdict)) {
	case "confirmed":
		s += 1000
	case "suspected":
		s += 600
	case "candidate":
		s += 300
	}
	if IsClassified(pr.Title) {
		s += 200
	}
	s += clampF(float64(pr.SignalCount), 0, 20) * 6
	s += clampF(float64(pr.NodeCount), 0, 10) * 9
	s += clampF(float64(len(pr.Devices)), 0, 10) * 3
	s += pr.Confidence * 60 // confidence only meaningful when the verdict isn't undetermined
	return s
}

func clampF(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

// ---- internal-label scrub (spec §10) ----------------------------------------

var scrubReplacers = []struct {
	re   *regexp.Regexp
	with string
}{
	{regexp.MustCompile(`(?i)\bunclassified correlation\b`), "low-evidence correlation"},
	{regexp.MustCompile(`(?i)\bowner:\s*unassigned\b`), "Recommended owner: Needs triage"},
	{regexp.MustCompile(`(?i)\b0% confidence\b`), "confidence not established"},
	{regexp.MustCompile(`(?i)\b(null|nil|undefined)\b`), "not available"},
}

// Scrub translates residual internal/debug wording into operational language. A
// final safety net over composed text (the per-field mappers do the heavy work).
func Scrub(s string) string {
	for _, r := range scrubReplacers {
		s = r.re.ReplaceAllString(s, r.with)
	}
	return s
}

// ---- dedup (spec §15) -------------------------------------------------------

// dedupeLines drops exact-duplicate lines (case-insensitive, trimmed), order-stable.
func dedupeLines(lines []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, l := range lines {
		k := strings.ToLower(strings.TrimSpace(l))
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, l)
	}
	return out
}

// ---- incident counts (spec §6) ----------------------------------------------

// ComputeCounts derives the normalized, labeled incident-count set from the
// tenant-scoped active-correlation list. `capped` records that the list itself
// was capped by the store limit, so the counts are a lower bound (disclosed, not
// silently truncated — spec §7). Every category has ONE definition here so no two
// answers can show conflicting numbers.
func ComputeCounts(probs []Problem, capped bool) IncidentCounts {
	c := IncidentCounts{ActiveCorrelationGroups: len(probs), Capped: capped}
	for _, pr := range probs {
		switch strings.ToLower(strings.TrimSpace(pr.Verdict)) {
		case "confirmed":
			c.ConfirmedCount++
		case "suspected":
			c.SuspectedCount++
		case "candidate":
			c.CandidateCount++
		default:
			c.UndeterminedCount++
		}
	}
	c.ActionableIncidentsCount = c.ConfirmedCount + c.SuspectedCount + c.CandidateCount
	// In our model an undetermined correlation IS a low-evidence watch item.
	c.LowEvidenceWatchItemsCount = c.UndeterminedCount
	return c
}

// CountsLegend explains the count categories a card shows, so multiple numbers
// never read as conflicting (spec §6). Only the lines relevant to the non-zero
// categories are returned.
func (c IncidentCounts) CountsLegend() []string {
	var out []string
	out = append(out, "Active correlation groups: every correlation the engine is currently tracking.")
	if c.ActionableIncidentsCount > 0 {
		out = append(out, "Actionable incidents: confirmed or suspected — the prioritized NOC work queue.")
	}
	if c.UndeterminedCount > 0 {
		out = append(out, "Low-evidence watch items: undetermined correlations under investigation, not yet actionable.")
	}
	return out
}

// ---- evidence-only fallback badges (spec §3) --------------------------------

// FallbackBadges returns the small mode badge for an evidence-only answer. Just
// the neutral "Evidence-only mode" chip — the provider REASON ("not configured"
// / "unavailable") is carried once in Answer.ProviderNote as a small footer, so
// it is never a loud top badge or a main answer sentence (spec §1/§8).
func FallbackBadges(providerConfigured bool) []string {
	return []string{"Evidence-only mode"}
}

// ProviderFallbackNote is the SINGLE small provider-fallback line rendered once
// as a footer/badge (spec §1). Never used as the main answer sentence.
func ProviderFallbackNote(providerConfigured bool) string {
	if providerConfigured {
		return "Evidence-only mode: AI provider unavailable."
	}
	return "Evidence-only mode: AI provider not configured."
}

// sortedUnique is a small helper for badge/label sets.
func sortedUnique(in []string) []string {
	out := dedupeLines(in)
	sort.Strings(out)
	return out
}
