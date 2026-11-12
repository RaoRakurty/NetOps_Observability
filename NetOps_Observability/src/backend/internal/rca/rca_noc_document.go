// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// rca_noc_document.go — the NOC RCA document (owner decisions D1/D3/D4,
// 2026-11-11, from the Fable review of P-424934).
//
// Three things live here:
//
//  1. The CONTEXT-STORY split (D1). A hypothesis that is a background story —
//     a standing posture or exposure finding co-occurring with a fault — is
//     taken out of the causal ranking before anything is worded. It is never
//     the headline, never counted as impact, never paints a break, and is
//     never the reason a document is promoted. It renders in the background
//     band instead.
//  2. The CONFIRMING PAIR (D3). The verdict's independent pair is read back
//     from the blob and each member's evidence plane looked up in the slice.
//     Security and the management plane are verdict planes: a pair with one of
//     them in it supports a verdict but does not anchor a document, a real-user
//     impact upgrade or an escalation.
//  3. The DOCUMENT projection: the ten sections in the order a NOC engineer
//     reads them (what broke · who is affected · when · cause and how sure ·
//     how we know · where the break is · background · other explanations ·
//     who owns the fix · what to do now), plus the "How to read this RCA"
//     guide. It reads fields the builder already derived — it decides nothing.

import (
	"encoding/json"
	"fmt"
	"netops/backend/internal/noclabel"
	"sort"
	"strings"
	"time"
)

// ---- D1: context stories ------------------------------------------------------

// isContextHyp — the engine's flag, or a pre-flag object's template id.
func isContextHyp(h rcaHypEntry) bool { return noclabel.IsContextStory(h.ID, h.ContextStory) }

// splitContextStories removes background stories from the ranking. The causal
// blob keeps every other field (grounding context) so the rest of the builder
// reads it exactly as before.
func splitContextStories(hb rcaHypBlob) (causal rcaHypBlob, background []rcaHypEntry) {
	causal = hb
	causal.Ranking.Hypotheses = nil
	for _, h := range hb.Ranking.Hypotheses {
		if isContextHyp(h) {
			background = append(background, h)
			continue
		}
		causal.Ranking.Hypotheses = append(causal.Ranking.Hypotheses, h)
	}
	return causal, background
}

var rcaTierRank = map[string]int{"undetermined": 0, "suspected": 1, "confirmed": 2}

// headlineVerdict — the verdict the document may speak. When the persisted top
// is causal it is the object's own tier. When the persisted top was a context
// story the object tier belongs to THAT story's gate, so the headline takes the
// causal leader's own gate tier, capped at the object tier (engine caps are
// downgrade-only and were applied to the object). No causal hypothesis at all
// → undetermined: there is nothing to be sure about.
func headlineVerdict(objectTier string, all, causal rcaHypBlob) string {
	objectTier = strings.ToLower(strings.TrimSpace(objectTier))
	if len(all.Ranking.Hypotheses) == 0 || !isContextHyp(all.Ranking.Hypotheses[0]) {
		return objectTier
	}
	if len(causal.Ranking.Hypotheses) == 0 {
		return "undetermined"
	}
	h := causal.Ranking.Hypotheses[0]
	t := strings.ToLower(strings.TrimSpace(h.Verdict.Tier))
	if _, ok := rcaTierRank[t]; !ok {
		t = "undetermined"
		if len(h.Satisfied) > 0 || h.Confidence > 0 {
			t = "suspected"
		}
	}
	if rcaTierRank[t] > rcaTierRank[objectTier] {
		return objectTier
	}
	return t
}

// ---- D3: the confirming pair -------------------------------------------------

// rcaMeasurementPlanes — the planes that MEASURE the network. Security (a rule
// verdict about captured state) and the management plane (a controller's
// statement) are verdict planes: they corroborate, they never anchor.
var rcaMeasurementPlanes = map[string]bool{
	"device_telemetry": true, "control_plane": true, "passive_flow": true,
	"active_probe": true, "active_verification": true,
}

// rcaConfirmingPair is the headline verdict's independent pair, as evidence.
type rcaConfirmingPair struct {
	Observers []string `json:"observers,omitempty"`
	// Planes: the evidence planes each pair member contributed, plain words.
	Planes []string `json:"planes,omitempty"`
	// Measured: both members are measurement planes AND between them they span
	// two different measurement planes.
	Measured bool   `json:"measured"`
	Basis    string `json:"basis"`
}

// Refutes reports a RECORDED pair that is not two measurement sources — the
// verdict rests on a security rule or a controller's statement. A blob that
// recorded no pair (an unconfirmed verdict, or an object older than the pair
// field) neither refutes nor proves: Measured stays false, so it can never
// promote a document, but it does not rewrite the legacy impact/escalation
// wording either.
func (p rcaConfirmingPair) Refutes() bool { return len(p.Observers) >= 2 && !p.Measured }

// buildConfirmingPair reads the headline hypothesis's independent_pair and
// looks each observer's planes up in the slice. A missing pair (an unconfirmed
// verdict, or a blob older than the pair field) is never measured.
func buildConfirmingPair(hb rcaHypBlob, signals []map[string]any) rcaConfirmingPair {
	p := rcaConfirmingPair{Basis: "No independent confirming pair was recorded for the leading explanation."}
	if len(hb.Ranking.Hypotheses) == 0 {
		return p
	}
	v := hb.Ranking.Hypotheses[0].Verdict
	if len(v.IndependentPair) < 2 {
		return p
	}
	planesOf := map[string]map[string]bool{}
	for _, sig := range signals {
		o := asString(sig["observer_id"])
		lane := strings.ToLower(asString(sig["modality_class"]))
		if o == "" || lane == "" {
			continue
		}
		if planesOf[o] == nil {
			planesOf[o] = map[string]bool{}
		}
		planesOf[o][lane] = true
	}
	measured := map[string]bool{}
	bothMeasure := true
	var planeWords []string
	for _, o := range v.IndependentPair[:2] {
		p.Observers = append(p.Observers, o)
		lanes := make([]string, 0, len(planesOf[o]))
		for l := range planesOf[o] {
			lanes = append(lanes, l)
		}
		sort.Strings(lanes)
		has := false
		for _, l := range lanes {
			if rcaMeasurementPlanes[l] {
				has = true
				measured[l] = true
			}
			planeWords = appendUnique(planeWords, rcaPlaneWords(l))
		}
		if !has {
			bothMeasure = false
		}
	}
	p.Planes = planeWords
	trustedMeasure := 0
	for _, m := range v.TrustedModalities {
		if rcaMeasurementPlanes[strings.ToLower(m)] {
			trustedMeasure++
		}
	}
	p.Measured = bothMeasure && len(measured) >= 2 && (len(v.TrustedModalities) == 0 || trustedMeasure >= 2)
	if p.Measured {
		p.Basis = "Two independent sources measured the same fault (" + strings.Join(planeWords, " and ") + ")."
	} else {
		p.Basis = "The confirming pair includes " + strings.Join(planeWords, " and ") +
			"; a security rule or a controller's own statement supports the case but is not a measurement of the fault."
	}
	return p
}

// rcaPlaneWords — an evidence plane in plain words (never a raw token).
func rcaPlaneWords(lane string) string {
	switch strings.ToLower(lane) {
	case "device_telemetry":
		return "device counters"
	case "control_plane":
		return "routing and link events"
	case "passive_flow":
		return "traffic records"
	case "active_probe":
		return "active checks"
	case "active_verification":
		return "a read-only device check"
	case "management_plane":
		return "a controller's own statement"
	case "security":
		return "a security rule"
	}
	return strings.ReplaceAll(lane, "_", " ")
}

// ---- D3: document eligibility facts ---------------------------------------------

type rcaDocEligibility struct {
	// CausalHeadline: a causal hypothesis leads (not undetermined, not a
	// background story).
	CausalHeadline bool `json:"causal_headline"`
	// ContextOnly: every hypothesis with evidence is a background story.
	ContextOnly bool `json:"context_only"`
	// NeverEstablished: the only fault evidence is a BGP peer that never came
	// up — a configuration ticket, never an RCA document.
	NeverEstablished bool `json:"never_established"`
	// ControllerOrHub: the faulting object is a controller or hub.
	ControllerOrHub bool `json:"controller_or_hub"`
	Sites           int  `json:"sites"`
	// PrimaryDevice / HeadlineID key the repeat-offender count.
	PrimaryDevice string `json:"primary_device,omitempty"`
	HeadlineID    string `json:"headline_id,omitempty"`
}

// rcaRecurrence — the repeat-offender count (stamped by the HTTP layer).
type rcaRecurrence struct {
	Known bool `json:"known"`
	// Count7d includes this case.
	Count7d int `json:"count_7d"`
}

// rcaBGPTransitionClass reads the BGP transition class an observation carries
// (session_lost | session_up | never_established | progressing | unknown).
// Contract (engine branch fix/rca-false-confirm-exposure-bgp):
//   - trap lane: bgp.transition_class (nested, or flattened as
//     "bgp.transition_class"), and the legacy top-level transition_class;
//   - controller lane (vManage): correlation_hints.bgp_transition_class (with
//     bgp_transition_basis beside it).
//
// correlation_hints.bgp_peer_routerid=unset is only an annotation and is never
// read: IOS/IOS-XE clears the remote router-id on teardown, so a session that
// WAS established and then dropped also reports 0.0.0.0.
func rcaBGPTransitionClass(at map[string]any) string {
	str := func(v any) string { return strings.ToLower(strings.TrimSpace(asString(v))) }
	if c := str(at["transition_class"]); c != "" {
		return c
	}
	if c := str(at["bgp.transition_class"]); c != "" {
		return c
	}
	if bgp, ok := at["bgp"].(map[string]any); ok {
		if c := str(bgp["transition_class"]); c != "" {
			return c
		}
	}
	if hints, ok := at["correlation_hints"].(map[string]any); ok {
		if c := str(hints["bgp_transition_class"]); c != "" {
			return c
		}
	}
	return ""
}

// rcaNeverEstablishedMark reports a BGP observation of a peer that never came
// up: the transition class (either lane) is never_established, or the
// observation carries never_established=true. Nothing else decides — "unknown"
// or an absent class is a possible real failure, and a 0.0.0.0 peer router id
// proves nothing (it is cleared on teardown of an established session too).
func rcaNeverEstablishedMark(sig map[string]any) bool {
	a := asString(sig["attrs"])
	if a == "" {
		return false
	}
	var at map[string]any
	if json.Unmarshal([]byte(a), &at) != nil {
		return false
	}
	if b, ok := at["never_established"].(bool); ok && b {
		return true
	}
	return rcaBGPTransitionClass(at) == "never_established"
}

// rcaBGPPeerKey — the peer a BGP observation is about (attrs peer/neighbor,
// else the entity).
func rcaBGPPeerKey(sig map[string]any) string {
	if a := asString(sig["attrs"]); a != "" {
		var at map[string]any
		if json.Unmarshal([]byte(a), &at) == nil {
			for _, k := range []string{"peer", "neighbor", "peer_address", "remote_address"} {
				if v := strings.TrimSpace(asString(at[k])); v != "" {
					return v
				}
			}
		}
	}
	return asString(sig["entity_id"])
}

// rcaBGPEstablished — the observation reports the session established/up.
func rcaBGPEstablished(sig map[string]any) bool {
	a := asString(sig["attrs"])
	var at map[string]any
	if a == "" || json.Unmarshal([]byte(a), &at) != nil {
		return false
	}
	st := strings.ToLower(asString(at["state"]))
	return st == "established" || st == "up" || rcaBGPTransitionClass(at) == "session_up"
}

// rcaNeverEstablishedOnly: every anomalous non-security observation is a BGP
// observation of a peer that never came up — at least one observation of that
// peer carries the never-established mark and none shows it established (a
// controller re-reports a dead peer without repeating every field).
func rcaNeverEstablishedOnly(anomalous []map[string]any) bool {
	marked, up := map[string]bool{}, map[string]bool{}
	var bgp []map[string]any
	for _, sig := range anomalous {
		if strings.ToLower(asString(sig["modality_class"])) == "security" {
			continue
		}
		if !strings.HasPrefix(asString(sig["kind"]), "bgp_") {
			return false // a real non-BGP fault is present
		}
		k := rcaBGPPeerKey(sig)
		if rcaNeverEstablishedMark(sig) {
			marked[k] = true
		}
		if rcaBGPEstablished(sig) {
			up[k] = true
		}
		bgp = append(bgp, sig)
	}
	if len(bgp) == 0 {
		return false
	}
	for _, sig := range bgp {
		k := rcaBGPPeerKey(sig)
		if !marked[k] || up[k] {
			return false
		}
	}
	return true
}

var rcaControllerHubRoles = map[string]bool{
	"controller": true, "wireless_controller": true, "wlc": true, "vsmart": true,
	"vbond": true, "vmanage": true, "hub": true, "sdwan_hub": true, "dc_hub": true,
	"headend": true, "orchestrator": true,
}

// rcaIsControllerOrHub: the anomalous evidence is ABOUT a controller or hub —
// its entity type, or a declared device role/tier in attrs. The witness that
// reported it (observer_type controller) is not the object and does not count.
func rcaIsControllerOrHub(anomalous []map[string]any) bool {
	for _, sig := range anomalous {
		if strings.ToLower(asString(sig["modality_class"])) == "security" {
			continue
		}
		switch strings.ToLower(asString(sig["entity_type"])) {
		case "controller", "wireless_controller":
			return true
		}
		a := asString(sig["attrs"])
		if a == "" {
			continue
		}
		var at map[string]any
		if json.Unmarshal([]byte(a), &at) != nil {
			continue
		}
		for _, k := range []string{"device_role", "role", "device_tier", "tier"} {
			r := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(asString(at[k]))), "-", "_")
			if rcaControllerHubRoles[r] {
				return true
			}
		}
	}
	return false
}

// ---- background band ---------------------------------------------------------------

type rcaBackgroundItem struct {
	Kind      string `json:"kind"` // context_story | standing_finding | change
	Title     string `json:"title"`
	Detail    string `json:"detail"`
	Source    string `json:"source"`
	FirstSeen string `json:"first_seen,omitempty"`
}

const rcaBackgroundNote = "Background on this device, not a cause. A standing finding has no start time and no mechanism, so it is never treated as the cause of a network fault. It may be unrelated."

// rcaFindingFirstSeen returns a dated finding's first-seen time, "" when the
// finding carries no start time (a standing property).
func rcaFindingFirstSeen(sig map[string]any) string {
	a := asString(sig["attrs"])
	if a == "" {
		return ""
	}
	var at map[string]any
	if json.Unmarshal([]byte(a), &at) != nil {
		return ""
	}
	for _, k := range []string{"first_seen", "first_seen_at", "onset", "onset_ts"} {
		if v := strings.TrimSpace(asString(at[k])); v != "" {
			if ts, ok := parseChTS(v); ok {
				return FmtUTC(ts)
			}
		}
	}
	return ""
}

// rcaIsStandingFindingKind — the security kinds that describe a standing
// property of the device (posture, exposure), as opposed to a dated detection.
func rcaIsStandingFindingKind(kind string) bool {
	return kind == "security_posture" || kind == "security_exposure"
}

// rcaDatedAnomalies drops undated standing findings (posture / exposure) from
// the anomalous set: they carry no onset and no lifecycle.
func rcaDatedAnomalies(anomalous []map[string]any) []map[string]any {
	out := make([]map[string]any, 0, len(anomalous))
	for _, sig := range anomalous {
		if rcaIsStandingFindingKind(asString(sig["kind"])) && rcaFindingFirstSeen(sig) == "" {
			continue
		}
		out = append(out, sig)
	}
	return out
}

func buildBackground(ctx []rcaHypEntry, signals []map[string]any, changes []rcaCloudChange) []rcaBackgroundItem {
	var out []rcaBackgroundItem
	for _, h := range ctx {
		if h.Confidence <= 0 && len(h.Satisfied) == 0 {
			continue
		}
		detail := strings.TrimSpace(h.OperatorPhrase)
		if detail != "" && !strings.HasSuffix(detail, ".") {
			detail += "."
		}
		out = append(out, rcaBackgroundItem{
			Kind:   "context_story",
			Title:  noclabel.SignatureTitle(h.ID),
			Detail: strings.TrimSpace(detail + " " + rcaBackgroundNote),
			Source: "security findings evaluated against this device",
		})
	}
	// Standing findings, one row per control (or per kind when no control).
	type agg struct {
		kind, title, source, first string
		n                          int
	}
	byKey := map[string]*agg{}
	var order []string
	for _, sig := range signals {
		kind := asString(sig["kind"])
		if !rcaIsStandingFindingKind(kind) && strings.ToLower(asString(sig["modality_class"])) != "security" {
			continue
		}
		if strings.HasSuffix(kind, "_clear") || kind == "security_signal" {
			continue // a dated detection is evidence, not a standing property
		}
		title := ""
		if a := asString(sig["attrs"]); a != "" {
			var at struct {
				ControlTitle string `json:"control_title"`
			}
			if json.Unmarshal([]byte(a), &at) == nil {
				title = strings.TrimSpace(at.ControlTitle)
			}
		}
		if title == "" {
			title = noclabel.Kind(kind)
		}
		key := kind + "|" + title
		g := byKey[key]
		if g == nil {
			g = &agg{kind: kind, title: title, source: rcaBackgroundSource(sig)}
			byKey[key] = g
			order = append(order, key)
		}
		g.n++
		if fs := rcaFindingFirstSeen(sig); fs != "" && (g.first == "" || fs < g.first) {
			g.first = fs
		}
	}
	sort.Strings(order)
	for _, k := range order {
		g := byKey[k]
		detail := fmt.Sprintf("%s (%s). Standing finding — recorded as background.", noclabel.Kind(g.kind), strings.ToLower(CountNoun(g.n, "observation")))
		if g.first != "" {
			detail = fmt.Sprintf("%s (%s), first seen %s. Recorded as background.", noclabel.Kind(g.kind), strings.ToLower(CountNoun(g.n, "observation")), g.first)
		}
		out = append(out, rcaBackgroundItem{Kind: "standing_finding", Title: g.title, Detail: detail, Source: g.source, FirstSeen: g.first})
	}
	// In-window changes the evidence does not tie to this case.
	for _, c := range changes {
		if c.Attached || c.Relationship == "same_resource" {
			continue
		}
		out = append(out, rcaBackgroundItem{
			Kind:   "change",
			Title:  strings.TrimSpace(orDefault(c.Provider, "Provider") + " change on " + orDefault(c.Resource, "an in-window resource")),
			Detail: "Happened in the same window but is not tied to this case by the evidence. Timing alone is not a cause.",
			Source: orDefault(c.EventSource, "provider change/audit stream"), FirstSeen: c.At,
		})
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out
}

// rcaBackgroundSource — who recorded a background finding, as a noun phrase
// for "Seen by".
func rcaBackgroundSource(sig map[string]any) string {
	if strings.ToLower(asString(sig["modality_class"])) == "security" || strings.ToLower(asString(sig["source"])) == "security" {
		return "a security rule checked against the device's configuration"
	}
	s := rcaPlainSource(sig)
	for _, v := range []string{" reported", " showed", " recorded", " found", " measured", " saw"} {
		s = strings.TrimSuffix(s, v)
	}
	return s
}

// ---- plain-words sources ---------------------------------------------------------------

// rcaControllerName names a controller from its observer id in vendor words
// (multi-vendor; unknown → "The controller").
func rcaControllerName(observer string) string {
	o := strings.ToLower(observer)
	for _, c := range []struct{ tok, name string }{
		{"vmanage", "vManage"}, {"meraki", "Meraki Dashboard"}, {"dnac", "Catalyst Center"},
		{"catalyst", "Catalyst Center"}, {"mist", "Juniper Mist"}, {"aruba", "Aruba Central"},
		{"versa", "Versa Director"}, {"fortimanager", "FortiManager"}, {"panorama", "Panorama"},
		{"nsp", "Nokia NSP"}, {"cloudvision", "Arista CloudVision"}, {"cvp", "Arista CloudVision"},
	} {
		if strings.Contains(o, c.tok) {
			return c.name
		}
	}
	return "The controller"
}

// rcaPlainSource names WHO saw an observation, as the opening of a sentence:
// "vManage reported", "The device's own counters showed", ...
func rcaPlainSource(sig map[string]any) string {
	path := strings.ToLower(asString(sig["collection_path"]))
	src := strings.ToLower(asString(sig["source"]))
	lane := strings.ToLower(asString(sig["modality_class"]))
	obs := asString(sig["observer_id"])
	switch {
	case lane == "security" || src == "security":
		return "A security rule found"
	case strings.HasPrefix(path, "via_controller") || src == "controller" || strings.ToLower(asString(sig["observer_type"])) == "controller":
		return rcaControllerName(obs) + " reported"
	case strings.HasPrefix(path, "via_cloud_api") || src == "cloud":
		return "The cloud provider's API reported"
	case src == "syslog":
		return "The device's own log recorded"
	case src == "trap":
		return "The device's own alarm reported"
	case src == "verification" || lane == "active_verification":
		return "A read-only check on the device showed"
	case src == "bgp":
		return "The BGP route monitor saw"
	case src == "flow" || lane == "passive_flow":
		return "Traffic records showed"
	case src == "probe" || lane == "active_probe":
		if obs != "" {
			return "Active checks from " + noclabel.Entity(obs) + " measured"
		}
		return "Active checks measured"
	case src == "metric" || lane == "device_telemetry":
		return "The device's own counters showed"
	case lane == "control_plane":
		return "The device's routing events showed"
	case lane == "management_plane":
		return rcaControllerName(obs) + " reported"
	}
	return "A monitoring source saw"
}

// ---- the document --------------------------------------------------------------

type rcaAffectedAxis struct {
	Axis   string `json:"axis"`
	State  string `json:"state"` // measured | indicated | not measured
	Detail string `json:"detail"`
}

type rcaWhenSection struct {
	FirstSeen   string `json:"first_seen,omitempty"`
	Status      string `json:"status"`
	Duration    string `json:"duration,omitempty"`
	RecoveredAt string `json:"recovered_at,omitempty"`
	Note        string `json:"note"`
}

type rcaCauseSection struct {
	Level          string   `json:"level"`  // confirmed | likely | suspected | undetermined
	Phrase         string   `json:"phrase"` // one of the four fixed phrases
	Cause          string   `json:"cause,omitempty"`
	Meaning        string   `json:"meaning,omitempty"`
	Statement      string   `json:"statement"`
	WouldConfirm   []string `json:"would_confirm,omitempty"`
	WhyNotFirmer   []string `json:"why_not_firmer,omitempty"`
	ConfirmingPair string   `json:"confirming_pair,omitempty"`
}

type rcaKnowRow struct {
	Source      string `json:"source"`
	Observation string `json:"observation"`
	Text        string `json:"text"`
}

type rcaOtherExplanation struct {
	Title string `json:"title"`
	Why   string `json:"why"`
}

type rcaOwnerSection struct {
	Owner       string `json:"owner"`
	Why         string `json:"why"`
	External    string `json:"external,omitempty"`
	Demarcation string `json:"demarcation,omitempty"`
}

type rcaPathSection struct {
	Available     bool   `json:"available"`
	BreakMeasured bool   `json:"break_measured"`
	Note          string `json:"note"`
}

// NocDocument — the ten sections, in the order a NOC engineer reads them.
type NocDocument struct {
	WhatBroke    string                `json:"what_broke"`
	WhoAffected  []rcaAffectedAxis     `json:"who_affected"`
	When         rcaWhenSection        `json:"when"`
	Cause        rcaCauseSection       `json:"cause"`
	HowWeKnow    []rcaKnowRow          `json:"how_we_know"`
	OneWitness   string                `json:"one_witness_note,omitempty"`
	Path         rcaPathSection        `json:"path"`
	Background   []rcaBackgroundItem   `json:"background"`
	Others       []rcaOtherExplanation `json:"other_explanations"`
	Owner        rcaOwnerSection       `json:"owner"`
	DoNow        []string              `json:"do_now"`
	Watch        []string              `json:"watch"`
	HowToRead    []string              `json:"how_to_read"`
	SectionNames []string              `json:"section_names"`
}

// RcaSectionNames — the document's section names, in order (UI + PDF).
var RcaSectionNames = []string{
	"What broke",
	"Who is affected",
	"When",
	"Cause and how sure we are",
	"How we know",
	"Where the break is",
	"Background on this device (not a cause)",
	"Other explanations considered",
	"Who owns the fix",
	"What to do now · Watch for recurrence",
}

// RcaHowToRead — the one-page reading guide (UI help panel + PDF last page).
var RcaHowToRead = []string{
	"Read sections 1 and 2 first: is this mine, and who is hurting?",
	"Take section 4's phrase literally. \"Confirmed cause\" means two independent sources measured the same fault. \"Possibly because of X\" means work the \"What would confirm it\" list before escalating.",
	"Section 5 names the sources. Several observations that all came through one controller count as one witness.",
	"On the path, red is a measured break and dotted is inferred.",
	"Section 7 is background and may be unrelated: do not file it as the cause.",
	"Section 9 says who to call.",
}

// rcaDocInput carries the builder's derived locals the projection reads.
type rcaDocInput struct {
	Rep       *Report
	Headline  *rcaHypothesis // nil when no causal hypothesis has evidence
	HB        rcaHypBlob     // causal blob
	Anomalous []map[string]any
	Required  string
	WhyNot    []string
	Lanes     map[string]int
	// Observed is what the evidence actually shows (RCA v2 §3.1) — section 1
	// names it, never an unobserved clause of the leading hypothesis.
	Observed rcaObservedCondition
	// TopMissing: the leading template still misses a required clause.
	TopMissing bool
}

// rcaHeadlineTitle — the headline cause in NOC words: the hypothesis row's own
// title (noclabel.HypothesisTitle — the explicit NOC map, then the catalog
// title; RCA v2 §3.2), never the event-phrase cascade.
func rcaHeadlineTitle(h *rcaHypothesis) string {
	if h == nil {
		return ""
	}
	return h.Title
}

func buildNocDocument(in rcaDocInput) NocDocument {
	rep := in.Rep
	d := NocDocument{
		SectionNames: append([]string(nil), RcaSectionNames...),
		HowToRead:    append([]string(nil), RcaHowToRead...),
		Background:   rep.Background,
	}

	// 1 · What broke — object, symptom, site; never a raw template title.
	// RCA v2 §3.1: while the leading hypothesis misses a required clause, what
	// broke is the OBSERVED condition, not the hypothesis.
	symptom := rcaHeadlineTitle(in.Headline)
	observedLeads := in.Observed.Label != "" && (in.Headline == nil || in.TopMissing)
	if observedLeads {
		symptom = in.Observed.Label
	}
	if symptom == "" {
		symptom = rcaDominantMeasuredNoun(in.Lanes)
	}
	object := ""
	switch {
	case observedLeads && !rep.FaultLocalization.Localized && in.Observed.Where != "":
		object = in.Observed.Where
	case rep.FaultLocalization.Localized && rep.FaultLocalization.Object != "":
		object = noclabel.Entity(rep.FaultLocalization.Object)
	case len(rep.Scope.Devices) > 0:
		object = noclabel.Entity(rep.Scope.Devices[0])
	case len(rep.Scope.Services) > 0:
		object = rep.Scope.Services[0]
	case len(rep.Scope.Targets) > 0:
		object = noclabel.Entity(rep.Scope.Targets[0])
	}
	line := symptom
	if object != "" {
		line += " on " + object
	}
	if len(rep.Scope.Sites) > 0 {
		line += " · site " + rep.Scope.Sites[0]
		if n := len(rep.Scope.Sites) - 1; n > 0 {
			line += fmt.Sprintf(" (+%d more)", n)
		}
	}
	d.WhatBroke = line

	// 2 · Who is affected — impact axes only, never the verdict.
	d.WhoAffected = buildAffectedAxes(rep)

	// 3 · When — dated events only.
	d.When = rcaWhenSection{
		FirstSeen: rep.Times.FirstObserved,
		Status:    rcaIncidentWords(rep.States.Incident),
		Note:      "Only dated events are listed. A standing finding with no start time is in section 7, not here.",
	}
	if rep.Times.DurationMS > 0 {
		d.When.Duration = FmtDurMS(rep.Times.DurationMS)
		switch rep.Times.DurationBasis {
		case "elapsed_still_active":
			d.When.Duration += " so far (still active)"
		case "to_last_observation":
			d.When.Duration += " (to the last observation)"
		}
	}
	if rep.Times.RecoveredCaptured {
		d.When.RecoveredAt = rep.Times.RecoveredAt
	}

	// 4 · Cause and how sure we are — one of the four phrases.
	level := noclabel.LevelForAnalysis(rep.States.Analysis)
	if in.Headline == nil {
		level = noclabel.LevelUndetermined
	}
	cause := rcaMidSentence(symptom)
	if in.Headline != nil {
		cause = rcaMidSentence(rcaHeadlineTitle(in.Headline))
	}
	d.Cause = rcaCauseSection{
		Level:     string(level),
		Phrase:    noclabel.PhraseFor(level, cause),
		Statement: rep.RootCause.Statement,
	}
	if in.Headline != nil && level != noclabel.LevelUndetermined {
		d.Cause.Cause = rcaHeadlineTitle(in.Headline)
		d.Cause.Meaning = in.Headline.Problem
	}
	if level != noclabel.LevelConfirmed {
		if in.Required != "" {
			d.Cause.WouldConfirm = append(d.Cause.WouldConfirm, in.Required)
		}
		if in.Headline != nil {
			for _, c := range in.Headline.ConfirmWhen {
				d.Cause.WouldConfirm = appendUnique(d.Cause.WouldConfirm, rcaCapitalize(c)+".")
			}
		}
		d.Cause.WhyNotFirmer = in.WhyNot
		if len(d.Cause.WouldConfirm) > 6 {
			d.Cause.WouldConfirm = d.Cause.WouldConfirm[:6]
		}
	}
	if len(rep.ConfirmingPair.Observers) >= 2 {
		d.Cause.ConfirmingPair = rep.ConfirmingPair.Basis
	}

	// 5 · How we know — the observations behind the headline, each naming its
	// source in plain words.
	d.HowWeKnow, d.OneWitness = buildHowWeKnow(in)

	// 6 · Where the break is.
	d.Path = buildPathSection(rep)

	// 8 · Other explanations considered — each with why it was ruled out.
	for i := range rep.Hypotheses {
		h := rep.Hypotheses[i]
		if in.Headline != nil && h.ID == in.Headline.ID {
			continue
		}
		why := ""
		switch {
		case h.CandidacyState == rcaRoleNearestCompetitor:
			why = "Not observed — none of the observations it requires was seen"
			if len(h.Missing) > 0 {
				why += " (it needs: " + strings.Join(firstN(h.Missing, 3), "; ") + ")"
			}
			why += ". Listed as the " + noclabel.NearestCompetitorNotObserved + "."
		case h.Contradicted && len(h.Contradicting) > 0:
			why = "Ruled out — evidence against it: " + strings.Join(firstN(h.Contradicting, 3), "; ") + "."
		case h.Contradicted:
			why = "Ruled out — the evidence contradicts it."
		case h.Type == "symptom classification":
			why = "Describes what was seen, not why — it is not a cause."
		case len(h.Missing) > 0:
			why = "Ranked lower — still missing: " + strings.Join(firstN(h.Missing, 3), "; ") + "."
		default:
			why = "Ranked lower — it matches less of the evidence than the leading explanation."
		}
		d.Others = append(d.Others, rcaOtherExplanation{Title: rcaHeadlineTitle(&h), Why: why})
	}

	// 9 · Who owns the fix.
	own := rep.Ownership
	d.Owner = rcaOwnerSection{Owner: own.EscalationOwner, Why: own.EscalationReason}
	if strings.HasPrefix(own.EscalationOwner, "Pending") {
		d.Owner.Owner = orDefault(own.TechnicalOwner, own.TriageOwner)
		d.Owner.Why = own.EscalationReason
		if own.TechnicalOwner == "" {
			d.Owner.Why = own.TriageReason + " " + own.EscalationReason
		}
	}
	if own.ExternalCandidate != "" {
		d.Owner.External = own.ExternalCandidate
		d.Owner.Demarcation = own.DemarcationBasis
	}

	// 10 · What to do now · Watch for recurrence.
	for _, a := range rep.Actions {
		s := a.Action
		if a.Owner != "" {
			s += " (owner: " + a.Owner + ")"
		}
		d.DoNow = append(d.DoNow, s)
	}
	if rep.Decision.MonitoringWindow != "" {
		d.Watch = append(d.Watch, "Monitoring window: "+rep.Decision.MonitoringWindow+".")
	}
	if rep.Decision.ReopenWhen != "" {
		d.Watch = append(d.Watch, "Reopens when "+rep.Decision.ReopenWhen+".")
	}
	return d
}

// buildPathSection — section 6. Red is claimed only for a break MEASURED on the
// path (a hop the spine recorded as failed/down); everything else is drawn
// dotted, as inferred. A background story never paints a break: it is not in
// the causal ranking and the spine is measurement, never a verdict.
func buildPathSection(rep *Report) rcaPathSection {
	p := rcaPathSection{Available: rep.Topology.Available}
	for _, h := range rep.Topology.Hops {
		if h.Fault == "broken" || strings.EqualFold(h.State, "down") {
			p.BreakMeasured = true
		}
	}
	switch {
	case !rep.Topology.Available:
		p.Note = orDefault(rep.Topology.Reason, "The network path was not measured for this case, so no break is drawn.")
	case p.BreakMeasured:
		p.Note = "Red marks a break that was measured on the path. Dotted lines are inferred, not measured."
	default:
		p.Note = "No break was measured on this path. Dotted lines are inferred, not measured."
	}
	return p
}

// rcaCapitalize upper-cases the first byte of a plain sentence.
func rcaCapitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// FmtDurMS — FmtDur over milliseconds.
func FmtDurMS(ms int64) string { return FmtDur(time.Duration(ms) * time.Millisecond) }

func rcaIncidentWords(incident string) string {
	switch incident {
	case "active":
		return "Still active"
	case "recovering":
		return "Recovering — recovery seen, still being watched"
	case "recovered", "closed":
		return "Recovered"
	case "no_longer_observed":
		return "No longer observed — no recovery evidence was captured"
	case "merged", "superseded":
		return "Merged into another case"
	}
	return rcaTitleCase(incident)
}

// rcaDominantMeasuredNoun — the dominant MEASUREMENT lane as a symptom noun when
// no causal hypothesis leads. Security never names what broke.
func rcaDominantMeasuredNoun(lanes map[string]int) string {
	best, dom := 0, ""
	for _, l := range rcaLaneOrder {
		if !rcaMeasurementPlanes[l] && l != "management_plane" {
			continue
		}
		if lanes[l] > best {
			best, dom = lanes[l], l
		}
	}
	switch dom {
	case "active_probe":
		return "Active-check degradation"
	case "passive_flow":
		return "Traffic anomaly"
	case "control_plane":
		return "Routing or link event"
	case "device_telemetry":
		return "Device health anomaly"
	case "management_plane":
		return "Controller-reported anomaly"
	}
	if lanes["security"] > 0 {
		return "Security finding (no network fault recorded)"
	}
	return "Telemetry anomaly"
}

// buildAffectedAxes — section 2. Each axis is measured / indicated / not
// measured, read from the impact axes and the provenance block. The verdict is
// never an input: a confirmed fault does not make anyone affected.
func buildAffectedAxes(rep *Report) []rcaAffectedAxis {
	var out []rcaAffectedAxis
	switch rep.States.ImpactRealUser {
	case "confirmed":
		out = append(out, rcaAffectedAxis{"Real users", "measured", "Real-user evidence (application or load-balancer errors) shows users were affected; the number of users is not measured."})
	case "detected", "indicator_detected":
		out = append(out, rcaAffectedAxis{"Real users", "indicated", "Real traffic changed or real-user errors appeared, but no independent measurement confirms users were affected."})
	case "none_detected":
		out = append(out, rcaAffectedAxis{"Real users", "measured", "Real-traffic telemetry covered the whole window and showed no user impact."})
	default:
		out = append(out, rcaAffectedAxis{"Real users", "not measured", "No real-user telemetry covered this case. Not measured is not the same as not affected."})
	}
	switch rep.States.ImpactSynthetic {
	case "confirmed":
		det := "Configured synthetic checks failed."
		for _, m := range rep.ImpactProvenance.Measures {
			if m.Measure == "synthetic_failure_rate" && m.Basis != "" {
				det = m.Basis
			}
		}
		out = append(out, rcaAffectedAxis{"Synthetic checks", "measured", det})
	case "none_detected":
		out = append(out, rcaAffectedAxis{"Synthetic checks", "measured", "Synthetic checks ran through the window and none failed."})
	default:
		out = append(out, rcaAffectedAxis{"Synthetic checks", "not measured", "No synthetic check covered this case."})
	}
	flow := rcaAffectedAxis{"Real traffic (flow records)", "not measured", "No traffic-flow change is attached to this case."}
	for _, m := range rep.ImpactProvenance.Measures {
		if m.Measure == "flow_volume_change" && m.Status != impactNotMeasured {
			flow = rcaAffectedAxis{"Real traffic (flow records)", "indicated", "Traffic volume changed. This is an indicator — demand shifts and collection loss look the same."}
		}
	}
	out = append(out, flow)
	if len(rep.Scope.Sites) > 0 {
		out = append(out, rcaAffectedAxis{"Sites", "indicated", strings.Join(firstN(rep.Scope.Sites, 5), ", ") + " — named by the evidence; other sites are not counted."})
	} else {
		out = append(out, rcaAffectedAxis{"Sites", "not measured", "No site is named by the evidence."})
	}
	if len(rep.Scope.Services) > 0 {
		out = append(out, rcaAffectedAxis{"Applications", "indicated", strings.Join(firstN(rep.Scope.Services, 5), ", ") + " — named by the evidence."})
	} else {
		out = append(out, rcaAffectedAxis{"Applications", "not measured", "No application is named by the evidence."})
	}
	return out
}

// buildHowWeKnow — section 5. The observations that matched the headline's
// clauses, grouped by who saw them. When every row came through one
// controller, the note says they count as one witness.
func buildHowWeKnow(in rcaDocInput) ([]rcaKnowRow, string) {
	matchKinds := map[string]bool{}
	if len(in.HB.Ranking.Hypotheses) > 0 {
		for _, c := range in.HB.Ranking.Hypotheses[0].Satisfied {
			for _, alt := range strings.Split(c, "|") {
				matchKinds[strings.TrimSpace(alt)] = true
			}
		}
	}
	type key struct{ src, kind string }
	counts := map[key]int{}
	var order []key
	controllers := map[string]bool{}
	direct := false
	for _, sig := range in.Anomalous {
		kind := asString(sig["kind"])
		if len(matchKinds) > 0 && !matchKinds[kind] {
			continue
		}
		if rcaIsStandingFindingKind(kind) {
			continue // background, never a reason the cause is believed
		}
		src := rcaPlainSource(sig)
		k := key{src, kind}
		if counts[k] == 0 {
			order = append(order, k)
		}
		counts[k]++
		if strings.HasSuffix(src, " reported") && (strings.HasPrefix(strings.ToLower(asString(sig["collection_path"])), "via_controller") ||
			strings.ToLower(asString(sig["source"])) == "controller") {
			controllers[strings.TrimSuffix(src, " reported")] = true
		} else {
			direct = true
		}
	}
	sort.SliceStable(order, func(i, j int) bool {
		if order[i].src != order[j].src {
			return order[i].src < order[j].src
		}
		return order[i].kind < order[j].kind
	})
	var rows []rcaKnowRow
	for _, k := range order {
		obs := noclabel.Kind(k.kind)
		rows = append(rows, rcaKnowRow{
			Source: k.src, Observation: obs,
			Text: fmt.Sprintf("%s %s (%s).", k.src, rcaMidSentence(obs), strings.ToLower(CountNoun(counts[k], "observation"))),
		})
		if len(rows) >= 8 {
			break
		}
	}
	note := ""
	if !direct && len(controllers) == 1 && len(rows) > 0 {
		for c := range controllers {
			note = "Every observation above came through " + c + ", so together they count as one witness."
		}
	}
	return rows, note
}
