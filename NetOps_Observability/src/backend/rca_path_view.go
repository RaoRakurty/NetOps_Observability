package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// rca_path_view.go — the UI-ready RCA Path View contract (Layer 3 overlay).
//
//   GET /api/correlations/{id}/rca-path-view
//
// Maps a correlation object's grounded evidence (corr_signals + corr_edges) onto
// a source→destination path plus OVERLAY ANNOTATIONS — where the issue sits, its
// status (suspected/confirmed/degraded/...), the evidence that supports it, what's
// missing to confirm, the likely owner, and how much we can see. It never invents
// a broken link and never mutates base topology — annotations are overlay-only.
//
// The path structure here is derived from the object's own entities (probe path,
// grounded locus, BGP peer). When real LLDP/CDP/BGP-LS base topology lands, the
// annotation target_ids resolve onto real topology edges; the contract is stable.

// ── response contract ───────────────────────────────────────────────────────

type rcaPathNode struct {
	ID     string `json:"id"`
	Type   string `json:"type"`             // observer | device | interface | peer | endpoint | cloud | boundary
	Kind   string `json:"kind"`             // shape hint: vantage|router|switch|firewall|gateway|cloud|target
	Label  string `json:"label"`            // raw label — Operator View genericizes it client-side
	Role   string `json:"role,omitempty"`   // observed | destination | fault | affected | peer | boundary
	Status string `json:"status,omitempty"` // overlay state for the node, if any
}

type rcaPathEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`  // path_segment | bgp_session | provider_boundary
	State  string `json:"state"` // healthy | degraded | suspected_down | confirmed_down | unknown
	Label  string `json:"label,omitempty"`
}

type rcaAnnotation struct {
	TargetType      string   `json:"target_type"` // node | edge | path_segment | boundary | path
	TargetID        string   `json:"target_id"`
	Status          string   `json:"status"` // observed|degraded|suspected_down|confirmed_down|insufficient_visibility|missing_evidence|internal_only
	Verdict         string   `json:"verdict"`
	Confidence      float64  `json:"confidence"`
	Owner           string   `json:"owner"`
	Visibility      string   `json:"visibility"`
	Reason          string   `json:"reason"`
	EvidenceRefs    []string `json:"evidence_refs"`
	MissingEvidence []string `json:"missing_evidence"`
}

type rcaPathView struct {
	CorrObjectID           string          `json:"corr_object_id"`
	Verdict                string          `json:"verdict"`
	Confidence             float64         `json:"confidence"`
	Internal               bool            `json:"internal"`
	Title                  string          `json:"title"`
	Summary                string          `json:"summary"`
	RecommendedAction      string          `json:"recommended_action"`
	Path                   rcaPath         `json:"path"`
	Annotations            []rcaAnnotation `json:"annotations"`
	EvidenceSummary        map[string]any  `json:"evidence_summary"`
	MissingEvidenceSummary []string        `json:"missing_evidence_summary"`
}

type rcaPath struct {
	Source      string        `json:"source"`
	Destination string        `json:"destination"`
	Nodes       []rcaPathNode `json:"nodes"`
	Edges       []rcaPathEdge `json:"edges"`
}

// ── handler ─────────────────────────────────────────────────────────────────

func (s *server) serveRcaPathView(w http.ResponseWriter, r *http.Request, id string) {
	version := intQuery(r, "version", 0, 0, 1<<30)
	meta, sigRows, evRows, edgeRows, status, err := s.loadCorrSlice(r, id, version)
	if err != nil {
		writeError(w, status, err)
		return
	}
	trigger := fmt.Sprintf("%v", meta["trigger_signal"])
	// enrich sigRows IN PLACE with attached/link_status (read-side derivation).
	mergeTimelineEvidence(sigRows, evRows, edgeRows, trigger)
	writeJSON(w, http.StatusOK, buildRcaPathView(id, meta, sigRows, edgeRows))
}

// ── pure mapping (unit-tested; no I/O) ──────────────────────────────────────

func attrStr(attrs any, key string) string {
	s, _ := attrs.(string)
	if s == "" {
		return ""
	}
	var m map[string]any
	if json.Unmarshal([]byte(s), &m) != nil {
		return ""
	}
	if v, ok := m[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// verdict tier → segment/node state for the located fault.
func faultState(verdict string) string {
	if verdict == "confirmed" {
		return "confirmed_down"
	}
	return "suspected_down"
}

// a probe signal that must NOT drive a customer-facing fault (decision #76).
func isDebugProbe(sig map[string]any) bool {
	auth := fmt.Sprintf("%v", sig["probe_authority"])
	scope := fmt.Sprintf("%v", sig["probe_scope"])
	return auth == "debug_only" || scope == "internal_self_probe" || scope == "synthetic_lab_probe"
}

// buildRcaPathView maps object evidence → UI-ready path + overlay annotations.
// Pure: deterministic in (meta, signals, edges), no I/O, no engine re-decision.
func buildRcaPathView(id string, meta map[string]any, sigRows, edgeRows []map[string]any) rcaPathView {
	verdict := strings.ToLower(fmt.Sprintf("%v", meta["verdict_tier"]))
	if verdict == "" || verdict == "<nil>" {
		verdict = "undetermined"
	}
	conf := asFloat(meta["top_confidence"])

	// attached, non-clear signals = the evidence the engine actually used.
	var attached []map[string]any
	for _, sig := range sigRows {
		if b, _ := sig["attached"].(bool); !b {
			continue
		}
		if strings.HasSuffix(fmt.Sprintf("%v", sig["kind"]), "_clear") {
			continue
		}
		attached = append(attached, sig)
	}

	// INTERNAL/DEBUG: every attached signal is an active probe AND debug/internal,
	// with no other plane → internal monitoring path (kept out of customer RCA).
	internal := len(attached) > 0
	probes, others := 0, 0
	for _, sig := range attached {
		if fmt.Sprintf("%v", sig["modality_class"]) == "active_probe" {
			probes++
			if !isDebugProbe(sig) {
				internal = false
			}
		} else {
			others++
		}
	}
	if probes == 0 || others > 0 {
		internal = false
	}

	// locus device: the entity the grounded topo edges converge on (shared:X).
	shareCount := map[string]int{}
	var seamRef string
	for _, e := range edgeRows {
		gk := fmt.Sprintf("%v", e["grounding_kind"])
		ref := fmt.Sprintf("%v", e["grounding_ref"])
		if gk == "topo" && strings.HasPrefix(ref, "shared:") {
			shareCount[strings.TrimPrefix(ref, "shared:")]++
		}
		if gk == "seam" && seamRef == "" {
			seamRef = ref
		}
	}
	locus := ""
	best := 0
	for k, n := range shareCount {
		if n > best {
			best, locus = n, k
		}
	}

	// path ends from a probe path entity (src->dst).
	var pathSig map[string]any
	for _, sig := range attached {
		if fmt.Sprintf("%v", sig["entity_type"]) == "path" {
			if pathSig == nil || (sig["is_trigger"] == true) {
				pathSig = sig
			}
		}
	}
	src, dst := "", ""
	if pathSig != nil {
		if a, b, ok := strings.Cut(fmt.Sprintf("%v", pathSig["entity_id"]), "->"); ok {
			src, dst = strings.TrimSpace(a), strings.TrimSpace(b)
		}
	}
	// `locus` stays GROUNDED-only (from shared:X). We never treat the probe
	// destination as a grounded fault — an unknown location must read as
	// "path degraded, location uncertain", not a pinned segment.

	state := faultState(verdict)
	if internal {
		state = "internal_only"
	}

	view := rcaPathView{CorrObjectID: id, Verdict: verdict, Confidence: conf, Internal: internal}
	view.EvidenceSummary, view.MissingEvidenceSummary = summarizeEvidence(attached, meta, verdict)
	view.Annotations = mapAnnotations(attached, edgeRows, locus, src, dst, verdict, conf, internal, seamRef)
	view.Path = buildPath(attached, locus, src, dst, state, internal)
	view.Title, view.Summary, view.RecommendedAction = narrate(verdict, internal, locus, view.Annotations)
	return view
}

// mapAnnotations turns each grounded evidence kind into an overlay annotation on
// the right target (interface edge, BGP session, device node, or whole path).
func mapAnnotations(attached, edgeRows []map[string]any, locus, src, dst, verdict string, conf float64, internal bool, seamRef string) []rcaAnnotation {
	var out []rcaAnnotation
	owner := "network_ops"
	visibility := "full"
	if seamRef != "" {
		owner = "wan_provider"
		visibility = "partial"
	}
	if internal {
		owner = "platform"
	}
	add := func(a rcaAnnotation) { out = append(out, a) }
	seenIface := map[string]bool{}

	for _, sig := range attached {
		et := fmt.Sprintf("%v", sig["entity_type"])
		eid := fmt.Sprintf("%v", sig["entity_id"])
		kind := fmt.Sprintf("%v", sig["kind"])
		sid := fmt.Sprintf("%v", sig["signal_id"])
		st := faultState(verdict)
		if internal {
			st = "internal_only"
		}
		switch {
		case et == "interface" || strings.Contains(kind, "link_state"):
			// Example 1: link_state_change on device interface → exact edge.
			if seenIface[eid] {
				continue
			}
			seenIface[eid] = true
			add(rcaAnnotation{TargetType: "edge", TargetID: eid, Status: st, Verdict: verdict, Confidence: conf,
				Owner: owner, Visibility: visibility, Reason: "interface state change grounded on this link", EvidenceRefs: []string{sid}, MissingEvidence: nil})
		case strings.Contains(kind, "bgp") || strings.Contains(kind, "adjacency") || strings.Contains(kind, "peer"):
			// Example 2: BGP adjacency down → BGP session edge (device→peer).
			peer := attrStr(sig["attrs"], "peer")
			if peer == "" && strings.Contains(eid, ":") {
				peer = eid[strings.Index(eid, ":")+1:]
			}
			dev := eid
			if i := strings.Index(eid, ":"); i > 0 {
				dev = eid[:i]
			}
			tgt := dev + "->" + peer
			add(rcaAnnotation{TargetType: "edge", TargetID: tgt, Status: st, Verdict: verdict, Confidence: conf,
				Owner: owner, Visibility: visibility, Reason: "BGP adjacency change on this session", EvidenceRefs: []string{sid}, MissingEvidence: nil})
		case et == "path":
			// Example 3: probe loss → segment if locus known, else whole path.
			tt, tid, reason := "path", eid, "active-check change on this path — location uncertain"
			if locus != "" {
				tt, tid, reason = "path_segment", locus, "active-check change grounded near this device"
			}
			pst := "degraded"
			if internal {
				pst = "internal_only"
			}
			add(rcaAnnotation{TargetType: tt, TargetID: tid, Status: pst, Verdict: verdict, Confidence: conf,
				Owner: owner, Visibility: visibility, Reason: reason, EvidenceRefs: []string{sid}, MissingEvidence: nil})
		default:
			// device-area annotation (resource/other) — don't draw a fake broken link.
			add(rcaAnnotation{TargetType: "node", TargetID: locusOrEntity(locus, eid), Status: st, Verdict: verdict, Confidence: conf,
				Owner: owner, Visibility: visibility, Reason: "issue localized to this device area", EvidenceRefs: []string{sid}, MissingEvidence: nil})
		}
	}
	return out
}

func locusOrEntity(locus, eid string) string {
	if locus != "" {
		return locus
	}
	if i := strings.Index(eid, ":"); i > 0 {
		return eid[:i]
	}
	return eid
}

// buildPath assembles the ordered source→destination node/edge chain (overlay
// states applied). BGP-only objects get device→peer (the "total path").
func buildPath(attached []map[string]any, locus, src, dst, state string, internal bool) rcaPath {
	p := rcaPath{Source: src, Destination: dst}
	addNode := func(n rcaPathNode) { p.Nodes = append(p.Nodes, n) }
	addEdge := func(e rcaPathEdge) { p.Edges = append(p.Edges, e) }

	prev := ""
	if src != "" {
		addNode(rcaPathNode{ID: src, Type: "observer", Kind: "vantage", Label: src, Role: "observed"})
		prev = src
	}
	if locus != "" {
		addNode(rcaPathNode{ID: locus, Type: "device", Kind: "router", Label: locus, Role: "fault", Status: state})
		if prev != "" {
			addEdge(rcaPathEdge{ID: prev + "~" + locus, Source: prev, Target: locus, Type: "path_segment", State: edgeStateInto(state)})
		}
		prev = locus
	}
	// BGP peer = the far end of the segment when there is no probe destination.
	peer := bgpPeer(attached)
	if peer != "" && dst == "" {
		addNode(rcaPathNode{ID: peer, Type: "peer", Kind: "router", Label: peer, Role: "peer"})
		if prev != "" {
			addEdge(rcaPathEdge{ID: prev + "~" + peer, Source: prev, Target: peer, Type: "bgp_session", State: state, Label: "BGP session"})
		}
	} else if dst != "" && dst != locus {
		addNode(rcaPathNode{ID: dst, Type: "endpoint", Kind: "target", Label: dst, Role: "destination"})
		if prev != "" {
			addEdge(rcaPathEdge{ID: prev + "~" + dst, Source: prev, Target: dst, Type: "path_segment", State: "healthy"})
		}
	}
	return p
}

func edgeStateInto(faultState string) string {
	if faultState == "internal_only" {
		return "unknown"
	}
	return "degraded"
}

func bgpPeer(attached []map[string]any) string {
	for _, sig := range attached {
		kind := fmt.Sprintf("%v", sig["kind"])
		if !strings.Contains(kind, "bgp") && !strings.Contains(kind, "adjacency") {
			continue
		}
		if p := attrStr(sig["attrs"], "peer"); p != "" {
			return p
		}
		eid := fmt.Sprintf("%v", sig["entity_id"])
		if i := strings.Index(eid, ":"); i > 0 {
			return eid[i+1:]
		}
	}
	return ""
}

// reasonTokenLabel maps raw engine vocabulary that appears inside verdict-reason
// strings to operator language (no schema tokens in customer-facing text).
var reasonTokenLabel = map[string]string{
	"active_probe":        "active path measurement",
	"control_plane":       "routing",
	"device_telemetry":    "device telemetry",
	"passive_flow":        "traffic flow",
	"internal_self_probe": "internal self-probe",
	"customer_path":       "customer-path probe",
	"synthetic_lab_probe": "lab probe",
}

// friendlyReasons rewrites engine reason strings into operator language by replacing
// raw modality/scope tokens (kept verbatim otherwise — the phrasing is already
// human-authored). Used for the "why not confirmed" + contradicting-evidence text.
func friendlyReasons(reasons []string) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		for tok, label := range reasonTokenLabel {
			r = strings.ReplaceAll(r, tok, label)
		}
		out = append(out, r)
	}
	return out
}

// summarizeEvidence rolls up the attached evidence by plane + the missing pieces.
func summarizeEvidence(attached []map[string]any, meta map[string]any, verdict string) (map[string]any, []string) {
	byModality := map[string]int{}
	observers := map[string]bool{}
	for _, sig := range attached {
		byModality[fmt.Sprintf("%v", sig["modality_class"])]++
		if o := fmt.Sprintf("%v", sig["observer_id"]); o != "" {
			observers[o] = true
		}
	}
	summary := map[string]any{
		"attached":         len(attached),
		"by_modality":      byModality,
		"observer_count":   len(observers),
		"observer_classes": distinctObserverClasses(attached),
	}
	// The anti-black-box payload: the INDEPENDENT confirming pair the engine actually
	// used, the decisive (trusted) modalities, the one-line verdict reason, and the
	// blast radius. Surfaced verbatim from the corr object so the UI shows the WHY
	// (e.g. "confirmed by A ⟂ B across 2 modalities, both trusted, non-fate-shared")
	// instead of an opaque score — the differentiator over correlation-as-causation.
	if h, ok := meta["hypotheses"].(string); ok && h != "" {
		var hd struct {
			Ranking struct {
				Hypotheses []struct {
					Contradicted   bool     `json:"contradicted"`
					Contradictions []string `json:"contradictions"`
					Satisfied      []string `json:"satisfied"`
					Verdict        struct {
						IndependentPair   []string `json:"independent_pair"`
						ModalityCoverage  []string `json:"modality_coverage"`
						TrustedModalities []string `json:"trusted_modalities"`
						Reasons           []string `json:"reasons"`
						FirstSteps        []string `json:"first_steps"`
					} `json:"verdict"`
				} `json:"hypotheses"`
			} `json:"ranking"`
		}
		if json.Unmarshal([]byte(h), &hd) == nil && len(hd.Ranking.Hypotheses) > 0 {
			top := hd.Ranking.Hypotheses[0]
			v := top.Verdict
			if len(v.IndependentPair) == 2 {
				summary["confirming_pair"] = v.IndependentPair
			}
			if len(v.TrustedModalities) > 0 {
				summary["decisive_modalities"] = v.TrustedModalities
			} else if len(v.ModalityCoverage) > 0 {
				summary["decisive_modalities"] = v.ModalityCoverage
			}
			if len(v.Reasons) > 0 {
				summary["verdict_reason"] = v.Reasons[0]
			}
			// WHY NOT confirmed: when the verdict is short of confirmed, the gate
			// reasons ARE the explanation — surface them all (the "explain why not"
			// product principle), friendly-mapped so no raw modality token leaks.
			if verdict != "confirmed" && len(v.Reasons) > 0 {
				summary["why_not_confirmed"] = friendlyReasons(v.Reasons)
			}
			// Evidence ROLES beyond supporting/missing: discriminating/contradicting
			// evidence the engine actually used to RULE OUT competing causes — shown so
			// the operator sees Correlix reasoned, not just pattern-matched.
			if len(top.Contradictions) > 0 {
				summary["contradicting"] = friendlyReasons(top.Contradictions)
			}
			summary["contradicted"] = top.Contradicted
			if len(v.FirstSteps) > 0 {
				// Guided remediation runbook — the engine's first-response steps for this
				// fault class. Read-only guidance (NOT auto-executed): the operator drives.
				summary["runbook"] = v.FirstSteps
			}
		}
	}
	if a, ok := meta["affected"].(string); ok && a != "" && a != "{}" {
		var af struct {
			Devices    []string `json:"devices"`
			Paths      []string `json:"paths"`
			Interfaces []string `json:"interfaces"`
		}
		if json.Unmarshal([]byte(a), &af) == nil {
			summary["blast_radius"] = map[string]int{
				"devices": len(af.Devices), "paths": len(af.Paths), "interfaces": len(af.Interfaces),
			}
		}
	}
	// engine-declared missing evidence + a derived "independent observer" note.
	var missing []string
	if em, ok := meta["evidence_missing"].(string); ok && em != "" && em != "[]" {
		var arr []string
		if json.Unmarshal([]byte(em), &arr) == nil {
			missing = append(missing, arr...)
		}
	}
	// Suspected = grounded but not independently confirmed → name the missing piece.
	if verdict == "suspected" {
		missing = append(missing, "independent observer (confirm from the neighbor side or a separate probe)")
	}
	return summary, missing
}

func distinctObserverClasses(attached []map[string]any) int {
	c := map[string]bool{}
	for _, sig := range attached {
		c[fmt.Sprintf("%v", sig["modality_class"])] = true
	}
	return len(c)
}

// narrate produces the operator title/summary/next-action (NOC language).
func narrate(verdict string, internal bool, locus string, ann []rcaAnnotation) (title, summary, action string) {
	switch {
	case internal:
		title = "Internal monitoring path"
	case verdict == "confirmed":
		title = "Likely fault location"
	case verdict == "suspected":
		title = "Where evidence points — not confirmed"
	default:
		title = "Observed path relationship"
	}
	where := locus
	if where == "" {
		where = "this path"
	}
	if internal {
		summary = "Internal monitoring check — not a customer-facing fault."
		action = "No customer action — internal self-monitoring."
		return
	}
	switch verdict {
	case "confirmed":
		summary = fmt.Sprintf("Fault localized to %s.", where)
		action = fmt.Sprintf("Act on %s. Owner: %s.", where, ownerOf(ann))
	case "suspected":
		summary = fmt.Sprintf("Possible fault on %s — evidence is grounded but not independently confirmed.", where)
		action = fmt.Sprintf("Check %s and the adjacent peer/provider handoff. Confirm from the neighbor side or an independent probe before escalating.", where)
	default:
		summary = fmt.Sprintf("Signals relate on %s, but the location is not yet established.", where)
		action = "Gather an independent observer before acting."
	}
	return
}

func ownerOf(ann []rcaAnnotation) string {
	for _, a := range ann {
		if a.Owner != "" {
			return a.Owner
		}
	}
	return "network_ops"
}
