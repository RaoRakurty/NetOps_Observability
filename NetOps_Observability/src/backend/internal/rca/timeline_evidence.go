// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package rca

// timeline_evidence.go — the read-side evidence-merge derivation (Phase-2
// W2.5, extracted from package main's correlations.go): re-derives per-signal
// graph linkage (attached/link_status + the reason phrase) from the corr
// object's edges, enriching signal rows IN PLACE for the timeline, path-view
// and ticketing consumers. Pure over the decoded ClickHouse rows.

import (
	"fmt"
	"strings"
)

func SignalNodeKey(sig map[string]any) string {
	return fmt.Sprintf("%v:%v:%v", sig["entity_type"], sig["entity_id"], sig["kind"])
}

// groundingTokens mirrors engine.py Node.tokens(): the identity tokens the
// grounding gate intersects to admit an edge — entity_id, declared entity_tokens,
// the device part of a 'device:iface' id, and the endpoints of an 'a->b' path id.
// Used here ONLY to EXPLAIN (read-side) why a concurrent signal did or didn't
// share grounding with the graph — never to admit edges.
func groundingTokens(sig map[string]any) map[string]bool {
	toks := map[string]bool{}
	id := fmt.Sprintf("%v", sig["entity_id"])
	if id != "" {
		toks[id] = true
	}
	switch et := sig["entity_tokens"].(type) {
	case []any:
		for _, t := range et {
			toks[fmt.Sprintf("%v", t)] = true
		}
	case []string:
		for _, t := range et {
			toks[t] = true
		}
	}
	if i := strings.Index(id, ":"); i > 0 {
		toks[id[:i]] = true
	}
	if strings.Contains(id, "->") {
		for _, p := range strings.Split(id, "->") {
			if p != "" {
				toks[p] = true
			}
		}
	}
	return toks
}

// missingOrUnknownIdentity flags a signal the engine could never ground because
// its entity is absent or unresolved (it can't share a token with anything).
func missingOrUnknownIdentity(id string) bool {
	switch strings.ToLower(strings.TrimSpace(id)) {
	case "", "unknown", "-", "none", "null":
		return true
	}
	return false
}

var _roleWord = map[string]string{
	"supports": "supporting", "contradicts": "contradicting", "discriminates": "discriminating",
}
var _roleRank = map[string]int{"supports": 1, "discriminates": 2, "contradicts": 3}

// MergeTimelineEvidence enriches the window signal slice IN PLACE with each
// signal's authoritative linkage to the object's causal graph, and returns the
// count rollup the Inspector summary uses. The engine records evidence only at
// the EDGE level, so per-signal linkage is DERIVED here at read time from the
// graph membership — it reports the engine's recorded reasoning, it never
// re-decides causality:
//
//   - attached  → the signal's episode is a node on ≥1 edge (or the singleton
//     trigger episode). Carries link_role (supporting/contradicting/
//     discriminating, from edge evidence) + the grounded edges it sits on.
//   - recovery  → a *_clear event; build_nodes() drops clears, so they are never
//     causal nodes (link_reason states exactly that).
//   - malformed → entity identity missing/unknown; can share no grounding token.
//   - unlinked  → concurrent-not-linked. link_reason distinguishes "shares a
//     topology/seam token but no edge met threshold" from "no shared token at
//     all" (faithful to the grounding gate; this is read-side explanation only).
//
// Pure (no I/O) so the join is unit-tested independently of ClickHouse.
func MergeTimelineEvidence(sigRows, evRows, edgeRows []map[string]any, trigger string) map[string]any {
	// Signal-level evidence (currently engine writes none; kept for forward-compat).
	evBySignal := map[string][]map[string]any{}
	byRole := map[string]int{}
	for _, e := range evRows {
		sid := fmt.Sprintf("%v", e["signal_id"])
		evBySignal[sid] = append(evBySignal[sid], e)
		byRole[fmt.Sprintf("%v", e["role"])]++
	}

	// Edge-evidence role per edge (subject_id = "from->to"). The engine emits only
	// 'supports' today; contradicting/discriminating light up automatically here
	// if it ever records them, with no UI change.
	edgeRoleBySubject := map[string]string{}
	for _, e := range evRows {
		if fmt.Sprintf("%v", e["subject_kind"]) == "edge" {
			edgeRoleBySubject[fmt.Sprintf("%v", e["subject_id"])] = fmt.Sprintf("%v", e["role"])
		}
	}

	// Graph membership: node keys on an edge, the grounded edges per node, the
	// grounding-kind rollup, and the strongest evidence role touching each node.
	attachedNodes := map[string]bool{}
	edgesByNode := map[string][]map[string]any{}
	roleByNode := map[string]string{}
	byGrounding := map[string]int{}
	for _, e := range edgeRows {
		from := fmt.Sprintf("%v", e["from_node"])
		to := fmt.Sprintf("%v", e["to_node"])
		attachedNodes[from] = true
		attachedNodes[to] = true
		byGrounding[fmt.Sprintf("%v", e["grounding_kind"])]++
		role := edgeRoleBySubject[from+"->"+to]
		if role == "" {
			role = "supports"
		}
		for _, n := range []string{from, to} {
			if _roleRank[role] > _roleRank[roleByNode[n]] {
				roleByNode[n] = role
			}
		}
		base := map[string]any{
			"grounding_kind": e["grounding_kind"], "grounding_ref": e["grounding_ref"],
			"weight": e["weight"], "direction_basis": e["direction_basis"],
		}
		fwd := map[string]any{"peer": to}
		rev := map[string]any{"peer": from}
		for k, v := range base {
			fwd[k] = v
			rev[k] = v
		}
		edgesByNode[from] = append(edgesByNode[from], fwd)
		edgesByNode[to] = append(edgesByNode[to], rev)
	}
	// A singleton object has 0 edges; its one episode is still "attached" (it IS
	// the object). Promote the trigger signal's node key so its signals render
	// linked rather than orphaned.
	for _, sig := range sigRows {
		if fmt.Sprintf("%v", sig["signal_id"]) == trigger {
			attachedNodes[SignalNodeKey(sig)] = true
			break
		}
	}

	// Pass 1: tokens of the graph (the attached episodes), so a concurrent signal
	// can be told "shares a token with the graph but no edge met threshold" vs
	// "no shared seam/topology token at all" — faithful to the grounding gate.
	graphTokens := map[string]bool{}
	for _, sig := range sigRows {
		if attachedNodes[SignalNodeKey(sig)] {
			for t := range groundingTokens(sig) {
				graphTokens[t] = true
			}
		}
	}

	byModality := map[string]int{}
	attachedByModality := map[string]int{}
	attachedObservers := map[string]bool{}
	byStatus := map[string]int{}
	attached, recovery, unlinked := 0, 0, 0
	for _, sig := range sigRows {
		sid := fmt.Sprintf("%v", sig["signal_id"])
		kind := fmt.Sprintf("%v", sig["kind"])
		modality := fmt.Sprintf("%v", sig["modality_class"])
		entityID := fmt.Sprintf("%v", sig["entity_id"])
		nodeKey := SignalNodeKey(sig)
		sig["evidence"] = evBySignal[sid] // nil → null
		sig["is_trigger"] = sid == trigger
		sig["linked_edges"] = nil
		sig["link_role"] = ""
		byModality[modality]++

		switch {
		case attachedNodes[nodeKey]:
			links := edgesByNode[nodeKey]
			role := roleByNode[nodeKey]
			if role == "" {
				role = "supports"
			}
			sig["attached"] = true
			sig["link_status"] = "attached"
			sig["link_role"] = _roleWord[role]
			sig["linked_edges"] = links
			sig["link_reason"] = attachedReason(links)
			attached++
			attachedByModality[modality]++
			if obs := fmt.Sprintf("%v", sig["observer_id"]); obs != "" {
				attachedObservers[obs] = true
			}
			byStatus["attached/"+_roleWord[role]]++
		case strings.HasSuffix(kind, "_clear"):
			sig["attached"] = false
			sig["link_status"] = "recovery"
			sig["link_reason"] = "recovery/clear event — clears close an episode and are never causal graph nodes"
			recovery++
			byStatus["recovery"]++
		case missingOrUnknownIdentity(entityID):
			sig["attached"] = false
			sig["link_status"] = "malformed"
			sig["link_reason"] = "entity identity missing/unknown — a signal with no resolvable entity can share no seam or topology token, so the engine cannot ground it"
			unlinked++
			byStatus["malformed"]++
		default:
			sig["attached"] = false
			sig["link_status"] = "unlinked"
			if tokensIntersect(groundingTokens(sig), graphTokens) {
				sig["link_reason"] = "shares a topology/seam token with the graph, but no edge met the attach threshold — the correlation weight fell short (timing too far apart and/or single-modality, so no reinforcement)"
			} else {
				sig["link_reason"] = "no shared seam endpoint or topology token connects this episode to the object's graph — the engine counted it as a topology-gap co-occurrence, never an edge"
			}
			unlinked++
			byStatus["concurrent-not-linked"]++
		}
	}
	return map[string]any{
		"total":                len(sigRows),
		"attached":             attached,
		"unattached":           len(sigRows) - attached,
		"recovery":             recovery,
		"unlinked":             unlinked,
		"attached_observers":   len(attachedObservers),
		"by_modality":          byModality,
		"attached_by_modality": attachedByModality,
		"by_role":              byRole,
		"by_grounding":         byGrounding,
		"by_status":            byStatus,
	}
}

// tokensIntersect reports whether two token sets share any member.
func tokensIntersect(a, b map[string]bool) bool {
	if len(a) > len(b) {
		a, b = b, a
	}
	for t := range a {
		if b[t] {
			return true
		}
	}
	return false
}

// attachedReason summarizes how a node is linked into the graph from the grounded
// edges it sits on — distinct grounding kinds + refs, e.g.
// "linked via seam sm-f50987032a4d, topo shared:api".
func attachedReason(links []map[string]any) string {
	if len(links) == 0 {
		return "graph node (singleton episode — opened on severity alone)"
	}
	seen := map[string]bool{}
	parts := make([]string, 0, len(links))
	for _, l := range links {
		key := fmt.Sprintf("%v %v", l["grounding_kind"], l["grounding_ref"])
		if seen[key] {
			continue
		}
		seen[key] = true
		parts = append(parts, fmt.Sprintf("%v %v", l["grounding_kind"], l["grounding_ref"]))
	}
	return "linked via " + strings.Join(parts, ", ")
}

// serveCorrelationDetail renders the object's latest version with its edges in
// one response. Two policy-scoped queries; the hypotheses JSON (ranking +
// embedded grounding context) is passed through verbatim for the UI to render.
