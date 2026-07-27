package rca

// rca_independence.go — provenance-based independence grouping (Phase B).
//
// The accounting layer must answer: how many INDEPENDENT sources actually stand
// behind a verdict? Raw observer counts over-state it — the same measurement
// stream emits RTT and loss, the raw and normalized copies of one reading arrive
// separately, retries repeat, a finding echoes its source signal. All of those
// are ONE observation, not many.
//
// An independence group collapses observers/observations that share a failure
// path (fate), derived ONLY from provenance:
//   - observer identity,
//   - co-location: agent_host / source_egress (a shared host or NAT egress fails
//     together),
//   - measurement stream: (seam, target, schedule) — the same probe schedule to
//     the same target is one stream however many metrics it emits.
//
// Owner constraint 2 (binding): execution_id ALONE NEVER establishes independence
// and is NEVER used to SEPARATE observers. Two signals with different execution_ids
// from the same schedule/host are the same stream — this file never reads
// execution_id. Absent co-location info never fabricates independence: two records
// with no shared, known fate key stay in distinct groups (fail-closed on the
// grouping — we under-collapse rather than invent a merge), while confirm-
// eligibility (below) is what actually gates whether a group can confirm.

import (
	"sort"
	"strings"
)

// SourceProvenance is the provenance fingerprint of one observation source. Built
// from stored signal fields only; no derived or invented values.
type SourceProvenance struct {
	ObserverID   string
	AgentHost    string
	SourceEgress string
	Modality     string
	SeamID       string
	Target       string
	ScheduleID   string
	// Kind + ProbeAuthority drive confirm-eligibility (not grouping).
	Kind           ObserverKind
	ProbeAuthority string
}

// ConfirmEligible mirrors the verdict gate's `trusted` rule (verdicts.py Witness):
// any non-probe modality may anchor a confirmation; a probe may only at HIGH/MEDIUM
// authority. A low/debug/unclassified probe SUPPORTS a suspicion but never confirms.
// Kind is advisory here — eligibility is decided by modality + probe authority so it
// agrees with the audited Python gate exactly.
func (p SourceProvenance) ConfirmEligible() bool {
	if strings.ToLower(strings.TrimSpace(p.Modality)) != "active_probe" {
		return true
	}
	switch strings.ToLower(strings.TrimSpace(p.ProbeAuthority)) {
	case "high", "medium":
		return true
	}
	return false
}

// sharesFateWith reports whether two sources share a failure path — the same
// independence relation the verdict gate enforces (signals.ProbeFate.shares_fate_with),
// re-derived here for the accounting layer so the two never disagree. NOTE: a
// shared measurement stream requires seam+target+schedule to ALL match (a shared
// target alone is not co-location).
func (p SourceProvenance) sharesFateWith(o SourceProvenance) bool {
	if p.ObserverID != "" && p.ObserverID == o.ObserverID {
		return true
	}
	if p.AgentHost != "" && p.AgentHost == o.AgentHost {
		return true
	}
	if p.SourceEgress != "" && p.SourceEgress == o.SourceEgress {
		return true
	}
	if p.SeamID != "" && p.SeamID == o.SeamID &&
		p.Target != "" && p.Target == o.Target &&
		p.ScheduleID != "" && p.ScheduleID == o.ScheduleID {
		return true
	}
	return false
}

// IndependenceGroup is one deduplicated independent source: the set of observer
// ids that share a fate, with the collective confirm-eligibility and modalities.
type IndependenceGroup struct {
	GroupID         string   `json:"group_id"`
	ObserverIDs     []string `json:"observer_ids"`
	Modalities      []string `json:"modalities"`
	ConfirmEligible bool     `json:"confirm_eligible"`
}

// GroupIndependence collapses provenance records into independence groups via
// union-find over the fate relation. Deterministic: the result depends only on the
// input set, not its order (groups + their members are sorted). Records with an
// empty observer id are ignored (they cannot be a source).
func GroupIndependence(records []SourceProvenance) []IndependenceGroup {
	// De-duplicate to distinct observer ids first — one observer is one node,
	// however many signals it produced. Keep the strongest (confirm-eligible)
	// facts and any non-empty co-location key seen for that observer.
	type node struct {
		prov     SourceProvenance
		eligible bool
	}
	nodes := map[string]*node{}
	var order []string
	for _, rec := range records {
		id := strings.TrimSpace(rec.ObserverID)
		if id == "" {
			continue
		}
		n, ok := nodes[id]
		if !ok {
			n = &node{prov: rec}
			nodes[id] = n
			order = append(order, id)
		} else {
			// Enrich co-location keys if this row carries one the node lacked.
			if n.prov.AgentHost == "" {
				n.prov.AgentHost = rec.AgentHost
			}
			if n.prov.SourceEgress == "" {
				n.prov.SourceEgress = rec.SourceEgress
			}
			if n.prov.SeamID == "" {
				n.prov.SeamID = rec.SeamID
			}
			if n.prov.Target == "" {
				n.prov.Target = rec.Target
			}
			if n.prov.ScheduleID == "" {
				n.prov.ScheduleID = rec.ScheduleID
			}
		}
		if rec.ConfirmEligible() {
			n.eligible = true
		}
	}
	sort.Strings(order)

	// Union-find over the fate relation.
	parent := map[string]string{}
	for _, id := range order {
		parent[id] = id
	}
	find := func(x string) string {
		for parent[x] != x {
			parent[x] = parent[parent[x]]
			x = parent[x]
		}
		return x
	}
	union := func(a, b string) { parent[find(a)] = find(b) }
	for i, a := range order {
		for _, b := range order[i+1:] {
			if nodes[a].prov.sharesFateWith(nodes[b].prov) {
				union(a, b)
			}
		}
	}

	// Collect components.
	members := map[string][]string{}
	for _, id := range order {
		root := find(id)
		members[root] = append(members[root], id)
	}
	var groups []IndependenceGroup
	for root, ids := range members {
		sort.Strings(ids)
		modSet := map[string]bool{}
		eligible := false
		for _, id := range ids {
			modSet[nodes[id].prov.Modality] = true
			if nodes[id].eligible {
				eligible = true
			}
		}
		var mods []string
		for m := range modSet {
			if m != "" {
				mods = append(mods, m)
			}
		}
		sort.Strings(mods)
		groups = append(groups, IndependenceGroup{
			GroupID:         "grp:" + root,
			ObserverIDs:     ids,
			Modalities:      mods,
			ConfirmEligible: eligible,
		})
	}
	sort.Slice(groups, func(i, j int) bool { return groups[i].GroupID < groups[j].GroupID })
	return groups
}

// ConfirmEligibleGroups returns the subset of groups that may anchor a
// confirmation — the mutually-independent confirming sources. Each group is
// independent of every other by construction (union-find over the fate relation),
// so their count is the independent-confirming-source count.
func ConfirmEligibleGroups(groups []IndependenceGroup) []IndependenceGroup {
	var out []IndependenceGroup
	for _, g := range groups {
		if g.ConfirmEligible {
			out = append(out, g)
		}
	}
	return out
}
