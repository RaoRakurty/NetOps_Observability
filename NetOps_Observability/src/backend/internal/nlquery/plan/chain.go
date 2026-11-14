// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package plan

// chain.go — correlated vs causal, kept distinct (tracker 337 N-S3).
//
// "What changed 30 minutes before every SD-WAN incident this week" lists the
// changes found near each incident. Being near is CORRELATION: every row is
// "temporal" and the answer says so. Only the correlation engine's causal chain
// may speak to cause, and today that chain names change KINDS per hypothesis,
// never one ledger row (N-D3: the `corroborating` label waits for the engine to
// name the individual change). So the strongest thing this file may say about
// a row is: "the engine's chain for this incident has a step of the same kind
// as this change" — label "chain_kind". It never says the row caused anything.
//
// The chain is read through an OPTIONAL Scope seam. A Scope without it, an
// incident whose analysis could not be read, or one with no change step leaves
// every row "temporal", and the answer says which incidents were not checked.

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Row relations (closed). The frontend's changes.ts words them.
const (
	// RelationTemporal: found in the window before the incident. Correlated in
	// time, not established as a cause.
	RelationTemporal = "temporal"
	// RelationChainKind: temporal AND the engine's causal chain for that
	// incident names a change step of this change's kind. Still not proof that
	// THIS change is the one the chain means.
	RelationChainKind = "chain_kind"
)

// Statement classes of a row's relation, matching ai/statement_class.go: the
// timing is a computed (DERIVED) fact; the chain step is the engine's own
// (CORRELIX_RCA) conclusion about the incident.
const (
	relationClassDerived = "DERIVED"
	relationClassRCA     = "CORRELIX_RCA"
)

// ChangeChain is the part of one incident's causal chain that concerns
// changes, as the engine stated it.
type ChangeChain struct {
	// Read is false when the analysis could not be read (rows stay temporal and
	// the answer says this incident was not checked against its chain).
	Read bool
	// Kinds are the engine change kinds (config_change, device_config_change,
	// cloud_change, cloud_audit, deploy_event, controller_policy_change) its
	// chain steps observed. Empty: the chain has no change step.
	Kinds []string
	// Step is the 1-based chain step of the first change kind (0 = none).
	Step int
	// Established: the engine itself confirmed the analysis, identified the
	// root cause, and directly observed that change step. Even then it is the
	// KIND that is established, not a particular ledger row.
	Established bool
	// Contradicted: the engine's primary sequence is contradicted, so its
	// change step establishes nothing and is not used.
	Contradicted bool
}

// ChangeChainScope is the OPTIONAL Scope seam for the engine's causal chain of
// one incident, read in the caller's scope. A foreign or unknown incident is
// ErrNotFound, never an empty chain that looks like an answer.
type ChangeChainScope interface {
	ChangeChain(ctx context.Context, incidentID string) (ChangeChain, error)
}

// engineKindsForType maps a change-ledger type onto the engine change kinds a
// change of that type can be observed as. A type with no engine counterpart
// (INFRASTRUCTURE_CHANGE: a change made through Correlix itself) never matches
// a chain step. Kept beside the engine's list in ai/statement_class.go
// (engineChangeKinds); a root test pins that every kind here is one of those.
var engineKindsForType = map[string][]string{
	"CONFIG_CHANGE":          {"config_change", "device_config_change", "controller_policy_change"},
	"NETWORK_CHANGE":         {"config_change", "device_config_change", "controller_policy_change"},
	"ROUTE_CHANGE":           {"config_change", "device_config_change", "cloud_change"},
	"SECURITY_POLICY_CHANGE": {"config_change", "device_config_change", "controller_policy_change", "cloud_change", "cloud_audit"},
	"DNS_CHANGE":             {"config_change", "cloud_change", "cloud_audit"},
	"CLOUD_CHANGE":           {"cloud_change", "cloud_audit"},
	"APPLICATION_DEPLOY":     {"deploy_event", "cloud_change"},
	"FEATURE_FLAG_CHANGE":    {"deploy_event"},
}

// EngineKindsForType exposes the mapping for the drift test.
func EngineKindsForType() map[string][]string {
	out := make(map[string][]string, len(engineKindsForType))
	for k, v := range engineKindsForType {
		out[k] = append([]string(nil), v...)
	}
	return out
}

// chainKindFor returns the engine kind of the chain that a change of ledger
// type typ matches, or "" — only from a READ, non-contradicted chain.
func chainKindFor(typ string, ch ChangeChain) string {
	if !ch.Read || ch.Contradicted || len(ch.Kinds) == 0 {
		return ""
	}
	named := map[string]bool{}
	for _, k := range ch.Kinds {
		named[strings.ToLower(strings.TrimSpace(k))] = true
	}
	for _, k := range engineKindsForType[strings.ToUpper(strings.TrimSpace(typ))] {
		if named[k] {
			return k
		}
	}
	return ""
}

// labelRow stamps the relation of one change row found near an incident.
func labelRow(r Row, ch ChangeChain) {
	r["relation"] = RelationTemporal
	r["relation_class"] = relationClassDerived
	k := chainKindFor(str(r["type"]), ch)
	if k == "" {
		return
	}
	r["relation"] = RelationChainKind
	r["relation_class"] = relationClassRCA
	r["chain_kind"] = k
	if ch.Step > 0 {
		r["chain_step"] = ch.Step
	}
	r["chain_established"] = ch.Established
}

// chainReport is what the answer says about the chain reads, in plain words.
type chainReport struct {
	checked, unread, noChangeStep, contradicted, matched int
	established                                          []string // display ids whose change KIND the engine established
}

func (c *chainReport) notes() []string {
	var out []string
	if c.checked == 0 && c.unread == 0 {
		return nil
	}
	if c.unread > 0 {
		out = append(out, countOf(c.unread, "incident's root-cause analysis could not be read, so its changes are", "incidents' root-cause analyses could not be read, so their changes are")+" shown as correlated in time only")
	}
	if c.noChangeStep > 0 {
		out = append(out, countOf(c.noChangeStep, "incident's causal chain names no change step, so its changes are", "incidents' causal chains name no change step, so their changes are")+" correlated in time only")
	}
	if c.contradicted > 0 {
		out = append(out, countOf(c.contradicted, "incident has", "incidents have")+" a contradicted causal chain; its change step is not used")
	}
	if c.matched > 0 {
		out = append(out, "\"same kind as a chain step\" means the engine's causal chain for that incident names a change of that kind — the chain does not name the individual change, so it is not established that this change caused it")
	}
	if len(c.established) > 0 {
		sort.Strings(c.established)
		out = append(out, "the engine established a change as the root cause of "+strings.Join(c.established, ", ")+" (the kind of change, not which record)")
	}
	return out
}

func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return strconv.Itoa(n) + " " + many
}

// summarizeChangesAroundIncidents writes the answer to "what changed N minutes
// before every X incident", one block per incident in the result's order.
// Wording rule (N-B4, N-S3): a temporal row is "correlated in time, not
// established as a cause"; a chain_kind row is "same kind as a step of the
// engine's causal chain" — never "caused".
func summarizeChangesAroundIncidents(b *strings.Builder, rs *ResultSet) {
	if len(rs.Rows) == 0 {
		b.WriteString("No changes were recorded in the window before any matching incident.")
		writeNotes(b, rs)
		return
	}
	type group struct {
		display, title string
		rows           []Row
	}
	var order []string
	groups := map[string]*group{}
	chainKind := 0
	for _, r := range rs.Rows {
		id := str(r["incident_id"])
		g, ok := groups[id]
		if !ok {
			g = &group{display: firstStr(str(r["incident_display_id"]), id), title: str(r["incident_title"])}
			groups[id] = g
			order = append(order, id)
		}
		g.rows = append(g.rows, r)
		if r["relation"] == RelationChainKind {
			chainKind++
		}
	}
	fmt.Fprintf(b, "%s found before %s", countOf(len(rs.Rows), "change was", "changes were"), countOf(len(order), "incident", "incidents"))
	if rs.Truncated {
		b.WriteString(" (more exist than are shown)")
	}
	b.WriteString(".")
	if chainKind == 0 {
		b.WriteString(" All of them are correlated in time only, not established as causes.")
	} else {
		fmt.Fprintf(b, " %s the same kind as a change step in that incident's causal chain (the chain names the kind, not the individual change); the rest are correlated in time only.",
			countOf(chainKind, "is", "are"))
	}
	for gi, id := range order {
		if gi == summaryItems {
			fmt.Fprintf(b, "\n… and %d more incidents.", len(order)-summaryItems)
			break
		}
		g := groups[id]
		head := g.display
		if g.title != "" {
			head += " " + g.title
		}
		b.WriteString("\n" + head + ":")
		for ri, r := range g.rows {
			if ri == 3 {
				fmt.Fprintf(b, "\n  … and %d more.", len(g.rows)-3)
				break
			}
			b.WriteString("\n  • " + changeLine(r) + " — " + relationPhrase(r))
		}
	}
	writeNotes(b, rs)
}

// relationPhrase is a row's relation in words: never "caused".
func relationPhrase(r Row) string {
	mins := ""
	if m, ok := r["minutes_before_incident"].(int); ok {
		switch {
		case m > 0:
			mins = strconv.Itoa(m) + " min before onset, "
		case m == 0:
			mins = "at onset, "
		default:
			mins = strconv.Itoa(-m) + " min after onset, "
		}
	}
	if r["relation"] == RelationChainKind {
		s := mins + "same kind as step"
		if st, ok := r["chain_step"].(int); ok && st > 0 {
			s += " " + strconv.Itoa(st)
		}
		return s + " of the engine's causal chain (" + str(r["chain_kind"]) + ") — not established that this change caused it"
	}
	return mins + "correlated in time, not established as a cause"
}
