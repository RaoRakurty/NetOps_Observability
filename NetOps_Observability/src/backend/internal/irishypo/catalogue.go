// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package irishypo

// catalogue.go — the CLOSED set of hypotheses an investigation can hold.
//
// Each Definition names one observation a read-only tool can settle, the skill
// layers that open it, the tool that tests it, and the server facts that
// support, reject or leave it unknown. Only facts from the closed condition
// vocabulary appear here — typed `state:` fields and protocol-diagnostic
// signature outcomes — so a hypothesis can only ever move on something the
// SERVER derived.
//
// Deliberately NOT in the catalogue:
//   - "a configuration change": get_recent_changes is signal-free on purpose
//     (ai/config_changes.go) — change proximity is an RCA scoring feature, and
//     letting it move a hypothesis here would smuggle it in ahead of the
//     scoring work that makes it defensible;
//   - "route missing" / "ARP/MAC entry missing": those facts describe a SUBJECT
//     address, and no skill's gather binds one today, so a full table read
//     would "reject" a hypothesis about an address nobody looked up.
//
// Engine terms are the words of the ENGINE's verdict phrase that name this
// hypothesis's domain. When the engine has a verdict and its phrase names none
// of them, a supported hypothesis is capped at INCONCLUSIVE (hypothesis.go).

// Definition is one catalogue entry.
type Definition struct {
	ID        string
	Statement string
	// Layers are the skill layers whose methods open this hypothesis.
	Layers []string
	// Tool is the gather step that tests it.
	Tool string
	// Support / Reject / Unknown are evaluated in that precedence after the
	// tool returned ok: Unknown first (the read could not see it), then both.
	Support []Cond
	Reject  []Cond
	Unknown []Cond
	// EngineTerms are verdict-phrase words that name this domain.
	EngineTerms []string
}

func (d Definition) proposedBy(layer string) bool {
	for _, l := range d.Layers {
		if l == layer {
			return true
		}
	}
	return false
}

// namedBy reports whether the engine's verdict phrase names this domain.
func (d Definition) namedBy(phrase map[string]bool) bool {
	for _, w := range d.EngineTerms {
		if phrase[w] {
			return true
		}
	}
	return false
}

func st(facet, value string) Cond { return Cond{Key: KeyStatePrefix + facet, Value: value} }

// stateUnread are the `state:collect` outcomes under which the battery read
// nothing a hypothesis could be settled on.
var stateUnread = []Cond{
	st("collect", "failed"), st("collect", "timed_out"),
	st("collect", "unsupported"), st("collect", "not_wired"),
}

// diagUnread are the diagnostic outcomes that captured nothing to score: the
// device rejected every command, or collection never ran here at all.
var diagUnread = []Cond{
	{Key: KeySignature, Value: SignatureUncollected},
	{Key: KeySignature, Value: SignatureNotCaptured},
}

const (
	toolDeviceState = "get_device_state"
	toolDiagnostic  = "run_protocol_diagnostic"
)

// Catalogue returns the hypothesis catalogue, in proposal order. A fresh copy
// each call, so no caller can mutate the package's definitions.
func Catalogue() []Definition {
	return []Definition{
		{
			ID: "link-down", Statement: "The interface in scope is down",
			Layers: []string{"physical"}, Tool: toolDeviceState,
			Support:     []Cond{st("if_oper", "down"), st("if_oper", "admin_down")},
			Reject:      []Cond{st("if_oper", "up")},
			Unknown:     stateUnread,
			EngineTerms: []string{"link", "interface", "port", "physical", "optic", "optics", "transceiver"},
		},
		{
			ID: "interface-errors", Statement: "The interface is counting errors, CRCs or drops",
			Layers: []string{"physical"}, Tool: toolDeviceState,
			Support:     []Cond{st("if_errors", "present")},
			Reject:      []Cond{st("if_errors", "none")},
			Unknown:     stateUnread,
			EngineTerms: []string{"errors", "error", "crc", "optic", "optics", "physical", "interface", "link"},
		},
		{
			ID: "bgp-session", Statement: "A BGP session on the device is not Established",
			Layers: []string{"bgp"}, Tool: toolDeviceState,
			Support: []Cond{st("bgp_peer", "idle"), st("bgp_peer", "active"),
				st("bgp_peer", "connect"), st("bgp_peer", "other")},
			Reject:      []Cond{st("bgp_peer", "established")},
			Unknown:     append(append([]Cond(nil), stateUnread...), st("bgp_peer", "none")),
			EngineTerms: []string{"bgp", "peer", "session", "neighbor", "neighbour"},
		},
		{
			ID: "bgp-fault-signature", Statement: "A known BGP fault signature matches the device's own output",
			Layers: []string{"bgp"}, Tool: toolDiagnostic,
			Support:     []Cond{{Key: KeySignature, Value: SignatureAny}},
			Reject:      []Cond{{Key: KeySignature, Value: SignatureNone}},
			Unknown:     diagUnread,
			EngineTerms: []string{"bgp", "peer", "session", "neighbor", "neighbour"},
		},
		{
			ID: "igp-adjacency", Statement: "An IGP adjacency on the device is not fully up",
			Layers: []string{"igp"}, Tool: toolDeviceState,
			Support:     []Cond{st("igp_nbr", "not_full"), st("igp_nbr", "none")},
			Reject:      []Cond{st("igp_nbr", "full")},
			Unknown:     stateUnread,
			EngineTerms: []string{"ospf", "isis", "is-is", "igp", "adjacency"},
		},
		{
			ID: "igp-fault-signature", Statement: "A known OSPF / IS-IS fault signature matches the device's own output",
			Layers: []string{"igp"}, Tool: toolDiagnostic,
			Support:     []Cond{{Key: KeySignature, Value: SignatureAny}},
			Reject:      []Cond{{Key: KeySignature, Value: SignatureNone}},
			Unknown:     diagUnread,
			EngineTerms: []string{"ospf", "isis", "is-is", "igp", "adjacency"},
		},
		{
			ID: "control-plane-pressure", Statement: "Control-plane CPU or memory on the device is above 90%",
			Layers: []string{"method"}, Tool: toolDeviceState,
			Support:     []Cond{st("platform", "cpu_high"), st("platform", "mem_high")},
			Reject:      []Cond{st("platform", "ok")},
			Unknown:     stateUnread,
			EngineTerms: []string{"cpu", "memory", "platform"},
		},
	}
}
