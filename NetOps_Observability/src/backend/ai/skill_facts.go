// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package ai

// skill_facts.go — DEVICE FACTS: what Correlix has DISCOVERED about the device
// in scope, as a closed vocabulary a skill may test (NetClaw ingestion,
// Batch 0, 2026-11-13).
//
// Before this, a skill was chosen from the question's words alone: nothing
// stopped the OSPF method from running against a device with no OSPF at all.
// The owner's rule is that Iris applies its methods to the network Correlix
// discovered, so a skill now says WHERE it applies (`applies_when:`) and a
// `next=` line may branch on a discovered fact (`fact:<key>=<value>`).
//
// THE THREE STATES. A fact is not a boolean:
//
//	holds    the server observed it (OSPF adjacency evidence on this device)
//	fails    the server READ the source that would show it and it is not there
//	unknown  nothing that would show it was read for this device
//
// "Unknown" is the common case and it is never "fails": an unread adjacency
// table is not an absent adjacency. A skill whose applies_when FAILS does not
// gather — the turn says why and moves to a method that fits (owner decision
// 2026-11-13: disclose and reroute). A skill whose applies_when is UNKNOWN runs
// and says what could not be established.
//
// §15. Every fact is derived by the SERVER from inventory, discovered topology
// and the collection configuration, re-validated here against the closed
// vocabulary. The model never supplies one, and a device string can never
// create a key or a value: SetValue / Observe drop anything outside the set.
//
// §3a. The seam that fills DeviceFacts (TroubleshootDeps.DeviceFacts) resolves
// the device through the caller's own inventory; another tenant's device is
// ErrNotFound, exactly like ResolveDevice.

import (
	"fmt"
	"sort"
	"strings"

	"netops/backend/internal/showparse"
)

// CondFactPrefix + a fact KEY is a device-fact condition (`fact:adjacency=ospf`).
const CondFactPrefix = "fact:"

// Fact keys.
const (
	FactRole      = "role"       // the discovery-driven device role
	FactWANFlavor = "wan_flavor" // sdwan | routed, for a WAN edge
	FactDialect   = "dialect"    // the show-command dialect (showparse) or none
	FactAdjacency = "adjacency"  // protocols the device is SEEN to run
	FactTelemetry = "telemetry"  // how Correlix collects from the device
)

// DialectNone is the dialect fact of a device whose platform resolves to no
// supported show-command dialect.
const DialectNone = "none"

// factValueAlt separates alternatives in one condition value
// (`fact:adjacency=ospf|isis` holds when either does).
const factValueAlt = "|"

// maxFactAlternatives bounds the alternatives one condition may name.
const maxFactAlternatives = 6

// skillFactRoles mirrors the canonical device roles of topology/roles.go. The ai
// package does not import topology (it must not depend on the canvas); the
// external test TestFactRolesMatchTheTopologyRoles keeps the two equal.
var skillFactRoles = map[string]bool{
	"access_switch": true, "distribution_switch": true, "core_router": true,
	"firewall": true, "load_balancer": true, "wan_edge": true, "carrier_hop": true,
	"dc_wan_edge": true, "dc_leaf": true, "dc_spine": true, "cloud_edge": true,
}

// skillFactValues is the closed vocabulary: KEY → its value set.
//
// Adding a key or a value is a deliberate edit here PLUS a derivation in the
// server seam (ai_troubleshoot_deps.go aiDeviceFacts); TestEverySkillAppliesWhenIsDerivable
// fails a skill that tests a value no derivation can produce.
var skillFactValues = map[string]map[string]bool{
	FactRole:      skillFactRoles,
	FactWANFlavor: {"sdwan": true, "routed": true},
	FactDialect:   factDialects(),
	// lldp means link-layer neighbour discovery: an LLDP or a CDP adjacency.
	FactAdjacency: {"bgp": true, "ospf": true, "isis": true, "bfd": true, "lldp": true, "overlay": true},
	// snmp / gnmi / api are the CONFIGURED collection methods (api = through a
	// controller); syslog / trap / flow are lanes the device was seen sending on.
	FactTelemetry: {"snmp": true, "gnmi": true, "api": true, "syslog": true, "trap": true, "flow": true},
}

// skillFactMulti are the keys that hold a SET of values (a device runs several
// protocols); the others hold exactly one value.
var skillFactMulti = map[string]bool{FactAdjacency: true, FactTelemetry: true}

func factDialects() map[string]bool {
	out := map[string]bool{DialectNone: true}
	for _, d := range showparse.Dialects() {
		out[string(d)] = true
	}
	return out
}

// FactKeys returns every fact key in sorted order.
func FactKeys() []string {
	out := make([]string, 0, len(skillFactValues))
	for k := range skillFactValues {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// validFact reports whether key=value is inside the closed vocabulary.
func validFact(key, value string) bool {
	vals, ok := skillFactValues[key]
	return ok && vals[value]
}

// DeviceFacts is the server-derived fact set for the device in scope. The zero
// value knows nothing: every condition is unknown.
type DeviceFacts struct {
	// single holds the one value of a single-valued key the server derived.
	single map[string]string
	// seen / absent hold "key=value" of a multi-valued key: observed, or read
	// and not observed.
	seen   map[string]bool
	absent map[string]bool
}

// SetValue records the one derived value of a single-valued key. A key or a
// value outside the vocabulary is refused (false) and nothing is recorded.
func (f *DeviceFacts) SetValue(key, value string) bool {
	value = strings.TrimSpace(value)
	if skillFactMulti[key] || !validFact(key, value) {
		return false
	}
	if f.single == nil {
		f.single = map[string]string{}
	}
	f.single[key] = value
	return true
}

// Observe records one value of a multi-valued key as observed (present) or as
// read-and-not-there (!present). An observation wins over an absence, so two
// sources that disagree read as observed. Out-of-vocabulary input is refused.
func (f *DeviceFacts) Observe(key, value string, present bool) bool {
	value = strings.TrimSpace(value)
	if !skillFactMulti[key] || !validFact(key, value) {
		return false
	}
	if f.seen == nil {
		f.seen, f.absent = map[string]bool{}, map[string]bool{}
	}
	kv := key + "=" + value
	if present {
		f.seen[kv] = true
		delete(f.absent, kv)
		return true
	}
	if !f.seen[kv] {
		f.absent[kv] = true
	}
	return true
}

// Empty reports whether nothing at all is known.
func (f DeviceFacts) Empty() bool {
	return len(f.single) == 0 && len(f.seen) == 0 && len(f.absent) == 0
}

// Value returns a single-valued key's derived value.
func (f DeviceFacts) Value(key string) (string, bool) {
	v, ok := f.single[key]
	return v, ok
}

// Seen returns the observed values of a multi-valued key, sorted.
func (f DeviceFacts) Seen(key string) []string {
	var out []string
	for kv := range f.seen {
		if k, v, _ := strings.Cut(kv, "="); k == key {
			out = append(out, v)
		}
	}
	sort.Strings(out)
	return out
}

// factTruth is the three-state outcome of one fact condition.
type factTruth int

const (
	factUnknown factTruth = iota
	factHolds
	factFails
)

// eval evaluates one `fact:` condition. Alternatives hold when ANY holds; they
// FAIL only when EVERY one was established false; otherwise they are unknown.
func (f DeviceFacts) eval(c SkillCondition) factTruth {
	key, ok := strings.CutPrefix(c.Key, CondFactPrefix)
	if !ok {
		return factUnknown
	}
	failed := 0
	alts := strings.Split(c.Value, factValueAlt)
	for _, v := range alts {
		switch f.evalOne(key, v) {
		case factHolds:
			return factHolds
		case factFails:
			failed++
		}
	}
	if failed == len(alts) {
		return factFails
	}
	return factUnknown
}

func (f DeviceFacts) evalOne(key, value string) factTruth {
	if skillFactMulti[key] {
		kv := key + "=" + value
		switch {
		case f.seen[kv]:
			return factHolds
		case f.absent[kv]:
			return factFails
		}
		return factUnknown
	}
	have, ok := f.single[key]
	switch {
	case !ok:
		return factUnknown
	case have == value:
		return factHolds
	}
	return factFails
}

// parseFactCondition validates the value side of a `fact:<key>=` condition:
// one vocabulary value, or up to maxFactAlternatives of them joined by "|".
func parseFactCondition(key, value string) (SkillCondition, error) {
	fk := strings.TrimPrefix(key, CondFactPrefix)
	vals, known := skillFactValues[fk]
	if !known {
		return SkillCondition{}, fmt.Errorf("fact key %q is not one of %v", fk, FactKeys())
	}
	alts := strings.Split(value, factValueAlt)
	if len(alts) > maxFactAlternatives {
		return SkillCondition{}, fmt.Errorf("fact condition %s=%s names %d alternatives; at most %d", key, value, len(alts), maxFactAlternatives)
	}
	seen := map[string]bool{}
	for _, a := range alts {
		if !vals[a] {
			return SkillCondition{}, fmt.Errorf("fact value %q is not one of %v for key %q", a, sortedKeys(vals), fk)
		}
		if seen[a] {
			return SkillCondition{}, fmt.Errorf("fact value %q is named twice", a)
		}
		seen[a] = true
	}
	return SkillCondition{Key: key, Value: value}, nil
}

// factLabel is the operator-facing wording of one fact value.
func factLabel(key, value string) string {
	switch key {
	case FactAdjacency:
		switch value {
		case "lldp":
			return "LLDP/CDP"
		case "overlay":
			return "SD-WAN overlay"
		case "isis":
			return "IS-IS"
		}
		return strings.ToUpper(value)
	case FactTelemetry:
		switch value {
		case "api":
			return "a controller"
		case "flow":
			return "flow export"
		}
		return strings.ToUpper(value)
	case FactRole:
		return strings.ReplaceAll(value, "_", " ")
	case FactWANFlavor:
		if value == "sdwan" {
			return "SD-WAN"
		}
		return "routed"
	}
	return value
}

func factLabels(key, value string) string {
	alts := strings.Split(value, factValueAlt)
	out := make([]string, 0, len(alts))
	for _, a := range alts {
		out = append(out, factLabel(key, a))
	}
	return strings.Join(out, " or ")
}

// factHuman renders a fact condition, evaluated as t, about the named device:
// the sentence the operator reads beside a reroute or a disclosure.
func factHuman(c SkillCondition, t factTruth, device string, f DeviceFacts) string {
	key := strings.TrimPrefix(c.Key, CondFactPrefix)
	device = firstNonEmpty(device, "the device")
	want := factLabels(key, c.Value)
	switch key {
	case FactAdjacency:
		switch t {
		case factHolds:
			return want + " adjacency evidence is discovered on " + device
		case factFails:
			return "no " + want + " adjacency is discovered on " + device
		}
		return "whether " + device + " runs " + want + " could not be established from what Correlix has discovered"
	case FactTelemetry:
		switch t {
		case factHolds:
			return device + " is collected through " + want
		case factFails:
			return device + " is not collected through " + want
		}
		return "whether " + device + " is collected through " + want + " could not be established"
	case FactDialect:
		have, _ := f.Value(FactDialect)
		switch t {
		case factHolds:
			return device + "'s platform reads as " + have
		case factFails:
			if have == DialectNone {
				return device + "'s platform matches no supported show-command dialect"
			}
			return device + "'s platform reads as " + have + ", not " + want
		}
		return device + "'s platform could not be matched to a show-command dialect"
	default: // role, wan_flavor
		have, _ := f.Value(key)
		noun := "role"
		if key == FactWANFlavor {
			noun = "WAN edge type"
		}
		switch t {
		case factHolds:
			return device + "'s " + noun + " is " + factLabel(key, have)
		case factFails:
			return device + "'s " + noun + " is " + factLabel(key, have) + ", not " + want
		}
		return device + "'s " + noun + " could not be classified"
	}
}

// ---- applicability ----------------------------------------------------------

// skillApplicability is the outcome of a skill's applies_when for one device.
type skillApplicability struct {
	Applies bool
	// Failed are the conditions established FALSE (any one makes Applies false).
	Failed []SkillCondition
	// Unknown are the conditions nothing could establish.
	Unknown []SkillCondition
}

// applicability evaluates sk's applies_when against f. A skill with no
// applies_when applies everywhere; otherwise every condition must hold or be
// unknown.
func (sk *Skill) applicability(f DeviceFacts) skillApplicability {
	out := skillApplicability{Applies: true}
	for _, c := range sk.AppliesWhen {
		switch f.eval(c) {
		case factFails:
			out.Applies = false
			out.Failed = append(out.Failed, c)
		case factUnknown:
			out.Unknown = append(out.Unknown, c)
		}
	}
	return out
}

// notApplicableNote is the disclosure for a skill that was NOT run because a
// discovered fact rules it out.
func notApplicableNote(sk *Skill, a skillApplicability, device string, f DeviceFacts) string {
	reasons := make([]string, 0, len(a.Failed))
	for _, c := range a.Failed {
		reasons = append(reasons, factHuman(c, factFails, device, f))
	}
	return "the " + humanizeSkillName(sk.Name) + " method does not apply here — " + strings.Join(reasons, "; ") +
		" — so it was not run and none of its device reads were issued"
}

// unknownApplicabilityNote is the disclosure for a skill that ran although
// whether it applies could not be established.
func unknownApplicabilityNote(sk *Skill, a skillApplicability, device string, f DeviceFacts) string {
	reasons := make([]string, 0, len(a.Unknown))
	for _, c := range a.Unknown {
		reasons = append(reasons, factHuman(c, factUnknown, device, f))
	}
	return "the " + humanizeSkillName(sk.Name) + " method ran without confirming it applies — " + strings.Join(reasons, "; ")
}
