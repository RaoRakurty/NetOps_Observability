// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package nms

import (
	"regexp"
	"strings"
)

// canonical_alarm_kinds.go — the shared fallback that turns a controller
// alarm's text into the correlation engine's CANONICAL kind (source-
// equivalence E2b; vManage has its own rule-keyed table, vmanage_kinds.go).
//
// Catalyst Center, Meraki, NDFC, Prime and Versa each classify the alarms they
// know specifically and used to send everything else — including BGP, OSPF,
// interface, uplink and reboot alarms — as `controller_alarm`, a kind no
// template, producer registry or modality table names. The RCA templates key on
// the kinds a device's own traps and syslog produce; a customer whose only
// source is one of these controllers could not match them.
//
// FIDELITY: doc_claimed. No payload from these controllers has been recorded on
// the lab yet; the rules follow the vendors' documented alarm naming. Each
// connector consults its own specific rules first and this table only as the
// fallback before `controller_alarm`. Modality is unchanged (management_plane).

// canonicalAlarmRule is one ordered rule: the first rule whose pattern matches
// the lower-cased alarm text decides the kind.
type canonicalAlarmRule struct {
	Pattern   *regexp.Regexp
	Kind      string
	StateKind string
}

// canonicalAlarmRules — ORDER MATTERS: specific before general. A transceiver
// alarm also mentions an interface; a BGP alarm may mention a link.
var canonicalAlarmRules = []canonicalAlarmRule{
	{Pattern: regexp.MustCompile(`\b(sfp|transceiver|optic)\b.*\bunsupported\b|\bunsupported\b.*\b(sfp|transceiver|optic)\b`), Kind: "transceiver_unsupported"},
	{Pattern: regexp.MustCompile(`\bbgp\b`), Kind: "bgp_adjacency_change", StateKind: "bgp"},
	{Pattern: regexp.MustCompile(`\bospf\b`), Kind: "ospf_adjacency_change", StateKind: "ospf"},
	{Pattern: regexp.MustCompile(`\bis-?is\b`), Kind: "isis_adjacency_change", StateKind: "isis"},
	{Pattern: regexp.MustCompile(`\beigrp\b|\brouting (neighbor|adjacency|peer)\b`), Kind: "routing_adjacency_change", StateKind: "routing"},
	// A process restarting is not the device restarting.
	{Pattern: regexp.MustCompile(`\b(reboot(ed)?|reload(ed)?|power[- ]?cycle(d)?|cold start|warm start|device restart(ed)?)\b`), Kind: "device_restart"},
	{Pattern: regexp.MustCompile(`\b(interface|port|link|uplink|wan)\b`), Kind: "link_state_change", StateKind: "interface"},
}

var processRestart = regexp.MustCompile(`\bprocess\b`)

// routingOrLifecycleKind returns the canonical kind when the alarm is a routing
// adjacency, a device restart or an optic — the classes a connector's generic
// "down on a device" rule must not swallow — or "".
func routingOrLifecycleKind(text string) string {
	k, _, ok := classifyAlarmText(text)
	if !ok || k == "link_state_change" {
		return ""
	}
	return k
}

// classifyAlarmText returns the canonical kind for an alarm's text, or ok=false
// when no rule matches (the caller then keeps `controller_alarm`).
func classifyAlarmText(text string) (kind, stateKind string, ok bool) {
	t := strings.ToLower(text)
	for _, r := range canonicalAlarmRules {
		if !r.Pattern.MatchString(t) {
			continue
		}
		if r.Kind == "device_restart" && processRestart.MatchString(t) {
			continue // "process restarted" — keep looking (or stay unclassified)
		}
		return r.Kind, r.StateKind, true
	}
	return "", "", false
}

// recoveryWords mark an alarm that reports a return to a good state. Whole
// words only: "uplink" is not "up".
var recoveryWords = regexp.MustCompile(`\b(up|restored|recovered|cleared|resolved|established|back online|came online|online again|reconnected)\b`)

// recoverableKinds are the kinds whose recovery is a `<kind>_clear`.
var recoverableKinds = map[string]bool{
	"link_state_change": true, "bgp_adjacency_change": true, "ospf_adjacency_change": true,
	"isis_adjacency_change": true, "routing_adjacency_change": true, "controller_device_unreachable": true,
	"controller_tunnel_state": true,
}

// alarmTextIsRecovery reports whether an alarm's text says the state came back.
func alarmTextIsRecovery(text string) bool {
	t := strings.ToLower(text)
	if strings.Contains(t, "down") || strings.Contains(t, "lost") || strings.Contains(t, "fail") {
		return false // "went down after coming up" is a fault
	}
	return recoveryWords.MatchString(t)
}

// applyRecovery turns a fault event into the engine's clear convention when its
// text reports a recovery: `<kind>_clear` at info, supporting, with its own
// dedupe identity — the same shape vManage recoveries take.
func applyRecovery(e *ControllerEvent, text string) {
	if strings.HasSuffix(e.NormalizedEventType, "_clear") || !recoverableKinds[e.NormalizedEventType] || !alarmTextIsRecovery(text) {
		return
	}
	e.NormalizedEventType += "_clear"
	e.Severity = "info"
	e.EvidenceRole = RoleSupporting
	if e.CorrelationHints == nil {
		e.CorrelationHints = map[string]string{}
	}
	e.CorrelationHints["transition"] = "recovery"
	if e.EventID != "" {
		e.EventID += ":clear"
	}
}
