// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Correlix

package logroutine

import (
	"net"
	"sort"
	"strings"
)

// The rule names. Each is the `_name` of its query clause, so OpenSearch
// reports in `matched_queries` which rule made a shown record routine and the
// event panel can say why in one line. The Logs page keys its wording on them
// (src/frontend/src/lib/routineMgmt.ts): renaming one is an API change.
const (
	RulePoll             = "routine_mgmt.poll"
	RuleMonitoringSource = "routine_mgmt.monitoring_source"
	RuleControllerSource = "routine_mgmt.controller_source"
	RuleSessionDetail    = "routine_mgmt.session_detail"
)

// AggName is the filter aggregation that counts the routine records matching
// a search, shown or hidden.
const AggName = "cx_routine_mgmt"

// MaxAddrs bounds each address list (every address becomes query clauses).
const MaxAddrs = 128

// Category is the only event_category a routine record can carry. The packs
// file refusals under security_audit, so a refusal can never reach this class.
const Category = "management_audit"

// sessionDetailTypes are the in-session steps that name no source of their
// own (RuleSessionDetail). Every value is an event_type a pack row emits.
var sessionDetailTypes = []string{
	"audit_session_groups",     // standard.yaml confd_session_groups
	"audit_session_terminated", // standard.yaml confd_session_terminated
	"netconf_rpc",              // standard.yaml confd_netconf_rpc
	"netconf_notification",     // standard.yaml confd_netconf_notification
	"ssh_session_opened",       // standard.yaml sshd_session
	"ssh_session_closed",       // standard.yaml sshd_session
}

// sessionDetailPrefixes: event types a pack templates from a captured word.
var sessionDetailPrefixes = []string{
	"netconf_action_", // standard.yaml confd_netconf_action: netconf_action_{action}
}

// machineInterfaces are the audit_via values of a programmatic interface: a
// person never types a session onto one of these. `cli`, `ssh`, `console`,
// `telnet` and the web UI are deliberately absent.
var machineInterfaces = []string{"snmp", "netconf", "restconf", "gnmi", "gnoi", "grpc"}

// failureWords: a record whose event_type or audit_action carries one of these
// is never routine, whatever else it says (defence in depth: the packs already
// file refusals as security_audit).
var failureWords = []string{"fail", "deni", "reject", "refus", "invalid"}

// Sources are the addresses of the automated systems whose sessions are
// routine. Only parsed IP addresses are kept; nothing else reaches a query.
type Sources struct {
	// Platform: Correlix's own addresses (CX_PLATFORM_ADDRESSES and the
	// probers' declared addresses).
	Platform []string
	// Controllers: the caller's own SD-WAN controller node addresses.
	Controllers []string
}

// CleanAddrs keeps the valid IP addresses of raw, canonical and de-duplicated,
// at most MaxAddrs of them. A CIDR or any other text is dropped: audit_source
// is a keyword field, so a network cannot be matched against it.
func CleanAddrs(raw []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, v := range raw {
		v = strings.TrimSpace(v)
		if strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]") {
			v = v[1 : len(v)-1]
		}
		ip := net.ParseIP(v)
		if ip == nil {
			continue
		}
		s := ip.String()
		if seen[s] {
			continue
		}
		if len(out) >= MaxAddrs {
			break
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Clause is the query that matches routine records. Each rule is a named,
// self-contained clause, so `matched_queries` on a hit names a rule only when
// that rule really classified the record.
func Clause(src Sources) map[string]any {
	rules := []any{
		rule(RulePoll, shouldOne(
			termCI("audit_via", "snmp"),
			map[string]any{"prefix": map[string]any{"event_type": map[string]any{"value": "snmp_", "case_insensitive": true}}},
		)),
	}
	if m := addrMatch(CleanAddrs(src.Platform)); m != nil {
		rules = append(rules, rule(RuleMonitoringSource, map[string]any{"bool": map[string]any{
			"filter": []any{m, machineInterface()},
		}}))
	}
	if m := addrMatch(CleanAddrs(src.Controllers)); m != nil {
		rules = append(rules, rule(RuleControllerSource, map[string]any{"bool": map[string]any{
			"filter": []any{m, shouldOne(
				machineInterface(),
				// sshd's own login line: vManage reaches the edge's NETCONF
				// over SSH. A person on the controller's SSH terminal is
				// still shown by the CLI session record that follows.
				map[string]any{"term": map[string]any{"event_type": "ssh_login_accepted"}},
			)},
		}}))
	}
	detail := []any{map[string]any{"terms": map[string]any{"event_type": append([]string(nil), sessionDetailTypes...)}}}
	for _, p := range sessionDetailPrefixes {
		detail = append(detail, map[string]any{"prefix": map[string]any{"event_type": map[string]any{"value": p}}})
	}
	rules = append(rules, rule(RuleSessionDetail, shouldOne(detail...)))
	return shouldOne(rules...)
}

// Exclusion is the filter that drops routine records (a post_filter or a
// must_not member). It never touches anything but this class.
func Exclusion(src Sources) map[string]any {
	return map[string]any{"bool": map[string]any{"must_not": []any{Clause(src)}}}
}

// Agg counts the routine records matching the search's query.
func Agg(src Sources) map[string]any {
	return map[string]any{"filter": Clause(src)}
}

// rule is one named rule: the management_audit category, the rule's own
// condition, and no failure word.
func rule(name string, cond map[string]any) map[string]any {
	return map[string]any{"bool": map[string]any{
		"_name":    name,
		"filter":   []any{map[string]any{"term": map[string]any{"event_category": Category}}, cond},
		"must_not": failureClauses(),
	}}
}

func failureClauses() []any {
	out := make([]any, 0, 2*len(failureWords))
	for _, field := range []string{"event_type", "audit_action"} {
		for _, w := range failureWords {
			out = append(out, map[string]any{"wildcard": map[string]any{field: map[string]any{"value": "*" + w + "*", "case_insensitive": true}}})
		}
	}
	return out
}

func machineInterface() map[string]any {
	var out []any
	for _, v := range machineInterfaces {
		out = append(out, termCI("audit_via", v))
		// IOS XE's dmiauthd names the transport too: "netconf over ssh".
		out = append(out, map[string]any{"prefix": map[string]any{"audit_via": map[string]any{"value": v + " over ", "case_insensitive": true}}})
	}
	return shouldOne(out...)
}

// addrMatch matches audit_source against the addresses as the packs write it:
// `{src}[:{port}]`, where ConfD brackets an IPv6 source. An unbracketed IPv6
// source with a port appended cannot be told apart from another address, so it
// is matched only without a port: such a record stays visible, the safe way.
// Nil when there are no addresses.
func addrMatch(addrs []string) map[string]any {
	if len(addrs) == 0 {
		return nil
	}
	var exact []string
	var parts []any
	for _, a := range addrs {
		if strings.Contains(a, ":") { // IPv6
			b := "[" + a + "]"
			exact = append(exact, a, b)
			parts = append(parts, map[string]any{"prefix": map[string]any{"audit_source": map[string]any{"value": b + ":"}}})
			continue
		}
		exact = append(exact, a)
		parts = append(parts, map[string]any{"prefix": map[string]any{"audit_source": map[string]any{"value": a + ":"}}})
	}
	parts = append([]any{map[string]any{"terms": map[string]any{"audit_source": exact}}}, parts...)
	return shouldOne(parts...)
}

func termCI(field, value string) map[string]any {
	return map[string]any{"term": map[string]any{field: map[string]any{"value": value, "case_insensitive": true}}}
}

func shouldOne(clauses ...any) map[string]any {
	return map[string]any{"bool": map[string]any{"should": clauses, "minimum_should_match": 1}}
}
